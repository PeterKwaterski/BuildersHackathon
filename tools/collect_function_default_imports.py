#!/usr/bin/env python3
"""Trace literal function defaults consumed while SQLGlot modules are imported."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from collect_dict_access import validate_source
from collect_function_defaults import (
    CALLABLE_NAME,
    ENTER_NAME,
    REFLECT_NAME,
    TRACKER_TEMPLATE,
    file_set_digest,
    instrument_tree,
    source_labels,
)


PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    return parser.parse_args()


def module_names(source: Path) -> list[str]:
    modules = []
    for path in sorted((source / "sqlglot").rglob("*.py")):
        relative = path.relative_to(source).with_suffix("")
        if relative.name == "__main__":
            continue
        parts = list(relative.parts)
        if parts[-1] == "__init__":
            parts.pop()
        modules.append(".".join(parts))
    return modules


def tasks(source: Path) -> list[dict[str, object]]:
    modules = module_names(source)
    dialect_tree = ast.parse((source / "sqlglot/dialects/__init__.py").read_text())
    dialects = next(
        ast.literal_eval(node.value)
        for node in dialect_tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "DIALECTS"
            for target in node.targets
        )
    )
    return [
        *({"kind": "module", "name": module} for module in modules),
        {
            "kind": "dialects",
            "name": "forward",
            "dialects": [dialect.lower() for dialect in dialects],
        },
        {
            "kind": "dialects",
            "name": "reverse",
            "dialects": [dialect.lower() for dialect in reversed(dialects)],
        },
    ]


DRIVER = r'''from __future__ import annotations
import hashlib
import importlib
import json
import os
import traceback
from pathlib import Path
import _br_function_defaults

task = json.loads(os.environ["FUNCTION_DEFAULT_IMPORT_TASK"])
token = hashlib.sha256(
    json.dumps(task, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
directory = Path(os.environ["FUNCTION_DEFAULT_IMPORT_CHILD_DIR"])
(directory / f"{token}.started").write_text(
    json.dumps(task, sort_keys=True, separators=(",", ":"))
)
status = "ok"
error = None
try:
    if task["kind"] == "module":
        importlib.import_module(task["name"])
    elif task["kind"] == "dialects":
        import sqlglot
        if len(sqlglot.Dialect._classes) != 1:
            raise RuntimeError("base import eagerly loaded dialects")
        for dialect in task["dialects"]:
            sqlglot.Dialect.get_or_raise(dialect)
    else:
        raise RuntimeError(f"unknown import task: {task!r}")
except BaseException:
    status = "error"
    error = traceback.format_exc()
events = {
    label: event for label, event in _br_function_defaults.document().items() if event
}
payload = {
    "error": error,
    "events": events,
    "status": status,
    "task": task,
}
temporary = directory / f"{token}.tmp"
temporary.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")))
temporary.replace(directory / f"{token}.json")
if status != "ok":
    raise SystemExit(1)
'''


def main() -> None:
    args = arguments()
    source = args.source.resolve()
    python = args.python.expanduser().absolute()
    output = args.output.resolve()
    manifest = args.manifest.resolve()
    validate_source(source)
    revision = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    if revision != PINNED_SHA:
        raise SystemExit(f"source is {revision}, expected {PINNED_SHA}")
    python_version = subprocess.check_output(
        [str(python), "-c", "import sys; print(sys.version)"], text=True
    ).strip()
    if not python_version.startswith("3.13."):
        raise SystemExit(f"production trace requires Python 3.13, got {python_version!r}")

    declared_tasks = tasks(source)
    canonical_tasks = json.dumps(
        declared_tasks, sort_keys=True, separators=(",", ":")
    ).encode()
    tasks_digest = hashlib.sha256(canonical_tasks).hexdigest()
    modules_digest = hashlib.sha256(
        "\0".join(module_names(source)).encode()
    ).hexdigest()
    collector_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    dependency_digest = hashlib.sha256(
        Path(__file__).with_name("collect_dict_access.py").read_bytes()
    ).hexdigest()
    instrumenter_digest = hashlib.sha256(
        Path(__file__).with_name("collect_function_defaults.py").read_bytes()
    ).hexdigest()
    functions = source_labels(source)
    by_path: dict[str, dict[tuple[int, str], str]] = {}
    for record in functions.values():
        relative, line, qualname = record["id"].split(":", 2)
        by_path.setdefault(relative, {})[(int(line), qualname.rsplit(".", 1)[-1])] = record["id"]

    output.parent.mkdir(parents=True, exist_ok=True)
    manifest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="blast-radius-function-default-import-") as temporary:
        temporary_path = Path(temporary)
        work = temporary_path / "sqlglot"
        support = temporary_path / "support"
        children = temporary_path / "children"
        shutil.copytree(
            source,
            work,
            ignore=shutil.ignore_patterns(
                ".git", ".pytest_cache", ".coverage*", "__pycache__", "*.pyc"
            ),
        )
        support.mkdir()
        children.mkdir()
        tracker = TRACKER_TEMPLATE.replace("__FUNCTIONS__", repr(functions))
        tracker = tracker.replace("__CALLABLE_NAME__", CALLABLE_NAME)
        tracker = tracker.replace("__ENTER_NAME__", ENTER_NAME)
        tracker = tracker.replace("__REFLECT_NAME__", REFLECT_NAME)
        (support / "_br_function_defaults.py").write_text(tracker)
        (support / "sitecustomize.py").write_text("import _br_function_defaults\n")
        (support / "import_driver.py").write_text(DRIVER)
        instrumented = 0
        for path in sorted((work / "sqlglot").rglob("*.py")):
            relative = path.relative_to(work).as_posix()
            instrumented += instrument_tree(path, by_path.get(relative, {}))
        support_digest = file_set_digest(support, list(support.glob("*.py")))
        instrumented_tree_digest = file_set_digest(
            work, list((work / "sqlglot").rglob("*.py"))
        )

        environment = os.environ.copy()
        environment.update({
            "BR_PARENT_TEST": "__IMPORT__",
            "FUNCTION_DEFAULT_IMPORT_CHILD_DIR": str(children),
            "PYTHONPATH": os.pathsep.join(
                (str(support), str(work), environment.get("PYTHONPATH", ""))
            ).rstrip(os.pathsep),
        })
        failures = []
        for task in declared_tasks:
            child_environment = environment | {
                "FUNCTION_DEFAULT_IMPORT_TASK": json.dumps(
                    task, sort_keys=True, separators=(",", ":")
                )
            }
            result = subprocess.run(
                [str(python), str(support / "import_driver.py")],
                cwd=work,
                env=child_environment,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            if result.returncode:
                failures.append((task, result.stderr[-2000:]))

        started = {path.stem for path in children.glob("*.started")}
        completed = {path.stem for path in children.glob("*.json")}
        expected_tokens = {
            hashlib.sha256(
                json.dumps(task, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            for task in declared_tasks
        }
        documents = [
            json.loads((children / f"{token}.json").read_text())
            for token in sorted(completed)
        ]
        if (
            failures
            or started != expected_tokens
            or completed != expected_tokens
            or any(document.get("status") != "ok" for document in documents)
        ):
            first = failures[0] if failures else "child accounting mismatch"
            raise SystemExit(f"inadmissible import trace: {first}")

        merged: dict[str, dict[str, set[str]]] = {}
        for document in documents:
            for label, events in document["events"].items():
                for kind, owners in events.items():
                    merged.setdefault(label, {}).setdefault(kind, set()).update(owners)
        ordered_events = {
            label: {
                kind: sorted(owners) for kind, owners in sorted(events.items())
            }
            for label, events in sorted(merged.items())
        }
        trace = json.dumps({
            "collector_sha256": collector_digest,
            "dependency_sha256": dependency_digest,
            "events": ordered_events,
            "instrumented": instrumented,
            "instrumenter_sha256": instrumenter_digest,
            "instrumented_tree_sha256": instrumented_tree_digest,
            "mode": "import-context",
            "modules_sha256": modules_digest,
            "python": python_version,
            "source_sha": revision,
            "support_sha256": support_digest,
            "tasks_sha256": tasks_digest,
        }, sort_keys=True, separators=(",", ":"))
        output.write_text(trace)
        manifest.write_text(json.dumps({
            "child_complete": started == completed == expected_tokens,
            "child_logs": len(completed),
            "child_starts": len(started),
            "child_tokens_sha256": hashlib.sha256(
                "\0".join(sorted(started)).encode()
            ).hexdigest(),
            "collector_sha256": collector_digest,
            "dependency_sha256": dependency_digest,
            "instrumented": instrumented,
            "instrumenter_sha256": instrumenter_digest,
            "instrumented_tree_sha256": instrumented_tree_digest,
            "mode": "import-context",
            "modules_sha256": modules_digest,
            "python": python_version,
            "source_sha": revision,
            "support_sha256": support_digest,
            "tasks_sha256": tasks_digest,
            "trace_sha256": hashlib.sha256(trace.encode()).hexdigest(),
        }, sort_keys=True, separators=(",", ":")))

    print(
        f"wrote {output} from {len(declared_tasks)} fresh import tasks, "
        f"{instrumented} instrumented sites"
    )


if __name__ == "__main__":
    main()
