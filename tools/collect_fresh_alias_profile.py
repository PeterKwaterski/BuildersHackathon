#!/usr/bin/env python3
"""Trace every inline ``alias_(table_(...))`` site in the pinned suite."""

from __future__ import annotations

import argparse
import ast
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from collect_dict_access import synchronous_worker_tests, validate_source


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--synchronous-workers", action="store_true")
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER)
    return parser.parse_args()


def source_sites(source: Path) -> dict[tuple[str, int], tuple[str, str]]:
    sites = {}
    for path in sorted((source / "sqlglot").rglob("*.py")):
        relative = path.relative_to(source).as_posix()
        tree = ast.parse(path.read_text(), filename=relative, type_comments=True)
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "exp"
                and node.func.attr == "alias_"
                and node.args
            ):
                continue
            inner = node.args[0]
            if not (
                isinstance(inner, ast.Call)
                and isinstance(inner.func, ast.Attribute)
                and isinstance(inner.func.value, ast.Name)
                and inner.func.value.id == "exp"
                and inner.func.attr == "table_"
                and len(inner.args) == 1
                and not inner.keywords
            ):
                continue
            argument = inner.args[0]
            if isinstance(argument, ast.Name):
                argument_kind = f"name:{argument.id}"
            elif isinstance(argument, ast.Constant) and type(argument.value) is str:
                argument_kind = "literal:str"
            else:
                argument_kind = "dynamic"
            label = f"{relative}:{node.lineno}:{node.end_lineno or node.lineno}"
            key = (relative, node.lineno)
            if key in sites:
                raise SystemExit(f"ambiguous site at {relative}:{node.lineno}")
            sites[key] = (label, argument_kind)
    return sites


TRACKER = r'''from __future__ import annotations

import atexit
import json
import os
import sys
import threading
from collections import defaultdict
from pathlib import Path

CURRENT_TEST = os.environ.get("BR_PARENT_TEST")
ROOT = os.environ["FRESH_ALIAS_SOURCE"]
SITES = __SITES__
FILES = {relative for relative, _ in SITES}
EVENTS = defaultdict(lambda: {"owners": set(), "types": set(), "bindings": set()})

def owner():
    return CURRENT_TEST or "__NO_TEST__"

def trace(frame, event, arg):
    if event != "line":
        return trace
    filename = frame.f_code.co_filename
    prefix = ROOT + os.sep
    if not filename.startswith(prefix):
        return trace
    relative = filename[len(prefix):]
    site = SITES.get((relative, frame.f_lineno))
    if site is None:
        return trace
    label, argument_kind = site
    module = frame.f_globals.get("exp")
    try:
        from sqlglot import expressions as canonical
        binding = (
            module is canonical
            and getattr(module, "alias_", None) is canonical.alias_
            and getattr(module, "table_", None) is canonical.table_
        )
    except BaseException:
        binding = False
    if argument_kind.startswith("name:"):
        value = frame.f_locals.get(argument_kind.split(":", 1)[1], _MISSING)
        value_type = f"{type(value).__module__}.{type(value).__qualname__}"
    elif argument_kind == "literal:str":
        value_type = "builtins.str"
    else:
        value_type = "dynamic"
    EVENTS[label]["owners"].add(owner())
    EVENTS[label]["types"].add(value_type)
    EVENTS[label]["bindings"].add(binding)
    return trace

def global_trace(frame, event, arg):
    if event != "call":
        return None
    filename = frame.f_code.co_filename
    prefix = ROOT + os.sep
    if filename.startswith(prefix) and filename[len(prefix):] in FILES:
        return trace
    return None

class _Missing: pass
_MISSING = _Missing()

def document():
    return {
        label: {
            "owners": sorted(event["owners"]),
            "types": sorted(event["types"]),
            "bindings": sorted(event["bindings"]),
        }
        for label, event in sorted(EVENTS.items())
    }

def write_child():
    directory = os.environ.get("FRESH_ALIAS_CHILD_DIR")
    if not directory or not CURRENT_TEST:
        return
    path = Path(directory, f"{os.getpid()}.json")
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(document(), sort_keys=True, separators=(",", ":")))
    temporary.replace(path)

sys.settrace(global_trace)
threading.settrace(global_trace)
atexit.register(write_child)
'''


PLUGIN = r'''from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import _br_fresh_alias

EXECUTED = set()

@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_protocol(item, nextitem):
    EXECUTED.add(item.nodeid)
    _br_fresh_alias.CURRENT_TEST = item.nodeid
    os.environ["BR_PARENT_TEST"] = item.nodeid
    try:
        yield
    finally:
        _br_fresh_alias.CURRENT_TEST = None
        os.environ.pop("BR_PARENT_TEST", None)

def pytest_sessionfinish(session, exitstatus):
    child_count = 0
    for path in sorted(Path(os.environ["FRESH_ALIAS_CHILD_DIR"]).glob("*.json")):
        child_count += 1
        for label, event in json.loads(path.read_text()).items():
            _br_fresh_alias.EVENTS[label]["owners"].update(event["owners"])
            _br_fresh_alias.EVENTS[label]["types"].update(event["types"])
            _br_fresh_alias.EVENTS[label]["bindings"].update(event["bindings"])
    Path(os.environ["FRESH_ALIAS_TRACE"]).write_text(
        json.dumps(_br_fresh_alias.document(), sort_keys=True, separators=(",", ":"))
    )
    Path(os.environ["FRESH_ALIAS_MANIFEST"]).write_text(json.dumps({
        "child_logs": child_count,
        "exitstatus": exitstatus,
        "mode": os.environ["FRESH_ALIAS_MODE"],
        "tests": sorted(EXECUTED),
    }, sort_keys=True, separators=(",", ":")))
'''


def main() -> None:
    args = arguments()
    source = args.source.resolve()
    python = args.python.expanduser().absolute()
    output = args.output.resolve()
    manifest = args.manifest.resolve()
    validate_source(source)
    sites = source_sites(source)
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="blast-radius-fresh-alias-") as temporary:
        temporary_path = Path(temporary)
        work = temporary_path / "sqlglot"
        support = temporary_path / "support"
        children = temporary_path / "children"
        shutil.copytree(source, work, ignore=shutil.ignore_patterns(
            ".git", ".pytest_cache", ".coverage*", "__pycache__", "*.pyc"
        ))
        support.mkdir()
        children.mkdir()
        tracker = TRACKER.replace("__SITES__", repr(sites))
        (support / "_br_fresh_alias.py").write_text(tracker)
        (support / "fresh_alias_plugin.py").write_text(PLUGIN)
        (support / "sitecustomize.py").write_text("import _br_fresh_alias\n")
        if args.synchronous_workers:
            synchronous_worker_tests(work)
        environment = os.environ.copy()
        environment.update({
            "FRESH_ALIAS_CHILD_DIR": str(children),
            "FRESH_ALIAS_MANIFEST": str(manifest),
            "FRESH_ALIAS_MODE": "synchronous-worker" if args.synchronous_workers else "normal",
            "FRESH_ALIAS_SOURCE": str(work),
            "FRESH_ALIAS_TRACE": str(output),
            "PYTHONPATH": os.pathsep.join((str(support), str(work), environment.get("PYTHONPATH", ""))).rstrip(os.pathsep),
            "SKIP_INTEGRATION": "0",
        })
        command = [str(python), "-m", "pytest", "-q", "-p", "fresh_alias_plugin"]
        command.extend(argument for argument in args.pytest_args if argument != "--")
        result = subprocess.run(command, cwd=work, env=environment, check=False)
        if result.returncode:
            raise SystemExit(f"pytest exited {result.returncode}; trace is not admissible")

    document = json.loads(manifest.read_text())
    expected = {test["id"] for test in json.loads(args.tests.read_text())["tests"]}
    missing = expected - set(document.get("tests", ()))
    if document.get("exitstatus") != 0 or missing:
        raise SystemExit(f"inadmissible suite manifest; {len(missing)} tests missing")
    print(f"wrote {output} for {len(sites)} sites and {len(document['tests'])} tests")


if __name__ == "__main__":
    main()
