#!/usr/bin/env python3
"""Trace simple literal-boundary ordering predicates in the pinned full suite."""

from __future__ import annotations

import argparse
import ast
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from collect_dict_access import (
    absolute_offset,
    source_offsets,
    synchronous_worker_tests,
    validate_source,
)


TRACKER = r'''from __future__ import annotations

import atexit
import builtins
import json
import operator
import os
from collections import defaultdict
from pathlib import Path

CURRENT_TEST = os.environ.get("BR_PARENT_TEST")
EVENTS = defaultdict(lambda: defaultdict(set))
OPS = {
    "Lt": operator.lt,
    "LtE": operator.le,
    "Gt": operator.gt,
    "GtE": operator.ge,
    "Eq": operator.eq,
    "NotEq": operator.ne,
}
SAFE = (type(None), bool, int, float, str, bytes)

def safe(value):
    return type(value) in SAFE or (
        type(value) is tuple and all(safe(item) for item in value)
    )

def compare(label, left, right, original):
    owner = CURRENT_TEST or "__NO_TEST__"
    if not safe(left) or not safe(right):
        EVENTS[label]["__UNSAFE__"].add(owner)
        return OPS[original](left, right)
    results = {}
    for name, operation in OPS.items():
        try:
            result = operation(left, right)
            results[name] = ["value", type(result).__qualname__, repr(result)]
        except BaseException as error:
            results[name] = ["error", type(error).__module__, type(error).__qualname__]
    signature = json.dumps(results, sort_keys=True, separators=(",", ":"))
    EVENTS[label][signature].add(owner)
    return OPS[original](left, right)

def write_child():
    directory = os.environ.get("PREDICATE_CHILD_DIR")
    if not directory or not CURRENT_TEST:
        return
    output = {
        label: {signature: sorted(owners) for signature, owners in sorted(events.items())}
        for label, events in sorted(EVENTS.items())
    }
    path = Path(directory, f"{os.getpid()}.json")
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(output, sort_keys=True, separators=(",", ":")))
    temporary.replace(path)

builtins._br_compare = compare
atexit.register(write_child)
'''


PLUGIN = r'''from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import _br_predicate

EXECUTED = set()

@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_protocol(item, nextitem):
    EXECUTED.add(item.nodeid)
    _br_predicate.CURRENT_TEST = item.nodeid
    os.environ["BR_PARENT_TEST"] = item.nodeid
    try:
        yield
    finally:
        _br_predicate.CURRENT_TEST = None
        os.environ.pop("BR_PARENT_TEST", None)

def pytest_sessionfinish(session, exitstatus):
    child_count = 0
    for path in Path(os.environ["PREDICATE_CHILD_DIR"]).glob("*.json"):
        child_count += 1
        for label, events in json.loads(path.read_text()).items():
            for signature, owners in events.items():
                _br_predicate.EVENTS[label][signature].update(owners)
    output = {
        label: {signature: sorted(owners) for signature, owners in sorted(events.items())}
        for label, events in sorted(_br_predicate.EVENTS.items())
    }
    Path(os.environ["PREDICATE_TRACE"]).write_text(
        json.dumps(output, sort_keys=True, separators=(",", ":"))
    )
    Path(os.environ["PREDICATE_MANIFEST"]).write_text(json.dumps({
        "exitstatus": exitstatus,
        "child_logs": child_count,
        "mode": os.environ["PREDICATE_MODE"],
        "tests": sorted(EXECUTED),
    }, sort_keys=True, separators=(",", ":")))
'''


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=Path("/usr/local/bin/python"))
    parser.add_argument("--tests", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--synchronous-workers", action="store_true")
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER)
    return parser.parse_args()


def literal_boundary(node: ast.Compare) -> bool:
    for operand in (node.left, node.comparators[0]):
        try:
            ast.literal_eval(operand)
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            continue
        return True
    return False


def instrument_source(source: Path) -> int:
    count = 0
    ordering = (ast.Lt, ast.LtE, ast.Gt, ast.GtE)
    for path in sorted((source / "sqlglot").rglob("*.py")):
        text = path.read_text()
        tree = ast.parse(text, filename=path.as_posix(), type_comments=True)
        lines, offsets = source_offsets(text)
        relative = path.relative_to(source).as_posix()
        edits = []
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Compare)
                and len(node.ops) == 1
                and len(node.comparators) == 1
                and isinstance(node.ops[0], ordering)
                and literal_boundary(node)
            ):
                continue
            label = (
                f"{relative}:{node.lineno}:{node.col_offset}:"
                f"{node.end_lineno}:{node.end_col_offset}"
            )
            left = ast.get_source_segment(text, node.left)
            right = ast.get_source_segment(text, node.comparators[0])
            if left is None or right is None:
                raise SystemExit(f"cannot recover predicate operands at {label}")
            replacement = (
                f"_br_compare({label!r}, {left}, {right}, "
                f"{type(node.ops[0]).__name__!r})"
            )
            start = absolute_offset(lines, offsets, node.lineno, node.col_offset)
            end = absolute_offset(
                lines, offsets, node.end_lineno, node.end_col_offset
            )
            edits.append((start, end, replacement))
            count += 1
        for start, end, replacement in sorted(edits, reverse=True):
            text = text[:start] + replacement + text[end:]
        if edits:
            path.write_text(text)
    return count


def main() -> None:
    args = arguments()
    source = args.source.resolve()
    python = args.python.expanduser().absolute()
    output = args.output.resolve()
    manifest = (args.manifest or output.with_suffix(".manifest.json")).resolve()
    validate_source(source)
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="blast-radius-predicate-trace-") as temporary:
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
        (support / "_br_predicate.py").write_text(TRACKER)
        (support / "predicate_plugin.py").write_text(PLUGIN)
        (support / "sitecustomize.py").write_text("import _br_predicate\n")
        if args.synchronous_workers:
            synchronous_worker_tests(work)
        instrumented = instrument_source(work)
        environment = os.environ.copy()
        environment.update(
            {
                "PREDICATE_CHILD_DIR": str(children),
                "PREDICATE_MANIFEST": str(manifest),
                "PREDICATE_MODE": (
                    "synchronous-worker" if args.synchronous_workers else "normal"
                ),
                "PREDICATE_TRACE": str(output),
                "PYTHONPATH": os.pathsep.join(
                    (str(support), str(work), environment.get("PYTHONPATH", ""))
                ).rstrip(os.pathsep),
                "SKIP_INTEGRATION": "0",
            }
        )
        command = [str(python), "-m", "pytest", "-q", "-p", "predicate_plugin"]
        command.extend(arg for arg in args.pytest_args if arg != "--")
        result = subprocess.run(command, cwd=work, env=environment, check=False)
        if result.returncode:
            raise SystemExit(f"pytest exited {result.returncode}; trace is not admissible")

    trace_manifest = json.loads(manifest.read_text())
    if trace_manifest.get("exitstatus") != 0:
        raise SystemExit("pytest manifest records a nonzero exit status")
    if args.tests and not args.pytest_args:
        expected = {test["id"] for test in json.loads(args.tests.read_text())["tests"]}
        missing = expected - set(trace_manifest.get("tests", ()))
        if missing:
            raise SystemExit(f"trace omitted {len(missing)} runtime tests")
    mode = "synchronous-worker" if args.synchronous_workers else "normal"
    print(
        f"wrote {output} from {instrumented} predicates, {mode} mode, and "
        f"{len(trace_manifest['tests'])} pytest nodes"
    )


if __name__ == "__main__":
    main()
