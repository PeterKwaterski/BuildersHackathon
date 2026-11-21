#!/usr/bin/env python3
"""Collect answer-independent per-key reads from the pinned sqlglot suite.

The collector works in a temporary copy.  It wraps module/class dictionary
literals without changing their source coordinates, runs the complete suite,
and records which pytest node owns each operation.  Worker-only executor paths
run synchronously, while real subprocesses inherit their parent node ID and
write process-local logs which are merged at session end.
"""

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


PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"

TRACKER = r'''from __future__ import annotations

import atexit
import builtins
import json
import os
from collections import defaultdict
from pathlib import Path


CURRENT_TEST = os.environ.get("BR_PARENT_TEST")
EVENTS = defaultdict(lambda: defaultdict(set))


def record(label, key):
    EVENTS[label][repr(key)].add(CURRENT_TEST or "__NO_TEST__")


class TrackingDict(dict):
    def __init__(self, source, label):
        super().__init__(source)
        self._br_label = label

    def __getitem__(self, key):
        record(self._br_label, key)
        return super().__getitem__(key)

    def get(self, key, default=None):
        record(self._br_label, key)
        return super().get(key, default)

    def __contains__(self, key):
        # Membership observes only key presence, which the runtime gate proves
        # unchanged for a value-only edit.
        record(self._br_label, ("__BR_WILDCARD__", "keys"))
        return super().__contains__(key)

    def __len__(self):
        record(self._br_label, ("__BR_WILDCARD__", "shape"))
        return super().__len__()

    def __iter__(self):
        record(self._br_label, ("__BR_WILDCARD__", "keys"))
        return super().__iter__()

    def __reversed__(self):
        record(self._br_label, ("__BR_WILDCARD__", "keys"))
        return super().__reversed__()

    def keys(self):
        record(self._br_label, ("__BR_WILDCARD__", "keys"))
        return super().keys()

    def items(self):
        record(self._br_label, ("__BR_WILDCARD__", "values"))
        return super().items()

    def values(self):
        record(self._br_label, ("__BR_WILDCARD__", "values"))
        return super().values()

    def copy(self):
        record(self._br_label, ("__BR_WILDCARD__", "values"))
        return super().copy()

    def setdefault(self, key, default=None):
        record(self._br_label, key)
        return super().setdefault(key, default)

    def pop(self, key, *default):
        record(self._br_label, key)
        return super().pop(key, *default)

    def popitem(self):
        record(self._br_label, ("__BR_WILDCARD__", "values"))
        return super().popitem()

    def __setitem__(self, key, value):
        record(self._br_label, key)
        return super().__setitem__(key, value)

    def __delitem__(self, key):
        record(self._br_label, key)
        return super().__delitem__(key)

    def clear(self):
        record(self._br_label, ("__BR_WILDCARD__", "shape"))
        return super().clear()

    def update(self, *args, **kwargs):
        record(self._br_label, ("__BR_WILDCARD__", "values"))
        return super().update(*args, **kwargs)

    def __or__(self, other):
        record(self._br_label, ("__BR_WILDCARD__", "values"))
        return super().__or__(other)

    def __ror__(self, other):
        record(self._br_label, ("__BR_WILDCARD__", "values"))
        return super().__ror__(other)

    def __ior__(self, other):
        record(self._br_label, ("__BR_WILDCARD__", "values"))
        return super().__ior__(other)

    def __eq__(self, other):
        record(self._br_label, ("__BR_WILDCARD__", "values"))
        return super().__eq__(other)

    def __ne__(self, other):
        record(self._br_label, ("__BR_WILDCARD__", "values"))
        return super().__ne__(other)

    def __repr__(self):
        record(self._br_label, ("__BR_WILDCARD__", "values"))
        return super().__repr__()

    def __str__(self):
        record(self._br_label, ("__BR_WILDCARD__", "values"))
        return super().__str__()

    def __sizeof__(self):
        record(self._br_label, ("__BR_WILDCARD__", "shape"))
        return super().__sizeof__()


def trace_dict(label, source):
    return TrackingDict(source, label)


def child_output():
    output_dir = os.environ.get("BR_TRACE_CHILD_DIR")
    if not output_dir or not CURRENT_TEST:
        return
    output = {
        label: {key: sorted(tests) for key, tests in sorted(keys.items())}
        for label, keys in sorted(EVENTS.items())
    }
    path = Path(output_dir, f"{os.getpid()}.json")
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(output, sort_keys=True, separators=(",", ":")))
    temporary.replace(path)


builtins._br_trace_dict = trace_dict
atexit.register(child_output)
'''

PLUGIN = r'''from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import _br_tracker


EXECUTED = set()


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_protocol(item, nextitem):
    EXECUTED.add(item.nodeid)
    _br_tracker.CURRENT_TEST = item.nodeid
    os.environ["BR_PARENT_TEST"] = item.nodeid
    try:
        yield
    finally:
        _br_tracker.CURRENT_TEST = None
        os.environ.pop("BR_PARENT_TEST", None)


def merge_child_logs():
    count = 0
    for path in sorted(Path(os.environ["BR_TRACE_CHILD_DIR"]).glob("*.json")):
        count += 1
        for label, events in json.loads(path.read_text()).items():
            for key, owners in events.items():
                _br_tracker.EVENTS[label][key].update(owners)
    return count


def pytest_sessionfinish(session, exitstatus):
    child_logs = merge_child_logs()
    output = {
        label: {key: sorted(tests) for key, tests in sorted(keys.items())}
        for label, keys in sorted(_br_tracker.EVENTS.items())
    }
    Path(os.environ["BR_TRACE_OUTPUT"]).write_text(
        json.dumps(output, sort_keys=True, separators=(",", ":"))
    )
    Path(os.environ["BR_TRACE_MANIFEST"]).write_text(
        json.dumps(
            {
                "child_logs": child_logs,
                "exitstatus": exitstatus,
                "tests": sorted(EXECUTED),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
'''

SYNC_OPTIMIZER = '''class ProcessPoolExecutor:
    """Synchronous executor used only by the dependency collector."""

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.shutdown()

    def submit(self, func, *args, **kwargs):
        future = Future()
        try:
            future.set_result(func(*args, **kwargs))
        except BaseException as error:
            future.set_exception(error)
        return future

    def shutdown(self, *args, **kwargs):
        pass


'''

SYNC_EXECUTOR = '''class ProcessPoolExecutor:
    """Synchronous executor used only by the dependency collector."""

    def __init__(self, *args, initializer=None, initargs=(), **kwargs):
        if initializer:
            initializer(*initargs)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.shutdown()

    def submit(self, func, *args, **kwargs):
        future = Future()
        try:
            future.set_result(func(*args, **kwargs))
        except BaseException as error:
            future.set_exception(error)
        return future

    def shutdown(self, *args, **kwargs):
        pass


'''


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--tests", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER)
    return parser.parse_args()


def replace_once(path: Path, old: str, new: str) -> None:
    source = path.read_text()
    if source.count(old) != 1:
        raise SystemExit(f"expected one pinned marker in {path}: {old!r}")
    path.write_text(source.replace(old, new))


def synchronous_worker_tests(source: Path) -> None:
    optimizer = source / "tests/test_optimizer.py"
    replace_once(
        optimizer,
        "from concurrent.futures import ProcessPoolExecutor, as_completed, wait",
        "from concurrent.futures import Future, as_completed, wait",
    )
    replace_once(
        optimizer,
        "def parse_and_optimize(func, sql, read_dialect, **kwargs):",
        SYNC_OPTIMIZER + "def parse_and_optimize(func, sql, read_dialect, **kwargs):",
    )

    executor = source / "tests/test_executor.py"
    replace_once(
        executor,
        "from concurrent.futures import ProcessPoolExecutor",
        "from concurrent.futures import Future",
    )
    replace_once(executor, "DIR_TPCH =", SYNC_EXECUTOR + "DIR_TPCH =")


def source_offsets(source: str) -> tuple[list[str], list[int]]:
    lines = source.splitlines(keepends=True)
    offsets = []
    position = 0
    for line in lines:
        offsets.append(position)
        position += len(line)
    return lines, offsets


def absolute_offset(
    lines: list[str], offsets: list[int], line: int, byte_column: int
) -> int:
    raw = lines[line - 1].encode("utf-8")
    prefix = raw[:byte_column].decode("utf-8")
    return offsets[line - 1] + len(prefix)


def instrument_source(source: Path) -> int:
    count = 0
    for path in sorted((source / "sqlglot").rglob("*.py")):
        text = path.read_text()
        tree = ast.parse(text, filename=path.as_posix(), type_comments=True)
        parents = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent
        lines, offsets = source_offsets(text)
        edits = []
        relative = path.relative_to(source).as_posix()
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            if not isinstance(node.value, ast.Dict):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if len(targets) != 1 or not isinstance(targets[0], ast.Name):
                continue
            if not isinstance(parents.get(node), (ast.Module, ast.ClassDef)):
                continue
            label = (
                f"{relative}:{node.lineno}:{node.end_lineno or node.lineno}:"
                f"{targets[0].id}"
            )
            start = absolute_offset(
                lines, offsets, node.value.lineno, node.value.col_offset
            )
            end = absolute_offset(
                lines,
                offsets,
                node.value.end_lineno,
                node.value.end_col_offset,
            )
            edits.extend(((end, ")"), (start, f"_br_trace_dict({label!r}, ")))
            count += 1
        for position, replacement in sorted(edits, reverse=True):
            text = text[:position] + replacement + text[position:]
        if edits:
            path.write_text(text)
    return count


def validate_source(source: Path) -> None:
    revision = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    if revision != PINNED_SHA:
        raise SystemExit(f"source is {revision}, expected {PINNED_SHA}")
    status = subprocess.check_output(
        ["git", "-C", str(source), "status", "--porcelain", "--", "sqlglot", "tests"],
        text=True,
    )
    if status:
        raise SystemExit("pinned sqlglot/tests checkout must be clean")


def main() -> None:
    args = arguments()
    source = args.source.resolve()
    # Keep a virtualenv's launcher path: resolving its symlink loses the
    # environment-specific sys.prefix and installed dependencies.
    python = args.python.expanduser().absolute()
    output = args.output.resolve()
    manifest = (args.manifest or output.with_suffix(".manifest.json")).resolve()
    validate_source(source)
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="blast-radius-dict-trace-") as temporary:
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
        (support / "_br_tracker.py").write_text(TRACKER)
        (support / "dict_tracking_plugin.py").write_text(PLUGIN)
        (support / "sitecustomize.py").write_text("import _br_tracker\n")

        synchronous_worker_tests(work)
        instrumented = instrument_source(work)
        environment = os.environ.copy()
        environment.update(
            {
                "BR_TRACE_CHILD_DIR": str(children),
                "BR_TRACE_MANIFEST": str(manifest),
                "BR_TRACE_OUTPUT": str(output),
                "PYTHONPATH": os.pathsep.join(
                    (str(support), str(work), environment.get("PYTHONPATH", ""))
                ).rstrip(os.pathsep),
                "SKIP_INTEGRATION": "0",
            }
        )
        command = [str(python), "-m", "pytest", "-q", "-p", "dict_tracking_plugin"]
        command.extend(arg for arg in args.pytest_args if arg != "--")
        result = subprocess.run(command, cwd=work, env=environment, check=False)
        if result.returncode:
            raise SystemExit(f"pytest exited {result.returncode}; trace is not admissible")

    trace_manifest = json.loads(manifest.read_text())
    if trace_manifest["exitstatus"] != 0:
        raise SystemExit("pytest manifest records a nonzero exit status")
    if args.tests and not args.pytest_args:
        expected = {
            test["id"] for test in json.loads(args.tests.read_text())["tests"]
        }
        executed = set(trace_manifest["tests"])
        missing = expected - executed
        if missing:
            raise SystemExit(f"trace omitted {len(missing)} runtime tests")
    print(
        f"wrote {output} from {instrumented} dictionaries and "
        f"{len(trace_manifest['tests'])} pytest nodes"
    )


if __name__ == "__main__":
    main()
