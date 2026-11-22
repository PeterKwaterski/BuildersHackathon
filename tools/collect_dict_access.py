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
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"
PINNED_SOURCE_DIGEST = "fc8e3c215f006385b628ef4612295b1d074b93b42de8c773997de3f40103d090"

TRACKER = r'''from __future__ import annotations

import atexit
import builtins
import concurrent.futures
import json
import os
import sys
from collections import defaultdict
from pathlib import Path


CURRENT_TEST = os.environ.get("BR_PARENT_TEST")
EVENTS = defaultdict(lambda: defaultdict(set))
IMPORT_EVENTS = set()
CREATIONS = defaultdict(set)
SUBMITTED_TASKS = set()
COMPLETED_TASKS = set()
TASK_WORKERS = defaultdict(set)
TASK_SEQUENCE = 0
ORIGINAL_PROCESS_POOL = concurrent.futures.ProcessPoolExecutor


def normalized_filename(filename):
    filename = filename.replace("\\", "/")
    matches = [
        (filename.rfind(marker), marker)
        for marker in ("/sqlglot/", "/tests/")
        if marker in filename
    ]
    if matches:
        position, marker = max(matches)
        return marker[1:] + filename[position + len(marker):]
    return filename


def owner():
    if CURRENT_TEST:
        return CURRENT_TEST
    frame = sys._getframe(2)
    while frame:
        filename = normalized_filename(frame.f_code.co_filename)
        if filename.startswith("tests/"):
            return "__BR_COLLECT_FILE__:" + filename
        frame = frame.f_back
    return "__NO_TEST__"


def import_site():
    frame = sys._getframe(3)
    filename = normalized_filename(frame.f_code.co_filename)
    return filename, frame.f_lineno, frame.f_code.co_name


def record(label, key, kind="read"):
    site = None
    if CURRENT_TEST:
        event_owner = CURRENT_TEST
    else:
        site = import_site()
        path, _line, function = site
        event_owner = (
            "__NO_TEST__"
            if function.endswith("Parser") and path.startswith("sqlglot/")
            else owner()
        )
    raw_key = repr(key)
    EVENTS[label][raw_key].add(event_owner)
    if event_owner == "__NO_TEST__":
        filename, line, function = site or import_site()
        IMPORT_EVENTS.add((label, raw_key, kind, filename, line, function))


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
        record(self._br_label, key, "mutation")
        return super().setdefault(key, default)

    def pop(self, key, *default):
        record(self._br_label, key, "mutation")
        return super().pop(key, *default)

    def popitem(self):
        record(self._br_label, ("__BR_WILDCARD__", "values"), "mutation")
        return super().popitem()

    def __setitem__(self, key, value):
        record(self._br_label, key, "mutation")
        return super().__setitem__(key, value)

    def __delitem__(self, key):
        record(self._br_label, key, "mutation")
        return super().__delitem__(key)

    def clear(self):
        record(self._br_label, ("__BR_WILDCARD__", "shape"), "mutation")
        return super().clear()

    def update(self, *args, **kwargs):
        record(self._br_label, ("__BR_WILDCARD__", "values"), "mutation")
        return super().update(*args, **kwargs)

    def __or__(self, other):
        record(self._br_label, ("__BR_WILDCARD__", "values"))
        return super().__or__(other)

    def __ror__(self, other):
        record(self._br_label, ("__BR_WILDCARD__", "values"))
        return super().__ror__(other)

    def __ior__(self, other):
        record(self._br_label, ("__BR_WILDCARD__", "values"), "mutation")
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

    def __reduce__(self):
        record(self._br_label, ("__BR_WILDCARD__", "values"), "pickle")
        return super().__reduce__()

    def __reduce_ex__(self, protocol):
        record(self._br_label, ("__BR_WILDCARD__", "values"), "pickle")
        return super().__reduce_ex__(protocol)


def trace_dict(label, source):
    CREATIONS[label].add(CURRENT_TEST or "__NO_TEST__")
    return TrackingDict(source, label)


def child_output():
    output_dir = os.environ.get("BR_TRACE_CHILD_DIR")
    if not output_dir or (not CURRENT_TEST and not COMPLETED_TASKS):
        return
    output = document()
    path = Path(output_dir, f"{os.getpid()}.json")
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(output, sort_keys=True, separators=(",", ":")))
    temporary.replace(path)


builtins._br_trace_dict = trace_dict
atexit.register(child_output)


def document():
    return {
        "events": {
            label: {key: sorted(tests) for key, tests in sorted(keys.items())}
            for label, keys in sorted(EVENTS.items())
        },
        "creations": {
            label: sorted(owners) for label, owners in sorted(CREATIONS.items())
        },
        "imports": [list(event) for event in sorted(IMPORT_EVENTS)],
        "tasks": {
            "completed": sorted(COMPLETED_TASKS),
            "submitted": sorted(SUBMITTED_TASKS),
            "workers": {
                task: sorted(workers) for task, workers in sorted(TASK_WORKERS.items())
            },
        },
    }


def run_with_owner(function, task, task_owner, args, kwargs):
    global CURRENT_TEST
    prior = CURRENT_TEST
    CURRENT_TEST = task_owner
    if task_owner:
        os.environ["BR_PARENT_TEST"] = task_owner
    else:
        os.environ.pop("BR_PARENT_TEST", None)
    try:
        return function(*args, **kwargs)
    finally:
        COMPLETED_TASKS.add(task)
        TASK_WORKERS[task].add(os.getpid())
        CURRENT_TEST = prior
        if prior:
            os.environ["BR_PARENT_TEST"] = prior
        else:
            os.environ.pop("BR_PARENT_TEST", None)


class AttributedProcessPoolExecutor(ORIGINAL_PROCESS_POOL):
    def __init__(self, *args, **kwargs):
        if kwargs.get("max_workers") is None:
            kwargs["max_workers"] = int(os.environ.get("BR_TRACE_MAX_WORKERS", "2"))
        super().__init__(*args, **kwargs)

    def submit(self, function, /, *args, **kwargs):
        global TASK_SEQUENCE
        task_owner = CURRENT_TEST or os.environ.get("BR_PARENT_TEST")
        task = f"{os.getpid()}:{task_owner or '__NO_TEST__'}#{TASK_SEQUENCE}"
        TASK_SEQUENCE += 1
        SUBMITTED_TASKS.add(task)
        return super().submit(run_with_owner, function, task, task_owner, args, kwargs)


concurrent.futures.ProcessPoolExecutor = AttributedProcessPoolExecutor
'''

PLUGIN = r'''from __future__ import annotations

import hashlib
import json
import os
import sys
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
        document = json.loads(path.read_text())
        for label, events in document.get("events", {}).items():
            for key, owners in events.items():
                _br_tracker.EVENTS[label][key].update(owners)
        _br_tracker.IMPORT_EVENTS.update(
            tuple(event) for event in document.get("imports", ())
        )
        for label, owners in document.get("creations", {}).items():
            _br_tracker.CREATIONS[label].update(owners)
        tasks = document.get("tasks", {})
        _br_tracker.SUBMITTED_TASKS.update(tasks.get("submitted", ()))
        _br_tracker.COMPLETED_TASKS.update(tasks.get("completed", ()))
        for task, workers in tasks.get("workers", {}).items():
            _br_tracker.TASK_WORKERS[task].update(workers)
    return count


def pytest_sessionfinish(session, exitstatus):
    child_logs = merge_child_logs()
    trace_raw = json.dumps(
        _br_tracker.document(), sort_keys=True, separators=(",", ":")
    )
    Path(os.environ["BR_TRACE_OUTPUT"]).write_text(trace_raw)
    Path(os.environ["BR_TRACE_MANIFEST"]).write_text(
        json.dumps(
            {
                "child_logs": child_logs,
                "exitstatus": exitstatus,
                "instrumented": int(os.environ["BR_TRACE_INSTRUMENTED"]),
                "mode": os.environ["BR_TRACE_MODE"],
                "python": sys.version,
                "pool_workers": int(os.environ["BR_TRACE_MAX_WORKERS"]),
                "roster_count": int(os.environ["BR_TRACE_ROSTER_COUNT"]),
                "roster_digest": os.environ["BR_TRACE_ROSTER_DIGEST"],
                "selection": "numbered-roster",
                "source_digest": os.environ["BR_TRACE_SOURCE_DIGEST"],
                "source_sha": os.environ["BR_TRACE_SOURCE_SHA"],
                "submitted_tasks": len(_br_tracker.SUBMITTED_TASKS),
                "completed_tasks": len(_br_tracker.COMPLETED_TASKS),
                "task_workers": len({
                    worker
                    for workers in _br_tracker.TASK_WORKERS.values()
                    for worker in workers
                }),
                "tracker_version": 5,
                "task_attribution": "submit-wrapper-v2",
                "tests": sorted(EXECUTED),
                "trace_sha256": hashlib.sha256(trace_raw.encode()).hexdigest(),
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
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--normal-workers", action="store_true")
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
    paths = sorted((source / "sqlglot").rglob("*.py"))
    paths.extend(sorted((source / "tests").rglob("*.py")))
    for path in paths:
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
            if not isinstance(node.value, (ast.Dict, ast.DictComp)):
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


def validate_source(source: Path, sources_path: Path) -> None:
    with gzip.open(sources_path, "rt", encoding="utf-8") as stream:
        expected = json.load(stream)
    if not isinstance(expected, dict) or any(
        type(path) is not str or type(text) is not str
        for path, text in expected.items()
    ):
        raise SystemExit("malformed pinned source bundle")
    digest = hashlib.sha256(
        "".join(f"{path}\0{expected[path]}\0" for path in sorted(expected)).encode()
    ).hexdigest()
    if digest != PINNED_SOURCE_DIGEST:
        raise SystemExit("pinned source bundle digest mismatch")
    expected_paths = {
        path for path in expected
        if path.startswith("sqlglot/") or path.startswith("tests/")
    }
    actual_paths = {
        path.relative_to(source).as_posix()
        for base in ("sqlglot", "tests")
        for path in (source / base).rglob("*.py")
    }
    if actual_paths != expected_paths:
        raise SystemExit("pinned source file inventory mismatch")
    for path in sorted(expected_paths):
        try:
            actual = (source / path).read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            raise SystemExit(f"unreadable pinned source {path}")
        if actual != expected[path]:
            raise SystemExit(f"pinned source bytes mismatch {path}")


def main() -> None:
    args = arguments()
    source = args.source.resolve()
    # Keep a virtualenv's launcher path: resolving its symlink loses the
    # environment-specific sys.prefix and installed dependencies.
    python = args.python.expanduser().absolute()
    output = args.output.resolve()
    manifest = (args.manifest or output.with_suffix(".manifest.json")).resolve()
    validate_source(source, args.sources.resolve())
    roster = json.loads(args.tests.read_text())["tests"]
    roster_ids = [test["id"] for test in roster]
    roster_digest = hashlib.sha256("\0".join(roster_ids).encode()).hexdigest()
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

        if not args.normal_workers:
            synchronous_worker_tests(work)
        instrumented = instrument_source(work)
        environment = os.environ.copy()
        environment.update(
            {
                "BR_TRACE_CHILD_DIR": str(children),
                "BR_TRACE_MANIFEST": str(manifest),
                "BR_TRACE_OUTPUT": str(output),
                "BR_TRACE_INSTRUMENTED": str(instrumented),
                "BR_TRACE_MODE": "normal" if args.normal_workers else "synchronous-worker",
                "BR_TRACE_MAX_WORKERS": "2",
                "BR_TRACE_ROSTER_COUNT": str(len(roster_ids)),
                "BR_TRACE_ROSTER_DIGEST": roster_digest,
                "BR_TRACE_SOURCE_SHA": PINNED_SHA,
                "BR_TRACE_SOURCE_DIGEST": PINNED_SOURCE_DIGEST,
                "PYTHONPATH": os.pathsep.join(
                    (str(support), str(work), environment.get("PYTHONPATH", ""))
                ).rstrip(os.pathsep),
                "SKIP_INTEGRATION": "0",
            }
        )
        command = [str(python), "-m", "pytest", "-q", "-p", "dict_tracking_plugin"]
        requested = [arg for arg in args.pytest_args if arg != "--"]
        command.extend(requested or roster_ids)
        result = subprocess.run(command, cwd=work, env=environment, check=False)
        if result.returncode:
            raise SystemExit(f"pytest exited {result.returncode}; trace is not admissible")

    trace_manifest = json.loads(manifest.read_text())
    if trace_manifest["exitstatus"] != 0:
        raise SystemExit("pytest manifest records a nonzero exit status")
    trace_raw = output.read_bytes()
    if trace_manifest.get("trace_sha256") != hashlib.sha256(trace_raw).hexdigest():
        raise SystemExit("trace and manifest digest mismatch")
    if trace_manifest.get("submitted_tasks") != trace_manifest.get("completed_tasks"):
        raise SystemExit("one or more submitted process-pool tasks lacks attribution")
    if not args.pytest_args:
        expected = set(roster_ids)
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
