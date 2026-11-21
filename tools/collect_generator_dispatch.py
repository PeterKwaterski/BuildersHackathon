#!/usr/bin/env python3
"""Collect source-derived Generator.TRANSFORMS readers from the pinned suite.

The collector runs only against a temporary copy.  It records the concrete
generator/expression pair presented to the two pinned TRANSFORMS consumers and
direct observations of every source TRANSFORMS dictionary.  It contains no
patch, answer, or failure information.
"""

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

from collect_dict_access import synchronous_worker_tests, validate_source

PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"


TRACKER = r'''from __future__ import annotations
import atexit
import builtins
import hashlib
import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path

CURRENT_TEST = os.environ.get("BR_PARENT_TEST")
PAIRS = defaultdict(set)
TABLES = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
OUTPUT_TOKEN = f"{os.getpid()}-{time.time_ns()}"
IS_CHILD = bool(CURRENT_TEST)
REGISTERED = False

def register_child():
    global IS_CHILD, OUTPUT_TOKEN, REGISTERED
    IS_CHILD = True
    REGISTERED = False
    OUTPUT_TOKEN = f"{os.getpid()}-{time.time_ns()}"

def ensure_registered():
    global REGISTERED
    directory = os.environ.get("GENERATOR_DISPATCH_CHILD_DIR")
    if IS_CHILD and not REGISTERED and directory and CURRENT_TEST:
        Path(directory, f"{OUTPUT_TOKEN}.started").write_text(CURRENT_TEST)
        REGISTERED = True

def owner():
    return CURRENT_TEST or "__NO_TEST__"

def fqn(value):
    cls = value if isinstance(value, type) else type(value)
    return f"{cls.__module__}.{cls.__qualname__}"

def stable_key(key):
    if isinstance(key, type):
        return ["type", key.__module__, key.__qualname__]
    if key is None or isinstance(key, (bool, int, str)):
        return [type(key).__name__, key]
    return ["opaque", type(key).__module__, type(key).__qualname__]

def record_pair(generator, expression, consumer):
    ensure_registered()
    PAIRS[json.dumps([consumer, fqn(generator), fqn(expression)], separators=(",", ":"))].add(owner())

def in_dispatch_builder():
    frame = sys._getframe(2)
    for _ in range(8):
        if frame is None:
            break
        if frame.f_code.co_name == "_build_dispatch" and frame.f_globals.get("__name__") == "sqlglot.generator":
            return True
        frame = frame.f_back
    return False

def callsite():
    frame = sys._getframe(2)
    while frame is not None:
        filename = frame.f_code.co_filename.replace("\\", "/")
        if frame.f_globals.get("__name__") != __name__:
            root = os.environ.get("GENERATOR_DISPATCH_SOURCE_ROOT", "").replace("\\", "/").rstrip("/")
            relative = filename[len(root) + 1:] if root and filename.startswith(root + "/") else filename
            return [relative, frame.f_lineno, frame.f_code.co_name]
        frame = frame.f_back
    return ["<unknown>", 0, "<unknown>"]

def record_table(label, operation, key=None):
    # Copying the complete table into Generator._dispatch stores callables but
    # does not observe their deferred bodies.  Actual dispatch is recorded at
    # the consumer immediately before invocation.
    if in_dispatch_builder():
        return
    ensure_registered()
    encoded = json.dumps({
        "key": stable_key(key) if key is not None else None,
        "site": callsite(),
    }, sort_keys=True, separators=(",", ":"))
    TABLES[label][operation][encoded].add(owner())

class TrackingTransforms(dict):
    def __init__(self, source, label):
        super().__init__(source)
        self._br_label = label
    def __getitem__(self, key):
        record_table(self._br_label, "value", key)
        return super().__getitem__(key)
    def get(self, key, default=None):
        record_table(self._br_label, "value", key)
        return super().get(key, default)
    def __contains__(self, key):
        record_table(self._br_label, "keys", key)
        return super().__contains__(key)
    def __iter__(self):
        record_table(self._br_label, "keys")
        return super().__iter__()
    def __reversed__(self):
        record_table(self._br_label, "keys")
        return super().__reversed__()
    def __len__(self):
        record_table(self._br_label, "shape")
        return super().__len__()
    def keys(self):
        record_table(self._br_label, "keys")
        return super().keys()
    def items(self):
        record_table(self._br_label, "values")
        return super().items()
    def values(self):
        record_table(self._br_label, "values")
        return super().values()
    def copy(self):
        record_table(self._br_label, "values")
        return super().copy()
    def __repr__(self):
        record_table(self._br_label, "values")
        return super().__repr__()
    def __eq__(self, other):
        record_table(self._br_label, "values")
        return super().__eq__(other)
    def __ne__(self, other):
        record_table(self._br_label, "values")
        return super().__ne__(other)
    def __or__(self, other):
        record_table(self._br_label, "values")
        return super().__or__(other)
    def __ror__(self, other):
        record_table(self._br_label, "values")
        return super().__ror__(other)
    def __ior__(self, other):
        record_table(self._br_label, "write")
        return super().__ior__(other)
    def __setitem__(self, key, value):
        record_table(self._br_label, "write", key)
        return super().__setitem__(key, value)
    def __delitem__(self, key):
        record_table(self._br_label, "write", key)
        return super().__delitem__(key)
    def pop(self, key, *default):
        record_table(self._br_label, "pop", key)
        return super().pop(key, *default)
    def popitem(self):
        record_table(self._br_label, "write")
        return super().popitem()
    def clear(self):
        record_table(self._br_label, "write")
        return super().clear()
    def update(self, *args, **kwargs):
        record_table(self._br_label, "write")
        return super().update(*args, **kwargs)
    def setdefault(self, key, default=None):
        record_table(self._br_label, "write", key)
        return super().setdefault(key, default)

def trace_transforms(label, source):
    return TrackingTransforms(source, label)

def document():
    return {
        "mode": os.environ.get("GENERATOR_DISPATCH_MODE"),
        "pairs": {key: sorted(owners) for key, owners in sorted(PAIRS.items())},
        "python": os.environ.get("GENERATOR_DISPATCH_PYTHON"),
        "source_sha": os.environ.get("GENERATOR_DISPATCH_SOURCE_SHA"),
        "tables": {
            label: {
                operation: {key: sorted(owners) for key, owners in sorted(keys.items())}
                for operation, keys in sorted(operations.items())
            }
            for label, operations in sorted(TABLES.items())
        },
        "test_digest": os.environ.get("GENERATOR_DISPATCH_TEST_DIGEST"),
    }

def write_child():
    directory = os.environ.get("GENERATOR_DISPATCH_CHILD_DIR")
    if not IS_CHILD or not REGISTERED or not directory or not CURRENT_TEST:
        return
    path = Path(directory, f"{OUTPUT_TOKEN}.json")
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(document(), sort_keys=True, separators=(",", ":")))
    temporary.replace(path)

builtins._br_record_generator_dispatch = record_pair
builtins._br_trace_transforms = trace_transforms
if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=register_child)
atexit.register(write_child)
'''


PLUGIN = r'''from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import pytest
import _br_generator_dispatch as tracker

EXECUTED = set()

@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_protocol(item, nextitem):
    EXECUTED.add(item.nodeid)
    tracker.CURRENT_TEST = item.nodeid
    os.environ["BR_PARENT_TEST"] = item.nodeid
    try:
        yield
    finally:
        tracker.CURRENT_TEST = None
        os.environ.pop("BR_PARENT_TEST", None)

def merge(document):
    if (
        document.get("mode") != os.environ["GENERATOR_DISPATCH_MODE"]
        or document.get("python") != os.environ["GENERATOR_DISPATCH_PYTHON"]
        or document.get("source_sha") != os.environ["GENERATOR_DISPATCH_SOURCE_SHA"]
        or document.get("test_digest") != os.environ["GENERATOR_DISPATCH_TEST_DIGEST"]
    ):
        raise RuntimeError("child generator-dispatch provenance mismatch")
    for key, owners in document.get("pairs", {}).items():
        tracker.PAIRS[key].update(owners)
    for label, operations in document.get("tables", {}).items():
        for operation, keys in operations.items():
            for key, owners in keys.items():
                tracker.TABLES[label][operation][key].update(owners)

def pytest_sessionfinish(session, exitstatus):
    child_directory = Path(os.environ["GENERATOR_DISPATCH_CHILD_DIR"])
    completed = {path.stem for path in child_directory.glob("*.json")}
    started = {path.stem for path in child_directory.glob("*.started")}
    for path in sorted(child_directory.glob("*.json")):
        merge(json.loads(path.read_text()))
    trace = json.dumps(tracker.document(), sort_keys=True, separators=(",", ":"))
    Path(os.environ["GENERATOR_DISPATCH_OUTPUT"]).write_text(trace)
    Path(os.environ["GENERATOR_DISPATCH_MANIFEST"]).write_text(json.dumps({
        "child_complete": started == completed,
        "child_logs": len(completed),
        "child_starts": len(started),
        "child_tokens_sha256": hashlib.sha256("\0".join(sorted(started)).encode()).hexdigest(),
        "exitstatus": exitstatus,
        "mode": os.environ["GENERATOR_DISPATCH_MODE"],
        "python": os.environ["GENERATOR_DISPATCH_PYTHON"],
        "source_sha": os.environ["GENERATOR_DISPATCH_SOURCE_SHA"],
        "test_digest": os.environ["GENERATOR_DISPATCH_TEST_DIGEST"],
        "tests": sorted(EXECUTED),
        "trace_sha256": hashlib.sha256(trace.encode()).hexdigest(),
    }, sort_keys=True, separators=(",", ":")))
'''


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


def source_offsets(source: str) -> tuple[list[str], list[int]]:
    lines = source.splitlines(keepends=True)
    offsets, position = [], 0
    for line in lines:
        offsets.append(position)
        position += len(line)
    return lines, offsets


def absolute_offset(lines: list[str], offsets: list[int], line: int, byte_column: int) -> int:
    prefix = lines[line - 1].encode("utf-8")[:byte_column].decode("utf-8")
    return offsets[line - 1] + len(prefix)


def transform_assignments(tree: ast.Module):
    result = []

    def visit(body: list[ast.stmt], owner: tuple[str, ...]) -> None:
        for statement in body:
            if isinstance(statement, ast.ClassDef):
                visit(statement.body, (*owner, statement.name))
                continue
            targets = statement.targets if isinstance(statement, ast.Assign) else (
                [statement.target] if isinstance(statement, ast.AnnAssign) else []
            )
            if (
                len(targets) == 1
                and isinstance(targets[0], ast.Name)
                and targets[0].id == "TRANSFORMS"
                and isinstance(getattr(statement, "value", None), ast.Dict)
            ):
                result.append((statement, owner))

    visit(tree.body, ())
    return result


def instrument_source(source: Path) -> int:
    count = 0
    for path in sorted((source / "sqlglot").rglob("*.py")):
        text = path.read_text()
        tree = ast.parse(text, filename=path.as_posix(), type_comments=True)
        lines, offsets = source_offsets(text)
        edits: list[tuple[int, str]] = []
        relative = path.relative_to(source).as_posix()
        for statement, owner in transform_assignments(tree):
            value = statement.value
            label = f"{relative}:{statement.lineno}:{statement.end_lineno or statement.lineno}:{'.'.join(owner)}"
            start = absolute_offset(lines, offsets, value.lineno, value.col_offset)
            end = absolute_offset(lines, offsets, value.end_lineno, value.end_col_offset)
            edits.extend(((end, ")"), (start, f"_br_trace_transforms({label!r}, ")))
            count += 1
        for position, replacement in sorted(edits, reverse=True):
            text = text[:position] + replacement + text[position:]
        if edits:
            path.write_text(text)

    generator = source / "sqlglot/generator.py"
    text = generator.read_text()
    dispatch_marker = "        handler = self._dispatch.get(expression.__class__)"
    direct_marker = "            transform = self.TRANSFORMS.get(expression.__class__)"
    if text.count(dispatch_marker) != 1 or text.count(direct_marker) != 1:
        raise SystemExit("pinned generator dispatch markers changed")
    text = text.replace(
        dispatch_marker,
        "        _br_record_generator_dispatch(self, expression, 'dispatch')\n" + dispatch_marker,
    ).replace(
        direct_marker,
        "            _br_record_generator_dispatch(self, expression, 'json-path')\n" + direct_marker,
    )
    generator.write_text(text)
    return count


def main() -> None:
    args = arguments()
    source = args.source.resolve()
    python = args.python.expanduser().absolute()
    output = args.output.resolve()
    manifest = args.manifest.resolve()
    validate_source(source)
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="blast-radius-generator-dispatch-") as temporary:
        root = Path(temporary)
        work, support, children = root / "sqlglot", root / "support", root / "children"
        shutil.copytree(source, work, ignore=shutil.ignore_patterns(
            ".git", ".pytest_cache", ".coverage*", "__pycache__", "*.pyc"
        ))
        support.mkdir()
        children.mkdir()
        if args.synchronous_workers:
            synchronous_worker_tests(work)
        instrumented = instrument_source(work)
        (support / "_br_generator_dispatch.py").write_text(TRACKER)
        (support / "generator_dispatch_plugin.py").write_text(PLUGIN)
        (support / "sitecustomize.py").write_text("import _br_generator_dispatch\n")
        environment = os.environ.copy()
        test_ids = [test["id"] for test in json.loads(args.tests.read_text())["tests"]]
        test_digest = hashlib.sha256("\0".join(test_ids).encode()).hexdigest()
        python_version = subprocess.check_output(
            [str(python), "-c", "import sys; print(sys.version)"], text=True
        ).strip()
        if not python_version.startswith("3.13."):
            raise SystemExit(f"production trace requires Python 3.13, got {python_version!r}")
        environment.update({
            "GENERATOR_DISPATCH_CHILD_DIR": str(children),
            "GENERATOR_DISPATCH_MANIFEST": str(manifest),
            "GENERATOR_DISPATCH_MODE": "synchronous-worker" if args.synchronous_workers else "normal",
            "GENERATOR_DISPATCH_OUTPUT": str(output),
            "GENERATOR_DISPATCH_PYTHON": python_version,
            "GENERATOR_DISPATCH_SOURCE_ROOT": str(work),
            "GENERATOR_DISPATCH_SOURCE_SHA": PINNED_SHA,
            "GENERATOR_DISPATCH_TEST_DIGEST": test_digest,
            "PYTHONPATH": os.pathsep.join((str(support), str(work), environment.get("PYTHONPATH", ""))).rstrip(os.pathsep),
            "SKIP_INTEGRATION": "0",
        })
        command = [str(python), "-m", "pytest", "-q", "-p", "generator_dispatch_plugin"]
        command.extend(argument for argument in args.pytest_args if argument != "--")
        result = subprocess.run(command, cwd=work, env=environment, check=False)
        if result.returncode:
            raise SystemExit(f"pytest exited {result.returncode}; trace is inadmissible")
    document = json.loads(manifest.read_text())
    expected = {test["id"] for test in json.loads(args.tests.read_text())["tests"]}
    missing = expected - set(document.get("tests", ()))
    if document.get("exitstatus") != 0 or (missing and not args.pytest_args):
        raise SystemExit(f"inadmissible manifest; {len(missing)} tests missing")
    print(f"wrote {output} from {instrumented} TRANSFORMS dictionaries and {len(document['tests'])} tests")


if __name__ == "__main__":
    main()
