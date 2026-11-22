#!/usr/bin/env python3
"""Trace single comparisons over exact immutable builtins in the pinned suite."""

from __future__ import annotations

import argparse
import ast
import hashlib
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
)


PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"
PYTHON_VERSION = [3, 13, 18]


def validate_source(source: Path) -> None:
    """Authenticate the detached pinned checkout without requiring git in the image."""
    try:
        revision = (source / ".git" / "HEAD").read_text().strip()
    except OSError as error:
        raise SystemExit("source lacks a readable detached git HEAD") from error
    if revision != PINNED_SHA:
        raise SystemExit(f"source is {revision}, expected {PINNED_SHA}")


TRACKER = r'''from __future__ import annotations

import atexit
import builtins
import json
import operator
import os
import struct
import uuid
from collections import OrderedDict, defaultdict
from concurrent.futures import ProcessPoolExecutor
from itertools import count
from pathlib import Path

CURRENT_TEST = os.environ.get("BR_PARENT_TEST")
ALLOWED_TESTS = json.loads(Path(os.environ["PREDICATE_ALLOWED_TESTS"]).read_text())
OWNER_INDEX = {owner: index for index, owner in enumerate(ALLOWED_TESTS)}
EVENTS = defaultdict(dict)
DIRTY = False
OUTCOME_CACHE = OrderedDict()
VALUE_CACHE = OrderedDict()
SIGNATURE_CACHE = OrderedDict()
IDENTITY_CACHE_LIMIT = 2048
VALUE_CACHE_LIMIT = 32768
SIGNATURE_CACHE_LIMIT = 256
PROCESS_TOKEN = uuid.uuid4().hex
TASK_COUNTER = count()
OPS = {
    "Lt": operator.lt,
    "LtE": operator.le,
    "Gt": operator.gt,
    "GtE": operator.ge,
    "Eq": operator.eq,
    "NotEq": operator.ne,
    "Is": operator.is_,
    "IsNot": operator.is_not,
    "In": lambda left, right: operator.contains(right, left),
    "NotIn": lambda left, right: not operator.contains(right, left),
}
SAFE = (type(None), bool, int, float, str, bytes, type)

def safe(value):
    return type(value) in SAFE or (
        type(value) is tuple and all(safe(item) for item in value)
    )

def domain(value):
    return [type(value).__module__, type(value).__qualname__]

def canonical_pair(left, right):
    seen = {}

    def freeze(value):
        identity = id(value)
        prior = seen.get(identity)
        if prior is not None and prior[0] is value:
            return ("ref", prior[1])
        label = len(seen)
        seen[identity] = (value, label)
        value_type = type(value)
        if value_type is tuple:
            return ("tuple", label, tuple(freeze(item) for item in value))
        if value_type is float:
            return ("float", label, struct.pack(">d", value))
        if value_type is type:
            return ("type", label, value)
        return (value_type.__name__, label, value)

    return freeze(left), freeze(right)

def record(label, signature, owner):
    global DIRTY
    event = EVENTS[label].setdefault(signature, [0, False, set()])
    before = (event[0], event[1], len(event[2]))
    if owner == "__NO_TEST__":
        event[1] = True
    elif owner in OWNER_INDEX:
        event[0] |= 1 << OWNER_INDEX[owner]
    else:
        event[2].add(owner)
    if before != (event[0], event[1], len(event[2])):
        DIRTY = True

def encode_events():
    return {
        label: {
            signature: [format(event[0], "x"), event[1], sorted(event[2])]
            for signature, event in sorted(events.items())
        }
        for label, events in sorted(EVENTS.items())
    }

def merge_event(label, signature, payload):
    event = EVENTS[label].setdefault(signature, [0, False, set()])
    event[0] |= int(payload[0], 16)
    event[1] |= payload[1]
    event[2].update(payload[2])

def serialize_signature(left, right, results):
    key = (
        tuple(domain(left)),
        tuple(domain(right)),
        tuple((name, *results[name]) for name in OPS),
    )
    signature = SIGNATURE_CACHE.get(key)
    if signature is not None:
        SIGNATURE_CACHE.move_to_end(key)
        return signature
    signature = json.dumps(
        {"left": domain(left), "outcomes": results, "right": domain(right)},
        sort_keys=True,
        separators=(",", ":"),
    )
    SIGNATURE_CACHE[key] = signature
    if len(SIGNATURE_CACHE) > SIGNATURE_CACHE_LIMIT:
        SIGNATURE_CACHE.popitem(last=False)
    return signature

def compare(label, left, right, original):
    owner = CURRENT_TEST or "__NO_TEST__"
    key = (type(left), id(left), type(right), id(right))
    cached = OUTCOME_CACHE.get(key)
    if cached is not None:
        cached_left, cached_right, signature = cached
        if cached_left is left and cached_right is right:
            OUTCOME_CACHE.move_to_end(key)
            record(label, signature, owner)
            return OPS[original](left, right)
    if not safe(left) or not safe(right):
        record(label, "__UNSAFE__", owner)
        return OPS[original](left, right)
    numeric = (bool, int, float)
    numeric_pair = type(left) in numeric and type(right) in numeric
    value_key = None
    if not numeric_pair:
        value_key = canonical_pair(left, right)
        signature = VALUE_CACHE.get(value_key)
        if signature is not None:
            VALUE_CACHE.move_to_end(value_key)
            record(label, signature, owner)
            return OPS[original](left, right)
    original_value = None
    original_error = None
    try:
        original_value = OPS[original](left, right)
    except BaseException as error:
        original_error = error

    results = {}
    if numeric_pair:
        base = {}
        for name in ("Lt", "Eq", "Gt"):
            if name == original and original_error is None:
                base[name] = original_value
            else:
                base[name] = OPS[name](left, right)
        values = {
            "Lt": base["Lt"],
            "LtE": base["Lt"] or base["Eq"],
            "Gt": base["Gt"],
            "GtE": base["Gt"] or base["Eq"],
            "Eq": base["Eq"],
            "NotEq": not base["Eq"],
            "Is": left is right,
            "IsNot": left is not right,
        }
        for name in OPS:
            if name in {"In", "NotIn"}:
                results[name] = ["error", "builtins", "TypeError"]
            else:
                result = values[name]
                results[name] = ["value", "bool", repr(result)]
    else:
        for name, operation in OPS.items():
            if name == original:
                if original_error is None:
                    results[name] = [
                        "value",
                        type(original_value).__qualname__,
                        repr(original_value),
                    ]
                else:
                    results[name] = [
                        "error",
                        type(original_error).__module__,
                        type(original_error).__qualname__,
                    ]
                continue
            try:
                result = operation(left, right)
                results[name] = ["value", type(result).__qualname__, repr(result)]
            except BaseException as error:
                results[name] = [
                    "error",
                    type(error).__module__,
                    type(error).__qualname__,
                ]
    signature = serialize_signature(left, right, results)
    OUTCOME_CACHE[key] = (left, right, signature)
    if len(OUTCOME_CACHE) > IDENTITY_CACHE_LIMIT:
        OUTCOME_CACHE.popitem(last=False)
    if value_key is not None:
        VALUE_CACHE[value_key] = signature
        if len(VALUE_CACHE) > VALUE_CACHE_LIMIT:
            VALUE_CACHE.popitem(last=False)
    record(label, signature, owner)
    if original_error is not None:
        raise original_error
    return original_value

def marker(directory, task_id, payload):
    path = Path(os.environ["PREDICATE_CHILD_DIR"], directory, task_id)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    temporary.replace(path)

def run_task(task_id, owner, function, args, kwargs):
    global CURRENT_TEST
    previous_test = CURRENT_TEST
    previous_parent = os.environ.get("BR_PARENT_TEST")
    CURRENT_TEST = owner
    if owner == "__NO_TEST__":
        os.environ.pop("BR_PARENT_TEST", None)
    else:
        os.environ["BR_PARENT_TEST"] = owner
    try:
        return function(*args, **kwargs)
    finally:
        # ProcessPoolExecutor workers can terminate through multiprocessing's
        # fast exit path, which does not guarantee Python atexit handlers.
        # Persist the cumulative per-worker event set at every task boundary.
        write_child()
        marker("completed", task_id, {"owner": owner})
        CURRENT_TEST = previous_test
        if previous_parent is None:
            os.environ.pop("BR_PARENT_TEST", None)
        else:
            os.environ["BR_PARENT_TEST"] = previous_parent

ORIGINAL_SUBMIT = ProcessPoolExecutor.submit

def submit(executor, function, /, *args, **kwargs):
    owner = CURRENT_TEST or "__NO_TEST__"
    task_id = f"{os.getpid()}-{PROCESS_TOKEN}-{next(TASK_COUNTER)}"
    marker("expected", task_id, {"owner": owner})
    return ORIGINAL_SUBMIT(executor, run_task, task_id, owner, function, args, kwargs)

ProcessPoolExecutor.submit = submit

def write_child():
    global DIRTY
    directory = os.environ.get("PREDICATE_CHILD_DIR")
    if not directory or not EVENTS or not DIRTY:
        return
    output = encode_events()
    path = Path(directory, "events", f"{os.getpid()}-{PROCESS_TOKEN}.json")
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(output, sort_keys=True, separators=(",", ":")))
    temporary.replace(path)
    DIRTY = False

builtins._br_compare = compare
atexit.register(write_child)
'''


PLUGIN = r'''from __future__ import annotations

import json
import os
import hashlib
import sys
from pathlib import Path

import pytest
import _br_predicate
from _pytest.subtests import SubtestReport

EXECUTED = []
EXECUTED_SET = set()
SUBTESTS = {"passed": 0, "failed": 0, "skipped": 0}

@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_protocol(item, nextitem):
    if item.nodeid not in EXECUTED_SET:
        EXECUTED_SET.add(item.nodeid)
        EXECUTED.append(item.nodeid)
    _br_predicate.CURRENT_TEST = item.nodeid
    os.environ["BR_PARENT_TEST"] = item.nodeid
    try:
        yield
    finally:
        _br_predicate.CURRENT_TEST = None
        os.environ.pop("BR_PARENT_TEST", None)

def pytest_runtest_logreport(report):
    if isinstance(report, SubtestReport):
        if report.passed:
            SUBTESTS["passed"] += 1
        elif report.failed:
            SUBTESTS["failed"] += 1
        elif report.skipped:
            SUBTESTS["skipped"] += 1

def pytest_sessionfinish(session, exitstatus):
    child_count = 0
    child_root = Path(os.environ["PREDICATE_CHILD_DIR"])
    for path in (child_root / "events").glob("*.json"):
        child_count += 1
        for label, events in json.loads(path.read_text()).items():
            for signature, owners in events.items():
                _br_predicate.merge_event(label, signature, owners)
    output = _br_predicate.encode_events()
    _br_predicate.DIRTY = False
    trace_text = json.dumps(output, sort_keys=True, separators=(",", ":"))
    Path(os.environ["PREDICATE_TRACE"]).write_text(trace_text)
    expected_tasks = {path.name for path in (child_root / "expected").iterdir()}
    completed_tasks = {path.name for path in (child_root / "completed").iterdir()}
    Path(os.environ["PREDICATE_MANIFEST"]).write_text(json.dumps({
        "completed_tasks": len(completed_tasks),
        "exitstatus": exitstatus,
        "child_logs": child_count,
        "expected_tasks": len(expected_tasks),
        "extra_tasks": sorted(completed_tasks - expected_tasks),
        "hash_seed": os.environ.get("PYTHONHASHSEED"),
        "instrumented_sites": int(os.environ["PREDICATE_INSTRUMENTED_SITES"]),
        "missing_tasks": sorted(expected_tasks - completed_tasks),
        "mode": os.environ["PREDICATE_MODE"],
        "python": list(sys.version_info[:3]),
        "subtests": SUBTESTS,
        "tests": EXECUTED,
        "trace_sha256": hashlib.sha256(trace_text.encode()).hexdigest(),
    }, sort_keys=True, separators=(",", ":")))
'''


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=Path("/usr/local/bin/python"))
    parser.add_argument("--tests", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument(
        "--candidate-census",
        type=Path,
        help="research-only JSONL census limiting instrumentation by source line",
    )
    parser.add_argument("--synchronous-workers", action="store_true")
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER)
    return parser.parse_args()


def instrument_source(
    source: Path, candidate_sites: set[tuple[str, int]] | None = None
) -> int:
    count = 0
    comparisons = (
        ast.Lt,
        ast.LtE,
        ast.Gt,
        ast.GtE,
        ast.Eq,
        ast.NotEq,
        ast.Is,
        ast.IsNot,
        ast.In,
        ast.NotIn,
    )
    for path in sorted((source / "sqlglot").rglob("*.py")):
        text = path.read_text()
        tree = ast.parse(text, filename=path.as_posix(), type_comments=True)
        if any(
            isinstance(node, ast.Name) and node.id == "_br_compare"
            for node in ast.walk(tree)
        ):
            raise SystemExit(f"source already binds or reads _br_compare in {path}")
        lines, offsets = source_offsets(text)
        relative = path.relative_to(source).as_posix()
        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        eligible = [
            node
            for node in ast.walk(tree)
            if (
                isinstance(node, ast.Compare)
                and len(node.ops) == 1
                and len(node.comparators) == 1
                and isinstance(node.ops[0], comparisons)
                and (
                    candidate_sites is None
                    or (relative, node.lineno) in candidate_sites
                )
            )
        ]
        eligible_set = set(eligible)
        children: dict[ast.AST | None, list[ast.Compare]] = {}
        positions = {}
        for node in eligible:
            parent = parents.get(node)
            while parent is not None and parent not in eligible_set:
                parent = parents.get(parent)
            children.setdefault(parent, []).append(node)
            positions[node] = (
                absolute_offset(lines, offsets, node.lineno, node.col_offset),
                absolute_offset(lines, offsets, node.end_lineno, node.end_col_offset),
            )

        def render_region(node: ast.AST, owner: ast.Compare) -> str:
            start = absolute_offset(lines, offsets, node.lineno, node.col_offset)
            end = absolute_offset(
                lines, offsets, node.end_lineno, node.end_col_offset
            )
            rendered = text[start:end]
            nested = [
                child
                for child in children.get(owner, ())
                if start <= positions[child][0] and positions[child][1] <= end
            ]
            for child in sorted(nested, key=lambda item: positions[item][0], reverse=True):
                child_start, child_end = positions[child]
                rendered = (
                    rendered[: child_start - start]
                    + render_compare(child)
                    + rendered[child_end - start :]
                )
            return rendered

        def render_compare(node: ast.Compare) -> str:
            label = (
                f"{relative}:{node.lineno}:{node.col_offset}:"
                f"{node.end_lineno}:{node.end_col_offset}"
            )
            left = render_region(node.left, node)
            right = render_region(node.comparators[0], node)
            return (
                f"_br_compare({label!r}, {left}, {right}, "
                f"{type(node.ops[0]).__name__!r})"
            )

        edits = [(*positions[node], render_compare(node)) for node in children.get(None, ())]
        for start, end, replacement in sorted(edits, reverse=True):
            text = text[:start] + replacement + text[end:]
        if eligible:
            path.write_text(text)
            count += len(eligible)
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
        for directory in ("events", "expected", "completed"):
            (children / directory).mkdir()
        allowed_tests = []
        if args.tests:
            test_document = json.loads(args.tests.read_text())
            allowed_tests = [test["id"] for test in test_document["tests"]]
        allowed_path = support / "allowed_tests.json"
        allowed_path.write_text(json.dumps(allowed_tests, separators=(",", ":")))
        (support / "_br_predicate.py").write_text(TRACKER)
        (support / "predicate_plugin.py").write_text(PLUGIN)
        (support / "sitecustomize.py").write_text("import _br_predicate\n")
        if args.synchronous_workers:
            synchronous_worker_tests(work)
        candidate_sites = None
        if args.candidate_census:
            candidate_sites = {
                (row["path"], row["line"])
                for line in args.candidate_census.read_text().splitlines()[1:]
                if line.strip()
                for row in [json.loads(line)]
                if row.get("combined")
            }
        instrumented = instrument_source(work, candidate_sites)
        environment = os.environ.copy()
        environment.update(
            {
                "PREDICATE_CHILD_DIR": str(children),
                "PREDICATE_ALLOWED_TESTS": str(allowed_path),
                "PREDICATE_MANIFEST": str(manifest),
                "PREDICATE_INSTRUMENTED_SITES": str(instrumented),
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
        if args.tests and not args.pytest_args:
            command.extend(
                f"--deselect={test_id}"
                for test_id in test_document.get("skipped", ())
            )
        command.extend(arg for arg in args.pytest_args if arg != "--")
        result = subprocess.run(command, cwd=work, env=environment, check=False)
        if result.returncode:
            raise SystemExit(f"pytest exited {result.returncode}; trace is not admissible")

    trace_manifest = json.loads(manifest.read_text())
    if trace_manifest.get("exitstatus") != 0:
        raise SystemExit("pytest manifest records a nonzero exit status")
    if trace_manifest.get("python") != PYTHON_VERSION:
        raise SystemExit(
            "comparison trace requires exact Python "
            + ".".join(map(str, PYTHON_VERSION))
        )
    if not isinstance(trace_manifest.get("hash_seed"), str):
        raise SystemExit("comparison trace requires an explicit PYTHONHASHSEED")
    if trace_manifest.get("instrumented_sites") != instrumented:
        raise SystemExit("manifest instrumentation count differs")
    if trace_manifest.get("trace_sha256") != hashlib.sha256(output.read_bytes()).hexdigest():
        raise SystemExit("manifest trace digest differs")
    if trace_manifest.get("missing_tasks") or trace_manifest.get("extra_tasks"):
        raise SystemExit(
            "process-task ledger is incomplete: "
            f"missing={len(trace_manifest.get('missing_tasks', ()))} "
            f"extra={len(trace_manifest.get('extra_tasks', ()))}"
        )
    if trace_manifest.get("expected_tasks") != trace_manifest.get("completed_tasks"):
        raise SystemExit("process-task ledger counts differ")
    if args.tests and not args.pytest_args:
        test_document = json.loads(args.tests.read_text())
        expected = [test["id"] for test in test_document["tests"]]
        collected = trace_manifest.get("tests")
        if collected != expected:
            raise SystemExit(
                "trace runtime roster differs: "
                f"expected={len(expected)} actual="
                f"{len(collected) if isinstance(collected, list) else 'invalid'}"
            )
        if trace_manifest.get("subtests") != {
            "failed": 0,
            "passed": 25_440,
            "skipped": 0,
        }:
            raise SystemExit("trace runtime subtest ledger differs")
    mode = "synchronous-worker" if args.synchronous_workers else "normal"
    print(
        f"wrote {output} from {instrumented} predicates, {mode} mode, and "
        f"{len(trace_manifest['tests'])} pytest nodes"
    )


if __name__ == "__main__":
    main()
