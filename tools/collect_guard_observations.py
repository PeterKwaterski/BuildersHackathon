#!/usr/bin/env python3
"""Collect per-test operand states for simple production guard expressions.

The collector runs only in a temporary copy of the pinned tree.  It preserves
the value and evaluation count of every wrapped operand, attributes ordinary
children through ``BR_PARENT_TEST``, and explicitly relabels persistent pool
tasks so a worker inherited from one test cannot contaminate another owner.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from collect_dict_access import synchronous_worker_tests, validate_source
from guard_profile_common import GUARD_NODES, label, none_comparison, source_sites, truth_form


PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"
TRUTH_HOOK = "_br_guard_truth_78c49f"
NONE_HOOK = "_br_guard_none_78c49f"


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--runtime-image", required=True)
    parser.add_argument("--synchronous-workers", action="store_true")
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER)
    return parser.parse_args()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_tracked_paths(source: Path) -> list[Path]:
    """Return the complete, safe Git-tracked inventory for materialization."""

    try:
        raw_paths = subprocess.check_output(
            ["git", "-C", str(source), "ls-files", "-z"],
        ).split(b"\0")
    except (OSError, subprocess.CalledProcessError) as error:
        raise SystemExit("cannot enumerate the pinned Git tree") from error
    result = []
    for raw in raw_paths:
        if not raw:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise SystemExit("non-UTF-8 path in pinned Git tree") from error
        relative = Path(text)
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise SystemExit(f"unsafe tracked path: {text!r}")
        path = source / relative
        if not path.is_file() and not path.is_symlink():
            raise SystemExit(f"unsupported tracked entry: {text!r}")
        result.append(relative)
    if not result or len(result) != len(set(result)):
        raise SystemExit("empty or duplicate tracked source inventory")
    return sorted(result, key=lambda path: path.as_posix())


def materialized_digest(root: Path, paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for relative in paths:
        path = root / relative
        digest.update(relative.as_posix().encode())
        digest.update(b"\0")
        if path.is_symlink():
            target = os.readlink(path)
            target_path = Path(target)
            if target_path.is_absolute() or ".." in target_path.parts:
                raise SystemExit(f"unsafe tracked symlink: {relative} -> {target}")
            digest.update(b"link\0" + target.encode())
        elif path.is_file():
            digest.update(b"exec\0" if os.access(path, os.X_OK) else b"file\0")
            digest.update(path.read_bytes())
        else:
            raise SystemExit(f"missing tracked entry: {relative}")
        digest.update(b"\0")
    return digest.hexdigest()


def copy_tracked_tree(source: Path, destination: Path, paths: list[Path]) -> str:
    destination.mkdir()
    for relative in paths:
        original = source / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if original.is_symlink():
            link = os.readlink(original)
            link_path = Path(link)
            if link_path.is_absolute() or ".." in link_path.parts:
                raise SystemExit(f"unsafe tracked symlink: {relative} -> {link}")
            target.symlink_to(link)
        else:
            shutil.copy2(original, target)
    expected = materialized_digest(source, paths)
    actual = materialized_digest(destination, paths)
    if actual != expected:
        raise SystemExit("tracked source materialization changed content or modes")
    return actual


def sensitive_test_files(source: Path, tracked: list[Path]) -> list[str]:
    """Conservatively quarantine files that observe allocation/lifetime state."""

    sensitive_modules = {"gc", "resource", "tracemalloc", "weakref"}
    result = []
    for relative in tracked:
        if not relative.as_posix().startswith("tests/") or relative.suffix != ".py":
            continue
        path = source / relative
        if path.is_symlink():
            continue
        try:
            tree = ast.parse(path.read_text(), filename=relative.as_posix())
        except (OSError, UnicodeError, SyntaxError, ValueError) as error:
            raise SystemExit(f"cannot inspect sensitive test file {relative}") from error
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
        if imported & sensitive_modules:
            result.append(relative.as_posix())
    return sorted(result)


def canonical_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


TRACKER = r'''from __future__ import annotations

import atexit
import builtins
import concurrent.futures
import hashlib
import importlib.machinery
import json
import os
import sys
import time
import tracemalloc
from collections import defaultdict
from pathlib import Path

from _br_guard_common import none_comparison_safe, truth_state

CURRENT_TEST = os.environ.get("BR_PARENT_TEST")
INITIAL_OWNER = CURRENT_TEST
EVENTS = defaultdict(lambda: defaultdict(set))
ESCAPED = set()
ROOT_PID = int(os.environ.setdefault("GUARD_ROOT_PID", str(os.getpid())))
IS_CHILD = os.getpid() != ROOT_PID
REGISTERED = False
OWNED_TASK_SEEN = False
OUTPUT_TOKEN = f"{os.getpid()}-{time.time_ns()}"
SUBMIT_COUNTER = 0
_ORIGINAL_TRACE_START = tracemalloc.start

def owner():
    return CURRENT_TEST or "__NO_TEST__"

def ensure_registered():
    global REGISTERED
    directory = os.environ.get("GUARD_CHILD_DIR")
    if IS_CHILD and not REGISTERED and directory:
        Path(directory, f"{OUTPUT_TOKEN}.started").write_text(owner())
        REGISTERED = True

def register_child():
    global IS_CHILD, REGISTERED, INITIAL_OWNER, OWNED_TASK_SEEN, OUTPUT_TOKEN
    IS_CHILD = True
    REGISTERED = False
    INITIAL_OWNER = CURRENT_TEST
    OWNED_TASK_SEEN = False
    OUTPUT_TOKEN = f"{os.getpid()}-{time.time_ns()}"

def atomic_json(path, payload):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    temporary.replace(path)

def task_sentry(stage, token, task_owner):
    directory = os.environ.get("GUARD_CHILD_DIR")
    if directory:
        atomic_json(
            Path(directory, "pool", stage, f"{token}.json"),
            {"owner": task_owner, "token": token},
        )

def relabel_initial_events():
    if not INITIAL_OWNER or INITIAL_OWNER == "__NO_TEST__":
        return
    for categories in EVENTS.values():
        for owners in categories.values():
            if INITIAL_OWNER in owners:
                owners.remove(INITIAL_OWNER)
                owners.add("__NO_TEST__")
    if INITIAL_OWNER in ESCAPED:
        ESCAPED.remove(INITIAL_OWNER)
        ESCAPED.add("__NO_TEST__")

def run_owned_task(task_owner, token, function, args, kwargs):
    global CURRENT_TEST, IS_CHILD, REGISTERED, OWNED_TASK_SEEN, OUTPUT_TOKEN
    if not IS_CHILD:
        IS_CHILD = True
        REGISTERED = False
        OUTPUT_TOKEN = f"{os.getpid()}-{time.time_ns()}"
    if not OWNED_TASK_SEEN:
        relabel_initial_events()
        OWNED_TASK_SEEN = True
    CURRENT_TEST = task_owner
    os.environ["BR_PARENT_TEST"] = task_owner
    ensure_registered()
    task_sentry("started", token, task_owner)
    try:
        return function(*args, **kwargs)
    finally:
        task_sentry("completed", token, task_owner)
        # multiprocessing workers terminate through os._exit on common paths,
        # bypassing Python atexit.  Persist the cumulative child document at
        # every owned task boundary.  Result serialization occurs after this
        # wrapper returns, so the submitting owner is quarantined in the root
        # trace by owned_submit below rather than pretending that interval is
        # attributable and complete.
        write_child()
        CURRENT_TEST = None
        os.environ.pop("BR_PARENT_TEST", None)

_ORIGINAL_SUBMIT = concurrent.futures.ProcessPoolExecutor.submit

def owned_submit(executor, function, /, *args, **kwargs):
    global SUBMIT_COUNTER
    SUBMIT_COUNTER += 1
    task_owner = owner()
    # The ProcessPoolExecutor serializes the return value after run_owned_task
    # has restored worker ownership.  Conservatively retain every test using a
    # persistent pool; child observations remain useful for completeness and
    # diagnostics but can never exempt that submitting test.
    ESCAPED.add(task_owner)
    token = hashlib.sha256(
        f"{os.getpid()}:{time.time_ns()}:{SUBMIT_COUNTER}:{task_owner}".encode()
    ).hexdigest()
    task_sentry("submitted", token, task_owner)
    return _ORIGINAL_SUBMIT(
        executor, run_owned_task, task_owner, token, function, args, kwargs
    )

def record(label, category):
    ensure_registered()
    EVENTS[label][category].add(owner())

def observe_truth(label, value):
    record(label, "seen")
    state = None if tracemalloc.is_tracing() else truth_state(value)
    record(label, state or "unknown")
    return value

def observe_none(label, value):
    record(label, "seen")
    if tracemalloc.is_tracing() or not none_comparison_safe(value):
        record(label, "unsafe-eq")
        record(label, "unsafe-ne")
    return value

def owned_trace_start(*args, **kwargs):
    # A memory-observation test can distinguish allocations introduced by the
    # collector itself.  Quarantine the complete owner, even if tracing starts
    # before a particular guard is reached.
    ESCAPED.add(owner())
    return _ORIGINAL_TRACE_START(*args, **kwargs)

def audit(event, args):
    # Any externally launched process may evade sitecustomize, environment
    # propagation, or child-log accounting. Such a test is never exempted.
    if event in {
        "subprocess.Popen", "os.exec", "os.system", "os.posix_spawn", "os.spawn"
    }:
        ESCAPED.add(owner())
        if IS_CHILD:
            # Persist before a possible exec replaces this interpreter and
            # bypasses Python atexit handlers.
            task_sentry("escaped", OUTPUT_TOKEN, owner())

def document():
    return {
        label: {category: sorted(owners) for category, owners in sorted(events.items())}
        for label, events in sorted(EVENTS.items())
    }

def write_child():
    directory = os.environ.get("GUARD_CHILD_DIR")
    if not IS_CHILD or not REGISTERED or not directory:
        return
    atomic_json(
        Path(directory, f"{OUTPUT_TOKEN}.json"),
        {"escaped": sorted(ESCAPED), "events": document(), "token": OUTPUT_TOKEN},
    )

def integrity():
    instrument = sys.modules.get("_br_guard_instrument")
    return (
        getattr(builtins, "__TRUTH_HOOK__", None) is observe_truth
        and getattr(builtins, "__NONE_HOOK__", None) is observe_none
        and concurrent.futures.ProcessPoolExecutor.submit is owned_submit
        and tracemalloc.start is owned_trace_start
        and instrument is not None
        and importlib.machinery.SourceFileLoader.get_code is instrument.instrumented_get_code
    )

builtins.__TRUTH_HOOK__ = observe_truth
builtins.__NONE_HOOK__ = observe_none
concurrent.futures.ProcessPoolExecutor.submit = owned_submit
tracemalloc.start = owned_trace_start
sys.addaudithook(audit)
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
import _br_guard_profile

EXECUTED = set()
SENSITIVE_FILES = set(json.loads(os.environ["GUARD_SENSITIVE_FILES"]))

def sentries(directory, stage):
    result = {}
    valid = True
    for path in sorted((directory / "pool" / stage).glob("*.json")):
        try:
            payload = json.loads(path.read_text())
        except (OSError, ValueError):
            valid = False
            continue
        if (
            set(payload) != {"owner", "token"}
            or payload.get("token") != path.stem
            or not isinstance(payload.get("owner"), str)
            or path.stem in result
        ):
            valid = False
            continue
        result[path.stem] = payload["owner"]
    return result, valid

@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_protocol(item, nextitem):
    EXECUTED.add(item.nodeid)
    _br_guard_profile.CURRENT_TEST = item.nodeid
    os.environ["BR_PARENT_TEST"] = item.nodeid
    if not _br_guard_profile.integrity():
        raise RuntimeError("guard-profile runtime hooks displaced before test")
    test_file = item.nodeid.split("::", 1)[0]
    if (
        test_file in SENSITIVE_FILES
        or any(word in item.nodeid.lower() for word in ("memory", "tracemalloc", "leak"))
    ):
        _br_guard_profile.ESCAPED.add(item.nodeid)
    try:
        yield
    finally:
        if not _br_guard_profile.integrity():
            raise RuntimeError("guard-profile runtime hooks displaced by test")
        _br_guard_profile.CURRENT_TEST = None
        os.environ.pop("BR_PARENT_TEST", None)

@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    if not _br_guard_profile.integrity():
        raise RuntimeError("guard-profile runtime hooks displaced at session finish")
    directory = Path(os.environ["GUARD_CHILD_DIR"])
    completed = {path.stem for path in directory.glob("*.json")}
    started = {path.stem for path in directory.glob("*.started")}
    submitted, submitted_valid = sentries(directory, "submitted")
    task_started, started_valid = sentries(directory, "started")
    task_completed, completed_valid = sentries(directory, "completed")
    external, external_valid = sentries(directory, "escaped")
    known = set(EXECUTED) | {"__NO_TEST__"}
    pool_complete = (
        submitted_valid and started_valid and completed_valid and external_valid
        and submitted == task_started == task_completed
        and set(submitted.values()) <= known
    )
    escaped = set(_br_guard_profile.ESCAPED)
    escaped.update(external.values())
    for path in sorted(directory.glob("*.json")):
        payload = json.loads(path.read_text())
        if payload.get("token") != path.stem:
            pool_complete = False
            continue
        escaped.update(payload.get("escaped", ()))
        for label, events in payload.get("events", {}).items():
            for category, owners in events.items():
                _br_guard_profile.EVENTS[label][category].update(owners)
    metadata = {
        "collector_sha256": os.environ["GUARD_COLLECTOR_SHA256"],
        "common_sha256": os.environ["GUARD_COMMON_SHA256"],
        "instrumented": int(os.environ["GUARD_INSTRUMENTED"]),
        "mode": os.environ["GUARD_MODE"],
        "python": os.environ["GUARD_PYTHON"],
        "runtime_image": os.environ["GUARD_RUNTIME_IMAGE"],
        "environment_sha256": os.environ["GUARD_ENVIRONMENT_SHA256"],
        "executed_materialized_sha256": os.environ["GUARD_EXECUTED_MATERIALIZED_SHA256"],
        "materialized_sha256": os.environ["GUARD_MATERIALIZED_SHA256"],
        "sensitive_files_sha256": os.environ["GUARD_SENSITIVE_FILES_SHA256"],
        "source_sha": os.environ["GUARD_SOURCE_SHA"],
        "source_tree": os.environ["GUARD_SOURCE_TREE"],
        "support_sha256": os.environ["GUARD_SUPPORT_SHA256"],
        "test_digest": os.environ["GUARD_TEST_DIGEST"],
        "worker_transform_sha256": os.environ["GUARD_WORKER_TRANSFORM_SHA256"],
    }
    trace = json.dumps(
        {"escaped": sorted(escaped), "events": _br_guard_profile.document(), "meta": metadata},
        sort_keys=True,
        separators=(",", ":"),
    )
    Path(os.environ["GUARD_TRACE"]).write_text(trace)
    rows = sorted(submitted.items())
    manifest = {
        **metadata,
        "child_complete": started == completed and pool_complete,
        "child_logs": len(completed),
        "child_starts": len(started),
        "exitstatus": exitstatus,
        "pool_task_complete": pool_complete,
        "pool_task_count": len(submitted),
        "pool_task_sha256": hashlib.sha256(
            json.dumps(rows, separators=(",", ":")).encode()
        ).hexdigest(),
        "tests": sorted(EXECUTED),
        "trace_sha256": hashlib.sha256(trace.encode()).hexdigest(),
    }
    Path(os.environ["GUARD_MANIFEST"]).write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    )
'''


INSTRUMENT_SUPPORT = r'''from __future__ import annotations

import ast
import importlib.machinery
import os
from pathlib import Path

from _br_guard_common import label, none_comparison, truth_form

TRUTH_HOOK = "__TRUTH_HOOK__"
NONE_HOOK = "__NONE_HOOK__"
ROOT = Path(os.environ["GUARD_WORK_ROOT"]).resolve()
ORIGINAL_GET_CODE = importlib.machinery.SourceFileLoader.get_code

class Instrumenter(ast.NodeTransformer):
    def __init__(self, relative):
        self.relative = relative

    def _guard(self, node):
        form = truth_form(node.test)
        if form is not None:
            _name, operand = form
            call = ast.copy_location(
                ast.Call(
                    ast.Name(TRUTH_HOOK, ast.Load()),
                    [ast.Constant(label(self.relative, "truth", node.test)), operand],
                    [],
                ),
                operand,
            )
            if node.test is operand:
                node.test = call
            elif isinstance(node.test, ast.UnaryOp):
                node.test.operand = call
            elif node.test.left is operand:
                node.test.left = call
            else:
                node.test.comparators[0] = call
        return self.generic_visit(node)

    visit_If = visit_While = visit_IfExp = _guard

    def visit_Compare(self, node):
        comparison = none_comparison(node)
        node = self.generic_visit(node)
        if comparison is None:
            return node
        _operator, _operand, side = comparison
        operand = node.left if side == "left" else node.comparators[0]
        call = ast.copy_location(
            ast.Call(
                ast.Name(NONE_HOOK, ast.Load()),
                [ast.Constant(label(self.relative, "none", node)), operand],
                [],
            ),
            operand,
        )
        if side == "left":
            node.left = call
        else:
            node.comparators[0] = call
        return node

def instrumented_get_code(loader, fullname):
    try:
        path = Path(loader.path).resolve()
        relative = path.relative_to(ROOT).as_posix()
    except (AttributeError, OSError, ValueError):
        return ORIGINAL_GET_CODE(loader, fullname)
    if not relative.startswith("sqlglot/") or not relative.endswith(".py"):
        return ORIGINAL_GET_CODE(loader, fullname)
    source = loader.get_data(loader.path)
    tree = ast.parse(source, filename=loader.path, type_comments=True)
    tree = ast.fix_missing_locations(Instrumenter(relative).visit(tree))
    return compile(tree, loader.path, "exec", dont_inherit=True)

importlib.machinery.SourceFileLoader.get_code = instrumented_get_code
'''


def generated_support_sources() -> dict[str, str]:
    """Return the exact support modules whose digest is admitted by the builder."""

    return {
        "_br_guard_profile.py": TRACKER.replace("__TRUTH_HOOK__", TRUTH_HOOK).replace(
            "__NONE_HOOK__", NONE_HOOK
        ),
        "guard_profile_plugin.py": PLUGIN,
        "_br_guard_common.py": Path(__file__).with_name("guard_profile_common.py").read_text(),
        "_br_guard_instrument.py": INSTRUMENT_SUPPORT.replace(
            "__TRUTH_HOOK__", TRUTH_HOOK
        ).replace("__NONE_HOOK__", NONE_HOOK),
        "sitecustomize.py": "import _br_guard_profile\nimport _br_guard_instrument\n",
    }


def generated_support_digest(sources: dict[str, str] | None = None) -> str:
    payload = sources if sources is not None else generated_support_sources()
    return hashlib.sha256(
        b"\0".join(
            name.encode() + b"\0" + payload[name].encode()
            for name in sorted(payload)
        )
    ).hexdigest()


class Instrumenter(ast.NodeTransformer):
    def __init__(self, relative: str):
        self.relative = relative
        self.count = 0

    def _guard(self, node):
        form = truth_form(node.test)
        if form is not None:
            _name, operand = form
            call = ast.copy_location(
                ast.Call(
                    ast.Name(TRUTH_HOOK, ast.Load()),
                    [ast.Constant(label(self.relative, "truth", node.test)), operand],
                    [],
                ),
                operand,
            )
            if node.test is operand:
                node.test = call
            elif isinstance(node.test, ast.UnaryOp):
                node.test.operand = call
            elif node.test.left is operand:
                node.test.left = call
            else:
                node.test.comparators[0] = call
            self.count += 1
        return self.generic_visit(node)

    visit_If = visit_While = visit_IfExp = _guard

    def visit_Compare(self, node):
        comparison = none_comparison(node)
        node = self.generic_visit(node)
        if comparison is None:
            return node
        _operator, _operand, side = comparison
        operand = node.left if side == "left" else node.comparators[0]
        call = ast.copy_location(
            ast.Call(
                ast.Name(NONE_HOOK, ast.Load()),
                [ast.Constant(label(self.relative, "none", node)), operand],
                [],
            ),
            operand,
        )
        if side == "left":
            node.left = call
        else:
            node.comparators[0] = call
        self.count += 1
        return node


def instrument_tree(path: Path, relative: str) -> int:
    text = path.read_text()
    if TRUTH_HOOK in text or NONE_HOOK in text:
        raise SystemExit(f"hook name collision in {relative}")
    tree = ast.parse(text, filename=relative, type_comments=True)
    instrumenter = Instrumenter(relative)
    changed = instrumenter.visit(tree)
    if instrumenter.count:
        ast.fix_missing_locations(changed)
        path.write_text(ast.unparse(changed) + "\n")
    return instrumenter.count


def main() -> None:
    args = arguments()
    source = args.source.resolve()
    python = args.python.expanduser().absolute()
    output = args.output.resolve()
    manifest = args.manifest.resolve()
    validate_source(source)
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.runtime_image):
        raise SystemExit("runtime image must be an immutable sha256 digest")
    revision = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    if revision != PINNED_SHA:
        raise SystemExit(f"source is {revision}, expected {PINNED_SHA}")
    tracked_status = subprocess.check_output(
        ["git", "-C", str(source), "status", "--porcelain=v1", "--untracked-files=no"],
        text=True,
    )
    if tracked_status:
        raise SystemExit("source has staged or unstaged tracked changes")
    source_tree = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD^{tree}"], text=True
    ).strip()
    tracked = git_tracked_paths(source)
    sensitive_files = sensitive_test_files(source, tracked)
    sensitive_files_sha256 = canonical_digest(sensitive_files)
    tests = json.loads(args.tests.read_text())["tests"]
    test_ids = [test["id"] for test in tests]
    test_digest = hashlib.sha256("\0".join(test_ids).encode()).hexdigest()
    mode = "synchronous-worker" if args.synchronous_workers else "normal"
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="blast-radius-guard-profile-") as temporary:
        temporary_path = Path(temporary)
        work = temporary_path / "sqlglot"
        support = temporary_path / "support"
        children = temporary_path / "children"
        materialized_sha256 = copy_tracked_tree(source, work, tracked)
        support.mkdir()
        children.mkdir()
        for stage in ("submitted", "started", "completed", "escaped"):
            (children / "pool" / stage).mkdir(parents=True)
        support_sources = generated_support_sources()
        for name, text in support_sources.items():
            (support / name).write_text(text)
        if args.synchronous_workers:
            synchronous_worker_tests(work)
        executed_materialized_sha256 = materialized_digest(work, tracked)
        instrumented = len(source_sites(source))
        reserved_support = set(support_sources)
        reserved_markers = {
            TRUTH_HOOK,
            NONE_HOOK,
            "_br_guard_profile",
            "_br_guard_common",
            "_br_guard_instrument",
            "guard_profile_plugin",
        }
        for relative in tracked:
            if relative.name in reserved_support:
                raise SystemExit(f"generated support module collision: {relative}")
            if relative.suffix != ".py":
                continue
            path = source / relative
            text = path.read_text()
            if any(marker in text for marker in reserved_markers):
                raise SystemExit(f"generated support marker collision in {relative}")
        support_digest = generated_support_digest(support_sources)
        inherited_contract = {
            key: os.environ.get(key)
            for key in (
                "HOME", "LANG", "LC_ALL", "LC_CTYPE", "LD_LIBRARY_PATH", "PATH",
                "PYTHONHOME", "TMPDIR", "TZ", "USER", "VIRTUAL_ENV",
            )
        }
        environment = {
            key: value for key, value in inherited_contract.items() if value is not None
        }
        environment.update({
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONNOUSERSITE": "1",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        })
        environment_sha256 = canonical_digest(environment)
        environment.update({
            "BR_PARENT_TEST": "",
            "GUARD_CHILD_DIR": str(children),
            "GUARD_COLLECTOR_SHA256": sha256(Path(__file__)),
            "GUARD_COMMON_SHA256": sha256(Path(__file__).with_name("guard_profile_common.py")),
            "GUARD_INSTRUMENTED": str(instrumented),
            "GUARD_MANIFEST": str(manifest),
            "GUARD_MODE": mode,
            "GUARD_ENVIRONMENT_SHA256": environment_sha256,
            "GUARD_EXECUTED_MATERIALIZED_SHA256": executed_materialized_sha256,
            "GUARD_MATERIALIZED_SHA256": materialized_sha256,
            "GUARD_PYTHON": subprocess.check_output(
                [str(python), "--version"], text=True, stderr=subprocess.STDOUT
            ).strip(),
            "GUARD_RUNTIME_IMAGE": args.runtime_image,
            "GUARD_SENSITIVE_FILES": json.dumps(sensitive_files, separators=(",", ":")),
            "GUARD_SENSITIVE_FILES_SHA256": sensitive_files_sha256,
            "GUARD_SOURCE_SHA": revision,
            "GUARD_SOURCE_TREE": source_tree,
            "GUARD_SUPPORT_SHA256": support_digest,
            "GUARD_TEST_DIGEST": test_digest,
            "GUARD_TRACE": str(output),
            "GUARD_WORKER_TRANSFORM_SHA256": sha256(
                Path(__file__).with_name("collect_dict_access.py")
            ),
            "GUARD_WORK_ROOT": str(work),
            "PYTHONPATH": os.pathsep.join(
                (str(support), str(work), environment.get("PYTHONPATH", ""))
            ).rstrip(os.pathsep),
            "SKIP_INTEGRATION": "0",
        })
        command = [str(python), "-m", "pytest", "-q", "-p", "guard_profile_plugin"]
        command.extend(argument for argument in args.pytest_args if argument != "--")
        result = subprocess.run(command, cwd=work, env=environment, check=False)
        if result.returncode:
            raise SystemExit(f"pytest exited {result.returncode}")

    document = json.loads(manifest.read_text())
    executed = document.get("tests", ())
    missing = set(test_ids) - set(executed)
    extra = set(executed) - set(test_ids)
    if (
        document.get("exitstatus") != 0
        or document.get("child_complete") is not True
        or document.get("pool_task_complete") is not True
        or missing
        or extra
        or len(executed) != len(test_ids)
    ):
        raise SystemExit(
            f"inadmissible suite manifest; {len(missing)} tests missing, "
            f"{len(extra)} extra"
        )
    if mode == "normal" and document.get("pool_task_count", 0) <= 0:
        raise SystemExit("normal trace lacks persistent-worker task accounting")
    if mode == "synchronous-worker" and document.get("pool_task_count") != 0:
        raise SystemExit("synchronous trace unexpectedly submitted pool tasks")
    print(f"wrote {output} from {instrumented} sites in {mode} mode")


if __name__ == "__main__":
    main()
