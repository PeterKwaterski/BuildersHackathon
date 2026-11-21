#!/usr/bin/env python3
"""Trace calls which omit literal Python function defaults in the pinned suite."""

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


SAFE = (type(None), bool, int, float, complex, str, bytes)
CALLABLE_NAME = "_blast_radius_default_callable_91e62f"
ENTER_NAME = "_blast_radius_default_enter_91e62f"
REFLECT_NAME = "_blast_radius_default_reflect_91e62f"
PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"


def file_set_digest(root: Path, paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths):
        relative = path.relative_to(root).as_posix().encode()
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


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


def safe_literal(value) -> bool:
    return type(value) in SAFE or (
        type(value) is tuple and all(safe_literal(item) for item in value)
    )


def source_labels(source: Path) -> dict[tuple[str, str], dict]:
    """Return unique runtime function identities and their literal defaults."""
    records: dict[tuple[str, str], dict | None] = {}
    for path in sorted((source / "sqlglot").rglob("*.py")):
        relative = path.relative_to(source).as_posix()
        module = relative.removesuffix("/__init__.py").removesuffix(".py").replace("/", ".")
        tree = ast.parse(path.read_text(), filename=relative, type_comments=True)

        def visit(body: list[ast.stmt], prefix: tuple[str, ...]) -> None:
            for statement in body:
                if isinstance(statement, ast.ClassDef):
                    visit(statement.body, (*prefix, statement.name))
                    continue
                if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                qualname = ".".join((*prefix, statement.name))
                function_id = f"{relative}:{statement.lineno}:{qualname}"
                positional = [*statement.args.posonlyargs, *statement.args.args]
                aligned = [None] * (len(positional) - len(statement.args.defaults)) + list(
                    statement.args.defaults
                )
                params = []
                for index, (argument, default) in enumerate(zip(positional, aligned)):
                    if default is None:
                        continue
                    try:
                        value = ast.literal_eval(default)
                    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                        continue
                    if safe_literal(value):
                        kind = (
                            "positional-only"
                            if index < len(statement.args.posonlyargs)
                            else "positional"
                        )
                        params.append({
                            "label": f"{function_id}:{argument.arg}:{default.lineno}:{default.end_lineno or default.lineno}",
                            "name": argument.arg,
                            "kind": kind,
                            "index": index,
                        })
                for argument, default in zip(
                    statement.args.kwonlyargs, statement.args.kw_defaults
                ):
                    if default is None:
                        continue
                    try:
                        value = ast.literal_eval(default)
                    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                        continue
                    if safe_literal(value):
                        params.append({
                            "label": f"{function_id}:{argument.arg}:{default.lineno}:{default.end_lineno or default.lineno}",
                            "name": argument.arg,
                            "kind": "keyword",
                            "index": None,
                        })
                if params:
                    key = (module, qualname)
                    record = {
                        "id": function_id,
                        "params": params,
                        "decorated": bool(statement.decorator_list),
                        "async": isinstance(statement, ast.AsyncFunctionDef),
                        "generator": any(
                            isinstance(node, (ast.Yield, ast.YieldFrom))
                            for node in ast.walk(statement)
                        ),
                    }
                    records[key] = record if key not in records else None
                visit(statement.body, (*prefix, statement.name, "<locals>"))

        visit(tree.body, ())
    return {key: value for key, value in records.items() if value is not None}


TRACKER_TEMPLATE = r'''from __future__ import annotations

import atexit
import builtins
import dis
import functools
import json
import os
import sys
import time
import types
from collections import defaultdict
from pathlib import Path

CURRENT_TEST = os.environ.get("BR_PARENT_TEST")
EVENTS = defaultdict(lambda: defaultdict(set))
FUNCTIONS = __FUNCTIONS__
BY_ID = {record["id"]: record for record in FUNCTIONS.values()}
TOKENS = {}
INSTRUCTIONS = {}
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
    directory = os.environ.get("FUNCTION_DEFAULT_CHILD_DIR")
    if IS_CHILD and not REGISTERED and directory and CURRENT_TEST:
        Path(directory, f"{OUTPUT_TOKEN}.started").write_text(CURRENT_TEST)
        REGISTERED = True

def owner():
    return CURRENT_TEST or "__NO_TEST__"

def record_function(function_id, kind):
    ensure_registered()
    record = BY_ID.get(function_id)
    if record:
        for parameter in record["params"]:
            EVENTS[parameter["label"]][kind].add(owner())

def resolve_one(value):
    bound = 0
    partial_args = 0
    partial_keywords = set()
    while type(value) is functools.partial:
        partial_args += len(value.args)
        partial_keywords.update((value.keywords or {}).keys())
        value = value.func
    if isinstance(value, types.MethodType):
        bound = 1
        value = value.__func__
    if isinstance(value, types.FunctionType):
        key = (value.__module__, value.__qualname__)
        record = FUNCTIONS.get(key)
        return [(record, bound, partial_args, partial_keywords, False)] if record else []
    if isinstance(value, type):
        result = []
        for name in ("__new__", "__init__"):
            candidate = vars(value).get(name)
            if isinstance(candidate, (staticmethod, classmethod)):
                candidate = candidate.__func__
            if isinstance(candidate, types.FunctionType):
                record = FUNCTIONS.get((candidate.__module__, candidate.__qualname__))
                if record:
                    # Class construction can route through a custom metaclass
                    # or __new__ before __init__, transforming arguments. Keep
                    # exact owner identity but treat every default as read.
                    result.append((record, 1, partial_args, partial_keywords, True))
        return result
    candidate = vars(type(value)).get("__call__")
    if isinstance(candidate, (staticmethod, classmethod)):
        candidate = candidate.__func__
    if isinstance(candidate, types.FunctionType):
        record = FUNCTIONS.get((candidate.__module__, candidate.__qualname__))
        if record:
            return [(record, 1, partial_args, partial_keywords, False)]
    return []

def outer_call_offset(frame):
    code = frame.f_code
    instructions = INSTRUCTIONS.get(code)
    if instructions is None:
        instructions = list(dis.get_instructions(code))
        INSTRUCTIONS[code] = instructions
    current_index = next(
        (index for index, instruction in enumerate(instructions) if instruction.offset == frame.f_lasti),
        None,
    )
    if current_index is None:
        return None
    position = instructions[current_index].positions
    if position is None:
        return None
    for instruction in instructions[current_index + 1:]:
        candidate = instruction.positions
        if (
            instruction.opname in {"CALL", "CALL_KW"}
            and candidate is not None
            and candidate.lineno == position.lineno
            and candidate.col_offset == position.col_offset
            and candidate.end_lineno == position.end_lineno
            and candidate.end_col_offset >= position.end_col_offset
        ):
            return instruction.offset
    return None

def traced_callable(value, positional_count, keyword_names, opaque):
    ensure_registered()
    frame = sys._getframe(1)
    offset = outer_call_offset(frame)
    resolved = resolve_one(value)
    function_ids = set()
    keywords = set(keyword_names)
    for record, bound, partial_args, partial_keywords, force_opaque in resolved:
        function_ids.add(record["id"])
        effective_positional = positional_count + bound + partial_args
        effective_keywords = keywords | partial_keywords
        for parameter in record["params"]:
            omitted = opaque or force_opaque or (
                parameter["kind"] == "positional-only"
                and parameter["index"] >= effective_positional
            ) or (
                parameter["kind"] == "positional"
                and parameter["index"] >= effective_positional
                and parameter["name"] not in effective_keywords
            ) or (
                parameter["kind"] == "keyword"
                and parameter["name"] not in effective_keywords
            )
            if omitted:
                EVENTS[parameter["label"]]["reader"].add(owner())
            EVENTS[parameter["label"]]["call"].add(owner())
    if offset is not None:
        key = (id(frame), frame.f_code, offset)
        # Clear an abandoned token before every execution of this syntactic
        # site. A site may alternate between candidate and native callables,
        # and argument evaluation may have raised before the prior target
        # entered. The code object in the key closes cross-code frame-id reuse;
        # a same-code CALL executes this clearing lookup before any callback.
        TOKENS.pop(key, None)
        if function_ids:
            TOKENS[key] = function_ids
    return value

def enter(function_id):
    frame = sys._getframe(1)
    caller = frame.f_back
    token = (
        TOKENS.pop((id(caller), caller.f_code, caller.f_lasti), None)
        if caller is not None
        else None
    )
    if token is None or function_id not in token:
        record_function(function_id, "opaque")
        # The call did not come directly from an instrumented Python CALL
        # site (for example, a native callback or decorator wrapper).  Its
        # exact argument binding is unavailable, so conservatively treat
        # every default as read by this owner.
        record_function(function_id, "reader")
    else:
        record_function(function_id, "entered")

def reflect(value):
    for record, _, _, _, _ in resolve_one(value):
        record_function(record["id"], "reflect")
        record_function(record["id"], "reader")
    return value

def document():
    labels = sorted(
        parameter["label"]
        for record in FUNCTIONS.values()
        for parameter in record["params"]
    )
    return {
        label: {kind: sorted(owners) for kind, owners in sorted(events.items())}
        for label in labels
        for events in (EVENTS[label],)
    }

def write_child():
    directory = os.environ.get("FUNCTION_DEFAULT_CHILD_DIR")
    if not IS_CHILD or not REGISTERED or not directory or not CURRENT_TEST:
        return
    path = Path(directory, f"{OUTPUT_TOKEN}.json")
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(document(), sort_keys=True, separators=(",", ":")))
    temporary.replace(path)

builtins.__CALLABLE_NAME__ = traced_callable
builtins.__ENTER_NAME__ = enter
builtins.__REFLECT_NAME__ = reflect
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
import _br_function_defaults

EXECUTED = set()

@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_protocol(item, nextitem):
    EXECUTED.add(item.nodeid)
    _br_function_defaults.CURRENT_TEST = item.nodeid
    os.environ["BR_PARENT_TEST"] = item.nodeid
    try:
        yield
    finally:
        _br_function_defaults.CURRENT_TEST = None
        os.environ.pop("BR_PARENT_TEST", None)

def pytest_sessionfinish(session, exitstatus):
    child_directory = Path(os.environ["FUNCTION_DEFAULT_CHILD_DIR"])
    completed = {path.stem for path in child_directory.glob("*.json")}
    started = {path.stem for path in child_directory.glob("*.started")}
    for path in sorted(child_directory.glob("*.json")):
        for label, events in json.loads(path.read_text()).items():
            for kind, owners in events.items():
                _br_function_defaults.EVENTS[label][kind].update(owners)
    trace = json.dumps({
        "collector_sha256": os.environ["FUNCTION_DEFAULT_COLLECTOR_SHA256"],
        "dependency_sha256": os.environ["FUNCTION_DEFAULT_DEPENDENCY_SHA256"],
        "events": _br_function_defaults.document(),
        "instrumented": int(os.environ["FUNCTION_DEFAULT_INSTRUMENTED"]),
        "instrumented_tree_sha256": os.environ["FUNCTION_DEFAULT_TREE_SHA256"],
        "mode": os.environ["FUNCTION_DEFAULT_MODE"],
        "python": os.environ["FUNCTION_DEFAULT_PYTHON"],
        "pytest_args_sha256": os.environ["FUNCTION_DEFAULT_PYTEST_ARGS_SHA256"],
        "source_sha": os.environ["FUNCTION_DEFAULT_SOURCE_SHA"],
        "support_sha256": os.environ["FUNCTION_DEFAULT_SUPPORT_SHA256"],
        "test_digest": os.environ["FUNCTION_DEFAULT_TEST_DIGEST"],
    }, sort_keys=True, separators=(",", ":"))
    Path(os.environ["FUNCTION_DEFAULT_TRACE"]).write_text(trace)
    Path(os.environ["FUNCTION_DEFAULT_MANIFEST"]).write_text(json.dumps({
        "child_complete": started == completed,
        "child_logs": len(completed),
        "child_starts": len(started),
        "child_tokens_sha256": hashlib.sha256("\0".join(sorted(started)).encode()).hexdigest(),
        "collector_sha256": os.environ["FUNCTION_DEFAULT_COLLECTOR_SHA256"],
        "dependency_sha256": os.environ["FUNCTION_DEFAULT_DEPENDENCY_SHA256"],
        "exitstatus": exitstatus,
        "instrumented": int(os.environ["FUNCTION_DEFAULT_INSTRUMENTED"]),
        "instrumented_tree_sha256": os.environ["FUNCTION_DEFAULT_TREE_SHA256"],
        "mode": os.environ["FUNCTION_DEFAULT_MODE"],
        "python": os.environ["FUNCTION_DEFAULT_PYTHON"],
        "pytest_args_sha256": os.environ["FUNCTION_DEFAULT_PYTEST_ARGS_SHA256"],
        "source_sha": os.environ["FUNCTION_DEFAULT_SOURCE_SHA"],
        "support_sha256": os.environ["FUNCTION_DEFAULT_SUPPORT_SHA256"],
        "test_digest": os.environ["FUNCTION_DEFAULT_TEST_DIGEST"],
        "tests": sorted(EXECUTED),
        "trace_sha256": hashlib.sha256(trace.encode()).hexdigest(),
    }, sort_keys=True, separators=(",", ":")))
'''


class Instrumenter(ast.NodeTransformer):
    def __init__(self, function_positions: dict[tuple[int, str], str]):
        self.function_positions = function_positions
        self.count = 0

    def _function(self, node):
        original_line = node.lineno
        node = self.generic_visit(node)
        function_id = self.function_positions.get((original_line, node.name))
        if function_id:
            call = ast.Expr(ast.Call(ast.Name(ENTER_NAME, ast.Load()), [ast.Constant(function_id)], []))
            ast.copy_location(call, node)
            if (
                node.body
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)
            ):
                node.body.insert(1, call)
            else:
                node.body.insert(0, call)
            self.count += 1
        return node

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function

    def visit_Call(self, node: ast.Call):
        node = self.generic_visit(node)
        if isinstance(node.func, ast.Name) and node.func.id in {
            CALLABLE_NAME, ENTER_NAME, REFLECT_NAME
        }:
            return node
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"signature", "getfullargspec"}
            and node.args
        ):
            node.args[0] = ast.copy_location(
                ast.Call(ast.Name(REFLECT_NAME, ast.Load()), [node.args[0]], []),
                node.args[0],
            )
        opaque = any(isinstance(argument, ast.Starred) for argument in node.args) or any(
            keyword.arg is None for keyword in node.keywords
        )
        wrapper = ast.Call(
            ast.Name(CALLABLE_NAME, ast.Load()),
            [
                node.func,
                ast.Constant(len(node.args)),
                ast.Tuple(
                    [ast.Constant(keyword.arg) for keyword in node.keywords if keyword.arg],
                    ast.Load(),
                ),
                ast.Constant(opaque),
            ],
            [],
        )
        node.func = ast.copy_location(wrapper, node.func)
        self.count += 1
        return node


def instrument_tree(path: Path, positions: dict[tuple[int, str], str]) -> int:
    text = path.read_text()
    if CALLABLE_NAME in text or ENTER_NAME in text or REFLECT_NAME in text:
        raise SystemExit(f"instrumentation binding collision in {path}")
    tree = ast.parse(text, filename=path.as_posix(), type_comments=True)
    instrumenter = Instrumenter(positions)
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
    collector_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    dependency_digest = hashlib.sha256(
        Path(__file__).with_name("collect_dict_access.py").read_bytes()
    ).hexdigest()
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest.parent.mkdir(parents=True, exist_ok=True)
    functions = source_labels(source)

    by_path: dict[str, dict[tuple[int, str], str]] = {}
    for record in functions.values():
        relative, line, qualname = record["id"].split(":", 2)
        by_path.setdefault(relative, {})[(int(line), qualname.rsplit(".", 1)[-1])] = record["id"]

    with tempfile.TemporaryDirectory(prefix="blast-radius-function-default-") as temporary:
        temporary_path = Path(temporary)
        work = temporary_path / "sqlglot"
        support = temporary_path / "support"
        children = temporary_path / "children"
        shutil.copytree(source, work, ignore=shutil.ignore_patterns(
            ".git", ".pytest_cache", ".coverage*", "__pycache__", "*.pyc"
        ))
        support.mkdir()
        children.mkdir()
        tracker = TRACKER_TEMPLATE.replace("__FUNCTIONS__", repr(functions))
        tracker = tracker.replace("__CALLABLE_NAME__", CALLABLE_NAME).replace("__ENTER_NAME__", ENTER_NAME)
        tracker = tracker.replace("__REFLECT_NAME__", REFLECT_NAME)
        (support / "_br_function_defaults.py").write_text(tracker)
        (support / "function_default_plugin.py").write_text(PLUGIN)
        (support / "sitecustomize.py").write_text("import _br_function_defaults\n")
        if args.synchronous_workers:
            synchronous_worker_tests(work)
        instrumented = 0
        for root_name in ("sqlglot", "tests"):
            for path in sorted((work / root_name).rglob("*.py")):
                relative = path.relative_to(work).as_posix()
                instrumented += instrument_tree(path, by_path.get(relative, {}))
        support_digest = file_set_digest(support, list(support.glob("*.py")))
        instrumented_tree_digest = file_set_digest(
            work,
            [
                path
                for root_name in ("sqlglot", "tests")
                for path in (work / root_name).rglob("*.py")
            ],
        )
        pytest_arguments = [
            argument for argument in args.pytest_args if argument != "--"
        ]
        pytest_args_digest = hashlib.sha256(
            json.dumps(pytest_arguments, separators=(",", ":")).encode()
        ).hexdigest()
        environment = os.environ.copy()
        test_ids = [test["id"] for test in json.loads(args.tests.read_text())["tests"]]
        test_digest = hashlib.sha256("\0".join(test_ids).encode()).hexdigest()
        python_version = subprocess.check_output(
            [str(python), "-c", "import sys; print(sys.version)"], text=True
        ).strip()
        if not python_version.startswith("3.13."):
            raise SystemExit(f"production trace requires Python 3.13, got {python_version!r}")
        environment.update({
            "FUNCTION_DEFAULT_COLLECTOR_SHA256": collector_digest,
            "FUNCTION_DEFAULT_DEPENDENCY_SHA256": dependency_digest,
            "FUNCTION_DEFAULT_CHILD_DIR": str(children),
            "FUNCTION_DEFAULT_INSTRUMENTED": str(instrumented),
            "FUNCTION_DEFAULT_MANIFEST": str(manifest),
            "FUNCTION_DEFAULT_MODE": "synchronous-worker" if args.synchronous_workers else "normal",
            "FUNCTION_DEFAULT_PYTHON": python_version,
            "FUNCTION_DEFAULT_PYTEST_ARGS_SHA256": pytest_args_digest,
            "FUNCTION_DEFAULT_SOURCE_SHA": PINNED_SHA,
            "FUNCTION_DEFAULT_SUPPORT_SHA256": support_digest,
            "FUNCTION_DEFAULT_TEST_DIGEST": test_digest,
            "FUNCTION_DEFAULT_TRACE": str(output),
            "FUNCTION_DEFAULT_TREE_SHA256": instrumented_tree_digest,
            "PYTHONPATH": os.pathsep.join((str(support), str(work), environment.get("PYTHONPATH", ""))).rstrip(os.pathsep),
            "SKIP_INTEGRATION": "0",
        })
        command = [str(python), "-m", "pytest", "-q", "-p", "function_default_plugin"]
        command.extend(pytest_arguments)
        result = subprocess.run(command, cwd=work, env=environment, check=False)
        if result.returncode:
            raise SystemExit(f"pytest exited {result.returncode}; trace is not admissible")

    document = json.loads(manifest.read_text())
    expected = {test["id"] for test in json.loads(args.tests.read_text())["tests"]}
    missing = expected - set(document.get("tests", ()))
    if document.get("exitstatus") != 0 or (missing and not args.pytest_args):
        raise SystemExit(f"inadmissible suite manifest; {len(missing)} tests missing")
    print(
        f"wrote {output} from {sum(len(r['params']) for r in functions.values())} defaults, "
        f"{instrumented} instrumented sites, and {len(document['tests'])} tests"
    )


if __name__ == "__main__":
    main()
