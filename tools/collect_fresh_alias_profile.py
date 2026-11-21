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
EVENTS = defaultdict(
    lambda: {"owners": set(), "types": set(), "bindings": set(), "modes": set()}
)

_SNAPSHOT_READY = False
_SNAPSHOT_TRUSTED = False
_SNAPSHOT_UNITTEST = False
_SNAPSHOT_CLEAN_IMPORT = False
_SNAPSHOT_MODE = None

def initialize(trusted=False, child=False):
    global _SNAPSHOT_READY, _SNAPSHOT_TRUSTED, _SNAPSHOT_UNITTEST
    global _SNAPSHOT_CLEAN_IMPORT
    global _SNAPSHOT_MODE
    global _canonical, _ORIGINAL_ALIAS, _ORIGINAL_TABLE_FUNCTION
    global _ALIAS_GLOBALS, _TABLE_GLOBALS, _ORIGINAL_MAYBE_PARSE
    global _ORIGINAL_TO_IDENTIFIER, _ORIGINAL_ALIAS_CLASS, _ORIGINAL_TABLE_CLASS
    global _ORIGINAL_TABLE_ALIAS_CLASS, _TO_IDENTIFIER_GLOBALS
    global _ORIGINAL_IDENTIFIER_CLASS, _ORIGINAL_MAYBE_COPY, _ORIGINAL_IDENTIFIER_RE
    global _MAYBE_PARSE_GLOBALS, _ORIGINAL_EXPR_CLASS, _ORIGINAL_TABLE_COPY
    global _ORIGINAL_TABLE_DEEPCOPY, _ORIGINAL_TABLE_SET, _ORIGINAL_TABLE_APPEND
    global _ORIGINAL_TABLE_SET_PARENT, _ORIGINAL_TABLE_INIT, _ORIGINAL_TABLE_NEW
    global _ORIGINAL_IDENTIFIER_COPY
    global _ORIGINAL_IDENTIFIER_DEEPCOPY, _ORIGINAL_IDENTIFIER_SET
    global _ORIGINAL_IDENTIFIER_APPEND, _ORIGINAL_IDENTIFIER_SET_PARENT
    global _ORIGINAL_IDENTIFIER_INIT, _ORIGINAL_IDENTIFIER_NEW
    global _ORIGINAL_DEEPCOPY_FUNCTION, _ORIGINAL_TABLE_ARG_TYPES
    global _ORIGINAL_IDENTIFIER_ARG_TYPES
    if _SNAPSHOT_READY:
        if trusted and not _SNAPSHOT_TRUSTED:
            raise RuntimeError("cannot trust a late canonical snapshot")
        return
    _SNAPSHOT_CLEAN_IMPORT = "sqlglot" not in sys.modules
    from sqlglot import expressions as canonical
    _canonical = canonical
    _ORIGINAL_ALIAS = canonical.alias_
    _ORIGINAL_TABLE_FUNCTION = canonical.table_
    _ALIAS_GLOBALS = _ORIGINAL_ALIAS.__globals__
    _TABLE_GLOBALS = _ORIGINAL_TABLE_FUNCTION.__globals__
    _ORIGINAL_MAYBE_PARSE = _ALIAS_GLOBALS["maybe_parse"]
    _ORIGINAL_TO_IDENTIFIER = _ALIAS_GLOBALS["to_identifier"]
    _ORIGINAL_ALIAS_CLASS = _ALIAS_GLOBALS["Alias"]
    _ORIGINAL_TABLE_CLASS = _TABLE_GLOBALS["Table"]
    _ORIGINAL_TABLE_ALIAS_CLASS = _TABLE_GLOBALS["TableAlias"]
    _TO_IDENTIFIER_GLOBALS = _ORIGINAL_TO_IDENTIFIER.__globals__
    _ORIGINAL_IDENTIFIER_CLASS = _TO_IDENTIFIER_GLOBALS["Identifier"]
    _ORIGINAL_MAYBE_COPY = _TO_IDENTIFIER_GLOBALS["maybe_copy"]
    _ORIGINAL_IDENTIFIER_RE = _TO_IDENTIFIER_GLOBALS["SAFE_IDENTIFIER_RE"]
    _MAYBE_PARSE_GLOBALS = _ORIGINAL_MAYBE_PARSE.__globals__
    _ORIGINAL_EXPR_CLASS = _MAYBE_PARSE_GLOBALS["Expr"]
    _ORIGINAL_TABLE_COPY = _ORIGINAL_TABLE_CLASS.copy
    _ORIGINAL_TABLE_DEEPCOPY = _ORIGINAL_TABLE_CLASS.__deepcopy__
    _ORIGINAL_TABLE_SET = _ORIGINAL_TABLE_CLASS.set
    _ORIGINAL_TABLE_APPEND = _ORIGINAL_TABLE_CLASS.append
    _ORIGINAL_TABLE_SET_PARENT = _ORIGINAL_TABLE_CLASS._set_parent
    _ORIGINAL_TABLE_INIT = _ORIGINAL_TABLE_CLASS.__init__
    _ORIGINAL_TABLE_NEW = _ORIGINAL_TABLE_CLASS.__new__
    _ORIGINAL_IDENTIFIER_COPY = _ORIGINAL_IDENTIFIER_CLASS.copy
    _ORIGINAL_IDENTIFIER_DEEPCOPY = _ORIGINAL_IDENTIFIER_CLASS.__deepcopy__
    _ORIGINAL_IDENTIFIER_SET = _ORIGINAL_IDENTIFIER_CLASS.set
    _ORIGINAL_IDENTIFIER_APPEND = _ORIGINAL_IDENTIFIER_CLASS.append
    _ORIGINAL_IDENTIFIER_SET_PARENT = _ORIGINAL_IDENTIFIER_CLASS._set_parent
    _ORIGINAL_IDENTIFIER_INIT = _ORIGINAL_IDENTIFIER_CLASS.__init__
    _ORIGINAL_IDENTIFIER_NEW = _ORIGINAL_IDENTIFIER_CLASS.__new__
    _ORIGINAL_DEEPCOPY_FUNCTION = _ORIGINAL_TABLE_DEEPCOPY.__globals__["deepcopy"]
    _ORIGINAL_TABLE_ARG_TYPES = dict(_ORIGINAL_TABLE_CLASS.arg_types)
    _ORIGINAL_IDENTIFIER_ARG_TYPES = dict(_ORIGINAL_IDENTIFIER_CLASS.arg_types)
    _SNAPSHOT_UNITTEST = _ALIAS_GLOBALS.get("UNITTEST") is True
    pytest_mode = "pytest" in sys.modules and _SNAPSHOT_UNITTEST and not child
    child_mode = (
        child
        and CURRENT_TEST is not None
        and "pytest" not in sys.modules
        and not _SNAPSHOT_UNITTEST
    )
    _SNAPSHOT_MODE = "pytest" if pytest_mode else "child" if child_mode else "late"
    _SNAPSHOT_TRUSTED = trusted and _SNAPSHOT_CLEAN_IMPORT and (pytest_mode or child_mode)
    _SNAPSHOT_READY = True

def owner():
    return CURRENT_TEST or "__NO_TEST__"

def bindings_ok(module):
    return (
        _SNAPSHOT_READY
        and _SNAPSHOT_TRUSTED
        and _SNAPSHOT_MODE in {"pytest", "child"}
        and module is _canonical
        and getattr(module, "alias_", None) is _ORIGINAL_ALIAS
        and getattr(module, "table_", None) is _ORIGINAL_TABLE_FUNCTION
        and _ALIAS_GLOBALS.get("maybe_parse") is _ORIGINAL_MAYBE_PARSE
        and _ALIAS_GLOBALS.get("to_identifier") is _ORIGINAL_TO_IDENTIFIER
        and _ALIAS_GLOBALS.get("Alias") is _ORIGINAL_ALIAS_CLASS
        and _TABLE_GLOBALS.get("Table") is _ORIGINAL_TABLE_CLASS
        and _TABLE_GLOBALS.get("TableAlias") is _ORIGINAL_TABLE_ALIAS_CLASS
        and _TABLE_GLOBALS.get("to_identifier") is _ORIGINAL_TO_IDENTIFIER
        and _TO_IDENTIFIER_GLOBALS.get("Identifier") is _ORIGINAL_IDENTIFIER_CLASS
        and _TO_IDENTIFIER_GLOBALS.get("maybe_copy") is _ORIGINAL_MAYBE_COPY
        and _TO_IDENTIFIER_GLOBALS.get("SAFE_IDENTIFIER_RE") is _ORIGINAL_IDENTIFIER_RE
        and _MAYBE_PARSE_GLOBALS.get("Expr") is _ORIGINAL_EXPR_CLASS
        and _ORIGINAL_TABLE_CLASS.copy is _ORIGINAL_TABLE_COPY
        and _ORIGINAL_TABLE_CLASS.__deepcopy__ is _ORIGINAL_TABLE_DEEPCOPY
        and _ORIGINAL_TABLE_CLASS.set is _ORIGINAL_TABLE_SET
        and _ORIGINAL_TABLE_CLASS.append is _ORIGINAL_TABLE_APPEND
        and _ORIGINAL_TABLE_CLASS._set_parent is _ORIGINAL_TABLE_SET_PARENT
        and _ORIGINAL_TABLE_CLASS.__init__ is _ORIGINAL_TABLE_INIT
        and _ORIGINAL_TABLE_CLASS.__new__ is _ORIGINAL_TABLE_NEW
        and _ORIGINAL_IDENTIFIER_CLASS.copy is _ORIGINAL_IDENTIFIER_COPY
        and _ORIGINAL_IDENTIFIER_CLASS.__deepcopy__ is _ORIGINAL_IDENTIFIER_DEEPCOPY
        and _ORIGINAL_IDENTIFIER_CLASS.set is _ORIGINAL_IDENTIFIER_SET
        and _ORIGINAL_IDENTIFIER_CLASS.append is _ORIGINAL_IDENTIFIER_APPEND
        and _ORIGINAL_IDENTIFIER_CLASS._set_parent is _ORIGINAL_IDENTIFIER_SET_PARENT
        and _ORIGINAL_IDENTIFIER_CLASS.__init__ is _ORIGINAL_IDENTIFIER_INIT
        and _ORIGINAL_IDENTIFIER_CLASS.__new__ is _ORIGINAL_IDENTIFIER_NEW
        and _ORIGINAL_TABLE_DEEPCOPY.__globals__.get("deepcopy") is _ORIGINAL_DEEPCOPY_FUNCTION
        and _ORIGINAL_TABLE_CLASS.arg_types == _ORIGINAL_TABLE_ARG_TYPES
        and _ORIGINAL_IDENTIFIER_CLASS.arg_types == _ORIGINAL_IDENTIFIER_ARG_TYPES
    )

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
        if not _SNAPSHOT_READY:
            initialize(trusted=False)
        binding = bindings_ok(module)
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
    EVENTS[label]["modes"].add(_SNAPSHOT_MODE or "none")
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
            "modes": sorted(event["modes"]),
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

if CURRENT_TEST and "pytest" not in sys.modules:
    initialize(trusted=True, child=True)

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

_br_fresh_alias.initialize(trusted=True)
if not (
    _br_fresh_alias._SNAPSHOT_TRUSTED
    and _br_fresh_alias._SNAPSHOT_UNITTEST
    and _br_fresh_alias._SNAPSHOT_CLEAN_IMPORT
    and _br_fresh_alias._SNAPSHOT_MODE == "pytest"
):
    raise RuntimeError("canonical snapshot was not captured in pytest UNITTEST mode")

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
            _br_fresh_alias.EVENTS[label]["modes"].update(event["modes"])
    Path(os.environ["FRESH_ALIAS_TRACE"]).write_text(
        json.dumps(_br_fresh_alias.document(), sort_keys=True, separators=(",", ":"))
    )
    Path(os.environ["FRESH_ALIAS_MANIFEST"]).write_text(json.dumps({
        "child_logs": child_count,
        "clean_import": _br_fresh_alias._SNAPSHOT_CLEAN_IMPORT,
        "exitstatus": exitstatus,
        "mode": os.environ["FRESH_ALIAS_MODE"],
        "snapshot_trusted": _br_fresh_alias._SNAPSHOT_TRUSTED,
        "snapshot_mode": _br_fresh_alias._SNAPSHOT_MODE,
        "tests": sorted(EXECUTED),
        "unittest": _br_fresh_alias._SNAPSHOT_UNITTEST,
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
        negative = r'''
import pytest
import _br_fresh_alias as tracker
tracker.initialize(trusted=True)
from sqlglot import expressions as exp

assert tracker.bindings_ok(exp)
original_alias = exp.alias_
exp.alias_ = lambda *args, **kwargs: None
assert not tracker.bindings_ok(exp)
exp.alias_ = original_alias
assert tracker.bindings_ok(exp)

table_globals = exp.table_.__globals__
original_table_class = table_globals["Table"]
table_globals["Table"] = object
assert not tracker.bindings_ok(exp)
table_globals["Table"] = original_table_class
assert tracker.bindings_ok(exp)

original_table_init = original_table_class.__init__
original_table_class.__init__ = lambda self, **kwargs: None
assert not tracker.bindings_ok(exp)
original_table_class.__init__ = original_table_init
assert tracker.bindings_ok(exp)
'''
        subprocess.run(
            [str(python), "-c", negative],
            cwd=work,
            env=environment,
            check=True,
        )
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
