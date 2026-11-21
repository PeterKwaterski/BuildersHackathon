#!/usr/bin/env python3
"""Trace direct reads of Python function code objects in the pinned suite."""

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


TRACKER_TEMPLATE = r'''from __future__ import annotations

import atexit
import json
import os
from collections import defaultdict
from pathlib import Path

CURRENT_TEST = os.environ.get("BR_PARENT_TEST")
EVENTS = defaultdict(set)
SOURCE_ROOT = Path(os.environ["CODE_REFLECTION_SOURCE_ROOT"]).resolve()

def owner():
    return CURRENT_TEST or "__NO_TEST__"

def read(value):
    code = value.__code__
    try:
        relative = Path(code.co_filename).resolve().relative_to(SOURCE_ROOT).as_posix()
    except (OSError, ValueError):
        return code
    if not relative.startswith("sqlglot/"):
        return code
    label = f"{relative}:{code.co_firstlineno}:{code.co_name}"
    EVENTS[label].add(owner())
    return code

def document():
    return {label: sorted(owners) for label, owners in sorted(EVENTS.items())}

def write_child():
    directory = os.environ.get("CODE_REFLECTION_CHILD_DIR")
    if not directory or not CURRENT_TEST:
        return
    path = Path(directory, f"{os.getpid()}.json")
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(document(), sort_keys=True, separators=(",", ":")))
    temporary.replace(path)

import builtins
builtins._br_code_read = read
atexit.register(write_child)
'''


PLUGIN = r'''from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import _br_code_reflection

EXECUTED = set()

@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_protocol(item, nextitem):
    EXECUTED.add(item.nodeid)
    _br_code_reflection.CURRENT_TEST = item.nodeid
    os.environ["BR_PARENT_TEST"] = item.nodeid
    try:
        yield
    finally:
        _br_code_reflection.CURRENT_TEST = None
        os.environ.pop("BR_PARENT_TEST", None)

def pytest_sessionfinish(session, exitstatus):
    child_count = 0
    for path in sorted(Path(os.environ["CODE_REFLECTION_CHILD_DIR"]).glob("*.json")):
        child_count += 1
        for label, owners in json.loads(path.read_text()).items():
            _br_code_reflection.EVENTS[label].update(owners)
    Path(os.environ["CODE_REFLECTION_TRACE"]).write_text(
        json.dumps(_br_code_reflection.document(), sort_keys=True, separators=(",", ":"))
    )
    Path(os.environ["CODE_REFLECTION_MANIFEST"]).write_text(json.dumps({
        "child_logs": child_count,
        "exitstatus": exitstatus,
        "mode": os.environ["CODE_REFLECTION_MODE"],
        "tests": sorted(EXECUTED),
    }, sort_keys=True, separators=(",", ":")))
'''


REFLECTIVE_INSPECT = {
    "findsource",
    "getclosurevars",
    "getsource",
    "getsourcelines",
}
REFLECTIVE_DIS = {"Bytecode", "code_info", "dis", "get_instructions", "show_code"}


def unsupported_reflection(tree: ast.Module, path: Path) -> None:
    """Fail if the pinned source uses a code-reading API we do not instrument."""
    inspect_modules = {"inspect"}
    dis_modules = {"dis"}
    direct = set()
    for node in ast.walk(tree):
        reserved = (
            isinstance(node, ast.Name) and node.id == "_br_code_read"
        ) or (
            isinstance(node, ast.arg) and node.arg == "_br_code_read"
        ) or (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node.name == "_br_code_read"
        ) or (
            isinstance(node, ast.alias)
            and (node.asname == "_br_code_read" or node.name == "_br_code_read")
        ) or (
            isinstance(node, (ast.Global, ast.Nonlocal)) and "_br_code_read" in node.names
        ) or (
            isinstance(node, ast.ExceptHandler) and node.name == "_br_code_read"
        ) or (
            isinstance(node, (ast.MatchAs, ast.MatchStar))
            and node.name == "_br_code_read"
        ) or (
            isinstance(node, ast.MatchMapping) and node.rest == "_br_code_read"
        )
        if reserved:
            raise SystemExit(f"reserved tracer binding at {path}:{node.lineno}")
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "inspect":
                    inspect_modules.add(alias.asname or alias.name)
                elif alias.name == "dis":
                    dis_modules.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module in {"inspect", "dis"}:
            allowed = REFLECTIVE_INSPECT if node.module == "inspect" else REFLECTIVE_DIS
            direct.update(alias.asname or alias.name for alias in node.names if alias.name in allowed)

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "__code__" and not isinstance(
            node.ctx, ast.Load
        ):
            raise SystemExit(f"write to __code__ at {path}:{node.lineno}")
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            if node.func.id in direct:
                raise SystemExit(f"unsupported code reflection at {path}:{node.lineno}")
            if (
                node.func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value == "__code__"
            ):
                raise SystemExit(f"dynamic __code__ read at {path}:{node.lineno}")
        elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if (
                node.func.value.id in inspect_modules
                and node.func.attr in REFLECTIVE_INSPECT
            ) or (
                node.func.value.id in dis_modules and node.func.attr in REFLECTIVE_DIS
            ):
                raise SystemExit(f"unsupported code reflection at {path}:{node.lineno}")


class Instrumenter(ast.NodeTransformer):
    def __init__(self) -> None:
        self.count = 0

    def visit_Attribute(self, node: ast.Attribute):
        node = self.generic_visit(node)
        if node.attr != "__code__" or not isinstance(node.ctx, ast.Load):
            return node
        self.count += 1
        return ast.copy_location(
            ast.Call(ast.Name("_br_code_read", ast.Load()), [node.value], []), node
        )


def instrument_file(path: Path, tree: ast.Module) -> int:
    unsupported_reflection(tree, path)
    instrumenter = Instrumenter()
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
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="blast-radius-code-reflection-") as temporary:
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
        (support / "_br_code_reflection.py").write_text(TRACKER_TEMPLATE)
        (support / "code_reflection_plugin.py").write_text(PLUGIN)
        (support / "sitecustomize.py").write_text("import _br_code_reflection\n")
        if args.synchronous_workers:
            synchronous_worker_tests(work)

        instrumented = 0
        for root_name in ("sqlglot", "tests"):
            for path in sorted((work / root_name).rglob("*.py")):
                relative = path.relative_to(work).as_posix()
                tree = ast.parse(path.read_text(), filename=relative, type_comments=True)
                instrumented += instrument_file(path, tree)

        environment = os.environ.copy()
        environment.update(
            {
                "CODE_REFLECTION_CHILD_DIR": str(children),
                "CODE_REFLECTION_MANIFEST": str(manifest),
                "CODE_REFLECTION_MODE": (
                    "synchronous-worker" if args.synchronous_workers else "normal"
                ),
                "CODE_REFLECTION_SOURCE_ROOT": str(work),
                "CODE_REFLECTION_TRACE": str(output),
                "PYTHONPATH": os.pathsep.join(
                    (str(support), str(work), environment.get("PYTHONPATH", ""))
                ).rstrip(os.pathsep),
                "SKIP_INTEGRATION": "0",
            }
        )
        command = [str(python), "-m", "pytest", "-q", "-p", "code_reflection_plugin"]
        command.extend(argument for argument in args.pytest_args if argument != "--")
        result = subprocess.run(command, cwd=work, env=environment, check=False)
        if result.returncode:
            raise SystemExit(f"pytest exited {result.returncode}; trace is not admissible")

    document = json.loads(manifest.read_text())
    expected = {test["id"] for test in json.loads(args.tests.read_text())["tests"]}
    missing = expected - set(document.get("tests", ()))
    if document.get("exitstatus") != 0 or missing:
        raise SystemExit(f"inadmissible suite manifest; {len(missing)} tests missing")
    print(
        f"wrote {output} from {instrumented} direct code-object read sites "
        f"and {len(document['tests'])} tests"
    )


if __name__ == "__main__":
    main()
