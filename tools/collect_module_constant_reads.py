#!/usr/bin/env python3
"""Trace owner-resolved reads of module-scope literal assignments."""

from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
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


def module_name(path: Path, root: Path) -> str:
    relative = path.relative_to(root).as_posix()
    return relative.removesuffix("/__init__.py").removesuffix(".py").replace("/", ".")


def resolve_import(current: str, is_package: bool, module: str | None, level: int) -> str:
    if not level:
        return module or ""
    package = current if is_package else current.rpartition(".")[0]
    return importlib.util.resolve_name("." * level + (module or ""), package)


def source_candidates(source: Path) -> dict[tuple[str, str], str]:
    labels: dict[tuple[str, str], str | None] = {}
    for path in sorted((source / "sqlglot").rglob("*.py")):
        relative = path.relative_to(source).as_posix()
        module = module_name(path, source)
        tree = ast.parse(path.read_text(), filename=relative, type_comments=True)
        for statement in tree.body:
            if isinstance(statement, ast.Assign):
                targets = statement.targets
            elif isinstance(statement, ast.AnnAssign):
                targets = [statement.target]
            else:
                continue
            if len(targets) != 1 or not isinstance(targets[0], ast.Name):
                continue
            value_node = getattr(statement, "value", None)
            if value_node is None:
                continue
            try:
                ast.literal_eval(value_node)
            except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                continue
            name = targets[0].id
            label = f"{relative}:{statement.lineno}:{statement.end_lineno or statement.lineno}:{name}"
            key = module, name
            labels[key] = label if key not in labels else None
    return {key: label for key, label in labels.items() if label is not None}


def parsed_files(work: Path) -> dict[Path, tuple[str, bool, ast.Module]]:
    result = {}
    for root_name in ("sqlglot", "tests"):
        for path in sorted((work / root_name).rglob("*.py")):
            relative = path.relative_to(work).as_posix()
            module = module_name(path, work)
            result[path] = (
                module,
                path.name == "__init__.py",
                ast.parse(path.read_text(), filename=relative, type_comments=True),
            )
    return result


def import_maps(
    files: dict[Path, tuple[str, bool, ast.Module]],
    candidates: dict[tuple[str, str], str],
) -> tuple[
    dict[str, dict[str, str]],
    dict[str, dict[str, str]],
    dict[tuple[str, str], str],
]:
    exports: dict[str, dict[str, str]] = defaultdict(dict)
    modules = {module for module, _, _ in files.values() if module.startswith("sqlglot")}
    for (module, name), label in candidates.items():
        exports[module][name] = label

    ambiguous: dict[str, set[str]] = defaultdict(set)
    changed = True
    while changed:
        changed = False
        for module, is_package, tree in files.values():
            if not module.startswith("sqlglot"):
                continue
            for statement in tree.body:
                if not isinstance(statement, ast.ImportFrom) or any(
                    alias.name == "*" for alias in statement.names
                ):
                    continue
                target = resolve_import(module, is_package, statement.module, statement.level)
                for alias in statement.names:
                    label = exports.get(target, {}).get(alias.name)
                    if label is None:
                        continue
                    local = alias.asname or alias.name
                    prior = exports[module].get(local)
                    if prior is not None and prior != label:
                        ambiguous[module].add(local)
                        exports[module].pop(local, None)
                        continue
                    if local not in ambiguous[module] and prior is None:
                        exports[module][local] = label
                        changed = True

    value_maps: dict[str, dict[str, str]] = {}
    module_maps: dict[str, dict[str, str]] = {}
    for module, is_package, tree in files.values():
        value_options: dict[str, set[str]] = defaultdict(set)
        module_options: dict[str, set[str]] = defaultdict(set)
        for name, label in exports.get(module, {}).items():
            value_options[name].add(label)
        for statement in tree.body:
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    local = alias.asname or alias.name.split(".", 1)[0]
                    module_options[local].add(
                        alias.name if alias.asname else alias.name.split(".", 1)[0]
                    )
            elif isinstance(statement, ast.ImportFrom) and not any(
                alias.name == "*" for alias in statement.names
            ):
                target = resolve_import(module, is_package, statement.module, statement.level)
                for alias in statement.names:
                    local = alias.asname or alias.name
                    label = exports.get(target, {}).get(alias.name)
                    if label is not None:
                        value_options[local].add(label)
                    submodule = f"{target}.{alias.name}" if target else alias.name
                    if submodule in modules:
                        module_options[local].add(submodule)
        value_maps[module] = {
            name: next(iter(options))
            for name, options in value_options.items()
            if len(options) == 1
        }
        module_maps[module] = {
            name: next(iter(options))
            for name, options in module_options.items()
            if len(options) == 1 and name not in value_options
        }
    qualified = {
        (module, name): label
        for module, values in exports.items()
        for name, label in values.items()
    }
    return value_maps, module_maps, qualified


TRACKER_TEMPLATE = r'''from __future__ import annotations

import atexit
import json
import os
from collections import defaultdict
from pathlib import Path

CURRENT_TEST = os.environ.get("BR_PARENT_TEST")
EVENTS = defaultdict(set)

def owner():
    return CURRENT_TEST or "__NO_TEST__"

def read(label, value):
    EVENTS[label].add(owner())
    return value

def document():
    return {label: sorted(owners) for label, owners in sorted(EVENTS.items())}

def write_child():
    directory = os.environ.get("MODULE_CONSTANT_CHILD_DIR")
    if not directory or not CURRENT_TEST:
        return
    path = Path(directory, f"{os.getpid()}.json")
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(document(), sort_keys=True, separators=(",", ":")))
    temporary.replace(path)

import builtins
builtins._br_module_constant_read = read
atexit.register(write_child)
'''


PLUGIN = r'''from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import _br_module_constant

EXECUTED = set()

@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_protocol(item, nextitem):
    EXECUTED.add(item.nodeid)
    _br_module_constant.CURRENT_TEST = item.nodeid
    os.environ["BR_PARENT_TEST"] = item.nodeid
    try:
        yield
    finally:
        _br_module_constant.CURRENT_TEST = None
        os.environ.pop("BR_PARENT_TEST", None)

def pytest_sessionfinish(session, exitstatus):
    child_count = 0
    for path in sorted(Path(os.environ["MODULE_CONSTANT_CHILD_DIR"]).glob("*.json")):
        child_count += 1
        for label, owners in json.loads(path.read_text()).items():
            _br_module_constant.EVENTS[label].update(owners)
    Path(os.environ["MODULE_CONSTANT_TRACE"]).write_text(
        json.dumps(_br_module_constant.document(), sort_keys=True, separators=(",", ":"))
    )
    Path(os.environ["MODULE_CONSTANT_MANIFEST"]).write_text(json.dumps({
        "child_logs": child_count,
        "exitstatus": exitstatus,
        "mode": os.environ["MODULE_CONSTANT_MODE"],
        "tests": sorted(EXECUTED),
    }, sort_keys=True, separators=(",", ":")))
'''


def flatten_attribute(node: ast.Attribute) -> tuple[str, list[str]] | None:
    parts = [node.attr]
    value = node.value
    while isinstance(value, ast.Attribute):
        parts.append(value.attr)
        value = value.value
    if not isinstance(value, ast.Name):
        return None
    return value.id, list(reversed(parts))


class Instrumenter(ast.NodeTransformer):
    def __init__(
        self,
        values: dict[str, str],
        modules: dict[str, str],
        qualified: dict[tuple[str, str], str],
    ):
        self.values = values
        self.modules = modules
        self.qualified = qualified
        self.count = 0

    def wrap(self, node: ast.expr, label: str) -> ast.expr:
        self.count += 1
        return ast.copy_location(
            ast.Call(
                ast.Name("_br_module_constant_read", ast.Load()),
                [ast.Constant(label), node],
                [],
            ),
            node,
        )

    def visit_Attribute(self, node: ast.Attribute):
        flattened = flatten_attribute(node) if isinstance(node.ctx, ast.Load) else None
        label = None
        if flattened:
            base, parts = flattened
            module = self.modules.get(base)
            if module and parts:
                target_module = ".".join((module, *parts[:-1]))
                label = self.qualified.get((target_module, parts[-1]))
        node = self.generic_visit(node)
        return self.wrap(node, label) if label else node

    def visit_Name(self, node: ast.Name):
        if not isinstance(node.ctx, ast.Load):
            return node
        label = self.values.get(node.id)
        return self.wrap(node, label) if label else node


def instrument_file(
    path: Path,
    tree: ast.Module,
    values: dict[str, str],
    modules: dict[str, str],
    qualified: dict[tuple[str, str], str],
) -> int:
    instrumenter = Instrumenter(values, modules, qualified)
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
    candidates = source_candidates(source)

    with tempfile.TemporaryDirectory(prefix="blast-radius-module-constant-") as temporary:
        temporary_path = Path(temporary)
        work = temporary_path / "sqlglot"
        support = temporary_path / "support"
        children = temporary_path / "children"
        shutil.copytree(source, work, ignore=shutil.ignore_patterns(
            ".git", ".pytest_cache", ".coverage*", "__pycache__", "*.pyc"
        ))
        support.mkdir()
        children.mkdir()
        (support / "_br_module_constant.py").write_text(TRACKER_TEMPLATE)
        (support / "module_constant_plugin.py").write_text(PLUGIN)
        (support / "sitecustomize.py").write_text("import _br_module_constant\n")
        if args.synchronous_workers:
            synchronous_worker_tests(work)
        files = parsed_files(work)
        value_maps, module_maps, qualified = import_maps(files, candidates)
        instrumented = 0
        for path, (module, _, tree) in files.items():
            instrumented += instrument_file(
                path,
                tree,
                value_maps.get(module, {}),
                module_maps.get(module, {}),
                qualified,
            )
        environment = os.environ.copy()
        environment.update({
            "MODULE_CONSTANT_CHILD_DIR": str(children),
            "MODULE_CONSTANT_MANIFEST": str(manifest),
            "MODULE_CONSTANT_MODE": "synchronous-worker" if args.synchronous_workers else "normal",
            "MODULE_CONSTANT_TRACE": str(output),
            "PYTHONPATH": os.pathsep.join((str(support), str(work), environment.get("PYTHONPATH", ""))).rstrip(os.pathsep),
            "SKIP_INTEGRATION": "0",
        })
        command = [str(python), "-m", "pytest", "-q", "-p", "module_constant_plugin"]
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
        f"wrote {output} from {len(candidates)} module constants, "
        f"{instrumented} read sites, and {len(document['tests'])} tests"
    )


if __name__ == "__main__":
    main()
