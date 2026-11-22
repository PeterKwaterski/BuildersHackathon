#!/usr/bin/env python3
"""Trace owner-resolved reads of module-scope literal assignments."""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

from collect_dict_access import PINNED_SHA, synchronous_worker_tests, validate_source


RUNTIME_HELPERS = {
    "_br_module_constant_read",
    "_br_module_constant_class_attr",
    "_br_module_constant_getattr",
    "_br_module_constant_hasattr",
    "_br_module_constant_vars",
    "_br_module_constant_class_dict",
    "_br_module_constant_dir",
    "_br_module_constant_reflect_call",
}

# Derived class aliases require a whole-program instance/subclass identity and
# native-escape proof. Keep the researched machinery disconnected until that
# separate proof exists; direct module readers and class-tuple constants do not
# depend on it.
DERIVED_CLASS_ALIASES_ENABLED = False


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
    kinds = source_candidate_kinds(source)
    labels: dict[tuple[str, str], str | None] = {}
    for path, (module, _is_package, tree) in parsed_files(source).items():
        if not module.startswith("sqlglot") or not path.is_relative_to(source / "sqlglot"):
            continue
        relative = path.relative_to(source).as_posix()
        for statement in tree.body:
            if isinstance(statement, ast.Assign):
                targets = statement.targets
            elif isinstance(statement, ast.AnnAssign):
                targets = [statement.target]
            else:
                continue
            if len(targets) != 1 or not isinstance(targets[0], ast.Name):
                continue
            name = targets[0].id
            key = module, name
            if key not in kinds:
                continue
            label = f"{relative}:{statement.lineno}:{statement.end_lineno or statement.lineno}:{name}"
            labels[key] = label if key not in labels else None
    return {key: label for key, label in labels.items() if label is not None}


def _absolute_import(current: str, is_package: bool, node: ast.ImportFrom) -> str:
    return resolve_import(current, is_package, node.module, node.level)


def _class_exports(files: dict[Path, tuple[str, bool, ast.Module]]) -> dict[str, set[str]]:
    """Names that are statically bound to classes, including re-exports."""

    exports: dict[str, set[str]] = defaultdict(set)
    sqlglot_files = [item for item in files.values() if item[0].startswith("sqlglot")]
    for module, _is_package, tree in sqlglot_files:
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and _last_top_level_binding(
                tree, node.name, sys.maxsize
            ) is node:
                exports[module].add(node.name)
    changed = True
    while changed:
        changed = False
        for module, is_package, tree in sqlglot_files:
            before = len(exports[module])
            for statement in tree.body:
                if not isinstance(statement, ast.ImportFrom):
                    continue
                target = _absolute_import(module, is_package, statement)
                for alias in statement.names:
                    local = alias.asname or alias.name
                    if (
                        alias.name != "*"
                        and alias.name in exports.get(target, ())
                        and _last_top_level_binding(tree, local, sys.maxsize) is statement
                    ):
                        exports[module].add(local)
            changed |= len(exports[module]) != before
    return exports


def _last_top_level_binding(tree: ast.Module, name: str, before: int) -> ast.stmt | None:
    binding = None
    for statement in tree.body:
        if statement.lineno >= before:
            break
        bound = set()
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(statement.name)
        elif isinstance(statement, ast.Import):
            bound.update(alias.asname or alias.name.split(".", 1)[0] for alias in statement.names)
        elif isinstance(statement, ast.ImportFrom):
            bound.update(alias.asname or alias.name for alias in statement.names if alias.name != "*")
        elif isinstance(statement, ast.Assign):
            bound.update(
                node.id
                for target in statement.targets
                for node in ast.walk(target)
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
            )
        elif isinstance(statement, (ast.AnnAssign, ast.AugAssign, ast.Delete)):
            bound.update(
                node.id
                for target in (
                    statement.targets if isinstance(statement, ast.Delete) else [statement.target]
                )
                for node in ast.walk(target)
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
                or isinstance(node, ast.Name) and isinstance(node.ctx, ast.Del)
            )
        if name in bound:
            binding = statement
    return binding


def _is_class_name(
    module: str,
    is_package: bool,
    tree: ast.Module,
    statement: ast.stmt,
    name: str,
    exports: dict[str, set[str]],
) -> bool:
    binding = _last_top_level_binding(tree, name, statement.lineno)
    if isinstance(binding, ast.ClassDef):
        return True
    if isinstance(binding, ast.ImportFrom):
        target = _absolute_import(module, is_package, binding)
        return any(
            (alias.asname or alias.name) == name and alias.name in exports.get(target, ())
            for alias in binding.names
        )
    return False


def _is_re_compile(tree: ast.Module, statement: ast.stmt, value: ast.AST) -> bool:
    if (
        not isinstance(value, ast.Call)
        or not isinstance(value.func, ast.Attribute)
        or value.func.attr != "compile"
        or not isinstance(value.func.value, ast.Name)
        or value.func.value.id != "re"
        or value.keywords
        or not 1 <= len(value.args) <= 2
        or not isinstance(value.args[0], ast.Constant)
        or type(value.args[0].value) is not str
        or (len(value.args) == 2 and not (
            isinstance(value.args[1], ast.Constant) and type(value.args[1].value) is int
        ))
    ):
        return False
    binding = _last_top_level_binding(tree, "re", statement.lineno)
    return isinstance(binding, ast.Import) and any(
        alias.name == "re" and (alias.asname is None or alias.asname == "re")
        for alias in binding.names
    )


def source_candidate_kinds(source: Path) -> dict[tuple[str, str], str]:
    """Candidate kind for uniquely bound, import-safe module assignments."""

    files = parsed_files(source)
    class_exports = _class_exports(files)
    kinds: dict[tuple[str, str], str | None] = {}
    for path, (module, is_package, tree) in files.items():
        if not module.startswith("sqlglot") or not path.is_relative_to(source / "sqlglot"):
            continue
        for statement in tree.body:
            if isinstance(statement, ast.Assign):
                targets = statement.targets
            elif isinstance(statement, ast.AnnAssign):
                targets = [statement.target]
            else:
                continue
            value = getattr(statement, "value", None)
            if len(targets) != 1 or not isinstance(targets[0], ast.Name) or value is None:
                continue
            try:
                ast.literal_eval(value)
            except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                if isinstance(value, ast.Tuple) and value.elts and all(
                    isinstance(item, ast.Name)
                    and _is_class_name(
                        module, is_package, tree, statement, item.id, class_exports
                    )
                    for item in value.elts
                ):
                    kind = "class-tuple"
                elif _is_re_compile(tree, statement, value):
                    kind = "re-pattern"
                else:
                    continue
            else:
                kind = "literal"
            key = module, targets[0].id
            kinds[key] = kind if key not in kinds else None
    return {key: kind for key, kind in kinds.items() if kind is not None}


def _export_surface(tree: ast.Module | None, names: set[str]) -> tuple[bool, set[str]]:
    """Whether a star-import surface is proved, and the names it contains."""

    if tree is None:
        return False, set()
    all_values = []
    all_targets = []
    for statement in tree.body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        if len(targets) != 1 or not isinstance(targets[0], ast.Name) or targets[0].id != "__all__":
            continue
        all_targets.append(targets[0])
        try:
            value = ast.literal_eval(statement.value)
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            return False, set()
        if not isinstance(value, (tuple, list)) or any(type(item) is not str for item in value):
            return False, set()
        all_values.append(set(value))
    if len(all_values) > 1:
        return False, set()
    all_mentions = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Name) and node.id == "__all__"
    ]
    if all_values:
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Name)
                and node.id == "__all__"
                and node is not all_targets[0]
            ):
                return False, set()
        return True, names & all_values[0]
    if all_mentions:
        return False, set()
    return True, {name for name in names if not name.startswith("_")}


def _public_exports(tree: ast.Module | None, names: set[str]) -> set[str]:
    resolved, exports = _export_surface(tree, names)
    return exports if resolved else set()


def unresolved_star_labels(
    files: dict[Path, tuple[str, bool, ast.Module]],
    candidates: dict[tuple[str, str], str],
) -> set[str]:
    """Candidate labels hidden behind an unprovable star-import surface."""

    trees = {module: tree for module, _is_package, tree in files.values()}
    exports: dict[str, dict[str, str]] = defaultdict(dict)
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
                if not isinstance(statement, ast.ImportFrom):
                    continue
                target = resolve_import(module, is_package, statement.module, statement.level)
                for alias in statement.names:
                    if alias.name == "*":
                        resolved, names = _export_surface(
                            trees.get(target), set(exports.get(target, ()))
                        )
                        if not resolved:
                            continue
                        incoming = ((name, exports[target][name]) for name in names)
                    else:
                        label = exports.get(target, {}).get(alias.name)
                        if label is None:
                            continue
                        incoming = ((alias.asname or alias.name, label),)
                    for local, label in incoming:
                        final_binding = _last_top_level_binding(tree, local, sys.maxsize)
                        if alias.name == "*":
                            if final_binding is not None and final_binding.lineno > statement.lineno:
                                continue
                        elif final_binding is not statement:
                            continue
                        prior = exports[module].get(local)
                        if prior is not None and prior != label:
                            ambiguous[module].add(local)
                            exports[module].pop(local, None)
                        elif local not in ambiguous[module] and prior is None:
                            exports[module][local] = label
                            changed = True
    unsafe = set()
    graph: dict[str, set[str]] = defaultdict(set)
    star_edges = []
    for module, is_package, tree in files.values():
        for statement in tree.body:
            if isinstance(statement, ast.ImportFrom):
                target = resolve_import(module, is_package, statement.module, statement.level)
                graph[module].add(target)
                if any(alias.name == "*" for alias in statement.names):
                    star_edges.append((module, target))

    def reaches(start: str, target: str) -> bool:
        pending = [start]
        seen = set()
        while pending:
            module = pending.pop()
            if module == target:
                return True
            if module in seen:
                continue
            seen.add(module)
            pending.extend(graph.get(module, ()))
        return False

    for importer, target in star_edges:
        if reaches(target, importer):
            unsafe.update(exports.get(target, {}).values())
            unsafe.update(exports.get(importer, {}).values())
    for module, is_package, tree in files.values():
        for statement in tree.body:
            if not isinstance(statement, ast.ImportFrom) or not any(
                alias.name == "*" for alias in statement.names
            ):
                continue
            target = resolve_import(module, is_package, statement.module, statement.level)
            resolved, _surface = _export_surface(trees.get(target), set(exports.get(target, ())))
            if not resolved:
                unsafe.update(exports.get(target, {}).values())
    return unsafe


def _legacy_literal_candidates(source: Path) -> dict[tuple[str, str], str]:
    """Kept for tests comparing the broadened discovery surface."""

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
    trees = {module: tree for module, _, tree in files.values()}
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
                if not isinstance(statement, ast.ImportFrom):
                    continue
                target = resolve_import(module, is_package, statement.module, statement.level)
                for alias in statement.names:
                    if alias.name == "*":
                        for name in _public_exports(trees.get(target), set(exports.get(target, ()))):
                            final_binding = _last_top_level_binding(tree, name, sys.maxsize)
                            if final_binding is not None and final_binding.lineno > statement.lineno:
                                continue
                            prior = exports[module].get(name)
                            label = exports[target][name]
                            if prior is not None and prior != label:
                                ambiguous[module].add(name)
                                exports[module].pop(name, None)
                            elif name not in ambiguous[module] and prior is None:
                                exports[module][name] = label
                                changed = True
                        continue
                    label = exports.get(target, {}).get(alias.name)
                    if label is None:
                        continue
                    local = alias.asname or alias.name
                    if _last_top_level_binding(tree, local, sys.maxsize) is not statement:
                        continue
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
            elif isinstance(statement, ast.ImportFrom):
                target = resolve_import(module, is_package, statement.module, statement.level)
                for name in _public_exports(trees.get(target), set(exports.get(target, ()))):
                    value_options[name].add(exports[target][name])
        rebound = {
            node.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del))
        }
        rebound.update(node.arg for node in ast.walk(tree) if isinstance(node, ast.arg))
        own_candidates = {name for candidate_module, name in candidates if candidate_module == module}
        value_maps[module] = {
            name: next(iter(options))
            for name, options in value_options.items()
            if len(options) == 1 and (name in own_candidates or name not in rebound)
        }
        module_maps[module] = {
            name: next(iter(options))
            for name, options in module_options.items()
            if len(options) == 1 and name not in value_options and name not in rebound
        }
    qualified = {
        (module, name): label
        for module, values in exports.items()
        for name, label in values.items()
    }
    return value_maps, module_maps, qualified


def _resolved_label(
    node: ast.AST,
    values: dict[str, str],
    modules: dict[str, str],
    qualified: dict[tuple[str, str], str],
) -> str | None:
    if isinstance(node, ast.Name):
        return values.get(node.id)
    if isinstance(node, ast.Attribute):
        flattened = flatten_attribute(node)
        if flattened:
            base, parts = flattened
            imported = modules.get(base)
            if imported and parts:
                return qualified.get((".".join((imported, *parts[:-1])), parts[-1]))
    return None


def class_alias_labels(
    files: dict[Path, tuple[str, bool, ast.Module]],
    value_maps: dict[str, dict[str, str]],
    module_maps: dict[str, dict[str, str]],
    qualified: dict[tuple[str, str], str],
) -> dict[tuple[str, str, str], str]:
    """Class attributes that bind exactly one profiled module value."""

    aliases: dict[tuple[str, str, str], str | None] = {}
    for module, _is_package, tree in files.values():
        values = value_maps.get(module, {})
        modules = module_maps.get(module, {})

        def visit(body: list[ast.stmt], owners: tuple[str, ...]) -> None:
            for statement in body:
                if not isinstance(statement, ast.ClassDef):
                    continue
                qualname = ".".join((*owners, statement.name))
                # A decorator, metaclass or nontrivial base can inspect or
                # rewrite the namespace while the class is being constructed.
                # In that case a later runtime attribute trace is not a
                # complete account of the module value's readers.
                plain = not statement.decorator_list and not statement.keywords and not statement.bases
                class_tree = ast.Module(body=statement.body, type_ignores=[])
                for item in statement.body:
                    if not plain:
                        continue
                    if isinstance(item, ast.Assign):
                        targets = item.targets
                    elif isinstance(item, ast.AnnAssign):
                        targets = [item.target]
                    else:
                        continue
                    if len(targets) != 1 or not isinstance(targets[0], ast.Name):
                        continue
                    name = targets[0].id
                    if _last_top_level_binding(class_tree, name, sys.maxsize) is not item:
                        continue
                    label = _resolved_label(item.value, values, modules, qualified)
                    if label is None:
                        continue
                    # A direct class-body read can copy/escape the alias before
                    # the runtime wrappers exist. Nested code objects are not
                    # executed by class construction and are handled normally.
                    direct_tail = statement.body[statement.body.index(item) + 1:]
                    escaped = False
                    for later in direct_tail:
                        if isinstance(later, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                            continue
                        if any(
                            isinstance(node, ast.Name)
                            and isinstance(node.ctx, ast.Load)
                            and node.id == name
                            for node in ast.walk(later)
                        ):
                            escaped = True
                            break
                    if escaped:
                        continue
                    key = module, qualname, name
                    aliases[key] = label if key not in aliases else None
                # Nested owners require a separate complete identity/escape
                # graph (``Outer.Inner``); keep this proof to top-level plain
                # classes only.

        visit(tree.body, ())
    return {key: label for key, label in aliases.items() if label is not None}


TRACKER_TEMPLATE = r'''from __future__ import annotations

import atexit
import json
import os
import time
from collections import defaultdict
from pathlib import Path

CURRENT_TEST = os.environ.get("BR_PARENT_TEST")
EVENTS = defaultdict(set)
CLASS_ALIASES = __CLASS_ALIASES__

def owner():
    return CURRENT_TEST or "__NO_TEST__"

def read(label, value):
    EVENTS[label].add(owner())
    return value

def class_alias_label(value, name):
    if not isinstance(name, str):
        return None
    classes = value.__mro__ if isinstance(value, type) else type(value).__mro__
    for cls in classes:
        try:
            namespace = type.__getattribute__(cls, "__dict__")
        except BaseException:
            continue
        if name in namespace:
            return CLASS_ALIASES.get((cls.__module__, cls.__qualname__, name))
    return None

def class_attr(value, name):
    label = class_alias_label(value, name)
    if label:
        EVENTS[label].add(owner())
    return getattr(value, name)

def class_alias_labels(value):
    classes = value.__mro__ if isinstance(value, type) else type(value).__mro__
    seen = set()
    for cls in classes:
        prefix = (cls.__module__, cls.__qualname__)
        for (module, qualname, name), label in CLASS_ALIASES.items():
            if (module, qualname) == prefix and label not in seen:
                seen.add(label)
                yield label

def class_getattr(value, name, *default):
    label = class_alias_label(value, name)
    if label:
        EVENTS[label].add(owner())
    return getattr(value, name, *default)

def class_hasattr(value, name):
    label = class_alias_label(value, name)
    if label:
        EVENTS[label].add(owner())
    return hasattr(value, name)

def class_record_all(value):
    for label in class_alias_labels(value):
        EVENTS[label].add(owner())

def class_vars(value):
    class_record_all(value)
    result = vars(value)
    return result

def class_dict(value):
    class_record_all(value)
    result = getattr(value, "__dict__")
    return result

def class_dir(value):
    class_record_all(value)
    return dir(value)

def reflect_call(function, value, *args, **kwargs):
    class_record_all(value)
    return function(value, *args, **kwargs)

def document():
    return {label: sorted(owners) for label, owners in sorted(EVENTS.items())}

def write_child():
    directory = os.environ.get("MODULE_CONSTANT_CHILD_DIR")
    if not directory or not CURRENT_TEST:
        return
    path = Path(directory, f"{os.getpid()}-{time.time_ns()}.json")
    temporary = path.with_suffix(".tmp")
    payload = document()
    for owners in payload.values():
        owners.append("__BR_CHILD__")
        owners.sort()
    temporary.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    temporary.replace(path)

import builtins
builtins._br_module_constant_read = read
builtins._br_module_constant_class_attr = class_attr
builtins._br_module_constant_getattr = class_getattr
builtins._br_module_constant_hasattr = class_hasattr
builtins._br_module_constant_vars = class_vars
builtins._br_module_constant_class_dict = class_dict
builtins._br_module_constant_dir = class_dir
builtins._br_module_constant_reflect_call = reflect_call
atexit.register(write_child)
'''


PLUGIN = r'''from __future__ import annotations

import json
import hashlib
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
    encoded = json.dumps(
        _br_module_constant.document(), sort_keys=True, separators=(",", ":")
    ).encode()
    Path(os.environ["MODULE_CONSTANT_TRACE"]).write_bytes(encoded)
    Path(os.environ["MODULE_CONSTANT_MANIFEST"]).write_text(json.dumps({
        "child_logs": child_count,
        "exitstatus": exitstatus,
        "mode": os.environ["MODULE_CONSTANT_MODE"],
        "source_sha": os.environ["MODULE_CONSTANT_SOURCE_SHA"],
        "test_digest": os.environ["MODULE_CONSTANT_TEST_DIGEST"],
        "trace_sha256": hashlib.sha256(encoded).hexdigest(),
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
        class_alias_names: set[str] | None = None,
        shadowed_helpers: set[str] | None = None,
    ):
        self.values = values
        self.modules = modules
        self.qualified = qualified
        self.class_alias_names = class_alias_names or set()
        self.shadowed_helpers = shadowed_helpers or set()
        self.alias_binding_values: set[int] = set()
        self.count = 0

    def find_alias_bindings(self, tree: ast.Module) -> None:
        def visit(body: list[ast.stmt]) -> None:
            for statement in body:
                if not isinstance(statement, ast.ClassDef):
                    continue
                for item in statement.body:
                    if isinstance(item, ast.Assign):
                        targets = item.targets
                    elif isinstance(item, ast.AnnAssign):
                        targets = [item.target]
                    else:
                        continue
                    if (
                        len(targets) == 1
                        and isinstance(targets[0], ast.Name)
                        and targets[0].id in self.class_alias_names
                        and _resolved_label(item.value, self.values, self.modules, self.qualified)
                    ):
                        self.alias_binding_values.add(id(item.value))
                visit(statement.body)

        visit(tree.body)

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
        if id(node) in self.alias_binding_values:
            return node
        if self.class_alias_names and node.attr == "__dict__" and isinstance(node.ctx, ast.Load):
            node = self.generic_visit(node)
            self.count += 1
            return ast.copy_location(
                ast.Call(
                    ast.Name("_br_module_constant_class_dict", ast.Load()),
                    [node.value],
                    [],
                ),
                node,
            )
        flattened = flatten_attribute(node) if isinstance(node.ctx, ast.Load) else None
        label = None
        if flattened:
            base, parts = flattened
            module = self.modules.get(base)
            if module and parts:
                target_module = ".".join((module, *parts[:-1]))
                label = self.qualified.get((target_module, parts[-1]))
        node = self.generic_visit(node)
        if label:
            return self.wrap(node, label)
        if isinstance(node.ctx, ast.Load) and node.attr in self.class_alias_names:
            self.count += 1
            return ast.copy_location(
                ast.Call(
                    ast.Name("_br_module_constant_class_attr", ast.Load()),
                    [node.value, ast.Constant(node.attr)],
                    [],
                ),
                node,
            )
        return node

    def visit_Call(self, node: ast.Call):
        module = None
        label = None
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in {"getattr", "hasattr"}
            and node.func.id not in self.shadowed_helpers
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and type(node.args[1].value) is str
        ):
            if isinstance(node.args[0], ast.Name):
                module = self.modules.get(node.args[0].id)
            elif isinstance(node.args[0], ast.Attribute):
                flattened = flatten_attribute(node.args[0])
                if flattened:
                    base, parts = flattened
                    imported = self.modules.get(base)
                    if imported:
                        module = ".".join((imported, *parts))
            label = self.qualified.get((module, node.args[1].value)) if module else None
        node = self.generic_visit(node)
        if isinstance(node.func, ast.Name):
            if (
                self.class_alias_names
                and node.func.id == "getattr"
                and node.func.id not in self.shadowed_helpers
                and node.args
            ):
                self.count += 1
                node.func = ast.copy_location(
                    ast.Name("_br_module_constant_getattr", ast.Load()), node.func
                )
            elif (
                self.class_alias_names
                and node.func.id == "hasattr"
                and node.func.id not in self.shadowed_helpers
                and len(node.args) == 2
            ):
                self.count += 1
                node.func = ast.copy_location(
                    ast.Name("_br_module_constant_hasattr", ast.Load()), node.func
                )
            elif (
                self.class_alias_names
                and node.func.id == "vars"
                and node.func.id not in self.shadowed_helpers
                and len(node.args) == 1
            ):
                self.count += 1
                node.func = ast.copy_location(
                    ast.Name("_br_module_constant_vars", ast.Load()), node.func
                )
            elif (
                self.class_alias_names
                and node.func.id == "dir"
                and node.func.id not in self.shadowed_helpers
                and len(node.args) == 1
            ):
                self.count += 1
                node.func = ast.copy_location(
                    ast.Name("_br_module_constant_dir", ast.Load()), node.func
                )
        elif (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"getmembers", "getmembers_static"}
            and node.args
        ):
            self.count += 1
            node = ast.copy_location(
                ast.Call(
                    ast.Name("_br_module_constant_reflect_call", ast.Load()),
                    [node.func, *node.args],
                    node.keywords,
                ),
                node,
            )
        return self.wrap(node, label) if label else node

    def visit_Name(self, node: ast.Name):
        if id(node) in self.alias_binding_values:
            return node
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
    class_alias_names: set[str] | None = None,
) -> int:
    helper_names = {"getattr", "hasattr", "vars", "dir"}
    shadowed_helpers = {
        node.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and node.id in helper_names
    }
    shadowed_helpers.update(
        node.arg for node in ast.walk(tree)
        if isinstance(node, ast.arg) and node.arg in helper_names
    )
    instrumenter = Instrumenter(
        values, modules, qualified, class_alias_names, shadowed_helpers
    )
    instrumenter.find_alias_bindings(tree)
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
    test_ids = [test["id"] for test in json.loads(args.tests.read_text())["tests"]]
    test_digest = hashlib.sha256("\0".join(test_ids).encode()).hexdigest()
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
        (support / "module_constant_plugin.py").write_text(PLUGIN)
        (support / "sitecustomize.py").write_text("import _br_module_constant\n")
        if args.synchronous_workers:
            synchronous_worker_tests(work)
        files = parsed_files(work)
        collisions = {
            node.id
            for _path, (_module, _package, tree) in files.items()
            for node in ast.walk(tree)
            if isinstance(node, ast.Name) and node.id in RUNTIME_HELPERS
        }
        if collisions:
            raise SystemExit(f"source collides with runtime helpers: {sorted(collisions)}")
        value_maps, module_maps, qualified = import_maps(files, candidates)
        class_aliases = (
            class_alias_labels(files, value_maps, module_maps, qualified)
            if DERIVED_CLASS_ALIASES_ENABLED
            else {}
        )
        alias_names = {name for _module, _qualname, name in class_aliases}
        tracker = TRACKER_TEMPLATE.replace("__CLASS_ALIASES__", repr(class_aliases))
        (support / "_br_module_constant.py").write_text(tracker)
        instrumented = 0
        for path, (module, _, tree) in files.items():
            instrumented += instrument_file(
                path,
                tree,
                value_maps.get(module, {}),
                module_maps.get(module, {}),
                qualified,
                alias_names,
            )
        environment = os.environ.copy()
        environment.update({
            "MODULE_CONSTANT_CHILD_DIR": str(children),
            "MODULE_CONSTANT_MANIFEST": str(manifest),
            "MODULE_CONSTANT_MODE": "synchronous-worker" if args.synchronous_workers else "normal",
            "MODULE_CONSTANT_SOURCE_SHA": PINNED_SHA,
            "MODULE_CONSTANT_TEST_DIGEST": test_digest,
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
    if (
        document.get("source_sha") != PINNED_SHA
        or document.get("test_digest") != test_digest
        or document.get("trace_sha256") != hashlib.sha256(output.read_bytes()).hexdigest()
    ):
        raise SystemExit("suite manifest is not bound to its source/tests/trace")
    print(
        f"wrote {output} from {len(candidates)} module constants, "
        f"{instrumented} read sites, and {len(document['tests'])} tests"
    )


if __name__ == "__main__":
    main()
