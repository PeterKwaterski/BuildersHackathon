#!/usr/bin/env python3
"""Build the complete owner-aware module-literal reader profile."""

from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import json
import subprocess
from collections import defaultdict
from pathlib import Path

from collect_module_constant_reads import (
    DERIVED_CLASS_ALIASES_ENABLED,
    class_alias_labels,
    collector_code_digest,
    flatten_attribute,
    import_maps,
    module_name,
    parsed_files,
    resolve_import,
    source_candidate_kinds,
    source_candidates,
    source_inventory_digest,
    unresolved_star_labels,
    validated_trace_document,
)


PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"
CHILD_SENTINEL = "__BR_CHILD__"
AMBIENT_PREFIX = "__BR_AMBIENT__:"
SERDE_LOAD_AST_SHA256 = "659b519ac3e700459bcf6b1b0e733dc220a9437e818dd34dbf529415b80cddaa"
SUBCLASSES_AST_SHA256 = "86e955dd0d21cbfb62e080f063b8a87b81fb6f28a42fde3b6342c97ad2a314bf"
IS_COMPILED_AST_SHA256 = "cee552b88c482f8a2cfbc3be92d9f7240880fd0b2426338d54517747f6a5e4c7"
OPTIMIZER_GETATTR_AST_SHA256 = "ab523efc4eb936a0e59bdec0156428904a2107c287d32c9aa8b316cbd5ec2f14"
TYPING_METADATA_TEST_AST_SHA256 = "52f8b14e75cc44673d10d8d926c29fb10c4bb88ed0c2829324301748c0f84e27"
SQLGLOTC_MODULE_PATCH_AST_SHA256 = "de6305a412c38ccafb4b58c860d08a2cdbfaba1dd4590bc9e62b9845ce2d06c0"
DIALECT_IMPORT_CACHE_TEST_AST_SHA256 = "87152a12c9abc3a5eb774a882924031a627b04f143e4c5b720a84e085473aa03"
EXECUTOR_ENV_MODULE_AST_SHA256 = "8b0919c9be54766a3586593dcee1ccc5097ed6aef1afb568f1590ab21a5ab1f8"
EXECUTOR_PYTHON_MODULE_AST_SHA256 = "72444981bcfa62f6a082d0fdf2ad3b8464d2b11b67088c1f7a95b9901aea8695"
EXECUTOR_CONTEXT_MODULE_AST_SHA256 = "baa03f665069c9b814230a0448eba0ed9f7af8961beee75d2d8dfe0ab3d5dd50"
PYTHON_GENERATOR_MODULE_AST_SHA256 = "afaf387a9833002d3b0475a721699ca27f393b90a5e5cd109e6c639364217128"
TRACE_SCHEMA_VERSION = 4
MODEL_SCHEMA_VERSION = 3


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, action="append", required=True)
    parser.add_argument("--trace", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def conservative_child_owners(
    owners: set[str], expected: set[str], test_ids: list[str]
) -> set[str]:
    """Expand only reads outside an attributed process-pool task."""
    result = set(owners)
    result.discard(CHILD_SENTINEL)
    ambient = {
        owner.removeprefix(AMBIENT_PREFIX)
        for owner in owners
        if owner.startswith(AMBIENT_PREFIX)
    }
    result.difference_update(
        owner for owner in tuple(result) if owner.startswith(AMBIENT_PREFIX)
    )
    if "__NO_TEST__" in ambient:
        result.add("__NO_TEST__")
    ambient_files = {
        owner.split("::", 1)[0] for owner in ambient if owner in expected
    }
    result.update(
        test_id
        for test_id in test_ids
        if test_id.split("::", 1)[0] in ambient_files
    )
    return result


def immutable_literal(value: object) -> bool:
    if value is None or value is Ellipsis:
        return True
    if type(value) in {bool, int, float, complex, str, bytes}:
        return True
    return type(value) is tuple and all(immutable_literal(item) for item in value)


def entries(source: Path):
    labels = source_candidates(source)
    kinds = source_candidate_kinds(source)
    result = []
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
            name = targets[0].id
            label = labels.get((module, name))
            if label is None:
                continue
            kind = kinds.get((module, name))
            if kind == "literal":
                value = ast.literal_eval(statement.value)
                immutable = immutable_literal(value)
            elif kind in {"class-tuple", "re-pattern"}:
                immutable = True
            else:
                continue
            result.append((relative, module, statement, name, label, kind, immutable))
    return result


def binding_names(node: ast.AST) -> set[str]:
    names = set()
    for item in ast.walk(node):
        if isinstance(item, ast.Name) and isinstance(item.ctx, (ast.Store, ast.Del)):
            names.add(item.id)
    return names


def opaque_class_aliases(
    files: dict[Path, tuple[str, bool, ast.Module]],
    aliases: dict[tuple[str, str, str], str],
) -> set[str]:
    """Labels whose derived owner class can reach uninstrumented reflection."""

    unsafe = set()
    owners_by_module: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    labels_by_owner_name: dict[str, set[str]] = defaultdict(set)
    labels_by_attribute: dict[str, set[str]] = defaultdict(set)
    for (module, qualname, attribute), label in aliases.items():
        owner = qualname.split(".", 1)[0]
        owners_by_module[module][owner].add(label)
        labels_by_owner_name[owner].add(label)
        labels_by_attribute[attribute].add(label)

    for _path, (module, is_package, tree) in files.items():
        reflective_names = {"getattr", "hasattr", "vars", "dir"}
        shadowed_reflection = {
            node.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Name)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and node.id in reflective_names
        }
        shadowed_reflection.update(
            node.arg for node in ast.walk(tree)
            if isinstance(node, ast.arg) and node.arg in reflective_names
        )
        local_owners: dict[str, set[str]] = defaultdict(set)
        for owner, labels in owners_by_module.get(module, {}).items():
            local_owners[owner].update(labels)
        for statement in tree.body:
            if not isinstance(statement, ast.ImportFrom):
                continue
            target = resolve_import(module, is_package, statement.module, statement.level)
            for alias in statement.names:
                if alias.name in owners_by_module.get(target, {}):
                    local_owners[alias.asname or alias.name].update(
                        owners_by_module[target][alias.name]
                    )

        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        annotation_nodes = set()
        for item in ast.walk(tree):
            roots = []
            if isinstance(item, ast.AnnAssign):
                roots.append(item.annotation)
            elif isinstance(item, ast.arg) and item.annotation is not None:
                roots.append(item.annotation)
            elif isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.returns is not None:
                roots.append(item.returns)
            for root in roots:
                annotation_nodes.update(ast.walk(root))
        for node in ast.walk(tree):
            labels = set()
            if isinstance(node, ast.Name):
                labels.update(local_owners.get(node.id, ()))
            elif isinstance(node, ast.Attribute):
                labels.update(labels_by_owner_name.get(node.attr, ()))
            if labels:
                if node in annotation_nodes:
                    continue
                parent = parents.get(node)
                if isinstance(parent, ast.Attribute) and parent.value is node:
                    continue
                if (
                    isinstance(parent, ast.Call)
                    and isinstance(parent.func, ast.Name)
                    and parent.func.id in {"isinstance", "issubclass"}
                    and node in parent.args[1:]
                ):
                    continue
                if (
                    isinstance(parent, ast.Call)
                    and parent.args
                    and parent.args[0] is node
                    and (
                        isinstance(parent.func, ast.Name)
                        and parent.func.id in {"getattr", "hasattr", "vars", "dir"}
                        and parent.func.id not in shadowed_reflection
                        or isinstance(parent.func, ast.Attribute)
                        and parent.func.attr in {"getmembers", "getmembers_static"}
                    )
                ):
                    continue
                unsafe.update(labels)

            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr not in {"getattr_static", "attrgetter"}:
                    continue
                names = {
                    argument.value
                    for argument in node.args
                    if isinstance(argument, ast.Constant) and type(argument.value) is str
                }
                if names:
                    for name in names:
                        unsafe.update(labels_by_attribute.get(name, ()))
                else:
                    unsafe.update(aliases.values())
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"eval", "exec"}
            ):
                unsafe.update(aliases.values())
    return unsafe


def static_unsafe(
    source: Path,
    candidates: dict[tuple[str, str], str],
    test_files: set[str] | None = None,
) -> set[str]:
    """Reject reads the source rewriter cannot owner-resolve without guessing."""

    all_files = parsed_files(source)
    active_test_paths = set(test_files or ())
    if test_files is not None:
        # Pytest imports conftest/package setup independently of numbered test
        # ownership. Numbered owner modules also import support modules such as
        # tests.helpers which have no direct manifest IDs but execute in the
        # same process and therefore remain part of the threat surface.
        active_test_paths.update({"tests/__init__.py", "tests/conftest.py"})
        path_by_module = {
            module: path.relative_to(source).as_posix()
            for path, (module, _is_package, _tree) in all_files.items()
            if path.is_relative_to(source / "tests")
        }
        available_test_paths = set(path_by_module.values())

        def add_test_ancestors(relative: str) -> bool:
            added = False
            parent = Path(relative).parent
            while parent.as_posix().startswith("tests"):
                for name in ("__init__.py", "conftest.py"):
                    candidate = (parent / name).as_posix()
                    if (
                        candidate in available_test_paths
                        and candidate not in active_test_paths
                    ):
                        active_test_paths.add(candidate)
                        added = True
                if parent.as_posix() == "tests":
                    break
                parent = parent.parent
            return added

        changed = True
        while changed:
            changed = False
            for relative in tuple(active_test_paths):
                changed |= add_test_ancestors(relative)
            for path, (module, is_package, tree) in all_files.items():
                relative = path.relative_to(source).as_posix()
                if relative not in active_test_paths:
                    continue
                imported_modules = set()
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        imported_modules.update(alias.name for alias in node.names)
                    elif isinstance(node, ast.ImportFrom):
                        target = resolve_import(
                            module, is_package, node.module, node.level
                        )
                        imported_modules.add(target)
                        imported_modules.update(
                            f"{target}.{alias.name}"
                            for alias in node.names
                            if alias.name != "*"
                        )
                    elif (
                        isinstance(node, ast.Call)
                        and (
                            isinstance(node.func, ast.Name)
                            and node.func.id == "__import__"
                            or isinstance(node.func, ast.Attribute)
                            and node.func.attr == "import_module"
                        )
                        and node.args
                        and isinstance(node.args[0], ast.Constant)
                        and type(node.args[0].value) is str
                    ):
                        imported_modules.add(node.args[0].value)
                for imported in imported_modules:
                    imported_path = path_by_module.get(imported)
                    if imported_path and imported_path not in active_test_paths:
                        active_test_paths.add(imported_path)
                        changed = True

    files = {
        path: value
        for path, value in all_files.items()
        if not path.is_relative_to(source / "tests")
        or test_files is None
        or path.relative_to(source).as_posix() in active_test_paths
    }
    values, module_aliases, qualified = import_maps(files, candidates)
    unsafe = set(unresolved_star_labels(files, candidates))
    aliases = (
        class_alias_labels(files, values, module_aliases, qualified)
        if DERIVED_CLASS_ALIASES_ENABLED
        else {}
    )
    unsafe.update(opaque_class_aliases(files, aliases))
    labels_by_module: dict[str, dict[str, str]] = defaultdict(dict)
    for (module, name), label in candidates.items():
        labels_by_module[module][name] = label
    export_modules = {module for module, _name in qualified}

    def module_surface(module: str, descendants: bool = False) -> set[str]:
        return {
            label
            for (exporter, _name), label in qualified.items()
            if exporter == module
            or descendants
            and exporter.startswith(module + ".")
        }

    def function_sha(tree: ast.Module, name: str) -> str | None:
        matches = [
            statement
            for statement in ast.walk(tree)
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
            and statement.name == name
        ]
        if len(matches) != 1:
            return None
        payload = ast.dump(matches[0], include_attributes=False).encode()
        return hashlib.sha256(payload).hexdigest()

    authenticated_functions = {
        (module, name): function_sha(tree, name) == expected
        for module, _is_package, tree in files.values()
        for name, expected in (
            (("_load", SERDE_LOAD_AST_SHA256),)
            if module == "sqlglot.serde"
            else (("subclasses", SUBCLASSES_AST_SHA256),)
            if module == "sqlglot.helper"
            else (("is_compiled", IS_COMPILED_AST_SHA256),)
            if module == "tests.helpers"
            else (("__getattr__", OPTIMIZER_GETATTR_AST_SHA256),)
            if module == "sqlglot.optimizer"
            else (("test_no_redundant_expression_metadata", TYPING_METADATA_TEST_AST_SHA256),)
            if module == "tests.test_typing"
            else (("setUpClass", SQLGLOTC_MODULE_PATCH_AST_SHA256),)
            if module == "tests.test_sqlglotc"
            else (("test_dialect_attribute_access_is_cached", DIALECT_IMPORT_CACHE_TEST_AST_SHA256),)
            if module == "tests.test_dialect_imports"
            else ()
        )
    }
    module_ast_hashes = {
        module: hashlib.sha256(
            ast.dump(tree, include_attributes=False).encode()
        ).hexdigest()
        for module, _is_package, tree in files.values()
    }
    executor_module_escape_authenticated = (
        module_ast_hashes.get("sqlglot.executor.env")
        == EXECUTOR_ENV_MODULE_AST_SHA256
        and module_ast_hashes.get("sqlglot.executor.python")
        == EXECUTOR_PYTHON_MODULE_AST_SHA256
        and module_ast_hashes.get("sqlglot.executor.context")
        == EXECUTOR_CONTEXT_MODULE_AST_SHA256
        and module_ast_hashes.get("sqlglot.generators.python")
        == PYTHON_GENERATOR_MODULE_AST_SHA256
    )

    dynamic_packages = {
        module
        for module, _is_package, tree in files.values()
        if any(
            isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
            and statement.name == "__getattr__"
            for statement in tree.body
        )
    }
    for package in dynamic_packages:
        unsafe.update(module_surface(package, descendants=True))

    # A second binding changes which object a later Name load denotes. Ignore
    # the unique candidate assignment itself; reject module bindings and
    # explicit global writes everywhere else.
    for path, (module, is_package, tree) in files.items():
        shadowed_reflection = {
            node.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Name)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and node.id in {"getattr", "hasattr", "vars", "dir"}
        }
        shadowed_reflection.update(
            node.arg for node in ast.walk(tree)
            if isinstance(node, ast.arg)
            and node.arg in {"getattr", "hasattr", "vars", "dir"}
        )
        own = labels_by_module.get(module, {})
        value_options: dict[str, set[str]] = defaultdict(set)
        module_options: dict[str, set[str]] = defaultdict(set)
        for name, label in own.items():
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
                    label = qualified.get((target, alias.name))
                    if label:
                        value_options[local].add(label)
                    submodule = f"{target}.{alias.name}" if target else alias.name
                    if submodule in labels_by_module or any(
                        candidate.startswith(submodule + ".")
                        for candidate in labels_by_module
                    ):
                        module_options[local].add(submodule)
        for local in value_options.keys() | module_options.keys():
            values = value_options.get(local, set())
            modules = module_options.get(local, set())
            if len(values) > 1 or len(modules) > 1 or (values and modules):
                unsafe.update(values)
                for imported in modules:
                    unsafe.update(module_surface(imported))

        reflective = {
            "getattr", "hasattr", "setattr", "delattr", "vars",
            "globals", "locals", "eval", "exec",
        }
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = node.value
                if isinstance(value, ast.Name) and value.id in reflective:
                    raise SystemExit(f"aliased reflective builtin at {path}:{node.lineno}")
            if isinstance(node, ast.ImportFrom) and node.module == "builtins" and any(
                alias.name in reflective for alias in node.names
            ):
                raise SystemExit(f"imported reflective builtin at {path}:{node.lineno}")
        for statement in tree.body:
            original = None
            if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
                target = statement.targets[0]
                if isinstance(target, ast.Name):
                    label = own.get(target.id)
                    if label and label.split(":", 3)[1] == str(statement.lineno):
                        original = target.id
            elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
                label = own.get(statement.target.id)
                if label and label.split(":", 3)[1] == str(statement.lineno):
                    original = statement.target.id
            rebound = binding_names(statement)
            if original:
                rebound.discard(original)
            for name in rebound.intersection(own):
                unsafe.add(own[name])

        # Nested imports are legal Python but absent from the top-level alias
        # map used by the trace rewriter. Resolve only candidate reads that
        # actually occur; a function-local ``import sqlglot`` alone is not a
        # read of every constant in the package.
        nested_modules: dict[str, set[str]] = defaultdict(set)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Import, ast.ImportFrom)) or node in tree.body:
                continue
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".", 1)[0]
                    nested_modules[local].add(
                        alias.name if alias.asname else alias.name.split(".", 1)[0]
                    )
            else:
                target = resolve_import(module, is_package, node.module, node.level)
                if any(alias.name == "*" for alias in node.names):
                    unsafe.update(module_surface(target))
                for alias in node.names:
                    label = candidates.get((target, alias.name))
                    if label:
                        unsafe.add(label)
                    submodule = f"{target}.{alias.name}" if target else alias.name
                    if submodule in labels_by_module or any(
                        candidate.startswith(submodule + ".") for candidate in labels_by_module
                    ):
                        nested_modules[alias.asname or alias.name].add(submodule)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Attribute) or not isinstance(node.ctx, ast.Load):
                continue
            flattened = flatten_attribute(node)
            if not flattened:
                continue
            base, parts = flattened
            if parts:
                for imported in nested_modules.get(base, ()):
                    label = qualified.get((".".join((imported, *parts[:-1])), parts[-1]))
                    if label:
                        unsafe.add(label)

        aliases = dict(module_aliases.get(module, {}))
        for local, imported_modules in nested_modules.items():
            previous = aliases.get(local)
            possible = set(imported_modules)
            if previous is not None:
                possible.add(previous)
            if len(possible) != 1:
                for imported in possible:
                    unsafe.update(module_surface(imported))
                aliases.pop(local, None)
            else:
                aliases[local] = possible.pop()

        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }

        def enclosing_function(node: ast.AST) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
            parent = parents.get(node)
            while parent is not None:
                if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return parent
                parent = parents.get(parent)
            return None

        def in_authenticated_function(node: ast.AST, name: str) -> bool:
            owner = enclosing_function(node)
            return bool(
                owner is not None
                and owner.name == name
                and authenticated_functions.get((module, name))
            )

        def in_authenticated_scope(node: ast.AST, name: str) -> bool:
            parent = parents.get(node)
            while parent is not None:
                if (
                    isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and parent.name == name
                ):
                    return bool(authenticated_functions.get((module, name)))
                parent = parents.get(parent)
            return False

        def safe_module_sink(node: ast.AST) -> bool:
            """Recognize pinned consumers that inspect module metadata only."""
            parent = parents.get(node)
            compiled_executor_environment = bool(
                executor_module_escape_authenticated
                and module == "sqlglot.executor.env"
                and isinstance(parent, ast.Dict)
                and any(
                    value is node
                    and isinstance(key, ast.Constant)
                    and key.value == "exp"
                    for key, value in zip(parent.keys, parent.values)
                )
            )
            fixed_patch_object = bool(
                module == "tests.test_optimizer"
                and isinstance(parent, ast.Call)
                and len(parent.args) >= 2
                and parent.args[0] is node
                and isinstance(parent.args[1], ast.Constant)
                and parent.args[1].value == "column_table_names"
                and isinstance(parent.func, ast.Attribute)
                and parent.func.attr == "object"
                and isinstance(parent.func.value, ast.Name)
                and parent.func.value.id == "patch"
            )
            metadata_only = bool(
                module in {"tests.test_generator", "tests.test_serde"}
                and authenticated_functions.get(("tests.helpers", "is_compiled"))
                and isinstance(parent, ast.Call)
                and parent.args
                and parent.args[0] is node
                and isinstance(parent.func, ast.Name)
                and parent.func.id == "is_compiled"
            )
            return compiled_executor_environment or fixed_patch_object or metadata_only

        def joined_string_prefix(node: ast.AST) -> str | None:
            if not isinstance(node, ast.JoinedStr) or not node.values:
                return None
            first = node.values[0]
            return first.value if isinstance(first, ast.Constant) and type(first.value) is str else None

        importlib_names = {"importlib"}
        dynamic_import_aliases = set()
        for candidate in ast.walk(tree):
            if isinstance(candidate, ast.Import):
                importlib_names.update(
                    alias.asname or alias.name
                    for alias in candidate.names
                    if alias.name == "importlib"
                )
            elif isinstance(candidate, ast.ImportFrom) and candidate.module == "importlib":
                dynamic_import_aliases.update(
                    alias.asname or alias.name
                    for alias in candidate.names
                    if alias.name == "import_module"
                )
            elif (
                isinstance(candidate, (ast.Assign, ast.AnnAssign))
                and isinstance(candidate.value, ast.Attribute)
                and candidate.value.attr == "import_module"
                and isinstance(candidate.value.value, ast.Name)
                and candidate.value.value.id in importlib_names
            ):
                targets = (
                    candidate.targets
                    if isinstance(candidate, ast.Assign)
                    else [candidate.target]
                )
                dynamic_import_aliases.update(
                    target.id for target in targets if isinstance(target, ast.Name)
                )

        def module_target(node: ast.AST) -> str | None:
            if isinstance(node, ast.Name):
                return aliases.get(node.id)
            if isinstance(node, ast.Attribute):
                flattened = flatten_attribute(node)
                if flattened:
                    base, parts = flattened
                    imported = aliases.get(base)
                    target = ".".join((imported, *parts)) if imported else None
                    if target in export_modules:
                        return target
            return None

        for node in ast.walk(tree):
            dynamic_import = False
            aliased_dynamic_import = False
            imported_name = None
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == "__import__":
                    dynamic_import = True
                elif isinstance(node.func, ast.Attribute) and node.func.attr == "import_module":
                    dynamic_import = True
                elif (
                    isinstance(node.func, ast.Name)
                    and node.func.id in dynamic_import_aliases
                ):
                    dynamic_import = True
                    aliased_dynamic_import = True
                if (
                    dynamic_import
                    and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and type(node.args[0].value) is str
                ):
                    imported_name = node.args[0].value
            if dynamic_import:
                # ``serde._load`` can acquire any module, but its authenticated
                # body immediately calls the requested attribute as a class.
                # Every candidate kind in this model is provably non-class and
                # non-callable; the runtime gate also preserves its exact type.
                # A candidate-name request therefore raises the same type-only
                # TypeError before either old or new value can be observed.
                if module == "sqlglot.serde" and in_authenticated_function(node, "_load"):
                    pass
                elif (
                    aliased_dynamic_import
                    and module == "tests.test_dialect_imports"
                    and in_authenticated_scope(
                        node, "test_dialect_attribute_access_is_cached"
                    )
                ):
                    # The pinned spy forwards only the name supplied by the
                    # authenticated Snowflake package-attribute lookup; the
                    # caller then reads that exact class and no other export.
                    pass
                # This pinned test dynamically imports typing parents and
                # observes only their fixed ``EXPRESSION_METADATA`` attribute.
                # Candidate names are distinct and the test source is part of
                # the authenticated numbered roster.
                elif module == "tests.test_typing" and in_authenticated_function(
                    node, "test_no_redundant_expression_metadata"
                ):
                    pass
                # The authenticated optimizer lazy loader is bounded to its
                # own package by its literal table and ``__name__`` fallback.
                elif module == "sqlglot.optimizer" and in_authenticated_function(
                    node, "__getattr__"
                ):
                    unsafe.update(module_surface(module, descendants=True))
                elif imported_name and imported_name.startswith("sqlglot"):
                    unsafe.update(module_surface(imported_name, descendants=True))
                elif imported_name is None:
                    prefix = joined_string_prefix(node.args[0]) if node.args else None
                    if prefix and prefix.startswith("sqlglot"):
                        unsafe.update(
                            label
                            for (exporter, _name), label in qualified.items()
                            if exporter.startswith(prefix)
                        )
                    else:
                        unsafe.update(candidates.values())
            if (
                isinstance(node, ast.Attribute)
                and node.attr == "modules"
                and isinstance(node.value, ast.Name)
                and node.value.id == "sys"
            ):
                parent = parents.get(node)
                membership_only = bool(
                    isinstance(parent, ast.Compare)
                    and parent.comparators
                    and parent.comparators[-1] is node
                    and isinstance(parent.ops[-1], (ast.In, ast.NotIn))
                )
                subclasses_only = (
                    module == "sqlglot.helper"
                    and in_authenticated_function(node, "subclasses")
                )
                fixed_patch_dict = (
                    module == "tests.test_sqlglotc"
                    and in_authenticated_function(
                        node, "setUpClass"
                    )
                )
                # Membership observes only registry keys. The authenticated
                # subclasses helper observes candidate values only through
                # ``inspect.isclass``; all modeled values are statically
                # non-classes before and after an admitted edit.
                if not (membership_only or subclasses_only or fixed_patch_dict):
                    unsafe.update(candidates.values())
            if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
                flattened = flatten_attribute(node)
                if flattened:
                    base, parts = flattened
                    imported = aliases.get(base)
                    if imported and parts:
                        label = qualified.get((".".join((imported, *parts[:-1])), parts[-1]))
                        if label:
                            unsafe.add(label)
            if not isinstance(node, (ast.Name, ast.Attribute)) or not isinstance(
                node.ctx, ast.Load
            ):
                continue
            imported = module_target(node)
            if not imported:
                continue
            parent = parents.get(node)
            if isinstance(parent, ast.Attribute) and parent.value is node:
                continue
            if (
                isinstance(parent, ast.Call)
                and isinstance(parent.func, ast.Name)
                and parent.func.id in {"getattr", "hasattr"}
                and parent.func.id not in shadowed_reflection
                and parent.args
                and parent.args[0] is node
            ):
                continue
            if safe_module_sink(node):
                continue
            if (
                module == "sqlglot.serde"
                and isinstance(node, ast.Name)
                and node.id == "exp"
                and in_authenticated_function(node, "_load")
            ):
                # The only bare module alias in the pinned loader feeds the
                # same authenticated non-class ``getattr(... )()`` path above.
                continue
            # Passing a module object to arbitrary Python/native code can
            # reflect over its namespace without an observable Attribute node.
            unsafe.update(
                label for (target, _name), label in qualified.items() if target == imported
            )
        # Reflection on a known module object bypasses direct Name/Attribute
        # rewriting. Exact names reject one candidate; dynamic names reject the
        # module. globals()/locals()/vars() reflection does the same for the
        # current module.
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "__dict__":
                target_module = module_target(node.value)
                if target_module:
                    unsafe.update(module_surface(target_module))
            if not isinstance(node, ast.Call):
                continue
            function = node.func.id if isinstance(node.func, ast.Name) else None
            if function in {"eval", "exec"}:
                unsafe.update(own.values())
            if function in {"globals", "locals"}:
                unsafe.update(own.values())
            if function == "vars" and (not node.args):
                unsafe.update(own.values())
            if function == "vars" and node.args:
                target_module = module_target(node.args[0])
                if target_module:
                    unsafe.update(module_surface(target_module))
            if function not in {"getattr", "hasattr", "setattr", "delattr"} or len(node.args) < 2:
                continue
            target_module = module_target(node.args[0])
            if not target_module:
                continue
            if isinstance(node.args[1], ast.Constant) and type(node.args[1].value) is str:
                label = qualified.get((target_module, node.args[1].value))
                if label and function in {"setattr", "delattr"}:
                    unsafe.add(label)
            else:
                unsafe.update(module_surface(target_module))

    return unsafe


def main() -> None:
    args = arguments()
    if len(args.manifest) != 2 or len(args.trace) != 2:
        raise SystemExit("exactly one normal and one synchronous-worker trace are required")
    source = args.source.resolve()
    revision = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    if revision != PINNED_SHA:
        raise SystemExit(f"source is {revision}, expected {PINNED_SHA}")
    tests = json.loads(args.tests.read_text())["tests"]
    test_ids = [test["id"] for test in tests]
    test_index = {test_id: index for index, test_id in enumerate(test_ids)}
    expected = set(test_ids)
    test_digest = hashlib.sha256("\0".join(test_ids).encode()).hexdigest()
    collector_sha256 = collector_code_digest()
    inventory_digest = source_inventory_digest(source)
    expected_manifest_keys = {
        "child_logs", "collector_sha256", "completed_tasks", "exitstatus", "mode",
        "pool_workers", "source_inventory_digest", "source_sha",
        "standalone_child_logs", "submitted_tasks", "task_attribution",
        "task_workers", "test_digest", "tests", "trace_sha256", "tracker_version",
    }
    manifests = [json.loads(path.read_text()) for path in args.manifest]
    if any(not isinstance(manifest, dict) for manifest in manifests) or {
        manifest.get("mode") for manifest in manifests
    } != {
        "normal", "synchronous-worker"
    }:
        raise SystemExit("both trace modes are required")
    documents = []
    evidence = {}
    for path, trace_path, manifest in zip(args.manifest, args.trace, manifests):
        mode = manifest.get("mode")
        executed = manifest.get("tests")
        if manifest.get("exitstatus") != 0 or executed != test_ids:
            missing = expected - set(executed or ())
            extras = set(executed or ()) - expected
            raise SystemExit(
                f"inadmissible exact-roster manifest {path}: "
                f"missing={len(missing)} extras={len(extras)} "
                f"order_match={executed == test_ids}"
            )
        raw = trace_path.read_bytes()
        if (
            not isinstance(manifest, dict)
            or set(manifest) != expected_manifest_keys
            or manifest.get("source_sha") != revision
            or manifest.get("collector_sha256") != collector_sha256
            or manifest.get("source_inventory_digest") != inventory_digest
            or manifest.get("test_digest") != test_digest
            or manifest.get("trace_sha256") != hashlib.sha256(raw).hexdigest()
            or manifest.get("tracker_version") != TRACE_SCHEMA_VERSION
            or manifest.get("task_attribution") != "submit-wrapper-v4-ambient"
            or manifest.get("pool_workers") != 2
            or type(manifest.get("child_logs")) is not int
            or type(manifest.get("standalone_child_logs")) is not int
            or manifest.get("standalone_child_logs") != 1
            or type(manifest.get("submitted_tasks")) is not int
            or type(manifest.get("completed_tasks")) is not int
            or manifest.get("submitted_tasks") != manifest.get("completed_tasks")
            or type(manifest.get("task_workers")) is not int
        ):
            raise SystemExit(f"manifest {path} is not bound to its source/tests/trace")
        document = json.loads(raw)
        events, tasks = validated_trace_document(document, mode)
        worker_count = len({
            worker for workers in tasks["workers"].values() for worker in workers
        })
        if (
            manifest["submitted_tasks"] != len(tasks["submitted"])
            or manifest["completed_tasks"] != len(tasks["completed"])
            or manifest["task_workers"] != worker_count
            or manifest["child_logs"]
            != worker_count + manifest["standalone_child_logs"]
        ):
            raise SystemExit(f"manifest {path} has incomplete child/task accounting")
        documents.append(events)
        evidence[mode] = {
            "child_logs": manifest["child_logs"],
            "completed_tasks": manifest["completed_tasks"],
            "manifest": hashlib.sha256(path.read_bytes()).hexdigest(),
            "standalone_child_logs": manifest["standalone_child_logs"],
            "task_workers": manifest["task_workers"],
            "trace": hashlib.sha256(raw).hexdigest(),
        }

    known_labels = set(source_candidates(source).values())
    unknown_labels = set().union(*(set(document) for document in documents)) - known_labels
    if unknown_labels:
        raise SystemExit(f"trace contains {len(unknown_labels)} unknown labels")
    unknown_owners = {
        owner
        for document in documents
        for owners in document.values()
        for owner in owners
        if owner not in {"__NO_TEST__", CHILD_SENTINEL}
        and owner not in expected
        and not (
            owner.startswith(AMBIENT_PREFIX)
            and owner.removeprefix(AMBIENT_PREFIX) in expected | {"__NO_TEST__"}
        )
    }
    if unknown_owners:
        raise SystemExit(f"trace contains {len(unknown_owners)} unknown test owners")

    source_entries = entries(source)
    unsafe = static_unsafe(
        source,
        source_candidates(source),
        {test_id.split("::", 1)[0] for test_id in test_ids},
    )
    profile: dict[str, list[list]] = defaultdict(list)
    states = defaultdict(int)
    for relative, _module, statement, name, label, kind, immutable in source_entries:
        observations = [document.get(label) for document in documents]
        owners = conservative_child_owners(
            set().union(*(set(item or ()) for item in observations)),
            expected,
            test_ids,
        )
        if not immutable:
            state = "mutable"
        elif label in unsafe:
            state = "static-unsafe"
        elif any(item is None for item in observations):
            state = "incomplete" if owners else "unobserved"
        elif "__NO_TEST__" in owners:
            state = "import-read"
        elif not owners:
            state = "unobserved"
        else:
            state = "safe"
        readers = sorted(test_index[owner] for owner in owners if owner in test_index)
        if state != "safe":
            readers = []
        profile[relative].append([
            statement.lineno,
            statement.end_lineno or statement.lineno,
            name,
            ast.dump(statement.value, include_attributes=False),
            kind,
            state,
            readers,
        ])
        states[state] += 1

    ordered = {
        path: sorted(values, key=lambda entry: (entry[0], entry[2]))
        for path, values in sorted(profile.items())
    }
    payload = {
        "d": ordered,
        "n": len(test_ids),
        "p": {
            "builder": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "collector": collector_sha256,
            "evidence": {mode: evidence[mode] for mode in sorted(evidence)},
            "source_inventory": inventory_digest,
        },
        "sha": revision,
        "t": test_digest,
        "v": MODEL_SCHEMA_VERSION,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    args.output.write_bytes(gzip.compress(raw, compresslevel=9, mtime=0))
    print(
        f"wrote {sum(map(len, ordered.values()))} module-constant profile entries: "
        + ", ".join(f"{key}={value}" for key, value in sorted(states.items()))
    )


if __name__ == "__main__":
    main()
