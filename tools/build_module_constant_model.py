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
    flatten_attribute,
    import_maps,
    module_name,
    parsed_files,
    resolve_import,
    source_candidates,
)


PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, action="append", required=True)
    parser.add_argument("--trace", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def immutable_literal(value: object) -> bool:
    if value is None or value is Ellipsis:
        return True
    if type(value) in {bool, int, float, complex, str, bytes}:
        return True
    return type(value) is tuple and all(immutable_literal(item) for item in value)


def entries(source: Path):
    labels = source_candidates(source)
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
            value = ast.literal_eval(statement.value)
            result.append((relative, module, statement, name, label, value))
    return result


def binding_names(node: ast.AST) -> set[str]:
    names = set()
    for item in ast.walk(node):
        if isinstance(item, ast.Name) and isinstance(item.ctx, (ast.Store, ast.Del)):
            names.add(item.id)
    return names


def static_unsafe(source: Path, candidates: dict[tuple[str, str], str]) -> set[str]:
    """Reject reads the source rewriter cannot owner-resolve without guessing."""

    files = parsed_files(source)
    _values, module_aliases, qualified = import_maps(files, candidates)
    unsafe = set()
    labels_by_module: dict[str, dict[str, str]] = defaultdict(dict)
    for (module, name), label in candidates.items():
        labels_by_module[module][name] = label

    # A second binding changes which object a later Name load denotes. Ignore
    # the unique candidate assignment itself; reject module bindings and
    # explicit global writes everywhere else.
    for path, (module, is_package, tree) in files.items():
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
                    unsafe.update(labels_by_module.get(imported, {}).values())

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
                    unsafe.update(labels_by_module.get(target, {}).values())
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
                    unsafe.update(labels_by_module.get(imported, {}).values())
                aliases.pop(local, None)
            else:
                aliases[local] = possible.pop()

        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }

        def module_target(node: ast.AST) -> str | None:
            if isinstance(node, ast.Name):
                return aliases.get(node.id)
            if isinstance(node, ast.Attribute):
                flattened = flatten_attribute(node)
                if flattened:
                    base, parts = flattened
                    imported = aliases.get(base)
                    target = ".".join((imported, *parts)) if imported else None
                    if target in labels_by_module:
                        return target
            return None

        for node in ast.walk(tree):
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
                    unsafe.update(labels_by_module.get(target_module, {}).values())
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
                    unsafe.update(labels_by_module.get(target_module, {}).values())
            if function not in {"getattr", "hasattr", "setattr", "delattr"} or len(node.args) < 2:
                continue
            target_module = module_target(node.args[0])
            if not target_module:
                continue
            if isinstance(node.args[1], ast.Constant) and type(node.args[1].value) is str:
                label = candidates.get((target_module, node.args[1].value))
                if label:
                    unsafe.add(label)
            else:
                unsafe.update(labels_by_module.get(target_module, {}).values())

        # Star imports are not represented by the owner's direct-name map.
        for statement in tree.body:
            if isinstance(statement, ast.ImportFrom) and any(a.name == "*" for a in statement.names):
                target = resolve_import(module, is_package, statement.module, statement.level)
                unsafe.update(labels_by_module.get(target, {}).values())

    return unsafe


def main() -> None:
    args = arguments()
    if len(args.manifest) < 2 or len(args.trace) < 2:
        raise SystemExit("normal and synchronous-worker traces are required")
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
    manifests = [json.loads(path.read_text()) for path in args.manifest]
    if not {"normal", "synchronous-worker"}.issubset(
        {manifest.get("mode") for manifest in manifests}
    ):
        raise SystemExit("both trace modes are required")
    for path, manifest in zip(args.manifest, manifests):
        missing = expected - set(manifest.get("tests", ()))
        if manifest.get("exitstatus") != 0 or missing:
            raise SystemExit(f"inadmissible manifest {path}: {len(missing)} tests missing")
        if not isinstance(manifest.get("child_logs"), int) or manifest["child_logs"] <= 0:
            raise SystemExit(f"manifest {path} lacks subprocess accounting")

    documents = [json.loads(path.read_text()) for path in args.trace]
    known_labels = set(source_candidates(source).values())
    unknown_labels = set().union(*(set(document) for document in documents)) - known_labels
    if unknown_labels:
        raise SystemExit(f"trace contains {len(unknown_labels)} unknown labels")
    unknown_owners = {
        owner
        for document in documents
        for owners in document.values()
        for owner in owners
        if owner != "__NO_TEST__" and owner not in expected
    }
    if unknown_owners:
        raise SystemExit(f"trace contains {len(unknown_owners)} unknown test owners")

    source_entries = entries(source)
    unsafe = static_unsafe(source, source_candidates(source))
    profile: dict[str, list[list]] = defaultdict(list)
    states = defaultdict(int)
    for relative, _module, statement, name, label, value in source_entries:
        observations = [document.get(label) for document in documents]
        owners = set().union(*(set(item or ()) for item in observations))
        if not immutable_literal(value):
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
        profile[relative].append([
            statement.lineno,
            statement.end_lineno or statement.lineno,
            name,
            ast.dump(statement.value, include_attributes=False),
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
        "sha": revision,
        "t": hashlib.sha256("\0".join(test_ids).encode()).hexdigest(),
        "v": 1,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    args.output.write_bytes(gzip.compress(raw, compresslevel=9, mtime=0))
    print(
        f"wrote {sum(map(len, ordered.values()))} module-constant profile entries: "
        + ", ".join(f"{key}={value}" for key, value in sorted(states.items()))
    )


if __name__ == "__main__":
    main()
