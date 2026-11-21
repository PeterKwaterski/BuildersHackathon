#!/usr/bin/env python3
"""Build the source-derived ``arg_types`` / ``required_args`` certificate."""

from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import json
import subprocess
from collections import defaultdict
from pathlib import Path


PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"
VALUE_WILDCARD = repr(("__BR_WILDCARD__", "values"))
EXPECTED_UNMAPPED_READERS = {
    "tests/dialects/test_snowflake.py::TestSnowflake::test_snowflake",
    "tests/test_generator.py::TestGenerator::test_fallback_function_sql",
    "tests/test_generator.py::TestGenerator::test_fallback_function_var_args_sql",
    "tests/test_optimizer.py::TestOptimizer::test_annotate_funcs",
}
HOOK_DUMP = ast.dump(
    ast.parse("cls.required_args = {k for k, v in cls.arg_types.items() if v}").body[0],
    include_attributes=False,
)
TRACKED_METHODS = {
    "get", "items", "keys", "values", "copy", "setdefault", "pop", "popitem",
    "clear", "update", "__getitem__", "__contains__", "__setitem__", "__delitem__",
    "__or__", "__ror__", "__ior__", "__eq__", "__ne__", "__sizeof__",
}


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, action="append", required=True)
    parser.add_argument("--trace", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def final_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }


def class_owner(node: ast.AST, parent_map: dict[ast.AST, ast.AST]) -> ast.ClassDef | None:
    current = parent_map.get(node)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return None
        if isinstance(current, ast.ClassDef):
            return current
        current = parent_map.get(current)
    return None


def enclosing_function(node: ast.AST, parent_map: dict[ast.AST, ast.AST]) -> ast.AST | None:
    current = parent_map.get(node)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return current
        current = parent_map.get(current)
    return None


def safe_arg_types_use(node: ast.AST, parent_map: dict[ast.AST, ast.AST]) -> bool:
    """Prove the dictionary reaches an operation intercepted by TrackingDict."""
    parent = parent_map.get(node)
    if isinstance(parent, ast.Attribute) and parent.value is node:
        call = parent_map.get(parent)
        return parent.attr in TRACKED_METHODS and isinstance(call, ast.Call) and call.func is parent
    if isinstance(parent, ast.Subscript) and parent.value is node:
        return True
    if isinstance(parent, ast.Compare):
        return any(
            comparator is node and isinstance(operator, (ast.In, ast.NotIn))
            for operator, comparator in zip(parent.ops, parent.comparators)
        )
    if isinstance(parent, ast.Call) and node in parent.args:
        return isinstance(parent.func, ast.Name) and parent.func.id in {
            "bool", "len", "list", "set", "tuple", "zip"
        }
    if isinstance(parent, (ast.For, ast.AsyncFor)) and parent.iter is node:
        return True
    if isinstance(parent, ast.comprehension) and parent.iter is node:
        return True
    if isinstance(parent, ast.Assign) and parent.value is node:
        targets = parent.targets
        if len(targets) != 1 or not isinstance(targets[0], ast.Name):
            return False
        name = targets[0].id
        scope = enclosing_function(parent, parent_map)
        if scope is None:
            return False
        loads = [
            item
            for item in ast.walk(scope)
            if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load) and item.id == name
        ]
        return bool(loads) and all(
            isinstance(parent_map.get(item), (ast.For, ast.AsyncFor))
            and parent_map[item].iter is item
            for item in loads
        )
    if isinstance(parent, ast.IfExp):
        grandparent = parent_map.get(parent)
        return isinstance(grandparent, ast.Assign) and grandparent.value is parent and safe_arg_types_use(parent, parent_map)
    return False


def validate_required_args(source: Path) -> None:
    loads = []
    strings = []
    hook_assignments = []
    for root_name in ("sqlglot", "tests"):
        for path in sorted((source / root_name).rglob("*.py")):
            relative = path.relative_to(source).as_posix()
            tree = ast.parse(path.read_text(), filename=relative, type_comments=True)
            parent_map = parents(tree)
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and node.value == "required_args":
                    strings.append((relative, node.lineno))
                if isinstance(node, ast.Attribute) and node.attr == "required_args":
                    if isinstance(node.ctx, ast.Load):
                        loads.append((relative, node, parent_map))
                    elif isinstance(node.ctx, ast.Store):
                        statement = parent_map.get(node)
                        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                            hook_assignments.append((relative, statement, node))

    if strings:
        raise SystemExit("reflective required_args string reference is unsupported")
    if len(loads) != 1:
        raise SystemExit(f"expected one required_args load, found {len(loads)}")
    relative, load, parent_map = loads[0]
    loop = parent_map.get(load)
    function = enclosing_function(load, parent_map)
    if not (
        relative == "sqlglot/expressions/core.py"
        and isinstance(loop, ast.For)
        and loop.iter is load
        and isinstance(function, ast.FunctionDef)
        and function.name == "error_messages"
    ):
        raise SystemExit("required_args consumer no longer matches the validated loop")

    matching = []
    for relative, statement, target in hook_assignments:
        if ast.dump(statement, include_attributes=False) == HOOK_DUMP:
            matching.append((relative, statement, target))
    if (
        len(hook_assignments) != 1
        or len(matching) != 1
        or matching[0][0] != "sqlglot/expressions/core.py"
    ):
        raise SystemExit("Expr.__init_subclass__ derivation no longer matches")

    # Apart from the class variable declaration and the validated hook, no
    # source or test may assign or mutate required_args.
    declarations = []
    for root_name in ("sqlglot", "tests"):
        for path in sorted((source / root_name).rglob("*.py")):
            tree = ast.parse(path.read_text(), type_comments=True)
            parent_map = parents(tree)
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and node.id == "required_args" and isinstance(node.ctx, ast.Store):
                    parent = parent_map.get(node)
                    if not isinstance(parent, ast.AnnAssign):
                        raise SystemExit("unsupported required_args assignment")
                    declarations.append((path.relative_to(source).as_posix(), parent))
    if len(declarations) != 1 or declarations[0][0] != "sqlglot/expressions/core.py":
        raise SystemExit("required_args declaration no longer matches")


def source_assignments(source: Path):
    assignments = []
    classes_by_name: dict[str, list[dict]] = defaultdict(list)
    all_modules = []
    for path in sorted((source / "sqlglot").rglob("*.py")):
        relative = path.relative_to(source).as_posix()
        tree = ast.parse(path.read_text(), filename=relative, type_comments=True)
        parent_map = parents(tree)
        all_modules.append((relative, tree, parent_map))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            direct = None
            for statement in node.body:
                if isinstance(statement, ast.Assign):
                    targets = statement.targets
                elif isinstance(statement, ast.AnnAssign):
                    targets = [statement.target]
                else:
                    continue
                if (
                    len(targets) == 1
                    and isinstance(targets[0], ast.Name)
                    and targets[0].id == "arg_types"
                    and isinstance(statement.value, ast.Dict)
                ):
                    label = f"{relative}:{statement.lineno}:{statement.end_lineno or statement.lineno}:arg_types"
                    direct = (relative, statement, label, node.name)
                    assignments.append(direct)
                    break
            classes_by_name[node.name].append({
                "bases": [final_name(base) for base in node.bases],
                "direct": direct,
                "node": node,
                "relative": relative,
            })
    return assignments, classes_by_name, all_modules


def validate_arg_types_uses(classes_by_name, modules) -> set[str]:
    forbidden = set()

    def effective(name: str, seen: set[str] | None = None):
        seen = set() if seen is None else seen
        if name in seen or len(classes_by_name.get(name, ())) != 1:
            return None
        seen.add(name)
        info = classes_by_name[name][0]
        if info["direct"] is not None:
            return info["direct"][2]
        candidates = {effective(base, seen.copy()) for base in info["bases"] if base}
        candidates.discard(None)
        return next(iter(candidates)) if len(candidates) == 1 else None

    for relative, tree, parent_map in modules:
        for node in ast.walk(tree):
            is_load = (
                isinstance(node, ast.Attribute)
                and node.attr == "arg_types"
                and isinstance(node.ctx, ast.Load)
            ) or (
                isinstance(node, ast.Name)
                and node.id == "arg_types"
                and isinstance(node.ctx, ast.Load)
            )
            if not is_load:
                continue
            function = enclosing_function(node, parent_map)
            if function is None:
                owner = final_name(node.value) if isinstance(node, ast.Attribute) else None
                label = effective(owner) if owner else None
                if label is None:
                    raise SystemExit(f"unresolved class-time arg_types load at {relative}:{node.lineno}")
                forbidden.add(label)
                continue
            if (
                isinstance(function, ast.FunctionDef)
                and function.name == "__init_subclass__"
                and isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "cls"
            ):
                continue
            if not safe_arg_types_use(node, parent_map):
                raise SystemExit(f"opaque arg_types use at {relative}:{node.lineno}")
    return forbidden


def merge_documents(documents: list[dict], key: str):
    merged = defaultdict(set)
    for document in documents:
        for label, owners in document.get(key, {}).items():
            merged[label].update(owners)
    return merged


def merge_key_documents(documents: list[dict], key: str):
    merged = defaultdict(lambda: defaultdict(set))
    for document in documents:
        for label, events in document.get(key, {}).items():
            for value, owners in events.items():
                merged[label][value].update(owners)
    return merged


def main() -> None:
    args = arguments()
    if len(args.manifest) < 2 or len(args.trace) < 2:
        raise SystemExit("normal and synchronous-worker evidence are required")
    source = args.source.resolve()
    revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    if revision != PINNED_SHA:
        raise SystemExit(f"source is {revision}, expected {PINNED_SHA}")

    tests = json.loads(args.tests.read_text())["tests"]
    test_ids = [test["id"] for test in tests]
    test_index = {test_id: index for index, test_id in enumerate(test_ids)}
    expected = set(test_ids)
    manifests = [json.loads(path.read_text()) for path in args.manifest]
    if not {"normal", "synchronous-worker"}.issubset({item.get("mode") for item in manifests}):
        raise SystemExit("manifests must include normal and synchronous-worker modes")
    for path, manifest in zip(args.manifest, manifests):
        missing = expected - set(manifest.get("tests", ()))
        if manifest.get("exitstatus") != 0 or missing:
            raise SystemExit(f"inadmissible manifest {path}: {len(missing)} tests missing")
        if not isinstance(manifest.get("child_logs"), int) or manifest["child_logs"] <= 0:
            raise SystemExit(f"manifest {path} lacks subprocess accounting")

    documents = [json.loads(path.read_text()) for path in args.trace]
    if any(
        "derived_keys" not in document
        or "derived_order" not in document
        or "keys" not in document
        for document in documents
    ):
        raise SystemExit("traces lack per-key requiredness/key-only evidence")
    if any(document.get("conflicts") for document in documents):
        raise SystemExit("derived identity map reported a conflict")
    unmapped = {
        owner
        for document in documents
        for owner in document.get("unmapped", ())
    }
    if unmapped != EXPECTED_UNMAPPED_READERS:
        raise SystemExit(
            "unexpected unmapped required_args readers: "
            f"missing={sorted(EXPECTED_UNMAPPED_READERS - unmapped)!r}, "
            f"extra={sorted(unmapped - EXPECTED_UNMAPPED_READERS)!r}"
        )
    validate_required_args(source)
    assignments, classes_by_name, modules = source_assignments(source)
    forbidden = validate_arg_types_uses(classes_by_name, modules)

    dict_events: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for document in documents:
        for label, events in document.get("dict", {}).items():
            for key, owners in events.items():
                dict_events[label][key].update(owners)
    derived_keys = merge_key_documents(documents, "derived_keys")
    derived_order = merge_documents(documents, "derived_order")

    certified: dict[str, list[list[object]]] = defaultdict(list)
    for relative, statement, label, _class_name in assignments:
        if label in forbidden:
            continue
        if any(label not in document.get("derivations", {}) for document in documents):
            continue
        events = dict_events[label]
        if any(
            "__NO_TEST__" in owners for key, owners in events.items() if key != VALUE_WILDCARD
        ):
            continue
        if "__NO_TEST__" in events.get(VALUE_WILDCARD, ()):
            continue
        dictionary = statement.value
        if any(key is None for key in dictionary.keys):
            continue
        order_owners = set()
        order_valid = True
        for key_node, value_node in zip(dictionary.keys, dictionary.values):
            try:
                runtime_key = ast.literal_eval(key_node)
                runtime_value = ast.literal_eval(value_node)
            except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                order_valid = False
                break
            if runtime_value:
                order_owners.update(
                    derived_keys.get(label, {}).get(repr(runtime_key), ())
                )
        if not order_valid:
            continue
        if order_owners != set(derived_order.get(label, ())):
            raise SystemExit(f"derived order evidence mismatch for {label}")
        # Changing membership can reorder a set even when the edited key is
        # present. If another currently required key is missing, retain that
        # owner for every key because error-message ordering may be observed.
        all_relevant_owners = {
            owner for owner in events.get(VALUE_WILDCARD, ())
        } | order_owners
        if any(owner not in expected for owner in all_relevant_owners):
            continue
        runtime_keys = []
        key_entries = []
        valid = True
        for key_node, value_node in zip(dictionary.keys, dictionary.values):
            try:
                runtime_key = ast.literal_eval(key_node)
                hash(runtime_key)
            except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                valid = False
                break
            if runtime_key in runtime_keys:
                valid = False
                break
            runtime_keys.append(runtime_key)
            owners = (
                set(all_relevant_owners)
                | set(events.get(repr(runtime_key), ()))
                | set(derived_keys.get(label, {}).get(repr(runtime_key), ()))
            )
            if "__NO_TEST__" in owners or any(owner not in expected for owner in owners):
                valid = False
                break
            key_entries.append([
                ast.dump(key_node, include_attributes=False),
                sorted(test_index[owner] for owner in owners),
            ])
        if valid and key_entries:
            certified[relative].append([
                statement.lineno,
                statement.end_lineno or statement.lineno,
                "arg_types",
                key_entries,
            ])

    output = {
        "d": {path: entries for path, entries in sorted(certified.items())},
        "n": len(test_ids),
        "sha": revision,
        "t": hashlib.sha256("\0".join(test_ids).encode()).hexdigest(),
        "v": 2,
    }
    raw = json.dumps(output, sort_keys=True, separators=(",", ":")).encode()
    args.output.write_bytes(gzip.compress(raw, compresslevel=9, mtime=0))
    print(
        f"certified {sum(map(len, certified.values()))} arg_types dictionaries "
        f"across {len(certified)} files"
    )


if __name__ == "__main__":
    main()
