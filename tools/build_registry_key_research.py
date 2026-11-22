#!/usr/bin/env python3
"""Build a closed, dual-mode parser-registry key-reader certificate."""

from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"
PINNED_SOURCE_DIGEST = "fc8e3c215f006385b628ef4612295b1d074b93b42de8c773997de3f40103d090"
TARGETS = {"FUNCTIONS", "FUNCTION_PARSERS"}
CERTIFIED_TARGETS = {"FUNCTION_PARSERS"}
WILDCARDS = {
    repr(("__BR_WILDCARD__", "keys")),
    repr(("__BR_WILDCARD__", "values")),
    repr(("__BR_WILDCARD__", "shape")),
}
SAFE_METHODS = {"get"}
SAFE_CALLS: set[str] = set()


@dataclass(frozen=True)
class RegistryAssignment:
    path: str
    start: int
    end: int
    value_start: int
    value_end: int
    owner: str
    name: str
    label: str
    value_dump: str


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--selector-model", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--trace", type=Path, action="append", required=True)
    parser.add_argument("--manifest", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}


def enclosing(node: ast.AST, parents: dict[ast.AST, ast.AST], kind):
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(current, kind):
            return current
    return None


def assignment_target(statement: ast.stmt) -> ast.Name | None:
    if isinstance(statement, ast.Assign):
        targets = statement.targets
    elif isinstance(statement, ast.AnnAssign):
        targets = [statement.target]
    else:
        return None
    return targets[0] if len(targets) == 1 and isinstance(targets[0], ast.Name) else None


def registry_assignments(
    trees: dict[str, ast.Module], parents: dict[str, dict[ast.AST, ast.AST]]
) -> tuple[list[RegistryAssignment], dict[ast.AST, RegistryAssignment]]:
    result = []
    by_statement = {}
    for path, tree in trees.items():
        if not (path == "sqlglot/parser.py" or path.startswith("sqlglot/parsers/") or path.startswith("tests/")):
            continue
        for statement in ast.walk(tree):
            target = assignment_target(statement) if isinstance(statement, ast.stmt) else None
            if target is None or target.id not in TARGETS:
                continue
            owner = parents[path].get(statement)
            if not isinstance(owner, ast.ClassDef):
                continue
            value = statement.value
            if not isinstance(value, (ast.Dict, ast.DictComp)):
                raise SystemExit(
                    f"unsupported registry constructor {path}:{statement.lineno}:"
                    f"{owner.name}.{target.id}:{type(value).__name__}"
                )
            label = f"{path}:{statement.lineno}:{statement.end_lineno or statement.lineno}:{target.id}"
            item = RegistryAssignment(
                path=path,
                start=statement.lineno,
                end=statement.end_lineno or statement.lineno,
                value_start=value.lineno,
                value_end=value.end_lineno or value.lineno,
                owner=owner.name,
                name=target.id,
                label=label,
                value_dump=ast.dump(value, include_attributes=False),
            )
            result.append(item)
            by_statement[statement] = item
    return sorted(result, key=lambda item: item.label), by_statement


def inside_registry_value(
    node: ast.AST,
    parents: dict[ast.AST, ast.AST],
    by_statement: dict[ast.AST, RegistryAssignment],
) -> bool:
    current = node
    while current in parents:
        current = parents[current]
        if current in by_statement:
            return True
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return False
    return False


def is_safe_use(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    parent = parents.get(node)
    if isinstance(parent, ast.Subscript) and parent.value is node:
        return True
    if isinstance(parent, ast.Attribute) and parent.value is node and parent.attr in SAFE_METHODS:
        call = parents.get(parent)
        return isinstance(call, ast.Call) and call.func is parent
    if isinstance(parent, ast.Compare):
        if node is parent.left:
            return all(isinstance(operator, (ast.Eq, ast.NotEq, ast.Is, ast.IsNot)) for operator in parent.ops)
        return any(
            comparator is node and isinstance(operator, (ast.In, ast.NotIn, ast.Eq, ast.NotEq, ast.Is, ast.IsNot))
            for operator, comparator in zip(parent.ops, parent.comparators)
        )
    if isinstance(parent, (ast.For, ast.AsyncFor)) and parent.iter is node:
        return True
    if isinstance(parent, ast.comprehension) and parent.iter is node:
        return True
    if isinstance(parent, ast.Call) and node in parent.args:
        return isinstance(parent.func, ast.Name) and parent.func.id in SAFE_CALLS
    return False


def static_channel_audit(
    sources: dict[str, str],
    trees: dict[str, ast.Module],
    parent_maps: dict[str, dict[ast.AST, ast.AST]],
    by_statement: dict[ast.AST, RegistryAssignment],
) -> dict[str, object]:
    aliases: list[tuple[str, ast.AST, str]] = []
    direct_uses = 0
    for path, tree in trees.items():
        parents = parent_maps[path]
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and (
                node.name == "Parser" or node.name.endswith("Parser")
            ):
                if any(keyword.arg == "metaclass" for keyword in node.keywords):
                    raise SystemExit(f"parser metaclass escape at {path}:{node.lineno}")
                for statement in node.body:
                    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)) and statement.name in {
                        "__getattribute__", "__getattr__", "__init_subclass__"
                    }:
                        raise SystemExit(f"parser descriptor hook at {path}:{statement.lineno}")

            if isinstance(node, ast.Attribute) and node.attr == "__dict__":
                text = ast.unparse(node.value).lower()
                owner = enclosing(node, parents, ast.ClassDef)
                if "parser" in text or (
                    text in {"self", "cls"}
                    and isinstance(owner, ast.ClassDef)
                    and (owner.name == "Parser" or owner.name.endswith("Parser"))
                ):
                    raise SystemExit(f"parser __dict__ reflection at {path}:{node.lineno}")

            if isinstance(node, ast.Call):
                function = node.func.id if isinstance(node.func, ast.Name) else (
                    node.func.attr if isinstance(node.func, ast.Attribute) else ""
                )
                if function in {"getattr", "hasattr", "vars", "getmembers", "getmembers_static"} and node.args:
                    receiver = ast.unparse(node.args[0]).lower()
                    owner = enclosing(node, parents, ast.ClassDef)
                    if "parser" in receiver or (
                        receiver in {"self", "cls"}
                        and isinstance(owner, ast.ClassDef)
                        and (owner.name == "Parser" or owner.name.endswith("Parser"))
                    ):
                        raise SystemExit(f"parser reflection at {path}:{node.lineno}")
                if (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "dict"
                    and any(
                        isinstance(argument, ast.Attribute) and argument.attr in TARGETS
                        for argument in node.args
                    )
                ):
                    raise SystemExit(f"native dict bypass at {path}:{node.lineno}")

            is_registry_load = (
                isinstance(node, ast.Attribute)
                and isinstance(node.ctx, ast.Load)
                and node.attr in TARGETS
            ) or (
                isinstance(node, ast.Name)
                and isinstance(node.ctx, ast.Load)
                and node.id in TARGETS
            )
            if not is_registry_load:
                continue
            direct_uses += 1
            if inside_registry_value(node, parents, by_statement):
                continue
            parent = parents.get(node)
            if isinstance(parent, (ast.Assign, ast.AnnAssign)) and parent.value is node:
                target = assignment_target(parent)
                function = enclosing(parent, parents, (ast.FunctionDef, ast.AsyncFunctionDef))
                if target is None or function is None:
                    raise SystemExit(f"registry alias escape at {path}:{node.lineno}")
                aliases.append((path, function, target.id))
                continue
            if not is_safe_use(node, parents):
                raise SystemExit(
                    f"opaque registry use at {path}:{node.lineno}:{ast.unparse(parent or node)}"
                )

    for path, function, name in aliases:
        parents = parent_maps[path]
        for node in ast.walk(function):
            if not (
                isinstance(node, ast.Name)
                and isinstance(node.ctx, ast.Load)
                and node.id == name
            ):
                continue
            # The RHS seed itself is handled above.
            parent = parents.get(node)
            if isinstance(parent, ast.Attribute) and parent.attr in TARGETS:
                continue
            if not is_safe_use(node, parents):
                raise SystemExit(f"local registry alias escape at {path}:{node.lineno}:{name}")

    return {
        "aliases": len(aliases),
        "direct_uses": direct_uses,
        "source_digest": hashlib.sha256(
            "".join(f"{path}\0{sources[path]}\0" for path in sorted(sources)).encode()
        ).hexdigest(),
    }


def trace_document(path: Path) -> dict:
    document = json.loads(path.read_text())
    if not isinstance(document, dict) or set(document) != {"creations", "events", "imports", "tasks"}:
        raise SystemExit(f"invalid trace document {path}")
    if (
        not isinstance(document["creations"], dict)
        or not isinstance(document["events"], dict)
        or not isinstance(document["imports"], list)
        or any(
            type(label) is not str
            or not isinstance(owners, list)
            or any(type(owner) is not str for owner in owners)
            or owners != sorted(set(owners))
            for label, owners in document["creations"].items()
        )
        or any(
            type(label) is not str
            or not isinstance(events, dict)
            or any(
                type(raw_key) is not str
                or not isinstance(owners, list)
                or any(type(owner) is not str for owner in owners)
                or owners != sorted(set(owners))
                for raw_key, owners in events.items()
            )
            for label, events in document["events"].items()
        )
    ):
        raise SystemExit(f"malformed trace payload {path}")
    tasks = document.get("tasks")
    if (
        not isinstance(tasks, dict)
        or set(tasks) != {"completed", "submitted", "workers"}
        or not isinstance(tasks["completed"], list)
        or not isinstance(tasks["submitted"], list)
        or not isinstance(tasks["workers"], dict)
        or tasks["completed"] != sorted(set(tasks["completed"]))
        or tasks["submitted"] != sorted(set(tasks["submitted"]))
        or any(type(task) is not str for task in tasks["completed"] + tasks["submitted"])
        or tasks["completed"] != tasks["submitted"]
        or set(tasks["workers"]) != set(tasks["completed"])
        or any(
            not isinstance(workers, list) or not workers
            or any(type(worker) is not int or worker <= 0 for worker in workers)
            or workers != sorted(set(workers))
            for workers in tasks["workers"].values()
        )
    ):
        raise SystemExit(f"incomplete task attribution in {path}")
    return document


def registry_key_domain(
    trees: dict[str, ast.Module], assignments: list[RegistryAssignment], target: str
) -> tuple[list[str], list[str]]:
    """Prove the literal key has no hidden unpack/derived duplicate."""
    if target != "FUNCTION_PARSERS":
        raise SystemExit(f"no closed key-domain theorem for {target}")

    sql_names = {}
    for tree in trees.values():
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef) or node.name not in {"ArgMax", "ArgMin"}:
                continue
            for statement in node.body:
                key = assignment_target(statement)
                if key is None or key.id != "_sql_names":
                    continue
                try:
                    values = ast.literal_eval(statement.value)
                except (ValueError, SyntaxError):
                    raise SystemExit(f"nonliteral {node.name}._sql_names")
                if not isinstance(values, list) or any(type(value) is not str for value in values):
                    raise SystemExit(f"invalid {node.name}._sql_names")
                sql_names[node.name] = values
    if set(sql_names) != {"ArgMax", "ArgMin"}:
        raise SystemExit("incomplete ArgMax/ArgMin key domains")

    explicit_counts: dict[str, int] = defaultdict(int)
    generated = set().union(*sql_names.values())
    assignment_by_location = {
        (item.path, item.start, item.name): item for item in assignments
    }

    def registry_items_call(node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "items"
            and (
                isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == target
                or isinstance(node.func.value, ast.Name)
                and node.func.value.id == target
            )
        )

    filter_sensitive = set()
    direct_dependencies = set()

    def validate_copy_comp(node: ast.DictComp, *, base: bool) -> None:
        if len(node.generators) != 1:
            raise SystemExit("multi-generator registry copy")
        generator = node.generators[0]
        iterator = generator.iter
        if generator.is_async:
            raise SystemExit("asynchronous registry copy")
        if registry_items_call(iterator):
            if (
                not isinstance(generator.target, (ast.Tuple, ast.List))
                or len(generator.target.elts) != 2
                or any(not isinstance(item, ast.Name) for item in generator.target.elts)
            ):
                raise SystemExit("non-pair registry copy target")
            key_name, value_name = (item.id for item in generator.target.elts)
            if (
                not isinstance(node.key, ast.Name)
                or node.key.id != key_name
                or not isinstance(node.value, ast.Name)
                or node.value.id != value_name
            ):
                raise SystemExit("transforming registry comprehension")
            for condition in generator.ifs:
                if (
                    not isinstance(condition, ast.Compare)
                    or not isinstance(condition.left, ast.Name)
                    or condition.left.id != key_name
                    or len(condition.ops) != 1
                    or len(condition.comparators) != 1
                    or not isinstance(condition.ops[0], (ast.NotEq, ast.NotIn))
                ):
                    raise SystemExit(f"opaque registry filter: {ast.unparse(condition)}")
                try:
                    excluded = ast.literal_eval(condition.comparators[0])
                except (ValueError, SyntaxError):
                    raise SystemExit(f"nonliteral registry filter: {ast.unparse(condition)}")
                excluded = [excluded] if type(excluded) is str else excluded
                if not isinstance(excluded, (tuple, list, set)) or any(
                    type(item) is not str for item in excluded
                ):
                    raise SystemExit(f"invalid registry filter: {ast.unparse(condition)}")
                filter_sensitive.update(excluded)
            return
        if base and (
            isinstance(iterator, ast.Call)
            and isinstance(iterator.func, ast.Attribute)
            and iterator.func.attr == "sql_names"
            and isinstance(iterator.func.value, ast.Attribute)
            and isinstance(iterator.func.value.value, ast.Name)
            and iterator.func.value.value.id == "exp"
            and iterator.func.value.attr in sql_names
        ):
            if (
                generator.ifs
                or not isinstance(generator.target, ast.Name)
                or not isinstance(node.key, ast.Name)
                or node.key.id != generator.target.id
            ):
                raise SystemExit("transforming generated base registry")
            return
        raise SystemExit(f"opaque registry comprehension: {ast.unparse(iterator)}")

    for path, tree in trees.items():
        for statement in ast.walk(tree):
            key = assignment_target(statement) if isinstance(statement, ast.stmt) else None
            if key is None or key.id != target:
                continue
            owner = enclosing(statement, parent_map(tree), ast.ClassDef)
            if not isinstance(owner, ast.ClassDef):
                continue
            item = assignment_by_location.get((path, statement.lineno, target))
            if item is None:
                raise SystemExit(f"unindexed registry assignment {path}:{statement.lineno}")
            value = statement.value
            if isinstance(value, ast.DictComp):
                validate_copy_comp(value, base=False)
                continue
            if not isinstance(value, ast.Dict):
                raise SystemExit("unsupported registry key-domain constructor")
            is_base = path == "sqlglot/parser.py" and owner.name == "Parser"
            for dependency in ast.walk(value):
                if not isinstance(dependency, ast.Subscript):
                    continue
                registry = dependency.value
                if not (
                    isinstance(registry, ast.Attribute) and registry.attr == target
                    or isinstance(registry, ast.Name) and registry.id == target
                ):
                    continue
                if not isinstance(dependency.slice, ast.Constant) or type(dependency.slice.value) is not str:
                    raise SystemExit(
                        f"computed registry dependency at {path}:{dependency.lineno}"
                    )
                direct_dependencies.add(dependency.slice.value)
            for dict_key, dict_value in zip(value.keys, value.values):
                if isinstance(dict_key, ast.Constant) and type(dict_key.value) is str:
                    explicit_counts[dict_key.value] += 1
                    continue
                if dict_key is not None:
                    raise SystemExit(f"computed explicit registry key at {path}:{dict_key.lineno}")
                if (
                    isinstance(dict_value, (ast.Attribute, ast.Name))
                    and (
                        isinstance(dict_value, ast.Attribute) and dict_value.attr == target
                        or isinstance(dict_value, ast.Name) and dict_value.id == target
                    )
                ):
                    continue
                if isinstance(dict_value, ast.DictComp):
                    validate_copy_comp(dict_value, base=is_base)
                    continue
                if (
                    isinstance(dict_value, ast.Call)
                    and isinstance(dict_value.func, ast.Attribute)
                    and isinstance(dict_value.func.value, ast.Name)
                    and dict_value.func.value.id == "dict"
                    and dict_value.func.attr == "fromkeys"
                    and dict_value.args
                ):
                    try:
                        keys = ast.literal_eval(dict_value.args[0])
                    except (ValueError, SyntaxError):
                        raise SystemExit("nonliteral registry fromkeys")
                    if not isinstance(keys, (tuple, list, set)) or any(type(item) is not str for item in keys):
                        raise SystemExit("invalid registry fromkeys")
                    for generated_key in keys:
                        explicit_counts[generated_key] += 1
                    continue
                raise SystemExit(
                    f"opaque registry unpack at {path}:{dict_value.lineno}:{ast.unparse(dict_value)}"
                )

    base_assignment = next(
        item for item in assignments
        if item.path == "sqlglot/parser.py" and item.owner == "Parser" and item.name == target
    )
    base_statement = next(
        statement for statement in ast.walk(trees[base_assignment.path])
        if isinstance(statement, (ast.Assign, ast.AnnAssign))
        and statement.lineno == base_assignment.start
    )
    base_literals = {
        key.value for key in base_statement.value.keys
        if isinstance(key, ast.Constant) and type(key.value) is str
    }
    safe = sorted(
        key for key in base_literals
        if explicit_counts[key] == 1
        and key not in generated
        and key not in filter_sensitive
        and key not in direct_dependencies
    )
    forbidden = sorted(
        set(explicit_counts) | generated | filter_sensitive | direct_dependencies
    )
    if not safe:
        raise SystemExit("key-domain proof admitted nothing")
    return safe, forbidden


def validate_import_events(
    document: dict,
    assignments: list[RegistryAssignment],
    expected_labels: set[str],
) -> list[list]:
    relevant = []
    imports_by_pair = set()
    for event in document["imports"]:
        if not isinstance(event, list) or len(event) != 6:
            raise SystemExit("malformed import event")
        label, raw_key, kind, path, line, function = event
        if not isinstance(label, str) or label.rsplit(":", 1)[-1] not in TARGETS:
            continue
        if label not in expected_labels or kind != "read" or type(line) is not int:
            raise SystemExit(f"unsafe import event: {event!r}")
        owners = [
            item for item in assignments
            if item.path == path
            and item.name == label.rsplit(":", 1)[-1]
            and item.value_start <= line <= item.value_end
        ]
        if not owners:
            raise SystemExit(f"unclosed import consumer: {event!r}")
        imports_by_pair.add((label, raw_key))
        relevant.append(event)

    for label, events in document["events"].items():
        if label.rsplit(":", 1)[-1] not in TARGETS:
            continue
        if label not in expected_labels:
            raise SystemExit(f"unknown registry label {label}")
        for raw_key, owners in events.items():
            if "__NO_TEST__" in owners and (label, raw_key) not in imports_by_pair:
                raise SystemExit(f"unattributed import read {label}:{raw_key}")
    return sorted(relevant)


def main() -> None:
    args = arguments()
    if len(args.trace) != 2 or len(args.manifest) != 2:
        raise SystemExit("normal and synchronous-worker evidence are both required")

    tests_document = json.loads(args.tests.read_text())
    tests = tests_document.get("tests") if isinstance(tests_document, dict) else None
    if not isinstance(tests, list) or any(
        not isinstance(test, dict)
        or type(test.get("id")) is not str
        or type(test.get("file")) is not str
        for test in tests
    ):
        raise SystemExit("malformed numbered roster")
    test_ids = [test["id"] for test in tests]
    if len(set(test_ids)) != len(test_ids):
        raise SystemExit("numbered roster contains duplicate test IDs")
    test_index = {test_id: index for index, test_id in enumerate(test_ids)}
    expected_tests = set(test_ids)
    tests_by_file: dict[str, set[int]] = defaultdict(set)
    for index, test in enumerate(tests):
        tests_by_file[test["file"]].add(index)
    roster_digest = hashlib.sha256("\0".join(test_ids).encode()).hexdigest()

    manifests = [json.loads(path.read_text()) for path in args.manifest]
    if {manifest.get("mode") for manifest in manifests} != {"normal", "synchronous-worker"}:
        raise SystemExit("trace modes are not complete")
    for path, manifest, trace_path in zip(args.manifest, manifests, args.trace):
        if (
            manifest.get("exitstatus") != 0
            or manifest.get("tracker_version") != 5
            or manifest.get("task_attribution") != "submit-wrapper-v2"
            or manifest.get("pool_workers") != 2
            or manifest.get("roster_count") != len(test_ids)
            or manifest.get("roster_digest") != roster_digest
            or manifest.get("selection") != "numbered-roster"
            or manifest.get("source_digest") != PINNED_SOURCE_DIGEST
            or manifest.get("source_sha") != PINNED_SHA
            or manifest.get("trace_sha256") != hashlib.sha256(trace_path.read_bytes()).hexdigest()
            or manifest.get("tests") != sorted(expected_tests)
            or not isinstance(manifest.get("child_logs"), int)
            or manifest["child_logs"] <= 0
            or not isinstance(manifest.get("instrumented"), int)
            or manifest["instrumented"] <= 0
            or type(manifest.get("submitted_tasks")) is not int
            or type(manifest.get("completed_tasks")) is not int
            or manifest["submitted_tasks"] != manifest["completed_tasks"]
            or type(manifest.get("task_workers")) is not int
            or manifest["task_workers"] < 0
            or not str(manifest.get("python", "")).startswith("3.13.")
        ):
            raise SystemExit(f"inadmissible suite manifest {path}")

    with gzip.open(args.sources, "rt", encoding="utf-8") as stream:
        sources = json.load(stream)
    with gzip.open(args.selector_model, "rt", encoding="utf-8") as stream:
        selector_model = json.load(stream)
    if selector_model.get("sha") != PINNED_SHA or selector_model.get("t") != test_ids:
        raise SystemExit("pinned selector model mismatch")

    trees = {
        path: ast.parse(source, filename=path, type_comments=True)
        for path, source in sources.items()
    }
    parents = {path: parent_map(tree) for path, tree in trees.items()}
    assignments, by_statement = registry_assignments(trees, parents)
    expected_labels = {assignment.label for assignment in assignments}
    audit = static_channel_audit(sources, trees, parents, by_statement)
    if audit["source_digest"] != PINNED_SOURCE_DIGEST:
        raise SystemExit("pinned source bundle digest mismatch")

    documents = [trace_document(path) for path in args.trace]
    for path, manifest, document in zip(args.manifest, manifests, documents):
        tasks = document["tasks"]
        worker_count = len({
            worker for workers in tasks["workers"].values() for worker in workers
        })
        if (
            manifest["submitted_tasks"] != len(tasks["submitted"])
            or manifest["completed_tasks"] != len(tasks["completed"])
            or manifest["task_workers"] != worker_count
        ):
            raise SystemExit(f"task manifest mismatch {path}")
    collection_prefix = "__BR_COLLECT_FILE__:"
    all_test_indices = set(range(len(test_ids)))

    def collection_readers(owner: str) -> set[int] | None:
        if not owner.startswith(collection_prefix):
            return None
        path = owner[len(collection_prefix):]
        if path in tests_by_file:
            return tests_by_file[path]
        if path.startswith("tests/") and path in sources:
            return all_test_indices
        return None

    unknown = set()
    for document in documents:
        owner_groups = list(document["creations"].values())
        owner_groups.extend(
            owners
            for events in document["events"].values()
            for owners in events.values()
        )
        for owners in owner_groups:
            for owner in owners:
                if owner == "__NO_TEST__" or owner in expected_tests:
                    continue
                if collection_readers(owner) is not None:
                    continue
                unknown.add(owner)
    if unknown:
        raise SystemExit(f"trace contains {len(unknown)} unknown test owners")

    import_events = []
    for document in documents:
        created = set(document["creations"])
        unknown_created = {
            label for label in created
            if label.rsplit(":", 1)[-1] in TARGETS and label not in expected_labels
        }
        if unknown_created:
            raise SystemExit(f"trace created unknown registry labels: {sorted(unknown_created)}")
        missing_created = expected_labels - created
        if missing_created:
            raise SystemExit(f"trace omitted {len(missing_created)} registry creations")
        for label, events in document["events"].items():
            if label.rsplit(":", 1)[-1] in TARGETS and label not in created:
                raise SystemExit(f"registry used without creation record: {label}")
        import_events.extend(validate_import_events(document, assignments, expected_labels))

    aggregate: dict[str, tuple[dict[str, list[int]], list[int]]] = {}
    collection_sensitive: dict[str, set[str]] = defaultdict(set)
    for name in sorted(TARGETS):
        keys: dict[str, set[int]] = defaultdict(set)
        wildcard: set[int] = set()
        suffix = ":" + name
        for document in documents:
            for label, events in document["events"].items():
                if not label.endswith(suffix):
                    continue
                for raw_key, owners in events.items():
                    if any(owner.startswith(collection_prefix) for owner in owners):
                        try:
                            collection_key = ast.literal_eval(raw_key)
                        except (ValueError, SyntaxError):
                            collection_key = None
                        if type(collection_key) is str:
                            collection_sensitive[name].add(collection_key)
                    resolved = {test_index[owner] for owner in owners if owner in test_index}
                    for owner in owners:
                        collection = collection_readers(owner)
                        if collection is not None:
                            resolved.update(collection)
                    if raw_key in WILDCARDS:
                        wildcard.update(resolved)
                        continue
                    try:
                        key = ast.literal_eval(raw_key)
                    except (ValueError, SyntaxError):
                        wildcard.update(resolved)
                        continue
                    if type(key) is str:
                        keys[key].update(resolved)
                    else:
                        wildcard.update(resolved)
        aggregate[name] = (
            {key: sorted(readers) for key, readers in sorted(keys.items())},
            sorted(wildcard),
        )

    key_domains = {}
    for name in sorted(CERTIFIED_TARGETS):
        safe, forbidden = registry_key_domain(trees, assignments, name)
        sensitive = collection_sensitive[name]
        key_domains[name] = (
            sorted(set(safe) - sensitive),
            sorted(set(forbidden) | sensitive),
        )

    base_tree = trees["sqlglot/parser.py"]
    entries = []
    for statement in base_tree.body:
        if not isinstance(statement, ast.ClassDef) or statement.name != "Parser":
            continue
        for item in statement.body:
            target = assignment_target(item)
            if target is None or target.id not in CERTIFIED_TARGETS or not isinstance(item.value, ast.Dict):
                continue
            key_readers, wildcard = aggregate[target.id]
            safe_keys, forbidden_keys = key_domains[target.id]
            entries.append([
                item.lineno,
                item.end_lineno or item.lineno,
                "Parser",
                target.id,
                ast.dump(item.value, include_attributes=False),
                hashlib.sha256(sources["sqlglot/parser.py"].encode("utf-8")).hexdigest(),
                hashlib.sha256(
                    ast.dump(base_tree, include_attributes=False).encode("utf-8")
                ).hexdigest(),
                key_readers,
                wildcard,
                safe_keys,
                forbidden_keys,
            ])

    import_raw = json.dumps(sorted(import_events), separators=(",", ":")).encode()
    assignment_raw = json.dumps(
        [assignment.__dict__ for assignment in assignments],
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    payload = {
        "audit": audit,
        "d": {"sqlglot/parser.py": sorted(entries)},
        "evidence": {
            "assignments": hashlib.sha256(assignment_raw).hexdigest(),
            "imports": hashlib.sha256(import_raw).hexdigest(),
            "manifests": [hashlib.sha256(path.read_bytes()).hexdigest() for path in args.manifest],
            "traces": [hashlib.sha256(path.read_bytes()).hexdigest() for path in args.trace],
        },
        "n": len(test_ids),
        "sha": PINNED_SHA,
        "state": "certified",
        "t": roster_digest,
        "v": 4,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    with args.output.open("wb") as raw_stream:
        with gzip.GzipFile(filename="", fileobj=raw_stream, mode="wb", mtime=0) as stream:
            stream.write(raw)
    print(json.dumps({
        "assignments": len(assignments),
        "bytes": args.output.stat().st_size,
        "entries": len(entries),
        "import_events": len(import_events),
        "wildcards": {name: len(values[1]) for name, values in aggregate.items()},
        "safe_keys": {name: len(values[0]) for name, values in key_domains.items()},
        "collection_sensitive": {
            name: len(values) for name, values in collection_sensitive.items()
        },
    }, sort_keys=True))


if __name__ == "__main__":
    main()
