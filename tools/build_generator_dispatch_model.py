#!/usr/bin/env python3
"""Build a compact source-derived Generator.TRANSFORMS reader certificate."""

from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import json
import subprocess
from collections import defaultdict
from pathlib import Path

from collect_generator_dispatch import transform_assignments


PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"
TRANSFORMS_CONSUMER_SHA256 = "df85ded1a23813f5f06c2215d0c92315d6c98e3e6ae00e0790fa3f02c411b027"
GENERATOR_CLASSES_SHA256 = "8b1230bb7ce5e42b5d5fac2d1457274505a0f28fb0dfd694a5f453fa95bb3deb"


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, action="append", required=True)
    parser.add_argument("--manifest", type=Path, action="append", required=True)
    parser.add_argument("--trace", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def source_inventory(source: Path):
    entries = {}
    assignments = {}
    ranges = defaultdict(list)
    for path in sorted((source / "sqlglot").rglob("*.py")):
        relative = path.relative_to(source).as_posix()
        module = relative.removesuffix("/__init__.py").removesuffix(".py").replace("/", ".")
        tree = ast.parse(path.read_text(), filename=relative, type_comments=True)

        def collect_assignment_ranges(body: list[ast.stmt], owner: tuple[str, ...]) -> None:
            for statement in body:
                if isinstance(statement, ast.ClassDef):
                    collect_assignment_ranges(statement.body, (*owner, statement.name))
                    continue
                targets = statement.targets if isinstance(statement, ast.Assign) else (
                    [statement.target] if isinstance(statement, ast.AnnAssign) else []
                )
                if (
                    len(targets) == 1
                    and isinstance(targets[0], ast.Name)
                    and targets[0].id == "TRANSFORMS"
                    and owner
                ):
                    ranges[relative].append(
                        (statement.lineno, statement.end_lineno or statement.lineno, owner[-1])
                    )

        collect_assignment_ranges(tree.body, ())
        for statement, owner in transform_assignments(tree):
            table_label = (
                f"{relative}:{statement.lineno}:{statement.end_lineno or statement.lineno}:"
                f"{'.'.join(owner)}"
            )
            class_name = f"{module}.{'.'.join(owner)}"
            assignments[table_label] = class_name
            for index, (key, value) in enumerate(zip(statement.value.keys, statement.value.values)):
                if key is None:
                    continue
                if not (
                    isinstance(key, ast.Attribute)
                    and isinstance(key.value, ast.Name)
                    and key.value.id == "exp"
                ):
                    raise SystemExit(f"unsupported key at {relative}:{key.lineno}")
                label = f"{table_label}:{index}:{key.attr}"
                if label in entries:
                    raise SystemExit(f"duplicate entry {label}")
                entries[label] = {
                    "end": statement.end_lineno or statement.lineno,
                    "index": index,
                    "key": ast.dump(key, include_attributes=False),
                    "key_name": key.attr,
                    "owner": ".".join(owner),
                    "path": relative,
                    "start": statement.lineno,
                    "table": table_label,
                    "value": ast.dump(value, include_attributes=False),
                    "value_kind": type(value).__name__,
                }
    return entries, assignments, ranges


def validate_static_consumers(source: Path) -> None:
    """Reject any new direct TRANSFORMS escape or consumer shape."""
    inventory = []
    paths = [*(source / "sqlglot").rglob("*.py"), *(source / "tests").rglob("*.py")]
    for path in sorted(paths):
        relative = path.relative_to(source).as_posix()
        tree = ast.parse(path.read_text(), filename=relative, type_comments=True)
        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "TRANSFORMS":
                parent = parents.get(node)
                ancestor = parent
                while ancestor is not None and not isinstance(ancestor, (ast.stmt, ast.Lambda)):
                    ancestor = parents.get(ancestor)
                inventory.append([
                    relative,
                    node.lineno,
                    type(parent).__name__,
                    ast.dump(parent, include_attributes=False),
                    type(ancestor).__name__ if ancestor else None,
                    getattr(ancestor, "lineno", None),
                ])
            elif isinstance(node, ast.Constant) and node.value == "TRANSFORMS":
                inventory.append([
                    relative,
                    node.lineno,
                    "string",
                    ast.dump(parents.get(node), include_attributes=False),
                ])
    digest = hashlib.sha256(json.dumps(inventory, separators=(",", ":")).encode()).hexdigest()
    if digest != TRANSFORMS_CONSUMER_SHA256:
        raise SystemExit(f"TRANSFORMS consumer inventory changed: {digest}")


def valid_owner_list(value, expected):
    return (
        isinstance(value, list)
        and value == sorted(set(value))
        and all(type(owner) is str and (owner == "__NO_TEST__" or owner in expected) for owner in value)
    )


def known_initialization_operation(
    operation: str, site_path: str, site_line: int, site_owner: str
) -> bool:
    """Return whether a pinned table mutation is part of dialect construction.

    Dialect metaclass construction removes unsupported JSONPath entries before
    the provenance snapshots are taken.  The path is source-root-relative, as
    emitted by the collector.
    """
    return (
        operation == "pop"
        and site_path == "sqlglot/dialects/dialect.py"
        and site_line == 355
        and site_owner == "__new__"
    )


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
    validate_static_consumers(source)
    test_document = json.loads(args.tests.read_text())
    tests = test_document["tests"]
    test_ids = [test["id"] for test in tests]
    expected, test_index = set(test_ids), {test_id: index for index, test_id in enumerate(test_ids)}
    skipped = set(test_document.get("skipped", ()))
    expected_executed = expected | skipped
    allowed_owners = expected_executed
    test_digest = hashlib.sha256("\0".join(test_ids).encode()).hexdigest()

    manifests = [json.loads(path.read_text()) for path in args.manifest]
    if {manifest.get("mode") for manifest in manifests} != {"normal", "synchronous-worker"}:
        raise SystemExit("exactly both trace modes are required")
    manifest_by_mode = {manifest.get("mode"): (path, manifest) for path, manifest in zip(args.manifest, manifests)}
    if len(manifest_by_mode) != 2:
        raise SystemExit("duplicate manifest mode")
    for path, manifest in manifest_by_mode.values():
        if (
            manifest.get("exitstatus") != 0
            or set(manifest.get("tests", ())) != expected_executed
            or not isinstance(manifest.get("child_logs"), int)
            or manifest["child_logs"] < 0
            or manifest.get("child_complete") is not True
            or manifest.get("child_starts") != manifest["child_logs"]
            or not isinstance(manifest.get("child_tokens_sha256"), str)
            or len(manifest["child_tokens_sha256"]) != 64
            or manifest.get("source_sha") != revision
            or manifest.get("test_digest") != test_digest
            or not isinstance(manifest.get("python"), str)
            or not manifest["python"].startswith("3.13.")
            or not isinstance(manifest.get("trace_sha256"), str)
            or len(manifest["trace_sha256"]) != 64
        ):
            raise SystemExit(f"inadmissible manifest {path}")
    if sum(manifest["child_logs"] for _, manifest in manifest_by_mode.values()) <= 0:
        raise SystemExit("trace pair lacks relevant child-process evidence")

    inventory, table_classes, assignment_ranges = source_inventory(source)
    if len(inventory) != 1350 or len(table_classes) != 28:
        raise SystemExit("source TRANSFORMS inventory changed")
    if len(args.provenance) != 2:
        raise SystemExit("forward and reverse provenance documents are required")
    provenance_documents = [json.loads(path.read_text()) for path in args.provenance]
    provenance_by_mode = {document.get("import_mode"): document for document in provenance_documents}
    if set(provenance_by_mode) != {"forward", "reverse"}:
        raise SystemExit("forward and reverse provenance modes are required")
    for mode, document in provenance_by_mode.items():
        if set(document) != {
            "classes", "dialects", "import_mode", "inventory", "json_path_keys", "modules",
            "opaque", "origins", "python", "source_sha"
        }:
            raise SystemExit("malformed provenance document")
        if document["inventory"] != sorted(inventory) or document["opaque"]:
            raise SystemExit("provenance inventory/opaque mismatch")
        if (
            document["source_sha"] != revision
            or not isinstance(document["python"], str)
            or not document["python"].startswith("3.13.")
            or hashlib.sha256("\0".join(sorted(document["classes"])).encode()).hexdigest()
            != GENERATOR_CLASSES_SHA256
            or not isinstance(document["modules"], list)
            or not isinstance(document["dialects"], list)
            or document["modules"]
            != sorted(set(document["modules"]), reverse=mode == "reverse")
            or document["dialects"]
            != sorted(set(document["dialects"]), reverse=mode == "reverse")
        ):
            raise SystemExit("provenance runtime/class/import identity mismatch")
    provenance = provenance_by_mode["forward"]
    reverse_provenance = provenance_by_mode["reverse"]
    if provenance["python"] != reverse_provenance["python"]:
        raise SystemExit("provenance Python runtimes differ")
    json_path_keys = set(provenance["json_path_keys"]) | set(reverse_provenance["json_path_keys"])
    for class_name in provenance["classes"]:
        forward_entries = {
            key: label for key, label in provenance["classes"][class_name].items()
            if key not in json_path_keys
        }
        reverse_entries = {
            key: label for key, label in reverse_provenance["classes"][class_name].items()
            if key not in json_path_keys
        }
        if forward_entries != reverse_entries:
            raise SystemExit(f"order-dependent non-JSON provenance for {class_name}")
    origins = provenance["origins"]
    if any(not isinstance(keys, list) or len(keys) != 1 for keys in origins.values()):
        raise SystemExit("ambiguous origin key mapping")
    effective_labels = {
        label for entries in provenance["classes"].values() for label in entries.values()
    }
    if not effective_labels.issubset(inventory) or set(origins) != effective_labels:
        raise SystemExit("effective provenance labels mismatch")

    documents = []
    for path in args.trace:
        raw_trace = path.read_bytes()
        document = json.loads(raw_trace)
        mode = document.get("mode") if isinstance(document, dict) else None
        manifest_record = manifest_by_mode.get(mode)
        if (
            manifest_record is None
            or document.get("source_sha") != revision
            or document.get("test_digest") != test_digest
            or document.get("python") != manifest_record[1].get("python")
            or hashlib.sha256(raw_trace).hexdigest() != manifest_record[1]["trace_sha256"]
        ):
            raise SystemExit(f"trace/manifest provenance mismatch for {path}")
        documents.append(document)
    if {document.get("mode") for document in documents} != {"normal", "synchronous-worker"}:
        raise SystemExit("trace modes are incomplete")
    readers = defaultdict(set)
    unsafe = defaultdict(set)
    origins_by_key = defaultdict(set)
    for label, keys in origins.items():
        origins_by_key[keys[0]].add(label)

    def add_owners(labels, owners, reason):
        if not valid_owner_list(owners, allowed_owners):
            raise SystemExit(f"invalid owner list for {reason}")
        for label in labels:
            if "__NO_TEST__" in owners:
                unsafe[label].add(reason)
            readers[label].update(test_index[owner] for owner in owners if owner in test_index)

    for document in documents:
        if not isinstance(document, dict) or set(document) != {
            "mode", "pairs", "python", "source_sha", "tables", "test_digest"
        }:
            raise SystemExit("malformed trace document")
        for raw_pair, owners in document["pairs"].items():
            try:
                consumer, generator_class, expression_class = json.loads(raw_pair)
            except (TypeError, ValueError, json.JSONDecodeError):
                raise SystemExit("malformed dispatch pair")
            if consumer not in {"dispatch", "json-path"}:
                raise SystemExit("unknown dispatch consumer")
            label = provenance["classes"].get(generator_class, {}).get(expression_class)
            labels = {label} if label else origins_by_key.get(expression_class, set())
            if labels:
                add_owners(labels, owners, f"pair:{consumer}:{generator_class}:{expression_class}")

        for table_label, operations in document["tables"].items():
            class_name = table_classes.get(table_label)
            if class_name is None or not isinstance(operations, dict):
                raise SystemExit(f"unknown trace table {table_label}")
            class_entries = provenance["classes"].get(class_name, {})
            for operation, events in operations.items():
                if operation not in {
                    "keys", "pop", "shape", "value", "values", "write"
                } or not isinstance(events, dict):
                    raise SystemExit(f"unknown table operation {operation}")
                for raw_event, owners in events.items():
                    try:
                        event = json.loads(raw_event)
                        key, site = event["key"], event["site"]
                        site_path, site_line, site_owner = site
                    except (TypeError, ValueError, KeyError, json.JSONDecodeError):
                        raise SystemExit("malformed table event")
                    if not valid_owner_list(owners, allowed_owners):
                        raise SystemExit("invalid table-event owners")
                    construction = any(
                        start <= site_line <= end and site_owner == owner_name
                        for start, end, owner_name in assignment_ranges.get(site_path, ())
                    )
                    known_initialization = known_initialization_operation(
                        operation, site_path, site_line, site_owner
                    )
                    if construction or known_initialization or operation in {"keys", "shape"}:
                        continue
                    if key is not None and (
                        isinstance(key, list) and len(key) == 3 and key[0] == "type"
                    ):
                        key_fqn = f"{key[1]}.{key[2]}"
                        label = class_entries.get(key_fqn)
                        labels = {label} if label else origins_by_key.get(key_fqn, set())
                    else:
                        labels = set(class_entries.values()) if key is None else set(inventory)
                    if operation in {"write", "pop"}:
                        for candidate in inventory:
                            unsafe[candidate].add(f"table-mutation:{site_path}:{site_line}")
                    elif operation in {"value", "values"} and labels:
                        add_owners(labels, owners, f"table:{operation}:{site_path}:{site_line}")

    records = defaultdict(list)
    states = defaultdict(int)
    for label, entry in sorted(inventory.items()):
        key_fqn = origins.get(label, [None])[0]
        if entry["value_kind"] != "Lambda":
            state = "unsupported-value"
        elif label not in effective_labels:
            state = "ineffective"
        elif key_fqn in json_path_keys:
            state = "json-path-order"
        elif unsafe[label]:
            state = "unsafe-observation"
        else:
            state = "safe"
        states[state] += 1
        records[entry["path"]].append([
            entry["start"], entry["end"], entry["owner"], entry["index"],
            entry["key"], entry["value"], state, sorted(readers[label]),
        ])

    ordered_records = {path: sorted(values) for path, values in sorted(records.items())}
    profile_digest = hashlib.sha256(
        json.dumps(ordered_records, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    payload = {
        "d": ordered_records,
        "n": len(test_ids),
        "p": profile_digest,
        "sha": revision,
        "t": test_digest,
        "v": 1,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    args.output.write_bytes(gzip.compress(raw, compresslevel=9, mtime=0))
    print(
        f"wrote {sum(map(len, records.values()))} generator entries: "
        + ", ".join(f"{key}={value}" for key, value in sorted(states.items()))
    )


if __name__ == "__main__":
    main()
