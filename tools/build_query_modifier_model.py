#!/usr/bin/env python3
"""Build a key-sensitive QUERY_MODIFIERS deletion research model."""

from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import json
import subprocess
from collections import defaultdict
from pathlib import Path

from collect_dict_access import PINNED_SHA, PINNED_SOURCE_DIGEST, validate_source
from collect_query_modifier_reads import SENSITIVE_LABEL, collector_bundle_digest


TARGET_CLASSES = {"SetOperation", "Select", "Subquery"}
WILDCARDS = {
    repr(("__BR_WILDCARD__", "keys")),
    repr(("__BR_WILDCARD__", "shape")),
    repr(("__BR_WILDCARD__", "values")),
}


def packed_cost(tests: list[dict]) -> float:
    candidates = []
    for worker_count in range(1, 9):
        loads = [0] * worker_count
        for test in sorted(tests, key=lambda item: item["seconds"], reverse=True):
            worker = loads.index(min(loads))
            loads[worker] += round(test["seconds"] * 1_000)
        candidates.append((max(loads, default=0) + 2_000 * worker_count) / 1_000)
    return min(candidates)


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--trace", type=Path, action="append", required=True)
    parser.add_argument("--manifest", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def load_trace(path: Path) -> dict:
    def sorted_unique_strings(value: object, *, nonempty: bool = False) -> bool:
        return bool(
            isinstance(value, list)
            and (value or not nonempty)
            and all(type(item) is str for item in value)
            and value == sorted(set(value))
        )

    def sorted_unique_pids(value: object) -> bool:
        return bool(
            isinstance(value, list)
            and value
            and all(type(item) is int and item > 0 for item in value)
            and value == sorted(set(value))
        )

    document = json.loads(path.read_text())
    if not isinstance(document, dict) or set(document) != {
        "creations", "events", "imports", "tasks"
    }:
        raise SystemExit(f"invalid trace envelope {path}")
    events = document["events"]
    if not isinstance(events, dict) or any(
        type(label) is not str
        or not isinstance(values, dict)
        or any(
            type(key) is not str
                or not sorted_unique_strings(owners)
            for key, owners in values.items()
        )
        for label, values in events.items()
    ):
        raise SystemExit(f"invalid trace events {path}")
    creations = document["creations"]
    imports = document["imports"]
    if (
        not isinstance(creations, dict)
        or any(
            type(label) is not str
            or not sorted_unique_strings(owners)
            for label, owners in creations.items()
        )
        or not isinstance(imports, list)
        or any(
            not isinstance(event, list)
            or len(event) != 6
            or any(type(value) is not str for value in event[:4])
            or type(event[4]) is not int
            or type(event[5]) is not str
            for event in imports
        )
    ):
        raise SystemExit(f"invalid trace provenance {path}")
    tasks = document["tasks"]
    if (
        not isinstance(tasks, dict)
        or set(tasks) != {"completed", "submitted", "workers"}
        or not sorted_unique_strings(tasks["completed"])
        or not sorted_unique_strings(tasks["submitted"])
        or not isinstance(tasks["workers"], dict)
        or tasks["completed"] != tasks["submitted"]
        or set(tasks["workers"]) != set(tasks["completed"])
        or any(
            type(task) is not str
            or not sorted_unique_pids(workers)
            for task, workers in tasks["workers"].items()
        )
    ):
        raise SystemExit(f"incomplete task ledger {path}")
    return document


def source_theorem(source: Path):
    revision = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    if revision != PINNED_SHA:
        raise SystemExit(f"source is {revision}, expected {PINNED_SHA}")
    core_path = source / "sqlglot/expressions/core.py"
    query_path = source / "sqlglot/expressions/query.py"
    core_source = core_path.read_text()
    core_tree = ast.parse(core_source, filename="sqlglot/expressions/core.py")
    assignments = [
        node
        for node in core_tree.body
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and any(
            isinstance(target, ast.Name) and target.id == "QUERY_MODIFIERS"
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
        )
    ]
    if len(assignments) != 1 or not isinstance(assignments[0].value, ast.Dict):
        raise SystemExit("QUERY_MODIFIERS is not one module dictionary")
    assignment = assignments[0]
    key_nodes = {}
    for key, value in zip(assignment.value.keys, assignment.value.values):
        if (
            not isinstance(key, ast.Constant)
            or type(key.value) is not str
            or not isinstance(value, ast.Constant)
            or value.value is not False
            or key.value in key_nodes
        ):
            raise SystemExit("QUERY_MODIFIERS key domain is not unique literal False")
        key_nodes[key.value] = key

    query_tree = ast.parse(query_path.read_text(), filename="sqlglot/expressions/query.py")
    labels = []
    unpack_loads = []
    for owner in query_tree.body:
        if not isinstance(owner, ast.ClassDef) or owner.name not in TARGET_CLASSES:
            continue
        matches = []
        for statement in owner.body:
            targets = statement.targets if isinstance(statement, ast.Assign) else (
                [statement.target] if isinstance(statement, ast.AnnAssign) else []
            )
            if (
                len(targets) == 1
                and isinstance(targets[0], ast.Name)
                and targets[0].id == "arg_types"
                and isinstance(statement.value, ast.Dict)
            ):
                matches.append(statement)
        if len(matches) != 1:
            raise SystemExit(f"{owner.name}.arg_types is not one dictionary")
        statement = matches[0]
        unpacks = [
            value
            for key, value in zip(statement.value.keys, statement.value.values)
            if key is None
        ]
        if len(unpacks) != 1 or not isinstance(unpacks[0], ast.Name) or unpacks[0].id != "QUERY_MODIFIERS":
            raise SystemExit(f"{owner.name}.arg_types does not exactly unpack QUERY_MODIFIERS")
        unpack_loads.extend(unpacks)
        labels.append(
            f"sqlglot/expressions/query.py:{statement.lineno}:"
            f"{statement.end_lineno or statement.lineno}:arg_types"
        )
    if len(labels) != len(TARGET_CLASSES):
        raise SystemExit("incomplete QUERY_MODIFIERS arg_types propagation")

    # Whole-source reference census: the only content consumers are the three
    # authenticated unpacks and the exact parser/generator sites rewritten by
    # the collector. Module-object escapes are separately rejected/proved by
    # the module-assignment static theorem in the integration lane.
    name_loads = [
        node for node in ast.walk(query_tree)
        if isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Load)
        and node.id == "QUERY_MODIFIERS"
    ]
    if {id(node) for node in name_loads} != {id(node) for node in unpack_loads}:
        raise SystemExit("unexpected local QUERY_MODIFIERS consumer")
    attribute_sites = []
    for root_name in ("sqlglot", "tests"):
        for path in sorted((source / root_name).rglob("*.py")):
            tree = ast.parse(path.read_text(), filename=path.as_posix())
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr == "QUERY_MODIFIERS":
                    attribute_sites.append((path.relative_to(source).as_posix(), node.lineno))
    if attribute_sites != [
        ("sqlglot/generator.py", 2037),
        ("sqlglot/generator.py", 2049),
        ("sqlglot/parser.py", 4454),
    ]:
        raise SystemExit(f"unexpected qualified QUERY_MODIFIERS consumers: {attribute_sites!r}")

    # The sensitive helpers call ``args.get``/``args.items`` exactly once. A
    # user-supplied mapping subclass could make even a false lookup observable,
    # so the collector records a wildcard whenever the runtime container is not
    # an exact dict. Pin the only source-visible rebindings as a second check.
    args_rebindings = []
    for root_name in ("sqlglot", "tests"):
        for path in sorted((source / root_name).rglob("*.py")):
            tree = ast.parse(path.read_text(), filename=path.as_posix())
            for node in ast.walk(tree):
                if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                    continue
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(isinstance(target, ast.Attribute) and target.attr == "args" for target in targets):
                    args_rebindings.append(
                        (path.relative_to(source).as_posix(), node.lineno, ast.unparse(node.value))
                    )
    if args_rebindings != [
        ("sqlglot/expressions/core.py", 117, "args"),
        ("tests/test_optimizer.py", 1899, "dict(reversed(node.args.items()))"),
    ]:
        raise SystemExit(f"unexpected Expr.args rebinding: {args_rebindings!r}")

    # A TrackingDict changes exact runtime type, so bind the complete direct
    # arg_types observation surface as well as its keyed trace. Every pinned
    # load below immediately performs an operation covered by the tracker;
    # there is no literal-name getattr/vars channel for ``arg_types``.
    arg_type_loads = []
    arg_type_stores = []
    literal_reflection = []
    for root_name in ("sqlglot", "tests"):
        for path in sorted((source / root_name).rglob("*.py")):
            tree = ast.parse(path.read_text(), filename=path.as_posix())
            relative = path.relative_to(source).as_posix()
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Attribute)
                    and isinstance(node.ctx, ast.Load)
                    and node.attr == "arg_types"
                ):
                    arg_type_loads.append((relative, node.lineno))
                elif (
                    isinstance(node, ast.Attribute)
                    and isinstance(node.ctx, (ast.Store, ast.Del))
                    and node.attr == "arg_types"
                ):
                    arg_type_stores.append((relative, node.lineno))
                elif isinstance(node, ast.Constant) and node.value == "arg_types":
                    literal_reflection.append((relative, node.lineno))
    if sorted(arg_type_loads) != [
        ("sqlglot/expressions/core.py", 110),
        ("sqlglot/expressions/core.py", 1317),
        ("sqlglot/expressions/core.py", 1332),
        ("sqlglot/expressions/core.py", 1339),
        ("sqlglot/expressions/core.py", 1423),
        ("sqlglot/expressions/core.py", 1680),
        ("sqlglot/expressions/core.py", 1686),
        ("sqlglot/expressions/core.py", 3111),
        ("sqlglot/expressions/functions.py", 74),
        ("sqlglot/expressions/query.py", 641),
        ("sqlglot/expressions/string.py", 35),
        ("sqlglot/generator.py", 5039),
        ("sqlglot/optimizer/merge_subqueries.py", 123),
        ("sqlglot/optimizer/simplify.py", 1964),
        ("sqlglot/optimizer/simplify.py", 1964),
        ("sqlglot/parser.py", 4187),
        ("sqlglot/parser.py", 5364),
        ("sqlglot/parsers/postgres.py", 42),
    ] or arg_type_stores or literal_reflection:
        raise SystemExit(
            "arg_types observation surface drift: "
            f"{arg_type_loads!r} {arg_type_stores!r} {literal_reflection!r}"
        )

    lines = core_source.splitlines(keepends=True)
    deletions = {}
    for key, node in key_nodes.items():
        line = lines[node.lineno - 1]
        if line.strip() != f'"{key}": False,':
            raise SystemExit(f"noncanonical QUERY_MODIFIERS line for {key}")
        changed = "".join(lines[: node.lineno - 1] + lines[node.lineno :])
        deletions[key] = hashlib.sha256(changed.encode()).hexdigest()
    source_label = (
        f"sqlglot/expressions/core.py:{assignment.lineno}:"
        f"{assignment.end_lineno or assignment.lineno}:QUERY_MODIFIERS"
    )
    return (
        source_label,
        sorted(labels),
        deletions,
        hashlib.sha256(core_source.encode()).hexdigest(),
    )


def main() -> None:
    args = arguments()
    if len(args.trace) != 2 or len(args.manifest) != 2:
        raise SystemExit("normal and synchronous-worker traces are required")
    validate_source(args.source.resolve(), args.sources.resolve())
    tests = json.loads(args.tests.read_text())["tests"]
    test_ids = [test["id"] for test in tests]
    if len(test_ids) != len(set(test_ids)):
        raise SystemExit("duplicate numbered test IDs")
    test_index = {test_id: index for index, test_id in enumerate(test_ids)}
    tests_by_file = defaultdict(set)
    for index, test in enumerate(tests):
        tests_by_file[test["file"]].add(index)
    roster_digest = hashlib.sha256("\0".join(test_ids).encode()).hexdigest()
    traces = [load_trace(path) for path in args.trace]
    manifests = [json.loads(path.read_text()) for path in args.manifest]
    if any(not isinstance(manifest, dict) for manifest in manifests) or {
        manifest.get("mode") for manifest in manifests
    } != {"normal", "synchronous-worker"}:
        raise SystemExit("trace modes are incomplete")
    bundle_digest = collector_bundle_digest()
    manifest_keys = {
        "child_logs", "collector_bundle_sha256", "completed_tasks", "exitstatus",
        "instrumented", "mode", "pool_workers", "python", "roster_count",
        "roster_digest", "selection", "source_digest", "source_sha",
        "submitted_tasks", "task_attribution", "task_workers", "tests",
        "trace_sha256", "tracker_version",
    }
    for manifest, trace_path, trace in zip(manifests, args.trace, traces):
        mode = manifest.get("mode")
        tasks = trace["tasks"]
        worker_count = len({
            worker for workers in tasks["workers"].values() for worker in workers
        })
        if (
            set(manifest) != manifest_keys
            or manifest.get("exitstatus") != 0
            or manifest.get("collector_bundle_sha256") != bundle_digest
            or manifest.get("tracker_version") != 5
            or manifest.get("task_attribution") != "submit-wrapper-v2"
            or manifest.get("pool_workers") != 2
            or manifest.get("selection") != "numbered-roster"
            or not str(manifest.get("python", "")).startswith("3.13.")
            or manifest.get("roster_count") != len(test_ids)
            or manifest.get("roster_digest") != roster_digest
            or manifest.get("source_digest") != PINNED_SOURCE_DIGEST
            or manifest.get("source_sha") != PINNED_SHA
            or manifest.get("trace_sha256") != hashlib.sha256(trace_path.read_bytes()).hexdigest()
            or manifest.get("tests") != sorted(test_ids)
            or manifest.get("submitted_tasks") != len(tasks["submitted"])
            or manifest.get("completed_tasks") != len(tasks["completed"])
            or manifest.get("task_workers") != worker_count
            or type(manifest.get("child_logs")) is not int
            or manifest.get("child_logs") != worker_count + 1
            or (mode == "normal" and not tasks["submitted"])
            or (mode == "synchronous-worker" and tasks["submitted"])
        ):
            raise SystemExit("inadmissible query-modifier manifest")

    source_label, arg_labels, deletion_digests, core_digest = source_theorem(args.source)
    merged = defaultdict(lambda: defaultdict(set))
    imports = defaultdict(set)
    for trace in traces:
        for label, values in trace["events"].items():
            for raw_key, owners in values.items():
                merged[label][raw_key].update(owners)
        for event in trace["imports"]:
            if not isinstance(event, list) or len(event) != 6:
                raise SystemExit("malformed import event")
            label, raw_key, kind, path, line, function = event
            imports[(label, raw_key)].add((kind, path, line, function))

    def allowed_import(label: str, raw_key: str, event: tuple) -> bool:
        kind, path, line, function = event
        if kind != "read":
            return False
        if label == source_label:
            return path == "sqlglot/expressions/query.py" and any(
                int(candidate.split(":")[1]) <= line <= int(candidate.split(":")[2])
                for candidate in arg_labels
            )
        if label in arg_labels:
            if path == "sqlglot/expressions/core.py" and line == 110 and function == "__init_subclass__":
                return raw_key == repr(("__BR_WILDCARD__", "values"))
            if label.startswith("sqlglot/expressions/query.py:1214:"):
                return (
                    path == "sqlglot/optimizer/merge_subqueries.py"
                    and line == 123
                    and raw_key == repr(("__BR_WILDCARD__", "keys"))
                )
        return False

    def indices(label: str, raw_key: str) -> set[int]:
        owners = set(merged.get(label, {}).get(raw_key, ()))
        events = imports.get((label, raw_key), set())
        if events and all(allowed_import(label, raw_key, event) for event in events):
            owners = {owner for owner in owners if not owner.startswith("__BR_COLLECT_FILE__:") and owner != "__NO_TEST__"}
        result = set()
        for owner in owners:
            if owner in test_index:
                result.add(test_index[owner])
            elif owner.startswith("__BR_COLLECT_FILE__:"):
                result.update(tests_by_file.get(owner.split(":", 1)[1], ()))
            else:
                raise SystemExit(f"unattributed query-modifier owner: {owner}")
        return result

    profile = {}
    for key in sorted(deletion_digests):
        readers = indices(SENSITIVE_LABEL, repr(key))
        for wildcard in WILDCARDS:
            readers.update(indices(SENSITIVE_LABEL, wildcard))
        # The three authenticated parser/generator loops suppress only their
        # generic source-dictionary iteration event and emit SENSITIVE_LABEL
        # instead. Every other exact, shape, reflection-backed or mutation
        # observation of QUERY_MODIFIERS remains a source-label dependency.
        readers.update(indices(source_label, repr(key)))
        for wildcard in WILDCARDS:
            readers.update(indices(source_label, wildcard))
        for label in arg_labels:
            readers.update(indices(label, repr(key)))
            for wildcard in WILDCARDS:
                readers.update(indices(label, wildcard))
        profile[key] = [deletion_digests[key], sorted(readers)]

    payload = {
        "d": profile,
        "n": len(test_ids),
        "p": {
            "builder": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "collector": bundle_digest,
            "manifests": sorted(
                hashlib.sha256(path.read_bytes()).hexdigest() for path in args.manifest
            ),
            "traces": sorted(
                hashlib.sha256(path.read_bytes()).hexdigest() for path in args.trace
            ),
        },
        "s": core_digest,
        "sha": PINNED_SHA,
        "t": roster_digest,
        "v": 1,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    args.output.write_bytes(gzip.compress(raw, compresslevel=9, mtime=0))
    for key, (_digest, readers) in profile.items():
        cost = packed_cost([tests[index] for index in readers])
        print(f"{key}: readers={len(readers)} cost={cost:.3f}s saving={36.817 - cost:.3f}s")


if __name__ == "__main__":
    main()
