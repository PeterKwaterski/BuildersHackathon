#!/usr/bin/env python3
"""Build the complete-suite single-comparison execution profile."""

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
PYTHON_VERSION = [3, 13, 18]
OPERATORS = {
    "Lt",
    "LtE",
    "Gt",
    "GtE",
    "Eq",
    "NotEq",
    "Is",
    "IsNot",
    "In",
    "NotIn",
}
OUTCOME_ORDER = (
    "Lt",
    "LtE",
    "Gt",
    "GtE",
    "Eq",
    "NotEq",
    "Is",
    "IsNot",
    "In",
    "NotIn",
)
SAFE_DOMAINS = {
    ("builtins", name)
    for name in ("NoneType", "bool", "int", "float", "str", "bytes", "type", "tuple")
}


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument(
        "--manifest",
        type=Path,
        action="append",
        required=True,
        help="successful normal and synchronous-worker suite manifests",
    )
    parser.add_argument(
        "--trace",
        type=Path,
        action="append",
        required=True,
        help="normal and synchronous-worker trace files",
    )
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def sites(source: Path) -> dict[str, tuple[str, list[int | str], str]]:
    result = {}
    for path in sorted((source / "sqlglot").rglob("*.py")):
        relative = path.relative_to(source).as_posix()
        tree = ast.parse(path.read_text(), filename=relative, type_comments=True)
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Compare)
                and len(node.ops) == 1
                and len(node.comparators) == 1
                and type(node.ops[0]).__name__ in OPERATORS
            ):
                continue
            coordinates = [
                node.lineno,
                node.col_offset,
                node.end_lineno,
                node.end_col_offset,
            ]
            label = f"{relative}:{':'.join(map(str, coordinates))}"
            result[label] = (relative, coordinates, type(node.ops[0]).__name__)
    return result


def valid_domain(value) -> bool:
    return (
        isinstance(value, list)
        and len(value) == 2
        and tuple(value) in SAFE_DOMAINS
    )


def parse_signature(value: str) -> tuple[list, list, dict] | None:
    try:
        signature = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return None
    if (
        not isinstance(signature, dict)
        or set(signature) != {"left", "right", "outcomes"}
        or not valid_domain(signature["left"])
        or not valid_domain(signature["right"])
        or not isinstance(signature["outcomes"], dict)
        or set(signature["outcomes"]) != OPERATORS
    ):
        return None
    for outcome in signature["outcomes"].values():
        if not isinstance(outcome, list) or len(outcome) != 3:
            return None
        if outcome[0] == "value":
            if outcome[1] != "bool" or outcome[2] not in {"True", "False"}:
                return None
        elif outcome[0] == "error":
            if not all(isinstance(item, str) and item for item in outcome[1:]):
                return None
        else:
            return None
    return signature["left"], signature["right"], signature["outcomes"]


def main() -> None:
    args = arguments()
    if len(args.manifest) < 3 or len(args.manifest) != len(args.trace):
        raise SystemExit(
            "paired normal, synchronous-worker, and adverse-seed runs are required"
        )
    source = args.source.resolve()
    revision = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    if revision != PINNED_SHA:
        raise SystemExit(f"source is {revision}, expected {PINNED_SHA}")
    source_sites = sites(source)

    test_document = json.loads(args.tests.read_text())
    test_ids = [test["id"] for test in test_document["tests"]]
    expected = set(test_ids)
    manifest_roster = expected
    manifests = [json.loads(path.read_text()) for path in args.manifest]
    modes = {manifest.get("mode") for manifest in manifests}
    if not {"normal", "synchronous-worker"}.issubset(modes):
        raise SystemExit("manifests must include normal and synchronous-worker modes")
    seeds = {manifest.get("hash_seed") for manifest in manifests}
    if "0" not in seeds or not any(seed != "0" for seed in seeds):
        raise SystemExit("manifests must include official seed 0 and an adverse seed")
    if not {("normal", "0"), ("synchronous-worker", "0")}.issubset(
        {(manifest.get("mode"), manifest.get("hash_seed")) for manifest in manifests}
    ):
        raise SystemExit("official seed 0 must cover both process modes")
    for path, trace_path, manifest in zip(args.manifest, args.trace, manifests):
        if manifest.get("exitstatus") != 0:
            raise SystemExit(f"{path} records a nonzero suite exit status")
        seed = manifest.get("hash_seed")
        if (
            not isinstance(seed, str)
            or not seed.isdecimal()
            or not 0 <= int(seed) <= 4_294_967_295
            or manifest.get("python") != PYTHON_VERSION
            or manifest.get("instrumented_sites") != len(source_sites)
            or manifest.get("trace_sha256")
            != hashlib.sha256(trace_path.read_bytes()).hexdigest()
        ):
            raise SystemExit(f"{path} run or trace authentication differs")
        ledger_counts = (manifest.get("expected_tasks"), manifest.get("completed_tasks"))
        if (
            not isinstance(manifest.get("child_logs"), int)
            or manifest["child_logs"] < 0
            or any(not isinstance(count, int) or count < 0 for count in ledger_counts)
            or ledger_counts[0] != ledger_counts[1]
            or manifest.get("missing_tasks") != []
            or manifest.get("extra_tasks") != []
        ):
            raise SystemExit(f"{path} lacks complete process-task accounting")
        if manifest.get("mode") == "normal" and ledger_counts[0] == 0:
            raise SystemExit(f"{path} did not ledger any normal-mode process tasks")
        collected = manifest.get("tests")
        if collected != test_ids:
            raise SystemExit(
                f"{path} runtime roster differs: "
                f"expected={len(test_ids)} actual="
                f"{len(collected) if isinstance(collected, list) else 'invalid'}"
            )
        if manifest.get("subtests") != {
            "failed": 0,
            "passed": 25_440,
            "skipped": 0,
        }:
            raise SystemExit(f"{path} runtime subtest ledger differs")

    trace_documents = [json.loads(path.read_text()) for path in args.trace]
    merged: dict[str, dict[str, list]] = defaultdict(dict)
    owner_count = len(manifest_roster)
    for document in trace_documents:
        if not isinstance(document, dict):
            raise SystemExit("trace root must be an object")
        for label, events in document.items():
            if not isinstance(events, dict):
                raise SystemExit(f"invalid events for {label}")
            for signature, ownership in events.items():
                if (
                    not isinstance(ownership, list)
                    or len(ownership) != 3
                    or not isinstance(ownership[0], str)
                    or not isinstance(ownership[1], bool)
                    or not isinstance(ownership[2], list)
                    or any(not isinstance(owner, str) for owner in ownership[2])
                ):
                    raise SystemExit(f"invalid owners for {label}")
                try:
                    owner_mask = int(ownership[0], 16)
                except ValueError as error:
                    raise SystemExit(f"invalid owner mask for {label}") from error
                if (
                    owner_mask < 0
                    or format(owner_mask, "x") != ownership[0]
                    or owner_mask >> owner_count
                ):
                    raise SystemExit(f"out-of-roster owner mask for {label}")
                event = merged[label].setdefault(signature, [0, False, set()])
                event[0] |= owner_mask
                event[1] |= ownership[1]
                event[2].update(ownership[2])

    unknown = {
        owner
        for events in merged.values()
        for ownership in events.values()
        for owner in ownership[2]
    }
    if unknown:
        raise SystemExit(f"trace contains {len(unknown)} unknown runtime test IDs")

    # This is deliberately a complete execution profile, not a filtered list
    # of candidate edits.  Every source site is emitted, including sites that
    # were unobserved or unsafe and can therefore only fall back at runtime.
    model: dict[str, list[list]] = defaultdict(list)
    for label, (path, coordinates, source_operator) in source_sites.items():
        events = merged.get(label)
        complete = all(label in document for document in trace_documents)
        signatures = [parse_signature(value) for value in (events or {})]
        if not events:
            state = "unobserved"
        elif not complete:
            state = "incomplete"
        elif any(
            ownership[1] or ownership[0] == 0 for ownership in events.values()
        ):
            state = "unattributed"
        elif any(signature is None for signature in signatures):
            state = "unsafe"
        else:
            state = "safe"

        observations = []
        if state == "safe":
            observations = sorted(
                [left, right, [outcomes[name] for name in OUTCOME_ORDER]]
                for left, right, outcomes in signatures
            )
        model[path].append(
            [*coordinates, source_operator, state, observations]
        )

    ordered = {
        path: sorted(entries, key=lambda entry: tuple(entry[:4]))
        for path, entries in sorted(model.items())
    }
    payload = {
        "d": ordered,
        "n": len(test_ids),
        "sha": revision,
        "t": hashlib.sha256("\0".join(test_ids).encode()).hexdigest(),
        "v": 3,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    args.output.write_bytes(gzip.compress(raw, compresslevel=9, mtime=0))
    safe = sum(entry[5] == "safe" for entries in ordered.values() for entry in entries)
    print(
        f"wrote a complete {sum(map(len, ordered.values()))}-site predicate profile "
        f"with {safe} safely observed sites"
    )


if __name__ == "__main__":
    main()
