#!/usr/bin/env python3
"""Build the complete-suite ordering predicate execution profile."""

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
ORDERING = {"Lt", "LtE", "Gt", "GtE"}
OUTCOME_ORDER = ("Lt", "LtE", "Gt", "GtE", "Eq", "NotEq")


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


def literal_boundary(node: ast.Compare) -> bool:
    for operand in (node.left, node.comparators[0]):
        try:
            ast.literal_eval(operand)
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            continue
        return True
    return False


def sites(source: Path) -> dict[str, tuple[str, list[int | str]]]:
    result = {}
    for path in sorted((source / "sqlglot").rglob("*.py")):
        relative = path.relative_to(source).as_posix()
        tree = ast.parse(path.read_text(), filename=relative, type_comments=True)
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Compare)
                and len(node.ops) == 1
                and len(node.comparators) == 1
                and type(node.ops[0]).__name__ in ORDERING
                and literal_boundary(node)
            ):
                continue
            coordinates = [
                node.lineno,
                node.col_offset,
                node.end_lineno,
                node.end_col_offset,
            ]
            label = f"{relative}:{':'.join(map(str, coordinates))}"
            result[label] = (relative, coordinates)
    return result


def parse_signature(value: str) -> dict | None:
    try:
        signature = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return None
    if set(signature) != {"Lt", "LtE", "Gt", "GtE", "Eq", "NotEq"}:
        return None
    for outcome in signature.values():
        if (
            not isinstance(outcome, list)
            or len(outcome) != 3
            or outcome[:2] != ["value", "bool"]
            or outcome[2] not in {"True", "False"}
        ):
            return None
    return signature


def main() -> None:
    args = arguments()
    if len(args.manifest) < 2 or len(args.trace) < 2:
        raise SystemExit("both normal and synchronous-worker runs are required")
    source = args.source.resolve()
    revision = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    if revision != PINNED_SHA:
        raise SystemExit(f"source is {revision}, expected {PINNED_SHA}")

    test_ids = [test["id"] for test in json.loads(args.tests.read_text())["tests"]]
    expected = set(test_ids)
    manifests = [json.loads(path.read_text()) for path in args.manifest]
    modes = {manifest.get("mode") for manifest in manifests}
    if not {"normal", "synchronous-worker"}.issubset(modes):
        raise SystemExit("manifests must include normal and synchronous-worker modes")
    for path, manifest in zip(args.manifest, manifests):
        if manifest.get("exitstatus") != 0:
            raise SystemExit(f"{path} records a nonzero suite exit status")
        if not isinstance(manifest.get("child_logs"), int) or manifest["child_logs"] <= 0:
            raise SystemExit(f"{path} lacks process trace accounting")
        missing = expected - set(manifest.get("tests", ()))
        if missing:
            raise SystemExit(f"{path} is missing {len(missing)} runtime test IDs")

    trace_documents = [json.loads(path.read_text()) for path in args.trace]
    merged: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for document in trace_documents:
        if not isinstance(document, dict):
            raise SystemExit("trace root must be an object")
        for label, events in document.items():
            if not isinstance(events, dict):
                raise SystemExit(f"invalid events for {label}")
            for signature, owners in events.items():
                if not isinstance(owners, list):
                    raise SystemExit(f"invalid owners for {label}")
                merged[label][signature].update(owners)

    unknown = {
        owner
        for events in merged.values()
        for owners in events.values()
        for owner in owners
        if owner not in expected and owner != "__NO_TEST__"
    }
    if unknown:
        raise SystemExit(f"trace contains {len(unknown)} unknown runtime test IDs")

    # This is deliberately a complete execution profile, not a filtered list
    # of candidate edits.  Every source site is emitted, including sites that
    # were unobserved or unsafe and can therefore only fall back at runtime.
    model: dict[str, list[list]] = defaultdict(list)
    for label, (path, coordinates) in sites(source).items():
        events = merged.get(label)
        complete = all(label in document for document in trace_documents)
        owners = {
            owner for values in (events or {}).values() for owner in values
        }
        signatures = [parse_signature(value) for value in (events or {})]
        if not events:
            state = "unobserved"
        elif not complete:
            state = "incomplete"
        elif "__NO_TEST__" in owners or not owners:
            state = "unattributed"
        elif any(signature is None for signature in signatures):
            state = "unsafe"
        else:
            state = "safe"

        source_operator = None
        tree = ast.parse((source / path).read_text(), filename=path, type_comments=True)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Compare)
                and [node.lineno, node.col_offset, node.end_lineno, node.end_col_offset]
                == coordinates
            ):
                source_operator = (
                    type(node.ops[0]).__name__ if len(node.ops) == 1 else None
                )
                break
        observations = []
        if state == "safe":
            observations = sorted(
                [signature[name][2] == "True" for name in OUTCOME_ORDER]
                for signature in signatures
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
        "v": 2,
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
