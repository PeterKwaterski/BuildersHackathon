#!/usr/bin/env python3
"""Build the complete inline fresh-table alias profile."""

from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import json
import subprocess
from collections import defaultdict
from pathlib import Path

from collect_fresh_alias_profile import source_sites


PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, action="append", required=True)
    parser.add_argument("--trace", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def call_dumps(source: Path) -> dict[str, tuple[int, int, str]]:
    result = {}
    labels = {value[0] for value in source_sites(source).values()}
    for path in sorted((source / "sqlglot").rglob("*.py")):
        relative = path.relative_to(source).as_posix()
        tree = ast.parse(path.read_text(), filename=relative, type_comments=True)
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "exp"
                and node.func.attr == "alias_"
                and node.args
                and isinstance(node.args[0], ast.Call)
                and isinstance(node.args[0].func, ast.Attribute)
                and isinstance(node.args[0].func.value, ast.Name)
                and node.args[0].func.value.id == "exp"
                and node.args[0].func.attr == "table_"
            ):
                continue
            label = f"{relative}:{getattr(node, 'lineno', 0)}:{getattr(node, 'end_lineno', 0)}"
            if label in labels:
                if label in result:
                    raise SystemExit(f"ambiguous source label {label}")
                result[label] = (
                    node.lineno,
                    node.end_lineno or node.lineno,
                    ast.dump(node, include_attributes=False),
                )
    if set(result) != labels:
        raise SystemExit("source labels do not resolve to exact calls")
    return result


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
    expected = set(test_ids)
    test_index = {test_id: index for index, test_id in enumerate(test_ids)}
    manifests = [json.loads(path.read_text()) for path in args.manifest]
    if {manifest.get("mode") for manifest in manifests} != {
        "normal", "synchronous-worker"
    }:
        raise SystemExit("exactly one complete trace of each mode is required")
    for path, manifest in zip(args.manifest, manifests):
        missing = expected - set(manifest.get("tests", ()))
        if manifest.get("exitstatus") != 0 or missing:
            raise SystemExit(f"inadmissible manifest {path}: {len(missing)} missing")
        if not isinstance(manifest.get("child_logs"), int) or manifest["child_logs"] <= 0:
            raise SystemExit(f"manifest {path} lacks subprocess accounting")
        if (
            manifest.get("snapshot_trusted") is not True
            or manifest.get("unittest") is not True
            or manifest.get("clean_import") is not True
            or manifest.get("snapshot_mode") != "pytest"
        ):
            raise SystemExit(f"manifest {path} lacks a trusted pytest-mode snapshot")

    documents = [json.loads(path.read_text()) for path in args.trace]
    source_entries = call_dumps(source)
    if any(set(document) - set(source_entries) for document in documents):
        raise SystemExit("trace contains an unknown source site")
    unknown = {
        owner
        for document in documents
        for event in document.values()
        for owner in event.get("owners", ())
        if owner != "__NO_TEST__" and owner not in expected
    }
    if unknown:
        raise SystemExit(f"trace contains {len(unknown)} unknown owners")

    profile: dict[str, list[list]] = defaultdict(list)
    states = defaultdict(int)
    for label, (start, end, call_dump) in sorted(source_entries.items()):
        relative = label.rsplit(":", 2)[0]
        observations = [document.get(label) for document in documents]
        owners = {
            owner
            for observation in observations
            if observation
            for owner in observation.get("owners", ())
        }
        if any(observation is None for observation in observations):
            state = "incomplete" if owners else "unobserved"
        elif "__NO_TEST__" in owners:
            state = "import-read"
        elif not owners:
            state = "unobserved"
        elif any(observation.get("types") != ["builtins.str"] for observation in observations):
            state = "unsafe-type"
        elif any(observation.get("bindings") != [True] for observation in observations):
            state = "unsafe-binding"
        elif any(
            not observation.get("modes")
            or not set(observation["modes"]).issubset({"pytest", "child"})
            for observation in observations
        ):
            state = "unsafe-snapshot"
        else:
            state = "safe"
        readers = sorted(test_index[owner] for owner in owners if owner in test_index)
        profile[relative].append([start, end, call_dump, state, readers])
        states[state] += 1

    ordered = {
        path: sorted(entries, key=lambda entry: (entry[0], entry[1]))
        for path, entries in sorted(profile.items())
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
        f"wrote {sum(map(len, ordered.values()))} fresh-alias entries: "
        + ", ".join(f"{key}={value}" for key, value in sorted(states.items()))
    )


if __name__ == "__main__":
    main()
