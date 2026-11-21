#!/usr/bin/env python3
"""Build an unfiltered function-code reflection ownership profile."""

from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import json
import subprocess
from collections import defaultdict
from pathlib import Path

from collect_code_reflections import unsupported_reflection


PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, action="append", required=True)
    parser.add_argument("--trace", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def candidates(source: Path) -> tuple[dict[str, list[list]], set[str]]:
    profile: dict[str, list[list]] = defaultdict(list)
    labels = set()
    for path in sorted((source / "sqlglot").rglob("*.py")):
        relative = path.relative_to(source).as_posix()
        tree = ast.parse(path.read_text(), filename=relative, type_comments=True)
        unsupported_reflection(tree, path)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                first = min(
                    [node.lineno, *(decorator.lineno for decorator in node.decorator_list)]
                )
                name = node.name
            elif isinstance(node, ast.Lambda):
                first = node.lineno
                name = "<lambda>"
            else:
                continue
            end = node.end_lineno or node.lineno
            label = f"{relative}:{first}:{name}"
            labels.add(label)
            profile[relative].append([first, end, name, label])
    return profile, labels


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

    source_profile, known_labels = candidates(source)
    documents = [json.loads(path.read_text()) for path in args.trace]
    unknown_labels = set().union(*(set(document) for document in documents)) - known_labels
    if unknown_labels:
        raise SystemExit(f"trace contains {len(unknown_labels)} unknown function labels")
    unknown_owners = {
        owner
        for document in documents
        for owners in document.values()
        for owner in owners
        if owner != "__NO_TEST__" and owner not in expected
    }
    if unknown_owners:
        raise SystemExit(f"trace contains {len(unknown_owners)} unknown test owners")

    states: dict[str, int] = defaultdict(int)
    profile: dict[str, list[list]] = {}
    for path, entries in source_profile.items():
        output_entries = []
        for first, end, name, label in entries:
            owners = set().union(*(set(document.get(label, ())) for document in documents))
            if "__NO_TEST__" in owners:
                state = "import-read"
                readers = list(range(len(test_ids)))
            elif owners:
                state = "observed"
                readers = sorted(test_index[owner] for owner in owners)
            else:
                state = "unobserved"
                readers = []
            output_entries.append([first, end, name, state, readers])
            states[state] += 1
        profile[path] = sorted(output_entries, key=lambda entry: (entry[0], entry[1], entry[2]))

    payload = {
        "d": dict(sorted(profile.items())),
        "n": len(test_ids),
        "p": hashlib.sha256(
            json.dumps(
                [
                    [path, entry[0], entry[1], entry[2]]
                    for path in sorted(profile)
                    for entry in profile[path]
                ],
                separators=(",", ":"),
            ).encode()
        ).hexdigest(),
        "sha": revision,
        "t": hashlib.sha256("\0".join(test_ids).encode()).hexdigest(),
        "v": 1,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    args.output.write_bytes(gzip.compress(raw, compresslevel=9, mtime=0))
    print(
        f"wrote {sum(map(len, profile.values()))} function entries: "
        + ", ".join(f"{key}={value}" for key, value in sorted(states.items()))
    )


if __name__ == "__main__":
    main()
