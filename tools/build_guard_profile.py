#!/usr/bin/env python3
"""Build a deterministic per-test guard profile from two complete trace modes."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path

from collect_guard_observations import (
    canonical_digest,
    copy_tracked_tree,
    generated_support_digest,
    git_tracked_paths,
    materialized_digest,
    sensitive_test_files,
    synchronous_worker_tests,
)
from guard_profile_common import STATE_NAMES, source_sites


PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, action="append", required=True)
    parser.add_argument("--trace", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def bitset(owners: set[str], indices: dict[str, int]) -> str:
    value = 0
    for owner in owners:
        if owner in indices:
            value |= 1 << indices[owner]
    return format(value, "x")


def load_pairs(manifests: list[Path], traces: list[Path]) -> dict[str, tuple[dict, dict]]:
    if len(manifests) != len(traces) or len(manifests) < 2:
        raise SystemExit("matching normal and synchronous trace/manifest pairs are required")
    pairs = {}
    for manifest_path, trace_path in zip(manifests, traces):
        manifest = json.loads(manifest_path.read_text())
        raw = trace_path.read_text()
        trace = json.loads(raw)
        mode = manifest.get("mode")
        if mode in pairs or mode not in {"normal", "synchronous-worker"}:
            raise SystemExit(f"invalid or duplicate mode in {manifest_path}")
        if hashlib.sha256(raw.encode()).hexdigest() != manifest.get("trace_sha256"):
            raise SystemExit(f"trace digest mismatch for {trace_path}")
        if trace.get("meta") != {
            key: manifest.get(key)
            for key in (
                "collector_sha256", "common_sha256", "environment_sha256",
                "executed_materialized_sha256", "instrumented", "materialized_sha256", "mode", "python",
                "runtime_image", "sensitive_files_sha256", "source_sha",
                "source_tree", "test_digest", "support_sha256", "worker_transform_sha256",
            )
        }:
            raise SystemExit(f"trace/manifest metadata mismatch for {mode}")
        pairs[mode] = manifest, trace
    if set(pairs) != {"normal", "synchronous-worker"}:
        raise SystemExit("both normal and synchronous-worker traces are required")
    return pairs


def main() -> None:
    args = arguments()
    source = args.source.resolve()
    revision = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    if revision != PINNED_SHA:
        raise SystemExit(f"source is {revision}, expected {PINNED_SHA}")
    tracked_status = subprocess.check_output(
        ["git", "-C", str(source), "status", "--porcelain=v1", "--untracked-files=no"],
        text=True,
    )
    if tracked_status:
        raise SystemExit("source has staged or unstaged tracked changes")
    source_tree = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD^{tree}"], text=True
    ).strip()
    tests = json.loads(args.tests.read_text())["tests"]
    test_ids = [test["id"] for test in tests]
    if (
        any(type(test_id) is not str for test_id in test_ids)
        or len(test_ids) != len(set(test_ids))
    ):
        raise SystemExit("test manifest IDs must be unique strings")
    indices = {test_id: index for index, test_id in enumerate(test_ids)}
    expected = set(test_ids)
    test_digest = hashlib.sha256("\0".join(test_ids).encode()).hexdigest()
    pairs = load_pairs(args.manifest, args.trace)
    tracked = git_tracked_paths(source)
    expected_materialized = materialized_digest(source, tracked)
    expected_sensitive = canonical_digest(sensitive_test_files(source, tracked))
    with tempfile.TemporaryDirectory(prefix="blast-radius-guard-build-") as temporary:
        synchronous_work = Path(temporary) / "sqlglot"
        copy_tracked_tree(source, synchronous_work, tracked)
        synchronous_worker_tests(synchronous_work)
        expected_executed = {
            "normal": expected_materialized,
            "synchronous-worker": materialized_digest(synchronous_work, tracked),
        }

    metadata_values = defaultdict(set)
    for mode, (manifest, trace) in pairs.items():
        manifest_tests = manifest.get("tests")
        if (
            manifest.get("exitstatus") != 0
            or manifest.get("child_complete") is not True
            or manifest.get("pool_task_complete") is not True
            or not isinstance(manifest_tests, list)
            or any(type(test_id) is not str for test_id in manifest_tests)
            or manifest_tests != sorted(set(manifest_tests))
            or set(manifest_tests) != expected
            or manifest.get("source_sha") != revision
            or manifest.get("source_tree") != source_tree
            or manifest.get("test_digest") != test_digest
            or manifest.get("executed_materialized_sha256") != expected_executed[mode]
            or type(manifest.get("child_logs")) is not int
            or type(manifest.get("child_starts")) is not int
            or manifest.get("child_logs") < 0
            or manifest.get("child_logs") != manifest.get("child_starts")
            or type(manifest.get("pool_task_count")) is not int
            or manifest.get("pool_task_count") < 0
            or not isinstance(manifest.get("pool_task_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", manifest.get("pool_task_sha256", ""))
            or not re.fullmatch(r"[0-9a-f]{64}", manifest.get("trace_sha256", ""))
        ):
            raise SystemExit(f"inadmissible {mode} manifest")
        if mode == "normal" and manifest.get("pool_task_count", 0) <= 0:
            raise SystemExit("normal manifest lacks pool-task evidence")
        if mode == "synchronous-worker" and manifest.get("pool_task_count") != 0:
            raise SystemExit("synchronous manifest contains pool tasks")
        for key in (
            "collector_sha256", "common_sha256", "environment_sha256", "instrumented",
            "materialized_sha256", "python", "runtime_image",
            "sensitive_files_sha256", "support_sha256", "worker_transform_sha256",
        ):
            metadata_values[key].add(manifest.get(key))
        if (
            set(trace) != {"escaped", "events", "meta"}
            or not isinstance(trace.get("events"), dict)
            or not isinstance(trace.get("escaped"), list)
        ):
            raise SystemExit(f"invalid {mode} trace root")
        if trace["escaped"] != sorted(set(trace["escaped"])) or any(
            type(owner) is not str for owner in trace["escaped"]
        ):
            raise SystemExit(f"invalid {mode} escaped owners")
    if any(len(values) != 1 for values in metadata_values.values()):
        raise SystemExit("trace modes do not share one collector/runtime provenance")

    inventory = source_sites(source)
    expected_collector = sha256(Path(__file__).with_name("collect_guard_observations.py"))
    expected_common = sha256(Path(__file__).with_name("guard_profile_common.py"))
    expected_worker_transform = sha256(Path(__file__).with_name("collect_dict_access.py"))
    if (
        metadata_values["collector_sha256"] != {expected_collector}
        or metadata_values["common_sha256"] != {expected_common}
        or metadata_values["support_sha256"] != {generated_support_digest()}
        or metadata_values["materialized_sha256"] != {expected_materialized}
        or metadata_values["sensitive_files_sha256"] != {expected_sensitive}
        or metadata_values["worker_transform_sha256"] != {expected_worker_transform}
        or metadata_values["instrumented"] != {len(inventory)}
        or not all(
            isinstance(value, str) and value.startswith("Python 3.13.")
            for value in metadata_values["python"]
        )
        or not all(
            isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value)
            for value in metadata_values["runtime_image"]
        )
        or not all(
            isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
            for value in metadata_values["environment_sha256"]
        )
    ):
        raise SystemExit("trace provenance does not match this builder/source/runtime")
    merged: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    escaped: set[str] = set()
    for _manifest, trace in pairs.values():
        escaped.update(trace["escaped"])
        for site_label, categories in trace["events"].items():
            if site_label not in inventory or not isinstance(categories, dict):
                raise SystemExit(f"trace contains unknown site {site_label}")
            for category, owners in categories.items():
                if not isinstance(owners, list) or any(type(owner) is not str for owner in owners):
                    raise SystemExit(f"invalid owners for {site_label}:{category}")
                if owners != sorted(set(owners)):
                    raise SystemExit(f"non-canonical owners for {site_label}:{category}")
                merged[site_label][category].update(owners)
    unknown_owners = (
        escaped
        | {
            owner
            for categories in merged.values()
            for owners in categories.values()
            for owner in owners
        }
    ) - expected - {"__NO_TEST__"}
    if unknown_owners:
        raise SystemExit(f"trace contains {len(unknown_owners)} unknown test owners")
    global_escape = "__NO_TEST__" in escaped
    escaped.discard("__NO_TEST__")

    profile: dict[str, list[list]] = defaultdict(list)
    states = defaultdict(int)
    for site_label, site in sorted(inventory.items()):
        categories = merged.get(site_label, {})
        owners = set().union(*categories.values()) if categories else set()
        state = "safe"
        if not categories:
            state = "unobserved"
        elif global_escape or "__NO_TEST__" in owners:
            state = "unattributed"
        expected_categories = (
            {"seen", "unknown", *STATE_NAMES}
            if site["kind"] == "truth"
            else {"seen", "unsafe-eq", "unsafe-ne"}
        )
        if set(categories) - expected_categories:
            state = "malformed"
        seen = set(categories.get("seen", ())) - {"__NO_TEST__"}
        if site["kind"] == "truth":
            unknown = set(categories.get("unknown", ())) - {"__NO_TEST__"}
            observed = set().union(
                *(set(categories.get(name, ())) for name in STATE_NAMES)
            ) - {"__NO_TEST__"}
            if observed | unknown != seen or any(
                not set(categories.get(name, ())) <= set(categories.get("seen", ()))
                for name in ("unknown", *STATE_NAMES)
            ):
                state = "malformed"
            unknown.update(escaped & seen)
            masks = [bitset(seen, indices), bitset(unknown, indices)]
            masks.extend(bitset(set(categories.get(name, ())), indices) for name in STATE_NAMES)
        else:
            unsafe_eq = set(categories.get("unsafe-eq", ())) - {"__NO_TEST__"}
            unsafe_ne = set(categories.get("unsafe-ne", ())) - {"__NO_TEST__"}
            if not unsafe_eq <= seen or not unsafe_ne <= seen:
                state = "malformed"
            unsafe_eq.update(escaped & seen)
            unsafe_ne.update(escaped & seen)
            masks = [bitset(seen, indices), bitset(unsafe_eq, indices), bitset(unsafe_ne, indices)]
        states[state] += 1
        entry = [
            *site["coordinates"], site["kind"], site["form"], site["operand"],
            site.get("side"), state, *masks,
        ]
        profile[site["path"]].append(entry)

    ordered = {
        path: sorted(entries, key=lambda entry: (entry[0], entry[1], entry[4]))
        for path, entries in sorted(profile.items())
    }
    provenance = {
        key: next(iter(values)) for key, values in sorted(metadata_values.items())
    }
    provenance["executed_materialized_sha256"] = {
        mode: manifest["executed_materialized_sha256"]
        for mode, (manifest, _trace) in sorted(pairs.items())
    }
    payload = {
        "d": ordered,
        "n": len(test_ids),
        "provenance": provenance,
        "sha": revision,
        "t": test_digest,
        "tree": source_tree,
        "v": 1,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    args.output.write_bytes(gzip.compress(raw, compresslevel=9, mtime=0))
    print(
        f"wrote {sum(map(len, ordered.values()))} guard sites: "
        + ", ".join(f"{name}={count}" for name, count in sorted(states.items()))
    )


if __name__ == "__main__":
    main()
