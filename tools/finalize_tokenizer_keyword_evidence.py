#!/usr/bin/env python3
"""Create the deterministic unsigned index for KEYWORDS evidence review."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


MODES = {"normal", "synchronous-worker"}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def payload(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trace", type=Path, action="append", required=True)
    parser.add_argument("--manifest", type=Path, action="append", required=True)
    parser.add_argument("--bundle", type=Path, action="append", required=True)
    parser.add_argument(
        "--purpose", choices=("full", "targeted-smoke"), required=True
    )
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def mode_documents(paths: list[Path]) -> dict[str, tuple[Path, dict]]:
    if len(paths) != 2:
        raise SystemExit("exactly two mode artifacts are required")
    result = {}
    for path in paths:
        document = json.loads(path.read_text())
        mode = document.get("mode") if isinstance(document, dict) else None
        if mode not in MODES or mode in result:
            raise SystemExit("duplicate or invalid evidence mode")
        result[mode] = (path.resolve(), document)
    if set(result) != MODES:
        raise SystemExit("normal and synchronous-worker evidence are mandatory")
    return result


def main() -> None:
    args = arguments()
    traces = mode_documents(args.trace)
    manifests = mode_documents(args.manifest)
    bundles = mode_documents(args.bundle)
    artifacts = {}
    commands = {}
    stable = None
    stable_fields = (
        "base_image", "builder_sha256", "collector_sha256", "core_sha256",
        "dependency_sha256", "dockerfile_sha256", "executed_digest",
        "finalizer_sha256", "image_id", "inventory_sha256",
        "lifecycle_dependency_sha256", "operations_sha256",
        "class_attribute_dependency_sha256",
        "python_environment_sha256", "reflection_sha256", "requirements_sha256",
        "selector_model_sha256", "source_sha", "source_tree_sha256",
        "static_sha256", "support_sha256", "test_digest", "tests_sha256",
        "tracker_version", "source_archive_sha256", "tracked_entries",
        "materialized_manifest_sha256", "base_materialized_tree_sha256",
        "review_public_key_sha256", "signature_module_sha256", "signer_sha256",
    )
    for mode in sorted(MODES):
        trace_path, trace = traces[mode]
        manifest_path, manifest = manifests[mode]
        bundle_path, bundle = bundles[mode]
        if manifest.get("trace_sha256") != digest(trace_path):
            raise SystemExit(f"{mode} manifest does not bind trace bytes")
        command = trace.get("collection_argv")
        if (
            not isinstance(command, list)
            or not command
            or any(type(item) is not str for item in command)
            or trace.get("collection_argv_sha256")
            != hashlib.sha256(payload(command)).hexdigest()
        ):
            raise SystemExit(f"{mode} collection argv is invalid")
        commands[mode] = command
        artifacts[mode] = {
            "trace_sha256": digest(trace_path),
            "trace_size": trace_path.stat().st_size,
            "manifest_sha256": digest(manifest_path),
            "manifest_size": manifest_path.stat().st_size,
            "bundle_sha256": digest(bundle_path),
            "bundle_size": bundle_path.stat().st_size,
        }
        if (
            trace.get("raw_bundle_sha256") != artifacts[mode]["bundle_sha256"]
            or trace.get("raw_bundle_size") != artifacts[mode]["bundle_size"]
            or bundle.get("schema") != 1
        ):
            raise SystemExit(f"{mode} trace does not bind its raw bundle")
        current = {field: trace.get(field) for field in stable_fields}
        if any(value is None for value in current.values()):
            raise SystemExit(f"{mode} lacks a trust-root pin")
        if stable is None:
            stable = current
        elif current != stable:
            raise SystemExit("mode evidence disagrees on stable provenance")
    assert stable is not None
    if (
        not re.fullmatch(r"sha256:[0-9a-f]{64}", str(stable["image_id"]))
        or not HEX64.fullmatch(str(stable["python_environment_sha256"]))
    ):
        raise SystemExit("invalid image/environment trust pins")
    index = {
        "schema": 1,
        "purpose": args.purpose,
        "artifacts": artifacts,
        "collection_argv": commands,
        "pins": stable,
    }
    raw = payload(index)
    args.output.write_bytes(raw)
    print(hashlib.sha256(raw).hexdigest())


if __name__ == "__main__":
    main()
