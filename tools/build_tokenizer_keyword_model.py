#!/usr/bin/env python3
"""Build the disconnected v0 zero-retrieval Tokenizer KEYWORDS model."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from collect_tokenizer_keyword_values import (
    BASE_IMAGE,
    COLLECTOR_DOCKERFILE,
    CORE_PATH,
    EXACT_TEST_COUNT,
    INVOCATION_ENVIRONMENT,
    PINNED_SHA,
    REVIEWED_CORE_SHA256,
    REVIEWED_INVENTORY_SHA256,
    REVIEWED_OPERATIONS_SHA256,
    REVIEWED_PYTEST_PLUGINS,
    REVIEWED_SOURCE_TREE_SHA256,
    REVIEWED_STATIC_SHA256,
    TESTS_SHA256,
    TOKEN,
    TRACKER_VERSION,
    canonical_process_logs,
    clean_environment,
    file_digest,
    instrument_core,
    json_digest,
    keyword_inventory,
    materialize_tracked_source,
    python_environment,
    replay_raw_bundle,
    retrieval_operations,
    static_contract,
    synchronous_worker_tests,
    tree_digest,
    tracked_manifest,
    validate_environment_document,
    validate_reviewed_source,
)
from tokenizer_keyword_signature import PUBLIC_KEY_SHA256, verify_signature


MODEL_VERSION = 0
COMMON_FIELDS = {
    "base_image", "builder_sha256", "collection_argv",
    "collection_argv_sha256", "collector_sha256", "core_origin_verified",
    "core_sha256", "dependency_sha256", "dockerfile_sha256",
    "executed_digest", "finalizer_sha256", "image_id",
    "instrumented_tree_sha256", "inventory_sha256",
    "lifecycle_dependency_sha256", "mode", "operations_sha256", "python",
    "class_attribute_dependency_sha256",
    "python_environment", "python_environment_sha256", "pytest_args_sha256",
    "pytest_plugins", "reflection_sha256", "requirements_sha256",
    "selector_model_sha256", "sentry_count", "sentry_sha256", "source_sha",
    "source_tree_sha256", "static_sha256", "support_sha256", "test_digest",
    "tests_sha256", "tracker_version", "signature_module_sha256",
    "signer_sha256", "review_public_key_sha256", "tracked_entries",
    "source_archive_sha256", "materialized_manifest_sha256",
    "base_materialized_tree_sha256", "mode_source_tree_sha256",
    "raw_bundle_sha256", "raw_bundle_size",
}
TRACE_FIELDS = COMMON_FIELDS | {"events"}
MANIFEST_FIELDS = COMMON_FIELDS | {
    "child_complete", "child_completions", "child_logs", "child_processes",
    "child_starts", "child_tokens_sha256", "core_class_module",
    "core_origin_suffix", "exitstatus", "sqlglotc_spec", "tests",
    "trace_sha256",
}
INDEX_FIELDS = {"schema", "purpose", "artifacts", "collection_argv", "pins"}
INDEX_PIN_FIELDS = {
    "base_image", "builder_sha256", "collector_sha256", "core_sha256",
    "dependency_sha256", "dockerfile_sha256", "executed_digest",
    "finalizer_sha256", "image_id", "inventory_sha256",
    "lifecycle_dependency_sha256", "operations_sha256",
    "class_attribute_dependency_sha256",
    "python_environment_sha256", "reflection_sha256", "requirements_sha256",
    "selector_model_sha256", "source_sha", "source_tree_sha256",
    "static_sha256", "support_sha256", "test_digest", "tests_sha256",
    "tracker_version",
    "source_archive_sha256", "tracked_entries",
    "materialized_manifest_sha256", "base_materialized_tree_sha256",
    "review_public_key_sha256", "signature_module_sha256", "signer_sha256",
}


def is_hex64(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def load_signed_index(
    index_path: Path, signature_path: Path, *, targeted_smoke: bool
) -> dict:
    raw = index_path.read_bytes()
    index = json.loads(raw)
    public_key = Path(__file__).with_name("tokenizer_keyword_review_public.pem")
    if (
        not isinstance(index, dict)
        or set(index) != INDEX_FIELDS
        or index.get("schema") != 1
        or index.get("purpose")
        != ("targeted-smoke" if targeted_smoke else "full")
        or not isinstance(index.get("artifacts"), dict)
        or set(index["artifacts"]) != {"normal", "synchronous-worker"}
        or not isinstance(index.get("collection_argv"), dict)
        or set(index["collection_argv"]) != {"normal", "synchronous-worker"}
        or not isinstance(index.get("pins"), dict)
        or set(index["pins"]) != INDEX_PIN_FIELDS
    ):
        raise SystemExit("missing or malformed evidence index")
    verify_signature(index_path, signature_path, public_key)
    for mode, artifact in index["artifacts"].items():
        if (
            not isinstance(artifact, dict)
            or set(artifact) != {
                "trace_sha256", "trace_size", "manifest_sha256", "manifest_size",
                "bundle_sha256", "bundle_size",
            }
            or not is_hex64(artifact.get("trace_sha256"))
            or not is_hex64(artifact.get("manifest_sha256"))
            or type(artifact.get("trace_size")) is not int
            or artifact["trace_size"] <= 0
            or type(artifact.get("manifest_size")) is not int
            or artifact["manifest_size"] <= 0
            or not is_hex64(artifact.get("bundle_sha256"))
            or type(artifact.get("bundle_size")) is not int
            or artifact["bundle_size"] <= 0
        ):
            raise SystemExit(f"malformed trust-root artifact for {mode}")
    for mode, command in index["collection_argv"].items():
        if (
            not isinstance(command, list)
            or not command
            or any(type(argument) is not str for argument in command)
        ):
            raise SystemExit(f"malformed trust-root argv for {mode}")
    pins = index["pins"]
    hash_fields = INDEX_PIN_FIELDS - {
        "base_image", "image_id", "source_sha", "tracker_version", "tracked_entries"
    }
    if (
        pins.get("base_image") != BASE_IMAGE
        or type(pins.get("image_id")) is not str
        or not pins["image_id"].startswith("sha256:")
        or not is_hex64(pins["image_id"].removeprefix("sha256:"))
        or pins.get("source_sha") != PINNED_SHA
        or pins.get("tracker_version") != TRACKER_VERSION
        or type(pins.get("tracked_entries")) is not int
        or pins["tracked_entries"] <= 0
        or any(not is_hex64(pins.get(field)) for field in hash_fields)
    ):
        raise SystemExit("malformed trust-root provenance pins")
    return index


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--trace", type=Path, action="append", required=True)
    parser.add_argument("--manifest", type=Path, action="append", required=True)
    parser.add_argument("--bundle", type=Path, action="append", required=True)
    parser.add_argument("--evidence-index", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--targeted-smoke", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def deterministic_payload(model: dict) -> bytes:
    raw = json.dumps(model, sort_keys=True, separators=(",", ":")).encode()
    return gzip.compress(raw, compresslevel=9, mtime=0)


def expected_support_digest() -> str:
    from collect_tokenizer_keyword_values import PLUGIN, RESERVED, TRACKER, file_set_digest

    files = {
        "_br_tokenizer_keyword_tracker.py": TRACKER.replace("__RESERVED__", RESERVED).encode(),
        "tokenizer_keyword_plugin.py": PLUGIN.encode(),
        "sitecustomize.py": b"import _br_tokenizer_keyword_tracker\n",
    }
    digest = hashlib.sha256()
    for name, content in sorted(files.items()):
        encoded = name.encode()
        digest.update(len(encoded).to_bytes(8, "big")); digest.update(encoded)
        digest.update(len(content).to_bytes(8, "big")); digest.update(content)
    return digest.hexdigest()


def expected_instrumented_tree(
    source: Path, operations: list[list[object]], *, synchronous: bool
) -> dict[str, str]:
    with tempfile.TemporaryDirectory(prefix="br-tokenizer-keyword-build-") as temporary:
        work = Path(temporary) / "source"
        materialization = materialize_tracked_source(source, work)
        base = tree_digest(work)
        if synchronous:
            synchronous_worker_tests(work)
        mode_tree = tree_digest(work)
        core = work / CORE_PATH
        core.write_text(instrument_core(core.read_text(), operations))
        return {
            "base": base,
            "mode": mode_tree,
            "instrumented": tree_digest(work),
            "archive": str(materialization["archive_sha256"]),
            "materialized": str(materialization["materialized_manifest_sha256"]),
        }


def zero_retrieval_states(
    keys: set[str], events_by_mode: dict[str, dict[str, list[str]]]
) -> tuple[dict[str, str], bool]:
    """Classify only absence of every first retrieval as safe."""
    global_poison = any(
        "__NON_STRING__" in events for events in events_by_mode.values()
    )
    observed = set()
    poisoned = set()
    for events in events_by_mode.values():
        for key, owners in events.items():
            if key == "__NON_STRING__":
                continue
            if set(owners) & {"__IMPORT__", "__NO_TEST__"}:
                poisoned.add(key)
            else:
                observed.add(key)
    states = {
        key: (
            "poison"
            if global_poison or key in poisoned
            else "observed" if key in observed
            else "safe-zero"
        )
        for key in keys
    }
    return states, global_poison


def validate_process_manifest(
    manifest: dict, trace_path: Path, expected_tests: list[str]
) -> list[list[object]]:
    processes = manifest.get("child_processes")
    if (
        manifest.get("exitstatus") != 0
        or manifest.get("tests") != expected_tests
        or manifest.get("child_complete") is not True
        or type(manifest.get("child_starts")) is not int
        or manifest.get("child_starts", 0) <= 0
        or manifest.get("child_starts") != manifest.get("child_logs")
        or manifest.get("child_starts") != manifest.get("child_completions")
        or not isinstance(processes, list)
        or len(processes) != manifest.get("child_starts")
    ):
        raise SystemExit("incomplete process/test census")
    if any(
        not isinstance(process, list)
        or len(process) != 2
        or type(process[0]) is not str
        or TOKEN.fullmatch(process[0]) is None
        or type(process[1]) is not int
        or process[1] <= 0
        or not process[0].startswith(f"{process[1]}-")
        for process in processes
    ):
        raise SystemExit("malformed process identity")
    if (
        processes != sorted(processes)
        or len({process[0] for process in processes}) != len(processes)
        or not is_hex64(manifest.get("child_tokens_sha256"))
        or manifest.get("child_tokens_sha256")
        != hashlib.sha256("\0".join(process[0] for process in processes).encode()).hexdigest()
        or not is_hex64(manifest.get("trace_sha256"))
        or manifest.get("trace_sha256") != file_digest(trace_path)
        or manifest.get("core_origin_suffix") != "/sqlglot/tokenizer_core.py"
        or manifest.get("core_class_module") != "sqlglot.tokenizer_core"
        or manifest.get("sqlglotc_spec") is not None
    ):
        raise SystemExit("invalid process/test provenance")
    return processes


def validate_evidence_schema(trace: object, manifest: object) -> None:
    if (
        not isinstance(trace, dict)
        or set(trace) != TRACE_FIELDS
        or not isinstance(manifest, dict)
        or set(manifest) != MANIFEST_FIELDS
    ):
        raise SystemExit("unknown or missing evidence fields")


def pytest_args_from_argv(argv: object) -> list[str]:
    if not isinstance(argv, list) or not argv or any(type(item) is not str for item in argv):
        raise SystemExit("malformed signed collection argv")
    separators = [index for index, item in enumerate(argv) if item == "--"]
    if len(separators) > 1:
        raise SystemExit("ambiguous signed collection argv")
    return argv[separators[0] + 1:] if separators else []


def load_evidence(
    traces: list[Path],
    manifests: list[Path],
    bundles: list[Path],
    evidence_index: Path,
    signature: Path,
    *,
    targeted_smoke: bool,
    source: Path,
    test_ids: list[str],
    executed: set[str],
    inventory_sha: str,
    static_sha: str,
    operations_sha: str,
) -> tuple[dict[str, dict[str, list[str]]], dict]:
    if len(traces) != 2 or len(manifests) != 2 or len(bundles) != 2:
        raise SystemExit("exactly two traces, manifests, and bundles are required")
    index = load_signed_index(
        evidence_index, signature, targeted_smoke=targeted_smoke
    )
    trace_by_mode = {}
    manifest_by_mode = {}
    for path in traces:
        document = json.loads(path.read_text())
        mode = document.get("mode") if isinstance(document, dict) else None
        if mode in trace_by_mode or mode not in {"normal", "synchronous-worker"}:
            raise SystemExit("duplicate/invalid trace mode")
        trace_by_mode[mode] = (path, document)
    for path in manifests:
        document = json.loads(path.read_text())
        mode = document.get("mode") if isinstance(document, dict) else None
        if mode in manifest_by_mode or mode not in {"normal", "synchronous-worker"}:
            raise SystemExit("duplicate/invalid manifest mode")
        manifest_by_mode[mode] = (path, document)
    bundle_by_mode = {}
    for path in bundles:
        document = json.loads(path.read_text())
        mode = document.get("mode") if isinstance(document, dict) else None
        if mode in bundle_by_mode or mode not in {"normal", "synchronous-worker"}:
            raise SystemExit("duplicate/invalid raw bundle mode")
        bundle_by_mode[mode] = path
    if (
        set(trace_by_mode) != {"normal", "synchronous-worker"}
        or set(manifest_by_mode) != set(trace_by_mode)
        or set(bundle_by_mode) != set(trace_by_mode)
    ):
        raise SystemExit("both exact modes are mandatory")

    repository = Path(__file__).resolve().parents[1]
    expected_trees = {
        "normal": expected_instrumented_tree(source, retrieval_operations(source), synchronous=False),
        "synchronous-worker": expected_instrumented_tree(
            source, retrieval_operations(source), synchronous=True
        ),
    }
    if (
        expected_trees["normal"]["base"]
        != expected_trees["synchronous-worker"]["base"]
        or expected_trees["normal"]["archive"]
        != expected_trees["synchronous-worker"]["archive"]
        or expected_trees["normal"]["materialized"]
        != expected_trees["synchronous-worker"]["materialized"]
    ):
        raise SystemExit("non-deterministic tracked source materialization")
    expected_common = {
        "collector_sha256": file_digest(Path(__file__).with_name("collect_tokenizer_keyword_values.py")),
        "builder_sha256": file_digest(Path(__file__)),
        "finalizer_sha256": file_digest(
            Path(__file__).with_name("finalize_tokenizer_keyword_evidence.py")
        ),
        "signature_module_sha256": file_digest(
            Path(__file__).with_name("tokenizer_keyword_signature.py")
        ),
        "signer_sha256": file_digest(
            Path(__file__).with_name("sign_tokenizer_keyword_evidence.py")
        ),
        "review_public_key_sha256": file_digest(
            Path(__file__).with_name("tokenizer_keyword_review_public.pem")
        ),
        "dependency_sha256": file_digest(Path(__file__).with_name("collect_dict_access.py")),
        "lifecycle_dependency_sha256": file_digest(
            Path(__file__).with_name("build_tokenizer_setting_flow.py")
        ),
        "class_attribute_dependency_sha256": file_digest(
            Path(__file__).with_name("collect_class_attribute_reads.py")
        ),
        "requirements_sha256": file_digest(repository / "requirements.lock"),
        "reflection_sha256": file_digest(repository / "code_reflection_model.json.gz"),
        "selector_model_sha256": file_digest(repository / "selector_model.json.gz"),
        "core_sha256": REVIEWED_CORE_SHA256,
        "inventory_sha256": inventory_sha,
        "static_sha256": static_sha,
        "operations_sha256": operations_sha,
        "image_id": index["pins"]["image_id"],
        "base_image": BASE_IMAGE,
        "dockerfile_sha256": file_digest(repository / COLLECTOR_DOCKERFILE),
        "source_sha": PINNED_SHA,
        "source_tree_sha256": REVIEWED_SOURCE_TREE_SHA256,
        "tracked_entries": len(tracked_manifest(source)),
        "source_archive_sha256": expected_trees["normal"]["archive"],
        "materialized_manifest_sha256": expected_trees["normal"]["materialized"],
        "base_materialized_tree_sha256": expected_trees["normal"]["base"],
        "test_digest": hashlib.sha256("\0".join(test_ids).encode()).hexdigest(),
        "tests_sha256": TESTS_SHA256,
        "tracker_version": TRACKER_VERSION,
        "support_sha256": expected_support_digest(),
        "core_origin_verified": True,
    }
    events_by_mode = {}
    environment_document = None
    plugin_document = None
    run_tests_document = None
    bound = {}
    for mode in ("normal", "synchronous-worker"):
        trace_path, trace = trace_by_mode[mode]
        manifest_path, manifest = manifest_by_mode[mode]
        bundle_path = bundle_by_mode[mode]
        artifact = index["artifacts"][mode]
        validate_evidence_schema(trace, manifest)
        if (
            file_digest(trace_path) != artifact["trace_sha256"]
            or trace_path.stat().st_size != artifact["trace_size"]
            or file_digest(manifest_path) != artifact["manifest_sha256"]
            or manifest_path.stat().st_size != artifact["manifest_size"]
            or file_digest(bundle_path) != artifact["bundle_sha256"]
            or bundle_path.stat().st_size != artifact["bundle_size"]
        ):
            raise SystemExit(f"{mode} evidence bytes/schema disagree with trust root")
        if any(trace[key] != manifest[key] for key in COMMON_FIELDS):
            raise SystemExit(f"trace/manifest mismatch in {mode}")
        if any(trace.get(field) != value for field, value in index["pins"].items()):
            raise SystemExit(f"{mode} trace disagrees with trust-root pins")
        manifest_tests = manifest.get("tests")
        if (
            not isinstance(manifest_tests, list)
            or not manifest_tests
            or manifest_tests != sorted(set(manifest_tests))
            or any(type(test) is not str or test not in executed for test in manifest_tests)
            or (not targeted_smoke and set(manifest_tests) != executed)
            or (targeted_smoke and set(manifest_tests) == executed)
            or (run_tests_document is not None and manifest_tests != run_tests_document)
        ):
            raise SystemExit(f"inadmissible executed test set in {mode}")
        run_tests_document = manifest_tests
        run_set = set(manifest_tests)
        pytest_arguments = pytest_args_from_argv(index["collection_argv"][mode])
        if targeted_smoke != bool(pytest_arguments):
            raise SystemExit("signed pytest argv disagrees with evidence purpose")
        if (
            trace.get("mode") != mode
            or trace.get("collector_sha256") != expected_common["collector_sha256"]
            or trace.get("builder_sha256") != expected_common["builder_sha256"]
            or trace.get("finalizer_sha256") != expected_common["finalizer_sha256"]
            or trace.get("dependency_sha256") != expected_common["dependency_sha256"]
            or trace.get("lifecycle_dependency_sha256")
            != expected_common["lifecycle_dependency_sha256"]
            or trace.get("class_attribute_dependency_sha256")
            != expected_common["class_attribute_dependency_sha256"]
            or trace.get("requirements_sha256") != expected_common["requirements_sha256"]
            or trace.get("reflection_sha256") != expected_common["reflection_sha256"]
            or trace.get("selector_model_sha256") != expected_common["selector_model_sha256"]
            or trace.get("core_sha256") != expected_common["core_sha256"]
            or trace.get("inventory_sha256") != inventory_sha
            or trace.get("static_sha256") != static_sha
            or trace.get("operations_sha256") != operations_sha
            or trace.get("source_sha") != PINNED_SHA
            or trace.get("source_tree_sha256") != expected_common["source_tree_sha256"]
            or trace.get("tracked_entries") != expected_common["tracked_entries"]
            or trace.get("source_archive_sha256") != expected_common["source_archive_sha256"]
            or trace.get("materialized_manifest_sha256")
            != expected_common["materialized_manifest_sha256"]
            or trace.get("base_materialized_tree_sha256")
            != expected_common["base_materialized_tree_sha256"]
            or trace.get("mode_source_tree_sha256") != expected_trees[mode]["mode"]
            or trace.get("test_digest") != expected_common["test_digest"]
            or trace.get("executed_digest")
            != hashlib.sha256("\0".join(manifest_tests).encode()).hexdigest()
            or trace.get("tests_sha256") != TESTS_SHA256
            or trace.get("pytest_args_sha256")
            != hashlib.sha256(
                json.dumps(pytest_arguments, separators=(",", ":")).encode()
            ).hexdigest()
            or trace.get("support_sha256") != expected_common["support_sha256"]
            or trace.get("signature_module_sha256")
            != expected_common["signature_module_sha256"]
            or trace.get("signer_sha256") != expected_common["signer_sha256"]
            or trace.get("review_public_key_sha256") != PUBLIC_KEY_SHA256
            or trace.get("image_id") != expected_common["image_id"]
            or trace.get("base_image") != expected_common["base_image"]
            or trace.get("dockerfile_sha256") != expected_common["dockerfile_sha256"]
            or trace.get("instrumented_tree_sha256")
            != expected_trees[mode]["instrumented"]
            or trace.get("raw_bundle_sha256") != artifact["bundle_sha256"]
            or trace.get("raw_bundle_size") != artifact["bundle_size"]
            or trace.get("tracker_version") != TRACKER_VERSION
            or trace.get("core_origin_verified") is not True
            or type(trace.get("python")) is not str
            or not trace["python"].startswith("3.13.")
            or trace.get("collection_argv") != index["collection_argv"][mode]
            or trace.get("collection_argv_sha256")
            != json_digest(index["collection_argv"][mode])
            or not isinstance(trace.get("pytest_plugins"), list)
            or not trace["pytest_plugins"]
            or any(type(name) is not str or not name for name in trace["pytest_plugins"])
            or tuple(trace["pytest_plugins"]) != REVIEWED_PYTEST_PLUGINS
            or type(trace.get("sentry_count")) is not int
            or trace["sentry_count"] < 2 * len(run_set) + 1
            or not is_hex64(trace.get("sentry_sha256"))
        ):
            raise SystemExit(f"inadmissible trace provenance in {mode}")
        current_environment = trace.get("python_environment")
        if (
            not validate_environment_document(current_environment)
            or trace.get("python_environment_sha256") != json_digest(current_environment)
            or trace.get("python_environment_sha256")
            != index["pins"]["python_environment_sha256"]
            or trace.get("python") != current_environment.get("version")
            or (
                environment_document is not None
                and current_environment != environment_document
            )
        ):
            raise SystemExit(f"collection environment mismatch in {mode}")
        environment_document = current_environment
        if plugin_document is not None and trace["pytest_plugins"] != plugin_document:
            raise SystemExit("pytest plugin inventory differs across modes")
        plugin_document = trace["pytest_plugins"]
        try:
            processes = validate_process_manifest(
                manifest, trace_path, manifest_tests
            )
        except SystemExit as error:
            raise SystemExit(f"incomplete lifecycle/test census in {mode}: {error}") from error
        events = trace.get("events")
        if not isinstance(events, dict):
            raise SystemExit("malformed event map")
        for key, owners in events.items():
            if (
                type(key) is not str
                or not isinstance(owners, list)
                or owners != sorted(set(owners))
                or any(owner not in run_set | {"__IMPORT__", "__NO_TEST__"} for owner in owners)
            ):
                raise SystemExit("malformed event owner")
            if key == "__NON_STRING__":
                pass
        events_by_mode[mode] = events
        with tempfile.TemporaryDirectory(prefix="br-keyword-replay-") as temporary:
            replay_mode, children, pytest_manifest = replay_raw_bundle(
                bundle_path, Path(temporary) / "replay"
            )
            raw_pytest = json.loads(pytest_manifest.read_text())
            if (
                replay_mode != mode
                or not isinstance(raw_pytest, dict)
                or set(raw_pytest) != {
                    "exitstatus", "tests", "pytest_plugins", "core_origin",
                    "core_class_module", "sqlglotc_spec",
                }
                or raw_pytest.get("exitstatus") != 0
                or raw_pytest.get("tests") != manifest_tests
                or raw_pytest.get("pytest_plugins") != trace["pytest_plugins"]
                or raw_pytest.get("core_class_module") != manifest["core_class_module"]
                or raw_pytest.get("sqlglotc_spec") is not None
                or type(raw_pytest.get("core_origin")) is not str
                or not raw_pytest["core_origin"].endswith(manifest["core_origin_suffix"])
            ):
                raise SystemExit(f"raw pytest manifest disagrees in {mode}")
            replay_events, replay_sentries, replay_processes = canonical_process_logs(
                children,
                run_set,
                trace["python_environment_sha256"],
                str(trace["python_environment"]["executable"]),
                trace["python"],
                raw_pytest["core_origin"],
            )
            if (
                replay_events != events
                or replay_processes != processes
                or len(replay_sentries) != trace["sentry_count"]
                or json_digest(replay_sentries) != trace["sentry_sha256"]
            ):
                raise SystemExit(f"raw lifecycle replay disagrees in {mode}")
        bound[mode] = {
            "trace_sha256": file_digest(trace_path),
            "manifest_sha256": file_digest(manifest_path),
            "bundle_sha256": file_digest(bundle_path),
            "child_starts": manifest["child_starts"],
            "child_tokens_sha256": manifest.get("child_tokens_sha256"),
            "instrumented_tree_sha256": trace.get("instrumented_tree_sha256"),
        }
    recomputed_environment = python_environment(
        Path(sys.executable).resolve(), clean_environment(Path(sys.executable).resolve())
    )
    if recomputed_environment != environment_document:
        raise SystemExit("builder interpreter/toolchain environment differs from collection")
    return events_by_mode, {
        "common": expected_common,
        "evidence_index_sha256": file_digest(evidence_index),
        "python_environment": environment_document,
        "python_environment_sha256": json_digest(environment_document),
        "modes": bound,
        "purpose": index["purpose"],
    }


def main() -> None:
    args = arguments()
    if dict(os.environ) != INVOCATION_ENVIRONMENT:
        raise SystemExit("builder invocation environment is not the exact allowlist")
    source = args.source.resolve()
    validate_reviewed_source(source)
    revision = subprocess.check_output(
        ["git", "-c", f"safe.directory={source}", "-C", str(source), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    if revision != PINNED_SHA:
        raise SystemExit("wrong source revision")
    tests_raw = args.tests.read_bytes()
    if hashlib.sha256(tests_raw).hexdigest() != TESTS_SHA256:
        raise SystemExit("wrong tests manifest")
    test_document = json.loads(tests_raw)
    test_ids = [test["id"] for test in test_document["tests"]]
    skipped = set(test_document.get("skipped", ()))
    if len(test_ids) != EXACT_TEST_COUNT or len(set(test_ids)) != EXACT_TEST_COUNT or len(skipped) != 1:
        raise SystemExit("wrong scored/skipped census")
    executed = set(test_ids) | skipped
    inventory = keyword_inventory(source)
    contract = static_contract(source)
    operations = retrieval_operations(source)
    if (
        json_digest(tracked_manifest(source)) != REVIEWED_SOURCE_TREE_SHA256
        or file_digest(source / CORE_PATH) != REVIEWED_CORE_SHA256
        or json_digest(inventory) != REVIEWED_INVENTORY_SHA256
        or json_digest(contract) != REVIEWED_STATIC_SHA256
        or json_digest(operations) != REVIEWED_OPERATIONS_SHA256
    ):
        raise SystemExit("reviewed source/static contract mismatch")
    events_by_mode, evidence = load_evidence(
        args.trace,
        args.manifest,
        args.bundle,
        args.evidence_index,
        args.signature,
        targeted_smoke=args.targeted_smoke,
        source=source,
        test_ids=test_ids,
        executed=executed,
        inventory_sha=json_digest(inventory),
        static_sha=json_digest(contract),
        operations_sha=json_digest(operations),
    )
    if args.targeted_smoke:
        states = {record[5]: "targeted-smoke-unknown" for record in inventory}
        global_poison = False
    else:
        states, global_poison = zero_retrieval_states(
            {record[5] for record in inventory}, events_by_mode
        )
    evidence["global_poison"] = global_poison
    evidence["event_maps_sha256"] = json_digest(events_by_mode)
    data = []
    for record in inventory:
        key = record[5]
        data.append([*record, states[key]])
    safe_keys = sorted({record[5] for record in data if record[-1] == "safe-zero"})
    model = {
        "v": MODEL_VERSION,
        "status": (
            "TARGETED-SMOKE/NO-SHIP"
            if args.targeted_smoke
            else "READY-FOR-AUDIT/NO-SHIP"
        ),
        "sha": PINNED_SHA,
        "n": len(test_ids),
        "t": hashlib.sha256("\0".join(test_ids).encode()).hexdigest(),
        "d": data,
        "safe_keys": safe_keys,
        "inventory": json_digest(inventory),
        "static": {"sha256": json_digest(contract), "document": contract},
        "operations": {"sha256": json_digest(operations), "document": operations},
        "evidence": evidence,
        "builder_sha256": file_digest(Path(__file__)),
    }
    args.output.write_bytes(deterministic_payload(model))
    print(
        f"{model['status']}: {len(safe_keys)} zero-retrieval keys / 616"
    )


if __name__ == "__main__":
    main()
