from __future__ import annotations

import ast
import copy
import gzip
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from build_tokenizer_keyword_model import (
    INDEX_PIN_FIELDS,
    MANIFEST_FIELDS,
    TRACE_FIELDS,
    deterministic_payload,
    expected_instrumented_tree,
    expected_support_digest,
    load_signed_index,
    validate_process_manifest,
    validate_evidence_schema,
    zero_retrieval_states,
)
from collect_tokenizer_keyword_values import (
    BASE_IMAGE,
    EXACT_TEST_COUNT,
    INVOCATION_ENVIRONMENT,
    PINNED_SHA,
    RESERVED,
    TESTS_SHA256,
    TRACKER,
    bundle_payload,
    canonical_events,
    canonical_process_logs,
    clean_environment,
    instrument_core,
    keyword_inventory,
    materialize_tracked_source,
    replay_raw_bundle,
    retrieval_operations,
    static_contract,
    validate_environment_document,
)


REPOSITORY = Path(__file__).resolve().parents[1]
PINNED_SOURCE = Path(
    "/home/silverdisk/BuildersHackathon-tokenizer-keyword-source"
)


class TokenizerKeywordStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not PINNED_SOURCE.is_dir():
            raise unittest.SkipTest("pinned SQLGlot checkout is unavailable")

    def test_exact_inventory_and_static_closure(self) -> None:
        inventory = keyword_inventory(PINNED_SOURCE)
        contract = static_contract(PINNED_SOURCE)
        self.assertEqual(len(inventory), 716)
        self.assertEqual(len({record[5] for record in inventory}), 616)
        self.assertEqual(len({(record[0], record[1]) for record in inventory}), 26)
        self.assertEqual(len(contract["reads"]), 31)
        self.assertEqual(len(contract["pops"]), 24)
        self.assertEqual(len(contract["tokenizer_lineage"]), 42)
        self.assertEqual(sum(bool(record[4]) for record in contract["tokenizer_lineage"]), 29)
        self.assertEqual(contract["hazards"], [])
        self.assertEqual(contract["reserved_hits"], [])

    def test_exact_retrieval_rewrite(self) -> None:
        operations = retrieval_operations(PINNED_SOURCE)
        original = (PINNED_SOURCE / "sqlglot/tokenizer_core.py").read_text()
        instrumented = instrument_core(original, operations)
        self.assertEqual(len(operations), 4)
        self.assertEqual(instrumented.count(f"{RESERVED}("), 4)
        self.assertEqual(len(instrumented) - len(original), 4 * (len(RESERVED) + 2))
        ast.parse(instrumented, type_comments=True)

    def test_instrumented_tree_digests_are_reproducible_and_mode_specific(self) -> None:
        operations = retrieval_operations(PINNED_SOURCE)
        normal = expected_instrumented_tree(
            PINNED_SOURCE, operations, synchronous=False
        )
        self.assertEqual(
            normal,
            expected_instrumented_tree(PINNED_SOURCE, operations, synchronous=False),
        )
        synchronous = expected_instrumented_tree(
            PINNED_SOURCE, operations, synchronous=True
        )
        self.assertNotEqual(normal, synchronous)

    def test_exact_scored_and_skipped_manifest(self) -> None:
        raw = (REPOSITORY / "sample/tests.json").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), TESTS_SHA256)
        document = json.loads(raw)
        scored = [item["id"] for item in document["tests"]]
        skipped = set(document.get("skipped", ()))
        self.assertEqual(len(scored), EXACT_TEST_COUNT)
        self.assertEqual(len(set(scored)), EXACT_TEST_COUNT)
        self.assertEqual(len(skipped), 1)
        self.assertTrue(skipped.isdisjoint(scored))

    def test_revision_is_pinned(self) -> None:
        revision = subprocess.check_output(
            [
                "git", "-c", f"safe.directory={PINNED_SOURCE}",
                "-C", str(PINNED_SOURCE), "rev-parse", "HEAD",
            ],
            text=True,
        ).strip()
        self.assertEqual(revision, PINNED_SHA)


class ZeroRetrievalProofTests(unittest.TestCase):
    def test_only_absence_in_both_modes_is_safe(self) -> None:
        states, poison = zero_retrieval_states(
            {"ZERO", "NORMAL", "SYNC", "IMPORT", "OWNERLESS"},
            {
                "normal": {
                    "NORMAL": ["tests/test_a.py::test_a"],
                    "IMPORT": ["__IMPORT__"],
                },
                "synchronous-worker": {
                    "SYNC": ["tests/test_b.py::test_b"],
                    "OWNERLESS": ["__NO_TEST__"],
                },
            },
        )
        self.assertFalse(poison)
        self.assertEqual(states["ZERO"], "safe-zero")
        self.assertEqual(states["NORMAL"], "observed")
        self.assertEqual(states["SYNC"], "observed")
        self.assertEqual(states["IMPORT"], "poison")
        self.assertEqual(states["OWNERLESS"], "poison")

    def test_non_string_query_poison_is_global(self) -> None:
        states, poison = zero_retrieval_states(
            {"A", "B"},
            {"normal": {"__NON_STRING__": ["__NO_TEST__"]}, "synchronous-worker": {}},
        )
        self.assertTrue(poison)
        self.assertEqual(states, {"A": "poison", "B": "poison"})

    def test_exact_model_payload_build_is_byte_repeatable(self) -> None:
        model = {
            "v": 0,
            "status": "READY-FOR-AUDIT/NO-SHIP",
            "safe_keys": ["A"],
            "d": [["sqlglot/example.py", "Tokenizer", 1, 2, 0, "A", "VAR", "ast", "safe-zero"]],
            "evidence": {
                "modes": {
                    "normal": {"trace_sha256": "a" * 64},
                    "synchronous-worker": {"trace_sha256": "b" * 64},
                }
            },
            "nested": {"b": 2, "a": 1},
        }
        first = deterministic_payload(model)
        second = deterministic_payload(copy.deepcopy(model))
        self.assertEqual(first, second)
        self.assertEqual(hashlib.sha256(first).hexdigest(), hashlib.sha256(second).hexdigest())
        self.assertEqual(json.loads(gzip.decompress(first)), model)
        self.assertEqual(expected_support_digest(), expected_support_digest())


class EvidenceValidationTests(unittest.TestCase):
    def test_allowlist_drops_git_loader_pytest_and_tracker_injection(self) -> None:
        poisoned = {
            "GIT_CONFIG_COUNT": "9", "GIT_DIR": "/evil", "GIT_WORK_TREE": "/evil",
            "LD_PRELOAD": "/evil.so", "LD_LIBRARY_PATH": "/evil",
            "PYTHONPATH": "/evil", "PYTEST_ADDOPTS": "-p evil",
            "TOKENIZER_KEYWORD_CHILD_DIR": "/evil", "BR_PARENT_TEST": "fake",
        }
        with mock.patch.dict(os.environ, poisoned, clear=False):
            environment = clean_environment(Path(sys.executable))
        self.assertTrue(set(environment) <= set(INVOCATION_ENVIRONMENT))
        self.assertEqual(environment["PYTHONPATH"], "/work/tools")
        self.assertTrue((set(poisoned) - {"PYTHONPATH"}).isdisjoint(environment))

    def test_git_archive_materialization_binds_root_inputs_and_excludes_ignored(self) -> None:
        with tempfile.TemporaryDirectory(prefix="br-keyword-tree-") as temporary:
            root = Path(temporary)
            source, destination = root / "source", root / "materialized"
            source.mkdir()
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            subprocess.run(["git", "-C", str(source), "config", "user.name", "test"], check=True)
            subprocess.run(["git", "-C", str(source), "config", "user.email", "test@example.invalid"], check=True)
            files = {
                ".gitignore": "*.so\n", "pytest.ini": "[pytest]\n",
                "sitecustomize.py": "raise RuntimeError('tracked and bound')\n",
                "tests/fixture.bin": "fixture\n", "package/code.py": "VALUE = 1\n",
            }
            for name, content in files.items():
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            (source / "ignored.so").write_bytes(b"native injection")
            subprocess.run(["git", "-C", str(source), "add", "."], check=True)
            subprocess.run(["git", "-C", str(source), "commit", "-qm", "fixture"], check=True)
            result = materialize_tracked_source(source, destination)
            self.assertEqual(result["tracked_entries"], len(files))
            self.assertTrue((destination / "pytest.ini").is_file())
            self.assertTrue((destination / "sitecustomize.py").is_file())
            self.assertTrue((destination / "tests/fixture.bin").is_file())
            self.assertFalse((destination / "ignored.so").exists())

    def test_raw_bundle_tamper_traversal_duplicate_and_noncanonical_reject(self) -> None:
        mode = "normal"
        valid = bundle_payload(
            mode,
            [
                ("pytest-manifest.json", b"{}"),
                ("children/1-1.started", b"{}"),
            ],
        )
        with tempfile.TemporaryDirectory(prefix="br-keyword-bundle-") as temporary:
            root = Path(temporary)
            bundle = root / "bundle.json"
            bundle.write_bytes(valid)
            replay_mode, _children, _manifest = replay_raw_bundle(bundle, root / "ok")
            self.assertEqual(replay_mode, mode)
            document = json.loads(valid)
            attacks = []
            tampered = copy.deepcopy(document)
            tampered["files"][0][3] = "e30K"
            attacks.append(tampered)
            traversal = copy.deepcopy(document)
            traversal["files"][0][0] = "../pytest-manifest.json"
            attacks.append(traversal)
            duplicate = copy.deepcopy(document)
            duplicate["files"].append(copy.deepcopy(duplicate["files"][0]))
            attacks.append(duplicate)
            reversed_records = copy.deepcopy(document)
            reversed_records["files"].reverse()
            attacks.append(reversed_records)
            for index, attack in enumerate(attacks):
                with self.subTest(index=index):
                    candidate = root / f"attack-{index}.json"
                    candidate.write_text(json.dumps(attack, separators=(",", ":")))
                    with self.assertRaises(SystemExit):
                        replay_raw_bundle(candidate, root / f"bad-{index}")

    def test_unknown_and_missing_trace_manifest_fields_reject(self) -> None:
        trace = {field: None for field in TRACE_FIELDS}
        manifest = {field: None for field in MANIFEST_FIELDS}
        validate_evidence_schema(trace, manifest)
        for target, mutation in (
            (trace, lambda value: value.update({"unknown": 1})),
            (trace, lambda value: value.pop("events")),
            (manifest, lambda value: value.update({"unknown": 1})),
            (manifest, lambda value: value.pop("tests")),
        ):
            with self.subTest(mutation=mutation):
                changed_trace = copy.deepcopy(trace)
                changed_manifest = copy.deepcopy(manifest)
                changed = changed_trace if target is trace else changed_manifest
                mutation(changed)
                with self.assertRaises(SystemExit):
                    validate_evidence_schema(changed_trace, changed_manifest)

    def test_minimal_and_malformed_environment_documents_reject(self) -> None:
        minimal = {
            "implementation": "CPython",
            "version": "3.13.FABRICATED",
            "pytest_environment": {},
        }
        self.assertFalse(validate_environment_document(minimal))
        valid = {
            "implementation": "CPython",
            "version": "3.13.11 (main)",
            "executable": "/usr/local/bin/python",
            "prefix": "/usr/local",
            "base_prefix": "/usr/local",
            "distributions": [["pytest", "9.0.1"]],
            "entry_points": [["pytest11", "example", "module", "pytest"]],
            "pytest_environment": {
                "PYTEST_ADDOPTS": None,
                "PYTEST_PLUGINS": None,
                "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            },
            "runtime_environment": {
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "TZ": "UTC",
                "PYTHONHASHSEED": "0",
                "PYTHONSAFEPATH": "1",
                "PYTHONPATH": "/work/tools",
                "PYTHONWARNINGS": None,
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            "toolchain": {
                "git": {
                    "path": "/usr/bin/git", "sha256": "a" * 64,
                    "version": "git version pinned", "package": "git=pinned",
                },
                "openssl": {
                    "path": "/usr/bin/openssl", "sha256": "b" * 64,
                    "version": "OpenSSL pinned", "package": "openssl=pinned",
                },
            },
        }
        self.assertTrue(validate_environment_document(valid))
        for mutate in (
            lambda value: value.update({"unknown": 1}),
            lambda value: value["distributions"].append(["pytest", "9.0.1"]),
            lambda value: value.__setitem__("entry_points", [["short"]]),
            lambda value: value["pytest_environment"].__setitem__(
                "PYTEST_DISABLE_PLUGIN_AUTOLOAD", None
            ),
            lambda value: value["distributions"].append(["PyTest", "9.0.1"]),
            lambda value: value["entry_points"].append(
                ["pytest11", "example", "different", "other"]
            ),
        ):
            with self.subTest(mutate=mutate):
                changed = copy.deepcopy(valid)
                mutate(changed)
                self.assertFalse(validate_environment_document(changed))

    def test_coordinated_fake_evidence_requires_external_signature(self) -> None:
        with tempfile.TemporaryDirectory(prefix="br-keyword-trust-") as temporary:
            root = Path(temporary)
            artifact = {
                "trace_sha256": "a" * 64,
                "trace_size": 1,
                "manifest_sha256": "b" * 64,
                "manifest_size": 1,
                "bundle_sha256": "d" * 64,
                "bundle_size": 1,
            }
            pins = {field: "c" * 64 for field in INDEX_PIN_FIELDS}
            pins.update(
                {
                    "base_image": BASE_IMAGE,
                    "image_id": "sha256:" + "e" * 64,
                    "source_sha": PINNED_SHA,
                    "tracker_version": 2,
                    "tracked_entries": 365,
                }
            )
            index = {
                "schema": 1,
                "purpose": "targeted-smoke",
                "artifacts": {
                    "normal": artifact,
                    "synchronous-worker": artifact,
                },
                "collection_argv": {
                    "normal": ["collector", "normal"],
                    "synchronous-worker": ["collector", "sync"],
                },
                "pins": pins,
            }
            index_path = root / "index.json"
            signature_path = root / "signature.json"
            raw = json.dumps(index, sort_keys=True, separators=(",", ":")).encode()
            index_path.write_bytes(raw)
            signature_path.write_text("{}")
            with self.assertRaises(SystemExit):
                load_signed_index(index_path, signature_path, targeted_smoke=True)
            private_key = Path(
                "/home/silverdisk/.blast-radius-evidence-review/"
                "tokenizer-keyword-ed25519-private.pem"
            )
            if not private_key.is_file():
                self.skipTest("external evidence review key is unavailable")
            subprocess.run(
                [
                    sys.executable,
                    str(REPOSITORY / "tools/sign_tokenizer_keyword_evidence.py"),
                    "--index", str(index_path),
                    "--private-key", str(private_key),
                    "--output", str(signature_path),
                ],
                check=True,
            )
            self.assertEqual(
                load_signed_index(index_path, signature_path, targeted_smoke=True),
                index,
            )
            index["unknown"] = True
            index_path.write_text(json.dumps(index, sort_keys=True, separators=(",", ":")))
            with self.assertRaises(SystemExit):
                load_signed_index(index_path, signature_path, targeted_smoke=True)

    def test_process_pairs_and_digests_are_strict(self) -> None:
        with tempfile.TemporaryDirectory(prefix="br-keyword-process-") as temporary:
            trace = Path(temporary) / "trace.json"
            trace.write_text("{}")
            token = "123-456"
            manifest = {
                "exitstatus": 0,
                "tests": ["test"],
                "child_complete": True,
                "child_starts": 1,
                "child_logs": 1,
                "child_completions": 1,
                "child_processes": [[token, 123]],
                "child_tokens_sha256": hashlib.sha256(token.encode()).hexdigest(),
                "trace_sha256": hashlib.sha256(b"{}").hexdigest(),
                "core_origin_suffix": "/sqlglot/tokenizer_core.py",
                "core_class_module": "sqlglot.tokenizer_core",
                "sqlglotc_spec": None,
            }
            self.assertEqual(
                validate_process_manifest(manifest, trace, ["test"]), [[token, 123]]
            )
            mutations = (
                lambda value: value.__setitem__("child_processes", [None]),
                lambda value: value.__setitem__("child_processes", [[token, True]]),
                lambda value: value.__setitem__("child_processes", [["123-0", 123]]),
                lambda value: value.__setitem__("child_processes", [["124-456", 123]]),
                lambda value: value.__setitem__("child_tokens_sha256", None),
                lambda value: value.__setitem__("trace_sha256", None),
            )
            for mutate in mutations:
                with self.subTest(mutate=mutate):
                    changed = copy.deepcopy(manifest)
                    mutate(changed)
                    with self.assertRaises(SystemExit):
                        validate_process_manifest(changed, trace, ["test"])


class TrackerAdversarialTests(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, Path, Path, dict[str, str]]:
        support, source, children = root / "support", root / "source", root / "children"
        support.mkdir()
        children.mkdir()
        (source / "sqlglot").mkdir(parents=True)
        (source / "sqlglot/__init__.py").write_text("")
        (source / "sqlglot/tokenizer_core.py").write_text(
            "class TokenizerCore:\n    pass\n"
        )
        (support / "_br_tokenizer_keyword_tracker.py").write_text(
            TRACKER.replace("__RESERVED__", RESERVED)
        )
        environment = os.environ.copy()
        environment.update(
            {
                "PYTHONPATH": os.pathsep.join((str(support), str(source))),
                "TOKENIZER_KEYWORD_CHILD_DIR": str(children),
                "TOKENIZER_KEYWORD_ENVIRONMENT_SHA256": "a" * 64,
                "TOKENIZER_KEYWORD_CORE_ORIGIN": str(
                    (source / "sqlglot/tokenizer_core.py").resolve()
                ),
            }
        )
        return support, source, children, environment

    def test_immediate_log_owner_poison_and_pid_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory(prefix="br-keyword-tracker-test-") as temporary:
            root = Path(temporary)
            _support, _source, children, environment = self.fixture(root)
            script = f'''\
import builtins
import _br_tokenizer_keyword_tracker as tracker
import sqlglot.tokenizer_core
tracker.importing = lambda: True
builtins.{RESERVED}("IMPORT")
tracker.importing = lambda: False
tracker.CURRENT_TEST = "tests/test_a.py::test_a"
builtins.{RESERVED}("OWNED")
tracker.CURRENT_TEST = None
builtins.{RESERVED}("OWNERLESS")
builtins.{RESERVED}(object())
'''
            subprocess.run([sys.executable, "-c", script], env=environment, check=True)
            starts = list(children.glob("*.started"))
            logs = list(children.glob("*.log.jsonl"))
            completions = list(children.glob("*.completed"))
            self.assertEqual(len(starts), 1)
            self.assertEqual(len(logs), 1)
            self.assertEqual(len(completions), 1)
            events = canonical_events(children, {"tests/test_a.py::test_a"})
            self.assertEqual(events["IMPORT"], ["__IMPORT__"])
            self.assertEqual(events["OWNED"], ["tests/test_a.py::test_a"])
            self.assertEqual(events["OWNERLESS"], ["__NO_TEST__"])
            self.assertEqual(events["__NON_STRING__"], ["__NO_TEST__"])

    def test_abrupt_retrieving_child_is_detectably_incomplete(self) -> None:
        if not hasattr(os, "fork"):
            self.skipTest("fork unavailable")
        with tempfile.TemporaryDirectory(prefix="br-keyword-fork-test-") as temporary:
            root = Path(temporary)
            _support, _source, children, environment = self.fixture(root)
            script = f'''\
import builtins, os
import _br_tokenizer_keyword_tracker
import sqlglot.tokenizer_core
pid = os.fork()
if pid == 0:
    builtins.{RESERVED}("CHILD")
    os._exit(0)
os.waitpid(pid, 0)
'''
            subprocess.run([sys.executable, "-c", script], env=environment, check=True)
            starts = {path.stem for path in children.glob("*.started")}
            logs = {
                path.name.removesuffix(".log.jsonl")
                for path in children.glob("*.log.jsonl")
            }
            completions = {path.stem for path in children.glob("*.completed")}
            self.assertEqual(starts, logs)
            self.assertTrue(starts)
            self.assertNotEqual(starts, completions)
            with self.assertRaises(SystemExit):
                canonical_events(children, set())

    def test_orphan_and_empty_process_artifacts_reject(self) -> None:
        with tempfile.TemporaryDirectory(prefix="br-keyword-artifacts-") as temporary:
            root = Path(temporary)
            _support, _source, children, environment = self.fixture(root)
            script = f'''import builtins
import _br_tokenizer_keyword_tracker
import sqlglot.tokenizer_core
builtins.{RESERVED}("KEY")
'''
            subprocess.run([sys.executable, "-c", script], env=environment, check=True)
            canonical_events(children, set())
            orphan = children / "orphan"
            orphan.write_text("x")
            with self.assertRaises(SystemExit):
                canonical_events(children, set())
            orphan.unlink()
            log = next(children.glob("*.log.jsonl"))
            log.write_text("")
            with self.assertRaises(SystemExit):
                canonical_events(children, set())

    def test_unknown_and_unstarted_task_sentries_reject(self) -> None:
        with tempfile.TemporaryDirectory(prefix="br-keyword-sentry-test-") as temporary:
            root = Path(temporary)
            _support, _source, children, environment = self.fixture(root)
            subprocess.run(
                [
                    sys.executable, "-c",
                    f"import builtins, _br_tokenizer_keyword_tracker, "
                    f"sqlglot.tokenizer_core; builtins.{RESERVED}('KEY')",
                ],
                env=environment,
                check=True,
            )
            log = next(children.glob("*.log.jsonl"))
            completion = next(children.glob("*.completed"))
            original_log = log.read_bytes()

            def seal() -> None:
                document = json.loads(completion.read_text())
                document["log_sha256"] = hashlib.sha256(log.read_bytes()).hexdigest()
                completion.write_text(
                    json.dumps(document, sort_keys=True, separators=(",", ":"))
                )

            for record in (
                ["sentry", "unknown-boundary", "__NO_TEST__"],
                ["sentry", "submit-start:123-456", "tests/test_a.py::test_a"],
            ):
                with self.subTest(record=record):
                    log.write_bytes(
                        original_log + json.dumps(record, separators=(",", ":")).encode() + b"\n"
                    )
                    seal()
                    with self.assertRaises(SystemExit):
                        canonical_events(children, {"tests/test_a.py::test_a"})

    def test_persistent_process_pool_relabels_each_task_owner(self) -> None:
        if not hasattr(os, "fork"):
            self.skipTest("fork unavailable")
        with tempfile.TemporaryDirectory(prefix="br-keyword-pool-owner-") as temporary:
            root = Path(temporary)
            support, _source, children, environment = self.fixture(root)
            (support / "task_module.py").write_text(
                f"import builtins, sqlglot.tokenizer_core\ndef run(key):\n    return builtins.{RESERVED}(key)\n"
            )
            script = '''import concurrent.futures, multiprocessing
import _br_tokenizer_keyword_tracker as tracker
from task_module import run
with concurrent.futures.ProcessPoolExecutor(
    max_workers=1, mp_context=multiprocessing.get_context("fork")
) as pool:
    tracker.CURRENT_TEST = "tests/test_a.py::test_a"
    assert pool.submit(run, "FIRST").result() == "FIRST"
    tracker.CURRENT_TEST = "tests/test_b.py::test_b"
    assert pool.submit(run, "SECOND").result() == "SECOND"
'''
            subprocess.run([sys.executable, "-c", script], env=environment, check=True)
            events = canonical_events(
                children, {"tests/test_a.py::test_a", "tests/test_b.py::test_b"}
            )
            self.assertEqual(events["FIRST"], ["tests/test_a.py::test_a"])
            self.assertEqual(events["SECOND"], ["tests/test_b.py::test_b"])

    def test_spawn_persistent_process_pool_relabels_each_task_owner(self) -> None:
        with tempfile.TemporaryDirectory(prefix="br-keyword-spawn-owner-") as temporary:
            root = Path(temporary)
            support, _source, children, environment = self.fixture(root)
            (support / "sitecustomize.py").write_text(
                "import _br_tokenizer_keyword_tracker\n"
            )
            (support / "task_module.py").write_text(
                f"import builtins, sqlglot.tokenizer_core\n"
                f"def run(key):\n    return builtins.{RESERVED}(key)\n"
            )
            driver = root / "driver.py"
            driver.write_text('''import concurrent.futures, multiprocessing
import _br_tokenizer_keyword_tracker as tracker
from task_module import run

def main():
    with concurrent.futures.ProcessPoolExecutor(
        max_workers=1, mp_context=multiprocessing.get_context("spawn")
    ) as pool:
        tracker.CURRENT_TEST = "tests/test_a.py::test_a"
        assert pool.submit(run, "SPAWN_FIRST").result() == "SPAWN_FIRST"
        tracker.CURRENT_TEST = "tests/test_b.py::test_b"
        assert pool.submit(run, "SPAWN_SECOND").result() == "SPAWN_SECOND"

if __name__ == "__main__":
    main()
''')
            subprocess.run([sys.executable, str(driver)], env=environment, check=True)
            events = canonical_events(
                children, {"tests/test_a.py::test_a", "tests/test_b.py::test_b"}
            )
            self.assertEqual(events["SPAWN_FIRST"], ["tests/test_a.py::test_a"])
            self.assertEqual(events["SPAWN_SECOND"], ["tests/test_b.py::test_b"])


if __name__ == "__main__":
    unittest.main()
