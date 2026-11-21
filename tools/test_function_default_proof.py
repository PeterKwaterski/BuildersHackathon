#!/usr/bin/env python3
"""Adversarial unit tests for the function-default artifact and runtime gate."""

from __future__ import annotations

import copy
import gzip
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import selector


PATH = "sqlglot/fake_defaults.py"
SOURCE = "def candidate(value=1):\n    return value\n"
VALUE_DUMP = "Constant(value=1)"


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def model() -> dict:
    data = {
        PATH: [[1, 1, 1, "candidate", "value", VALUE_DUMP, "safe", [3]]]
    }
    return {
        "d": data,
        "n": 10,
        "p": digest(data),
        "sha": "pinned",
        "t": "tests",
        "v": 1,
    }


def change(new_source: str) -> dict:
    old_lines = SOURCE.splitlines()
    new_lines = new_source.splitlines()
    patch = "\n".join(
        [
            f"diff --git a/{PATH} b/{PATH}",
            f"--- a/{PATH}",
            f"+++ b/{PATH}",
            f"@@ -1,{len(old_lines)} +1,{len(new_lines)} @@",
            *(f"-{line}" for line in old_lines),
            *(f"+{line}" for line in new_lines),
            "",
        ]
    )
    with tempfile.NamedTemporaryFile("w", delete=False) as output:
        output.write(patch)
        path = Path(output.name)
    try:
        return selector.patch_changes(path)[0]
    finally:
        path.unlink()


class FunctionDefaultProofTests(unittest.TestCase):
    def test_validator_rejects_non_mapping_payloads(self):
        for payload in (None, [], "", 1, True):
            with self.subTest(payload=payload):
                self.assertFalse(selector.valid_function_default_model(payload))

    def test_pinned_sources_requires_exact_raw_gzip_hash(self):
        document = {PATH: SOURCE}
        raw = gzip.compress(
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode(),
            mtime=0,
        )
        with tempfile.TemporaryDirectory() as directory:
            source_path = Path(directory) / "semantic_sources.json.gz"
            source_path.write_bytes(raw)
            with (
                mock.patch.object(selector, "SEMANTIC_SOURCES", source_path),
                mock.patch.object(
                    selector,
                    "SEMANTIC_SOURCES_SHA256",
                    hashlib.sha256(raw).hexdigest(),
                ),
            ):
                selector._PINNED_SOURCES = None
                self.assertEqual(selector.pinned_sources(), document)
                source_path.write_bytes(raw + b"tampered")
                selector._PINNED_SOURCES = None
                self.assertEqual(selector.pinned_sources(), {})
                self.assertIsNone(
                    selector.function_default_edit(
                        change("def candidate(value=2):\n    return value\n"),
                        PATH,
                        model(),
                    )
                )
                syntax_patch = Path(directory) / "syntax.patch"
                syntax_patch.write_text(
                    "\n".join(
                        [
                            f"diff --git a/{PATH} b/{PATH}",
                            f"--- a/{PATH}",
                            f"+++ b/{PATH}",
                            "@@ -1,2 +1,2 @@",
                            "-def candidate(value=1):",
                            "+def candidate(value=1",
                            "     return value",
                            "",
                        ]
                    )
                )
                self.assertEqual(
                    selector.selected_indices(syntax_patch, {}, {0, 1}),
                    {0, 1},
                )

                malformed = b"not gzip"
                source_path.write_bytes(malformed)
                selector.SEMANTIC_SOURCES_SHA256 = hashlib.sha256(malformed).hexdigest()
                selector._PINNED_SOURCES = None
                self.assertEqual(selector.pinned_sources(), {})
        selector._PINNED_SOURCES = None

    def test_complete_reader_and_state_payload_is_digest_bound(self):
        profile = model()
        with (
            mock.patch.object(selector, "pinned_sources", return_value={PATH: SOURCE}),
            mock.patch.object(
                selector, "FUNCTION_DEFAULT_PROFILE_SHA256", profile["p"]
            ),
        ):
            self.assertTrue(selector.valid_function_default_model(profile))
            for mutate in (
                lambda value: value["d"][PATH][0].__setitem__(7, []),
                lambda value: value["d"][PATH][0].__setitem__(6, "import-read"),
                lambda value: value.__setitem__("p", "0" * 64),
                lambda value: value.__setitem__("extra", True),
            ):
                changed = copy.deepcopy(profile)
                mutate(changed)
                self.assertFalse(selector.valid_function_default_model(changed))

            # Recomputing the mutable artifact's own digest cannot bypass the
            # independently pinned selector constant.
            changed = copy.deepcopy(profile)
            changed["d"][PATH][0][7] = []
            changed["p"] = digest(changed["d"])
            self.assertFalse(selector.valid_function_default_model(changed))

    def test_runtime_gate_accepts_only_the_one_literal_default_edit(self):
        profile = model()
        with mock.patch.object(selector, "pinned_sources", return_value={PATH: SOURCE}):
            self.assertEqual(
                selector.function_default_edit(
                    change("def candidate(value=2):\n    return value\n"),
                    PATH,
                    profile,
                ),
                {3},
            )
            self.assertIsNone(
                selector.function_default_edit(
                    change("def candidate(value=2):\n    return value + 1\n"),
                    PATH,
                    profile,
                )
            )

    def test_non_safe_or_non_intersecting_entries_skip_source_reconstruction(self):
        profile = model()
        outside = change("def candidate(value=2):\n    return value\n")
        outside["lines"] = {50}
        with mock.patch.object(selector, "patched_source") as patched:
            self.assertIsNone(selector.function_default_edit(outside, PATH, profile))
            patched.assert_not_called()

            unsafe = copy.deepcopy(profile)
            unsafe["d"][PATH][0][6] = "import-read"
            self.assertIsNone(
                selector.function_default_edit(
                    change("def candidate(value=2):\n    return value\n"),
                    PATH,
                    unsafe,
                )
            )
            patched.assert_not_called()

    def test_corrupt_sources_block_early_new_module_proof(self):
        parsed = change("def candidate(value=2):\n    return value\n")
        new_module = mock.Mock(return_value={1})
        with (
            mock.patch.object(selector, "patch_changes", return_value=[parsed]),
            mock.patch.object(selector, "pinned_sources", return_value={}),
            mock.patch.object(selector, "isolated_new_module_indices", new_module),
        ):
            self.assertEqual(
                selector.selected_indices(Path("unused.patch"), {}, {0, 1}),
                {0, 1},
            )
        new_module.assert_not_called()

    def test_reflection_readers_are_unioned_before_default_continue(self):
        parsed = change("def candidate(value=2):\n    return value\n")
        base_model = {"f": {}, "h": set(), "x": {}}
        all_indices = set(range(10))
        with (
            mock.patch.object(selector, "patch_changes", return_value=[parsed]),
            mock.patch.object(selector, "pinned_sources", return_value={PATH: SOURCE}),
            mock.patch.object(selector, "invalid_python_patch", return_value=False),
            mock.patch.object(selector, "code_reflection_indices", return_value={9}),
            mock.patch.object(selector, "inert_comment_addition", return_value=False),
            mock.patch.object(selector, "semantic_noop_edit", return_value=None),
            mock.patch.object(selector, "local_annotation_only_edit", return_value=False),
            mock.patch.object(selector, "proven_identity_equality", return_value=False),
            mock.patch.object(selector, "function_default_edit", return_value={3}),
        ):
            self.assertEqual(
                selector.selected_indices(
                    Path("unused.patch"),
                    base_model,
                    all_indices,
                    reflection_model={"d": {}},
                    default_model=model(),
                ),
                {3, 9},
            )

if __name__ == "__main__":
    unittest.main()
