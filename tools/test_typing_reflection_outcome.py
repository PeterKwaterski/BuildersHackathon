#!/usr/bin/env python3
"""Adversarial checks for the typing code-reflection outcome proof."""

from __future__ import annotations

import difflib
import gzip
import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

import selector


class TypingReflectionOutcomeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with gzip.open(selector.CODE_REFLECTION_MODEL, "rt", encoding="utf-8") as stream:
            cls.model = json.load(stream)
        cls.path = "sqlglot/typing/__init__.py"
        cls.source = selector.pinned_sources()[cls.path]

    def change(self, replacements: dict[str, str]) -> dict:
        changed = self.source
        for old, new in replacements.items():
            self.assertGreaterEqual(changed.count(old), 1, old)
            changed = changed.replace(old, new, 1)
        patch = f"diff --git a/{self.path} b/{self.path}\n" + "".join(
            difflib.unified_diff(
                self.source.splitlines(keepends=True),
                changed.splitlines(keepends=True),
                fromfile=f"a/{self.path}",
                tofile=f"b/{self.path}",
                n=3,
            )
        )
        with tempfile.NamedTemporaryFile("w", suffix=".patch") as stream:
            stream.write(patch)
            stream.flush()
            changes = selector.patch_changes(Path(stream.name))
        self.assertEqual(len(changes), 1)
        return changes[0]

    def rename_change(self) -> dict:
        return self.change(
            {
                "    this: exp.Expr = expression.this\n": "    that: exp.Expr = expression.this\n",
                "        this.type\n": "        that.type\n",
                "        if this.is_type(exp.DType.UNKNOWN, *exp.DataType.NUMERIC_TYPES)\n": "        if that.is_type(exp.DType.UNKNOWN, *exp.DataType.NUMERIC_TYPES)\n",
            }
        )

    def double_rename_change(self) -> dict:
        first_start = self.source.index("def annotate_by_numeric_arg")
        second_start = self.source.index("def annotate_int_as_double")
        second_end = self.source.index("\n\nTIMESTAMP_EXPRESSIONS", second_start)
        first = self.source[first_start:second_start]
        second = self.source[second_start:second_end]

        def renamed(function: str) -> str:
            return (
                function.replace("this: exp.Expr", "that: exp.Expr")
                .replace("this.type", "that.type")
                .replace("this.is_type", "that.is_type")
            )

        return self.change({first: renamed(first), second: renamed(second)})

    def test_unique_same_width_local_rename_cannot_create_duplicate(self) -> None:
        change = self.rename_change()
        proof = selector.semantic_noop_edit(change, self.path)
        self.assertEqual(proof, "local-binding-rename")
        self.assertTrue(
            selector.typing_reflection_outcome_equivalent(
                change, self.path, self.model, proof, False
            )
        )

    def test_selection_omits_only_the_proven_reader_and_fails_closed(self) -> None:
        change = self.rename_change()
        with mock.patch.object(selector, "patch_changes", return_value=[change]):
            self.assertEqual(
                selector.selected_indices(
                    Path("unused.patch"),
                    {},
                    {1619},
                    reflection_model=self.model,
                ),
                set(),
            )
            self.assertEqual(
                selector.selected_indices(
                    Path("unused.patch"),
                    {},
                    {1619},
                    reflection_model=None,
                ),
                {1619},
            )

    def test_prospective_collision_fails_closed(self) -> None:
        change = self.rename_change()
        changed = selector.patched_source(change, self.path)
        self.assertIsNotNone(changed)
        root = compile(changed, self.path, "exec", dont_inherit=True)
        target = next(
            code
            for code in selector._nested_code_objects(root)
            if code.co_name == "annotate_by_numeric_arg" and code.co_firstlineno == 15
        )
        collision = selector._typing_test_code_fingerprint(target)
        prior = selector._TYPING_CODE_FINGERPRINTS
        selector._TYPING_CODE_FINGERPRINTS = Counter({collision: 1})
        try:
            self.assertFalse(
                selector.typing_reflection_outcome_equivalent(
                    change,
                    self.path,
                    self.model,
                    "local-binding-rename",
                    False,
                )
            )
        finally:
            selector._TYPING_CODE_FINGERPRINTS = prior

    def test_two_changed_functions_cannot_converge_on_novel_fingerprint(self) -> None:
        change = self.double_rename_change()
        proof = selector.semantic_noop_edit(change, self.path)
        self.assertEqual(proof, "local-binding-rename")
        collision = (b"prospective", (), ("that",), ())
        actual_fingerprint = selector._typing_test_code_fingerprint

        def synthetic_fingerprint(code):
            if code.co_name in {"annotate_by_numeric_arg", "annotate_int_as_double"}:
                if "that" in code.co_varnames:
                    return collision
                return (b"original", (), (code.co_name,), ())
            return actual_fingerprint(code)

        prior = selector._TYPING_CODE_FINGERPRINTS
        selector._TYPING_CODE_FINGERPRINTS = Counter()
        try:
            with mock.patch.object(
                selector,
                "_typing_test_code_fingerprint",
                side_effect=synthetic_fingerprint,
            ):
                self.assertFalse(
                    selector.typing_reflection_outcome_equivalent(
                        change, self.path, self.model, proof, False
                    )
                )
        finally:
            selector._TYPING_CODE_FINGERPRINTS = prior

    def test_ignored_local_annotation_preserves_reflection_outcome(self) -> None:
        change = self.change(
            {"    this: exp.Expr = expression.this\n": "    this: object   = expression.this\n"}
        )
        self.assertTrue(selector.local_annotation_only_edit(change, self.path))
        self.assertTrue(
            selector.typing_reflection_outcome_equivalent(
                change, self.path, self.model, None, True
            )
        )

    def test_behavior_change_and_model_tamper_retain_reader(self) -> None:
        change = self.change({"        else exp.DType.INT,\n": "        else exp.DType.BIGINT,\n"})
        self.assertFalse(
            selector.typing_reflection_outcome_equivalent(
                change, self.path, self.model, None, False
            )
        )
        tampered = json.loads(json.dumps(self.model))
        for entry in tampered["d"][self.path]:
            if entry[0] == 15:
                entry[4] = [0]
        self.assertFalse(
            selector.typing_reflection_outcome_equivalent(
                change,
                self.path,
                tampered,
                "local-binding-rename",
                False,
            )
        )


if __name__ == "__main__":
    unittest.main()
