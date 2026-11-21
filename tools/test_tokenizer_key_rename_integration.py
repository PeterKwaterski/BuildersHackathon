#!/usr/bin/env python3
from __future__ import annotations

import difflib
import gzip
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import selector
from tokenizer_key_rename_runtime import load_key_rename_context


class TokenizerKeyRenameIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.context = load_key_rename_context(
            selector.TOKENIZER_KEY_RENAME_MODEL.read_bytes(),
            selector.TOKENIZER_KEY_RENAME_MODEL_SHA256,
            selector.SEMANTIC_SOURCES.read_bytes(),
            selector.SEMANTIC_SOURCES_SHA256,
        )
        if cls.context is None:
            raise AssertionError("bundled rename model failed")
        with gzip.open(selector.MODEL, "rt", encoding="utf-8") as model_file:
            cls.model = json.load(model_file)
        cls.model["h"] = set(cls.model.get("h", ()))
        cls.all_indices = set(range(len(cls.model["t"])))

    def select(self, context, reflection_model={"d": {}}):
        path = "sqlglot/dialects/bigquery.py"
        source = self.context.sources[path]
        changed = source.replace(
            '"TIMESTAMP": TokenType.TIMESTAMPTZ',
            '"TIMESTAMPX": TokenType.TIMESTAMPTZ',
            1,
        )
        text = f"diff --git a/{path} b/{path}\n" + "".join(difflib.unified_diff(
            source.splitlines(True), changed.splitlines(True),
            fromfile=f"a/{path}", tofile=f"b/{path}",
        ))
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as patch:
            patch.write(text)
            patch.flush()
            return selector.selected_indices(
                Path(patch.name), self.model, self.all_indices,
                reflection_model=reflection_model,
                tokenizer_key_rename_context=context,
            )

    def test_explicit_context_selects_complete_owner_set(self):
        selected = self.select(self.context)
        self.assertEqual(selected, set(self.context.events["TIMESTAMP"]))
        self.assertEqual(len(selected), 109)

    def test_missing_context_falls_back_to_ordinary_coverage(self):
        selected = self.select(None)
        self.assertNotEqual(selected, set(self.context.events["TIMESTAMP"]))
        self.assertTrue(selected)

    def test_missing_reflection_profile_falls_back_broadly(self):
        selected = self.select(self.context, reflection_model=None)
        self.assertNotEqual(selected, set(self.context.events["TIMESTAMP"]))
        self.assertTrue(selected)

    def test_main_feature_is_enabled_after_adversarial_audit(self):
        self.assertIs(selector.TOKENIZER_KEY_RENAME_ENABLED, True)


if __name__ == "__main__":
    unittest.main()
