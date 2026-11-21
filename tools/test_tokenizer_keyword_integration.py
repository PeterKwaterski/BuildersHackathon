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
from tokenizer_keyword_runtime import load_context


class TokenizerKeywordIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        model_raw = selector.TOKENIZER_KEYWORD_MODEL.read_bytes()
        sources_raw = selector.SEMANTIC_SOURCES.read_bytes()
        cls.context = load_context(
            model_raw,
            selector.TOKENIZER_KEYWORD_MODEL_SHA256,
            sources_raw,
            selector.SEMANTIC_SOURCES_SHA256,
        )
        if cls.context is None:
            raise AssertionError("exact bundled tokenizer keyword model did not validate")
        with gzip.open(selector.MODEL, "rt", encoding="utf-8") as model_file:
            cls.selector_model = json.load(model_file)
        cls.selector_model["h"] = set(cls.selector_model.get("h", ()))
        cls.all_indices = set(range(len(cls.selector_model["t"])))
        cls.reflection_model = {"d": {}}

    def select(self, path: str, replacements: list[tuple[str, str]], context):
        source = self.context.sources[path]
        changed = source
        for old, new in replacements:
            self.assertEqual(changed.count(old), 1)
            changed = changed.replace(old, new, 1)
        patch_text = f"diff --git a/{path} b/{path}\n" + "".join(
            difflib.unified_diff(
                source.splitlines(True),
                changed.splitlines(True),
                fromfile=f"a/{path}",
                tofile=f"b/{path}",
            )
        )
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as patch:
            patch.write(patch_text)
            patch.flush()
            return selector.selected_indices(
                Path(patch.name),
                self.selector_model,
                self.all_indices,
                reflection_model=self.reflection_model,
                tokenizer_keyword_context=context,
            )

    def test_safe_value_edit_selects_no_retrieval_readers(self):
        self.assertEqual(
            self.select(
                "sqlglot/dialects/hive.py",
                [("\"ADD ARCHIVE\": TokenType.COMMAND", "\"ADD ARCHIVE\": TokenType.SELECT")],
                self.context,
            ),
            set(),
        )

    def test_missing_context_and_observed_key_fall_back(self):
        safe_edit = [
            ("\"ADD ARCHIVE\": TokenType.COMMAND", "\"ADD ARCHIVE\": TokenType.SELECT")
        ]
        self.assertTrue(self.select("sqlglot/dialects/hive.py", safe_edit, None))
        self.assertTrue(
            self.select(
                "sqlglot/dialects/clickhouse.py",
                [("\"ATTACH\": TokenType.COMMAND", "\"ATTACH\": TokenType.SELECT")],
                self.context,
            )
        )

    def test_multiple_value_edits_fall_back(self):
        self.assertTrue(
            self.select(
                "sqlglot/dialects/hive.py",
                [
                    ("\"ADD ARCHIVE\": TokenType.COMMAND", "\"ADD ARCHIVE\": TokenType.SELECT"),
                    ("\"ADD FILES\": TokenType.COMMAND", "\"ADD FILES\": TokenType.SELECT"),
                ],
                self.context,
            )
        )


if __name__ == "__main__":
    unittest.main()
