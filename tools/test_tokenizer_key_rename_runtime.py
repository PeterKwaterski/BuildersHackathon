#!/usr/bin/env python3
from __future__ import annotations

import copy
import ast
import difflib
import gzip
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import selector
import tokenizer_key_rename_runtime as runtime


def deterministic(document: dict) -> bytes:
    return gzip.compress(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode(),
        compresslevel=9,
        mtime=0,
    )


class TokenizerKeyRenameRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = (ROOT / "tokenizer_key_rename_model.json.gz").read_bytes()
        cls.document = json.loads(gzip.decompress(cls.raw))
        cls.sources_raw = (ROOT / "semantic_sources.json.gz").read_bytes()
        cls.context = runtime.load_key_rename_context(
            cls.raw,
            runtime.MODEL_SHA256,
            cls.sources_raw,
            runtime.PINNED_SEMANTIC_SOURCES_SHA256,
        )
        if cls.context is None:
            raise AssertionError("bundled key-rename context did not validate")

    def patch(self, path: str, old: str, new: str, count: int = 1):
        source = self.context.sources[path]
        self.assertGreaterEqual(source.count(old), count)
        changed = source.replace(old, new, count)
        text = f"diff --git a/{path} b/{path}\n" + "".join(
            difflib.unified_diff(
                source.splitlines(True), changed.splitlines(True),
                fromfile=f"a/{path}", tofile=f"b/{path}",
            )
        )
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as patch:
            patch.write(text)
            patch.flush()
            return selector.patch_changes(Path(patch.name))

    def rename(self, path: str, old: str, new: str):
        return runtime.tokenizer_key_rename_patch(self.patch(path, old, new), self.context)

    def expected(self, old: str, new: str) -> set[int]:
        terminals = {
            entry.key
            for entries in self.context.entries_by_path.values()
            for entry in entries
            if runtime.KEY_IDENTIFIER.fullmatch(entry.key)
            and new.startswith(entry.key)
            and len(entry.key) >= len(old)
        } | {new}
        result = set(self.context.events[old])
        for key in terminals:
            result.update(self.context.events.get(key, ()))
        return result

    def test_absent_new_uses_old_owner_union(self):
        result = self.rename(
            "sqlglot/dialects/bigquery.py",
            '"TIMESTAMP": TokenType.TIMESTAMPTZ',
            '"TIMESTAMPX": TokenType.TIMESTAMPTZ',
        )
        self.assertEqual(result, self.expected("TIMESTAMP", "TIMESTAMPX"))
        self.assertEqual(len(result), 109)

    def test_present_new_and_multiple_terminal_prefixes_are_unioned(self):
        result = self.rename(
            "sqlglot/dialects/bigquery.py",
            '"TIMESTAMP": TokenType.TIMESTAMPTZ',
            '"TIMESTAMPNTZFROMPARTS": TokenType.TIMESTAMPTZ',
        )
        self.assertEqual(result, self.expected("TIMESTAMP", "TIMESTAMPNTZFROMPARTS"))
        self.assertTrue(self.context.events["TIMESTAMPNTZ"] <= result)
        self.assertTrue(self.context.events["TIMESTAMPNTZFROMPARTS"] <= result)

    def test_new_prefix_of_longer_terminal_is_safe(self):
        result = self.rename(
            "sqlglot/dialects/bigquery.py",
            '"TIMESTAMP": TokenType.TIMESTAMPTZ',
            '"TIMESTAMPN": TokenType.TIMESTAMPTZ',
        )
        self.assertEqual(result, self.expected("TIMESTAMP", "TIMESTAMPN"))

    def test_single_identifier_cannot_enter_keyword_trie_guard(self):
        # The pinned trie includes only keys containing whitespace or a
        # SINGLE_TOKENS string. Every statically admitted SINGLE_TOKENS key
        # contains punctuation, which the gate's identifier regex forbids.
        sources = json.loads(gzip.decompress(self.sources_raw))
        token_keys = set()
        assignment_shapes = set()
        annotation_only = 0
        for path, source in sources.items():
            if not path.endswith(".py"):
                continue
            tree = ast.parse(source, filename=path)
            for node in ast.walk(tree):
                if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                    continue
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if not any(isinstance(target, ast.Name) and target.id == "SINGLE_TOKENS" for target in targets):
                    continue
                if node.value is None:
                    annotation_only += 1
                    continue
                assignment_shapes.add(type(node.value).__name__)
                if isinstance(node.value, ast.Dict):
                    token_keys.update(
                        key.value for key in node.value.keys
                        if isinstance(key, ast.Constant) and type(key.value) is str
                    )
        self.assertEqual(assignment_shapes, {"Dict", "Call"})
        self.assertGreater(annotation_only, 0)
        self.assertTrue(token_keys)
        self.assertTrue(all(runtime.KEY_IDENTIFIER.search(key) is None for key in token_keys))
        tokens_source = sources["sqlglot/tokens.py"]
        self.assertIn('if " " in key or any(single in key for single in cls.SINGLE_TOKENS)', tokens_source)
        self.assertFalse(self.document["audit"]["pop_keys"] == [])

    def test_unrelated_new_and_poisoned_prefix_fail_closed(self):
        self.assertIsNone(self.rename(
            "sqlglot/dialects/bigquery.py",
            '"TIMESTAMP": TokenType.TIMESTAMPTZ',
            '"SELECTX": TokenType.TIMESTAMPTZ',
        ))
        self.assertIsNone(self.rename(
            "sqlglot/tokens.py", '"IN": TokenType.IN', '"INTERVALX": TokenType.IN'
        ))

    def test_literal_collision_fails_closed(self):
        self.assertIsNone(self.rename(
            "sqlglot/tokens.py",
            '"TIMESTAMP": TokenType.TIMESTAMP',
            '"TIMESTAMPTZ": TokenType.TIMESTAMP',
        ))

    def test_nonidentifier_multword_lowercase_and_value_changes_fail(self):
        cases = (
            ('"TIMESTAMP": TokenType.TIMESTAMPTZ', '"TIMESTAMP X": TokenType.TIMESTAMPTZ'),
            ('"TIMESTAMP": TokenType.TIMESTAMPTZ', '"timestampx": TokenType.TIMESTAMPTZ'),
            ('"TIMESTAMP": TokenType.TIMESTAMPTZ', '"TIMESTAMPX": TokenType.TIMESTAMP'),
            ('"TIMESTAMP": TokenType.TIMESTAMPTZ', '("TIMESTAMPX"): TokenType.TIMESTAMPTZ'),
        )
        for old, new in cases:
            with self.subTest(new=new):
                self.assertIsNone(self.rename("sqlglot/dialects/bigquery.py", old, new))

    def test_parser_mapping_and_multi_edit_fail_closed(self):
        parser_source = self.context.sources["sqlglot/parser.py"]
        self.assertIn("LOG", parser_source)
        changes = self.patch("sqlglot/parser.py", '"LOG"', '"LOGX"')
        self.assertIsNone(runtime.tokenizer_key_rename_patch(changes, self.context))
        changes = self.patch(
            "sqlglot/dialects/bigquery.py",
            '"TIMESTAMP": TokenType.TIMESTAMPTZ',
            '"TIMESTAMPX": TokenType.TIMESTAMPTZ',
        )
        self.assertIsNone(runtime.tokenizer_key_rename_patch(changes * 2, self.context))

    def test_patch_transport_tamper_fails_closed(self):
        changes = self.patch(
            "sqlglot/dialects/bigquery.py",
            '"TIMESTAMP": TokenType.TIMESTAMPTZ',
            '"TIMESTAMPX": TokenType.TIMESTAMPTZ',
        )
        mutations = (
            lambda change: change.update(binary=True),
            lambda change: change.update(new="sqlglot/tokens.py"),
            lambda change: change.update(no_newline_marker=True),
            lambda change: change["removed"].append("fake"),
            lambda change: change["hunks"][0].update(old_count=999),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                value = copy.deepcopy(changes)
                mutate(value[0])
                self.assertIsNone(runtime.tokenizer_key_rename_patch(value, self.context))

    def test_model_event_provenance_and_audit_tamper_fail_closed(self):
        mutations = (
            lambda value: value["events"].pop("TIMESTAMP"),
            lambda value: value["events"]["TIMESTAMP"].append(9999),
            lambda value: value["poison_keys"].remove("INT"),
            lambda value: value["audit"].update(theorem="missing-prefix-closure"),
            lambda value: value["audit"].update(whole_map_observers=[["x"]]),
            lambda value: value["evidence"].update(mode_event_sha256="0" * 64),
            lambda value: value["evidence"]["traces"]["normal"].update(child_starts=1),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                document = copy.deepcopy(self.document)
                mutate(document)
                raw = deterministic(document)
                sha = hashlib.sha256(raw).hexdigest()
                with mock.patch.object(runtime, "MODEL_SHA256", sha):
                    self.assertIsNone(runtime.load_key_rename_context(
                        raw, sha, self.sources_raw,
                        runtime.PINNED_SEMANTIC_SOURCES_SHA256,
                    ))

    def test_wrong_model_and_source_hashes_fail_closed(self):
        self.assertIsNone(runtime.load_key_rename_context(
            self.raw, "0" * 64, self.sources_raw,
            runtime.PINNED_SEMANTIC_SOURCES_SHA256,
        ))
        self.assertIsNone(runtime.load_key_rename_context(
            self.raw, runtime.MODEL_SHA256, self.sources_raw, "0" * 64,
        ))


if __name__ == "__main__":
    unittest.main()
