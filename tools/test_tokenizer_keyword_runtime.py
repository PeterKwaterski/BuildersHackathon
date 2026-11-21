#!/usr/bin/env python3
from __future__ import annotations

import copy
import difflib
import gzip
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import selector
import tokenizer_keyword_runtime as runtime


EVIDENCE = Path(os.environ.get(
    "TOKENIZER_KEYWORD_MODEL",
    ROOT / "tokenizer_keyword_model.json.gz",
))


def deterministic_model(document: dict) -> bytes:
    return gzip.compress(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode(),
        compresslevel=9,
        mtime=0,
    )


class TokenizerKeywordRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.full_raw = EVIDENCE.read_bytes()
        cls.full = json.loads(gzip.decompress(cls.full_raw))
        cls.sources_raw = (ROOT / "semantic_sources.json.gz").read_bytes()
        cls.sources_sha = hashlib.sha256(cls.sources_raw).hexdigest()
        cls.full_sha = hashlib.sha256(cls.full_raw).hexdigest()
        cls.context = runtime.load_context(
            cls.full_raw, cls.full_sha, cls.sources_raw, cls.sources_sha
        )
        if cls.context is None:
            raise AssertionError("synthetic full runtime fixture did not validate")

    @classmethod
    def model_with_safe_keys(cls, safe_keys: set[str]) -> dict:
        value = copy.deepcopy(cls.full)
        for record in value["d"]:
            record[-1] = "safe-zero" if record[5] in safe_keys else "observed"
        value["safe_keys"] = sorted(safe_keys)
        return value

    def context_for(self, model: dict):
        raw = deterministic_model(model)
        return runtime.load_context(
            raw, hashlib.sha256(raw).hexdigest(), self.sources_raw, self.sources_sha
        )

    def patch_for_sources(self, replacements: list[tuple[str, str, str, int]]):
        chunks = []
        by_path: dict[str, list[tuple[str, str, int]]] = {}
        for path, old, new, count in replacements:
            by_path.setdefault(path, []).append((old, new, count))
        for path, edits in by_path.items():
            source = self.context.sources[path]
            changed = source
            for old, new, count in edits:
                self.assertGreaterEqual(changed.count(old), count)
                offset = 0
                for _ in range(count):
                    index = changed.index(old, offset)
                    changed = changed[:index] + new + changed[index + len(old):]
                    offset = index + len(new)
            chunks.append(f"diff --git a/{path} b/{path}\n")
            chunks.extend(
                difflib.unified_diff(
                    source.splitlines(True),
                    changed.splitlines(True),
                    fromfile=f"a/{path}",
                    tofile=f"b/{path}",
                )
            )
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as patch:
            patch.write("".join(chunks))
            patch.flush()
            return selector.patch_changes(Path(patch.name))

    def patch(self, path: str, old: str, new: str, count: int = 1):
        return self.patch_for_sources([(path, old, new, count)])

    def test_exact_base_and_dialect_replacements_are_recognized(self):
        cases = (
            (
                "sqlglot/tokens.py",
                '"SHORT": TokenType.SMALLINT',
                '"SHORT": TokenType.SELECT',
            ),
            (
                "sqlglot/dialects/clickhouse.py",
                '"FLOAT32": TokenType.FLOAT',
                '"FLOAT32": TokenType.SELECT',
            ),
            (
                "sqlglot/dialects/hive.py",
                '"ADD ARCHIVE": TokenType.COMMAND',
                '"ADD ARCHIVE": TokenType.SELECT',
            ),
        )
        for path, old, new in cases:
            with self.subTest(path=path):
                self.assertEqual(
                    runtime.tokenizer_keyword_patch(
                        self.patch(path, old, new), self.context
                    ),
                    set(),
                )

    def test_observed_key_fails_closed(self):
        model = self.model_with_safe_keys({"UNLOAD"})
        context = self.context_for(model)
        self.assertIsNotNone(context)
        changes = self.patch(
            "sqlglot/dialects/clickhouse.py",
            '"ATTACH": TokenType.COMMAND',
            '"ATTACH": TokenType.SELECT',
        )
        self.assertIsNone(runtime.tokenizer_keyword_patch(changes, context))

    def test_noncanonical_value_and_key_shapes_fail_closed(self):
        path = "sqlglot/dialects/hive.py"
        old = '"ADD ARCHIVE": TokenType.COMMAND'
        replacements = (
            '"ADD ARCHIVE": TT.SELECT',
            '"ADD ARCHIVE": TokenType["SELECT"]',
            '"ADD ARCHIVE": getattr(TokenType, "SELECT")',
            '"ADD ARCHIVE": TokenType.DOES_NOT_EXIST',
            '"ADD ARCHIVEX": TokenType.SELECT',
            '"ADD ARCHIVE": TokenType.SELECT  # second edit',
            '"ADD ARCHIVE": (TokenType.SELECT)',
        )
        for new in replacements:
            with self.subTest(new=new):
                self.assertIsNone(
                    runtime.tokenizer_keyword_patch(
                        self.patch(path, old, new), self.context
                    )
                )

    def test_second_edit_and_second_file_fail_closed(self):
        same_file = self.patch_for_sources(
            [
                (
                    "sqlglot/dialects/athena.py",
                    '"UNLOAD": TokenType.COMMAND',
                    '"UNLOAD": TokenType.SELECT',
                    2,
                )
            ]
        )
        self.assertIsNone(runtime.tokenizer_keyword_patch(same_file, self.context))

        two_files = self.patch_for_sources(
            [
                (
                    "sqlglot/dialects/hive.py",
                    '"ADD ARCHIVE": TokenType.COMMAND',
                    '"ADD ARCHIVE": TokenType.SELECT',
                    1,
                ),
                (
                    "sqlglot/dialects/clickhouse.py",
                    '"ATTACH": TokenType.COMMAND',
                    '"ATTACH": TokenType.SELECT',
                    1,
                ),
            ]
        )
        self.assertEqual(len(two_files), 2)
        self.assertIsNone(runtime.tokenizer_keyword_patch(two_files, self.context))

    def test_patch_transport_tampering_fails_closed(self):
        changes = self.patch(
            "sqlglot/dialects/hive.py",
            '"ADD ARCHIVE": TokenType.COMMAND',
            '"ADD ARCHIVE": TokenType.SELECT',
        )
        mutations = (
            lambda change: change.update(binary=True),
            lambda change: change.update(non_lf=True),
            lambda change: change.update(no_newline_marker=True),
            lambda change: change.update(new_file_mode="100644"),
            lambda change: change.update(new="sqlglot/dialects/other.py"),
            lambda change: change.update(diff_new="sqlglot/dialects/other.py"),
            lambda change: change["removed"].append("fake"),
            lambda change: change["payload"].reverse(),
            lambda change: change.update(lines={1}),
            lambda change: change.update(added_at=[(1, "fake")]),
            lambda change: change.update(added_new_at=[(1, "fake")]),
            lambda change: change["hunks"][0].update(old_count=999),
            lambda change: change["hunks"][0]["lines"].append((" ", "fake")),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                value = copy.deepcopy(changes)
                mutate(value[0])
                self.assertIsNone(runtime.tokenizer_keyword_patch(value, self.context))

    def test_exact_full_model_and_wrong_artifact_hashes(self):
        self.assertIsNotNone(
            runtime.load_context(
                self.full_raw, self.full_sha, self.sources_raw, self.sources_sha
            )
        )
        self.assertIsNone(
            runtime.load_context(
                self.full_raw, "0" * 64, self.sources_raw, self.sources_sha
            )
        )
        self.assertIsNone(
            runtime.load_context(
                self.full_raw, self.full_sha, self.sources_raw, "0" * 64
            )
        )

    def test_model_schema_and_provenance_tampering_fails_closed(self):
        mutations = (
            lambda value: value.update(status="SHIP"),
            lambda value: value.update(v=False),
            lambda value: value.update(n="1620"),
            lambda value: value.update(builder_sha256="0" * 64),
            lambda value: value.update(inventory="0" * 64),
            lambda value: value["d"].pop(),
            lambda value: value["d"][0].__setitem__(6, "SELECT"),
            lambda value: value["safe_keys"].append("ZZZ"),
            lambda value: value["static"].update(sha256="0" * 64),
            lambda value: value["static"]["document"].update(hazards=[["x"]]),
            lambda value: value["operations"].update(sha256="0" * 64),
            lambda value: value["evidence"].update(purpose="targeted-smoke"),
            lambda value: value["evidence"]["common"].update(image_id="sha256:" + "0" * 64),
            lambda value: value["evidence"]["modes"]["normal"].update(child_starts=0),
            lambda value: value["evidence"]["python_environment"].update(implementation="PyPy"),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                value = copy.deepcopy(self.full)
                mutate(value)
                self.assertIsNone(self.context_for(value))

    def test_malformed_runtime_inputs_fail_closed(self):
        for changes in (None, {}, [], [None], ["change"], [object()]):
            with self.subTest(changes=type(changes).__name__):
                self.assertIsNone(
                    runtime.tokenizer_keyword_patch(changes, self.context)
                )
        changes = self.patch(
            "sqlglot/dialects/hive.py",
            '"ADD ARCHIVE": TokenType.COMMAND',
            '"ADD ARCHIVE": TokenType.SELECT',
        )
        malformed = copy.deepcopy(changes)
        malformed[0]["hunks"][0]["lines"] = [object()]
        self.assertIsNone(runtime.tokenizer_keyword_patch(malformed, self.context))
        self.assertIsNone(
            runtime.load_context(
                b"not gzip", "0" * 64, self.sources_raw, self.sources_sha
            )
        )

    def test_source_inventory_binding_and_enum_tampering_fails_closed(self):
        sources = json.loads(gzip.decompress(self.sources_raw))
        attacks = (
            (
                "sqlglot/dialects/athena.py",
                "from sqlglot.tokens import TokenType",
                "from sqlglot.tokens import TokenType as TT",
            ),
            (
                "sqlglot/dialects/athena.py",
                '"UNLOAD": TokenType.COMMAND',
                '"UNLOAD2": TokenType.COMMAND',
            ),
            (
                "sqlglot/tokenizer_core.py",
                "    SELECT = auto()",
                "    SELECT = 1",
            ),
        )
        for path, old, new in attacks:
            with self.subTest(path=path, old=old):
                changed = copy.deepcopy(sources)
                self.assertIn(old, changed[path])
                changed[path] = changed[path].replace(old, new, 1)
                raw = gzip.compress(
                    json.dumps(changed, sort_keys=True, separators=(",", ":")).encode(),
                    compresslevel=9,
                    mtime=0,
                )
                self.assertIsNone(
                    runtime.load_context(
                        self.full_raw,
                        self.full_sha,
                        raw,
                        hashlib.sha256(raw).hexdigest(),
                    )
                )

    def test_context_is_immutable_and_does_not_alias_input(self):
        with self.assertRaises(TypeError):
            self.context.sources["sqlglot/tokens.py"] = "tampered"
        with self.assertRaises(TypeError):
            self.context.entries_by_path["sqlglot/tokens.py"] = ()
        with self.assertRaises(AttributeError):
            self.context.model_sha256 = "0" * 64


if __name__ == "__main__":
    unittest.main()
