import copy
import gzip
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import selector


class ImportRuntimeSplitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with gzip.open(selector.IMPORT_LINE_PROFILE, "rt", encoding="utf-8") as source:
            cls.profile = json.load(source)

    def change(self, text: str) -> dict:
        with tempfile.NamedTemporaryFile("w", suffix=".patch", delete=False) as source:
            source.write(text)
            patch = Path(source.name)
        self.addCleanup(patch.unlink, missing_ok=True)
        changes = selector.patch_changes(patch)
        self.assertEqual(len(changes), 1)
        return changes[0]

    def artifact(self, payload: dict) -> tuple[Path, str]:
        raw = gzip.compress(
            json.dumps(payload, separators=(",", ":")).encode("utf-8"), mtime=0
        )
        with tempfile.NamedTemporaryFile("wb", suffix=".json.gz", delete=False) as target:
            target.write(raw)
            path = Path(target.name)
        self.addCleanup(path.unlink, missing_ok=True)
        return path, hashlib.sha256(raw).hexdigest()

    def test_artifact_digest_roster_and_schema_fail_closed(self) -> None:
        tests_path = Path(__file__).resolve().parents[1] / "sample/tests.json"
        tests = json.loads(tests_path.read_text(encoding="utf-8"))["tests"]
        digest = hashlib.sha256(
            "\0".join(test["id"] for test in tests).encode("utf-8")
        ).hexdigest()
        loaded = selector.load_import_line_profile(
            selector.IMPORT_LINE_PROFILE,
            selector.IMPORT_LINE_PROFILE_SHA256,
            self.profile["sha"],
            digest,
            tests,
        )
        self.assertEqual(loaded, self.profile)
        self.assertIsNone(
            selector.load_import_line_profile(
                selector.IMPORT_LINE_PROFILE, "0" * 64, self.profile["sha"], digest, tests
            )
        )
        for mutate in (
            lambda payload: payload.update(failures=[["x", "Error", "x"]]),
            lambda payload: payload.update(modules=[]),
            lambda payload: payload["files"].__setitem__(
                "sqlglot/parser.py", [False]
            ),
            lambda payload: payload["files"].__setitem__(
                "sqlglot/parser.py", [[8467]]
            ),
        ):
            payload = copy.deepcopy(self.profile)
            mutate(payload)
            path, artifact_digest = self.artifact(payload)
            self.assertIsNone(
                selector.load_import_line_profile(
                    path, artifact_digest, self.profile["sha"], digest, tests
                )
            )

    def test_public_parser_nonimport_branches_are_admitted(self) -> None:
        patches = (
            """diff --git a/sqlglot/parser.py b/sqlglot/parser.py
--- a/sqlglot/parser.py
+++ b/sqlglot/parser.py
@@ -8464,7 +8464,7 @@ class Parser:
             if isinstance(default, exp.Interval) and default.this.sql().upper() == "END":
                 default = exp.column("interval")
             else:
-                self.raise_error("Expected END after CASE", self._prev)
+                self.raise_error("Expected END after CASEX", self._prev)
\x20
         return self.expression(
""",
            """diff --git a/sqlglot/parser.py b/sqlglot/parser.py
--- a/sqlglot/parser.py
+++ b/sqlglot/parser.py
@@ -9076,7 +9076,7 @@ class Parser:
         if self.SUPPORTS_NTH_VALUE_FROM_MODIFIER and isinstance(this, exp.NthValue):
             if self._match_text_seq("FROM", "FIRST"):
                 this.set("from_first", True)
-            elif self._match_text_seq("FROM", "LAST"):
+            elif self._match_text_seq("FROMX", "LAST"):
                 this.set("from_first", False)
\x20
         # T-SQL allows the OVER (...) syntax after WITHIN GROUP.
""",
        )
        for patch in patches:
            change = self.change(patch)
            path = change["old"]
            self.assertTrue(selector.deferred_import_body_edit(change, path, self.profile))

    def test_import_executed_statement_is_rejected(self) -> None:
        change = self.change(
            """diff --git a/sqlglot/parser.py b/sqlglot/parser.py
--- a/sqlglot/parser.py
+++ b/sqlglot/parser.py
@@ -8440,7 +8440,7 @@ class Parser:
         return self.expression(exp.Slice(this=this, expression=end, step=step))
\x20
     def _parse_case(self) -> exp.Expr | None:
-        if self._match(TokenType.DOT, advance=False):
+        if self._match(TokenType.COMMA, advance=False):
             # Avoid raising on valid expressions like case.*, supported by, e.g., spark & snowflake
             self._retreat(self._index - 1)
             return None
"""
        )
        self.assertFalse(
            selector.deferred_import_body_edit(change, change["old"], self.profile)
        )

    def test_profile_and_owner_fail_closed(self) -> None:
        change = self.change(
            """diff --git a/sqlglot/parser.py b/sqlglot/parser.py
--- a/sqlglot/parser.py
+++ b/sqlglot/parser.py
@@ -8464,7 +8464,7 @@ class Parser:
             if isinstance(default, exp.Interval) and default.this.sql().upper() == "END":
                 default = exp.column("interval")
             else:
-                self.raise_error("Expected END after CASE", self._prev)
+                self.raise_error("Expected END after CASEX", self._prev)
\x20
         return self.expression(
"""
        )
        tampered = copy.deepcopy(self.profile)
        tampered["files"]["sqlglot/parser.py"].append(8467)
        self.assertFalse(selector.deferred_import_body_edit(change, change["old"], tampered))
        self.assertFalse(selector.deferred_import_body_edit(change, change["old"], None))

        uncensused = self.change(
            """diff --git a/sqlglot/parser.py b/sqlglot/parser.py
--- a/sqlglot/parser.py
+++ b/sqlglot/parser.py
@@ -8486,5 +8486,5 @@ class Parser:
     def _parse_if(self) -> exp.Expr | None:
-        if self._match(TokenType.L_PAREN):
+        if self._match(TokenType.R_PAREN):
             args = self._parse_csv(
"""
        )
        self.assertFalse(
            selector.deferred_import_body_edit(
                uncensused, uncensused["old"], self.profile
            )
        )

    def test_directive_code_observer_path_and_missing_profile_file_reject(self) -> None:
        base = """diff --git a/sqlglot/parser.py b/sqlglot/parser.py
--- a/sqlglot/parser.py
+++ b/sqlglot/parser.py
@@ -8464,7 +8464,7 @@ class Parser:
             if isinstance(default, exp.Interval) and default.this.sql().upper() == "END":
                 default = exp.column("interval")
             else:
-                self.raise_error("Expected END after CASE", self._prev)
+{replacement}
\x20
         return self.expression(
"""
        replacements = (
            '                self.raise_error("Expected END after CASEX", self._prev)  # noqa',
            "                self.raise_error(str(self._parse_case.__code__.co_consts), self._prev)",
        )
        for replacement in replacements:
            change = self.change(base.format(replacement=replacement))
            self.assertFalse(
                selector.deferred_import_body_edit(change, change["old"], self.profile)
            )

        change = self.change(
            base.format(
                replacement='                self.raise_error("Expected END after CASEX", self._prev)'
            )
        )
        missing = copy.deepcopy(self.profile)
        del missing["files"]["sqlglot/parser.py"]
        self.assertFalse(selector.deferred_import_body_edit(change, change["old"], missing))
        changed_header = copy.deepcopy(change)
        changed_header["diff_new"] = "sqlglot/parser2.py"
        self.assertFalse(
            selector.deferred_import_body_edit(
                changed_header, changed_header["old"], self.profile
            )
        )
        self.assertTrue(selector.parser_methods_are_call_only())

    def test_package_source_code_and_string_observers_reject(self) -> None:
        saved = (
            selector._PINNED_SOURCES,
            selector._SOURCE_TREES,
            selector._SOURCE_INDEXES,
            selector._PARSER_METHOD_CALL_ONLY,
        )

        def restore() -> None:
            (
                selector._PINNED_SOURCES,
                selector._SOURCE_TREES,
                selector._SOURCE_INDEXES,
                selector._PARSER_METHOD_CALL_ONLY,
            ) = saved

        self.addCleanup(restore)
        hostile_sources = (
            "observed = Parser._parse_case.__code__.co_consts\n",
            'observed = getattr(Parser, "_parse_window")\n',
        )
        for source in hostile_sources:
            selector._PINNED_SOURCES = {"sqlglot/hostile.py": source}
            selector._SOURCE_TREES = {}
            selector._SOURCE_INDEXES = {}
            selector._PARSER_METHOD_CALL_ONLY = None
            self.assertFalse(selector.parser_methods_are_call_only())


if __name__ == "__main__":
    unittest.main()
