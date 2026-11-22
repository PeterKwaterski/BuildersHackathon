from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).parent))

import selector
from verify_prospective_executor_memo import module_signature, state_signature


class TpcPlanCandidateTests(unittest.TestCase):
    def patch(self, source: str) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "case.patch"
        path.write_text(source, encoding="utf-8")
        return path

    def assert_patch_applies(self, patch: Path) -> None:
        change = selector.patch_changes(patch)[0]
        self.assertIsNotNone(selector.patched_source(change, change["old"]))

    def test_public_multi_statement_and_boolean_control_edits_are_rejected(self) -> None:
        self.assertFalse(
            selector.tpc_plan_patch_eligible(ROOT / "sample/commits/2jrq.patch")
        )

    def test_public_single_literal_edit_is_admitted(self) -> None:
        self.assertTrue(
            selector.tpc_plan_patch_eligible(ROOT / "sample/commits/5y72.patch")
        )

    def test_function_docstring_only_certificate(self) -> None:
        patch = self.patch(
            """diff --git a/sqlglot/optimizer/normalize.py b/sqlglot/optimizer/normalize.py
--- a/sqlglot/optimizer/normalize.py
+++ b/sqlglot/optimizer/normalize.py
@@ -26,6 +26,7 @@ def normalize(expression, dnf=False, max_distance=128):
         expression: expression to normalize
         dnf: rewrite in disjunctive normal form instead.
         max_distance (int): the maximal estimated distance from cnf/dnf to attempt conversion
+    # TODO: revisit
     Returns:
         sqlglot.Expr: normalized expression
     \"\"\"
"""
        )
        self.assertTrue(selector.tpc_function_docstring_only(patch))

    def test_behavioral_token_is_not_docstring_only(self) -> None:
        self.assertFalse(
            selector.tpc_function_docstring_only(ROOT / "sample/commits/5y72.patch")
        )

    def test_function_docstring_plus_behavior_is_not_docstring_only(self) -> None:
        patch = self.patch(
            """diff --git a/sqlglot/optimizer/normalize.py b/sqlglot/optimizer/normalize.py
--- a/sqlglot/optimizer/normalize.py
+++ b/sqlglot/optimizer/normalize.py
@@ -26,7 +26,7 @@ def normalize(expression, dnf=False, max_distance=128):
         expression: expression to normalize
         dnf: rewrite in disjunctive normal form instead.
-        max_distance (int): the maximal estimated distance from cnf/dnf to attempt conversion
+        max_distance (int): the maximal estimated distance from cnf/dnf to attempt conversion.
     Returns:
         sqlglot.Expr: normalized expression
     \"\"\"
-    simplifier = Simplifier(annotate_new_expressions=False)
+    simplifier = Simplifier(annotate_new_expressions=True)
"""
        )
        self.assert_patch_applies(patch)
        self.assertFalse(selector.tpc_function_docstring_only(patch))

    def test_module_docstring_is_not_function_docstring_only(self) -> None:
        patch = self.patch(
            """diff --git a/sqlglot/optimizer/normalize.py b/sqlglot/optimizer/normalize.py
--- a/sqlglot/optimizer/normalize.py
+++ b/sqlglot/optimizer/normalize.py
@@ -1,1 +1,3 @@
+\"\"\"Normalize SQL expressions.\"\"\"
+
 from __future__ import annotations
"""
        )
        self.assert_patch_applies(patch)
        self.assertFalse(selector.tpc_function_docstring_only(patch))

    def test_encoding_cookie_plus_docstring_is_not_docstring_only(self) -> None:
        patch = self.patch(
            """diff --git a/sqlglot/optimizer/normalize.py b/sqlglot/optimizer/normalize.py
--- a/sqlglot/optimizer/normalize.py
+++ b/sqlglot/optimizer/normalize.py
@@ -1,1 +1,2 @@
+# coding: unicode_escape
 from __future__ import annotations
@@ -26,6 +27,6 @@ def normalize(expression, dnf=False, max_distance=128):
         expression: expression to normalize
         dnf: rewrite in disjunctive normal form instead.
-        max_distance (int): the maximal estimated distance from cnf/dnf to attempt conversion
+        max_distance (int): the maximal estimated distance from cnf/dnf to attempt conversion.
     Returns:
         sqlglot.Expr: normalized expression
     \"\"\"
"""
        )
        self.assert_patch_applies(patch)
        self.assertFalse(selector.tpc_function_docstring_only(patch))

    def test_identifier_docstring_is_not_docstring_only(self) -> None:
        patch = self.patch(
            """diff --git a/sqlglot/optimizer/simplify.py b/sqlglot/optimizer/simplify.py
--- a/sqlglot/optimizer/simplify.py
+++ b/sqlglot/optimizer/simplify.py
@@ -274,7 +274,7 @@ def _datetrunc_eq_expression(
 def _datetrunc_eq_expression(
     left: exp.Expr, drange: DateRange, target_type: exp.DataType | None
 ) -> exp.Expr:
-    \"\"\"Get the logical expression for a date range\"\"\"
+    \"\"\"kashimo_unique_doc\"\"\"
     return exp.and_(
         left >= date_literal(drange[0], target_type),
         left < date_literal(drange[1], target_type),
"""
        )
        self.assert_patch_applies(patch)
        self.assertFalse(selector.tpc_function_docstring_only(patch))

    def test_non_optimizer_docstring_is_not_function_docstring_only(self) -> None:
        patch = self.patch(
            """diff --git a/sqlglot/expressions.py b/sqlglot/expressions.py
--- a/sqlglot/expressions.py
+++ b/sqlglot/expressions.py
@@ -1,1 +1,1 @@ def helper():
-    \"\"\"Old.\"\"\"
+    \"\"\"New.\"\"\"
"""
        )
        self.assertFalse(selector.tpc_function_docstring_only(patch))

    def test_state_signature_observes_mapping_replacement(self) -> None:
        state = {"ABS": abs, "ROUND": round}
        before = state_signature(state)
        state["ABS"] = round
        self.assertNotEqual(before, state_signature(state))

    def test_module_signature_observes_new_persistent_binding(self) -> None:
        class Module:
            pass

        module = Module()
        module.__dict__["safe"] = 1
        before = module_signature(module)
        module.__dict__["armed"] = True
        self.assertNotEqual(before, module_signature(module))


if __name__ == "__main__":
    unittest.main()
