import tempfile
import unittest
from pathlib import Path

import selector
from semantic import SemanticProof


PATCH = Path(__file__).parents[1] / "sample" / "commits" / "2haz.patch"
ADDED = "+            if self.normalization_strategy == NormalizationStrategy.UPPERCASE"


class EnumIdentityEqualityTest(unittest.TestCase):
    def change(self, transform=lambda text: text):
        patch = transform(PATCH.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.patch"
            path.write_text(patch, encoding="utf-8")
            changes = selector.patch_changes(path)
        self.assertEqual(len(changes), 1)
        return changes[0]

    def admitted(self, change):
        return selector.proven_enum_identity_equality(
            change, "sqlglot/dialects/dialect.py", set()
        )

    def dialect_change(self, line, old, new):
        patch = (
            "diff --git a/sqlglot/dialects/dialect.py b/sqlglot/dialects/dialect.py\n"
            "index fed01b2..508980a 100644\n"
            "--- a/sqlglot/dialects/dialect.py\n"
            "+++ b/sqlglot/dialects/dialect.py\n"
            f"@@ -{line},1 +{line},1 @@\n"
            f"-{old}\n"
            f"+{new}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.patch"
            path.write_text(patch, encoding="utf-8")
            change = selector.patch_changes(path)[0]
        return self.admitted(change)

    def test_exact_operator_only_edit_accepts(self):
        self.assertTrue(self.admitted(self.change()))

    def test_same_line_comment_rejects(self):
        self.assertFalse(
            self.admitted(self.change(lambda text: text.replace(ADDED, ADDED + "  # note")))
        )

    def test_same_line_whitespace_rejects(self):
        self.assertFalse(
            self.admitted(
                self.change(lambda text: text.replace(ADDED, ADDED.replace(" == ", "  == ")))
            )
        )

    def test_extra_operand_change_rejects(self):
        self.assertFalse(
            self.admitted(
                self.change(lambda text: text.replace(ADDED, ADDED.replace("UPPERCASE", "LOWERCASE")))
            )
        )

    def test_additional_line_change_rejects(self):
        self.assertFalse(
            self.admitted(
                self.change(
                    lambda text: text.replace(
                        "             else str.isupper",
                        "-            else str.isupper\n+            else str.lower",
                    )
                )
            )
        )

    def test_certified_local_alias_sites_accept(self):
        for line, member in (
            (1223, "CASE_SENSITIVE"),
            (1226, "CASE_INSENSITIVE_EXCEPT_TABLES"),
        ):
            old = f"        if strategy is NormalizationStrategy.{member}:"
            new = f"        if strategy == NormalizationStrategy.{member}:"
            with self.subTest(line=line):
                self.assertTrue(self.dialect_change(line, old, new))

    def test_local_alias_with_any_unproved_write_rejects(self):
        safe = """\
from enum import Enum
class E(Enum):
    A = 1
class C:
    def f(self):
        self.value = E.A
        alias = self.value
        return alias is E.A
"""
        hostile = safe.replace(
            "        return alias is E.A\n",
            "        alias = object()\n        return alias is E.A\n",
        )
        self.assertTrue(SemanticProof({"sqlglot/x.py": safe}).covers("sqlglot/x.py", {8}))
        self.assertFalse(
            SemanticProof({"sqlglot/x.py": hostile}).covers("sqlglot/x.py", {9})
        )


if __name__ == "__main__":
    unittest.main()
