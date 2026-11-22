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
        return self.source_change("sqlglot/dialects/dialect.py", line, old, new)

    def source_change(self, path, line, old, new):
        patch = (
            f"diff --git a/{path} b/{path}\n"
            "index fed01b2..508980a 100644\n"
            f"--- a/{path}\n"
            f"+++ b/{path}\n"
            f"@@ -{line},1 +{line},1 @@\n"
            f"-{old}\n"
            f"+{new}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.patch"
            path.write_text(patch, encoding="utf-8")
            change = selector.patch_changes(path)[0]
        return selector.proven_enum_identity_equality(change, change["old"], set())

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

    def local_alias_ranges(self, body, signature="self, flag=True"):
        source = f"""\
from enum import Enum
class E(Enum):
    A = 1
class C:
    def __init__(self):
        self.value = E.A
    def f({signature}):
{body}
"""
        return SemanticProof({"sqlglot/x.py": source})._safe_ranges("sqlglot/x.py")

    def test_local_alias_conditional_store_rejects(self):
        self.assertEqual(
            self.local_alias_ranges(
                "        if flag:\n"
                "            alias = self.value\n"
                "        return alias is E.A"
            ),
            [],
        )

    def test_local_alias_parameter_rejects(self):
        self.assertEqual(
            self.local_alias_ranges(
                "        alias = self.value\n        return alias is E.A",
                signature="self, alias",
            ),
            [],
        )

    def test_local_alias_comprehension_rebind_rejects(self):
        self.assertEqual(
            self.local_alias_ranges(
                "        alias = self.value\n"
                "        values = [alias for alias in ()]\n"
                "        return alias is E.A"
            ),
            [],
        )

    def test_local_alias_nested_use_rejects(self):
        self.assertEqual(
            self.local_alias_ranges(
                "        alias = self.value\n"
                "        def nested():\n"
                "            return alias is E.A\n"
                "        return nested()"
            ),
            [],
        )

    def test_local_alias_use_before_store_rejects(self):
        self.assertEqual(
            self.local_alias_ranges(
                "        if alias is E.A:\n"
                "            return True\n"
                "        alias = self.value\n"
                "        return False"
            ),
            [],
        )

    def test_closed_parser_class_enum_sites_accept(self):
        for line, member in (
            (6399, "HIGH"),
            (6493, "LOW"),
            (6495, "EQUALITY"),
            (6497, "COMPARISON"),
        ):
            old = f"            self.IS_PREDICATE_PRECEDENCE is IsPredicatePrecedence.{member}"
            prefix = "if " if line != 6399 else ""
            if line != 6399:
                old = f"            if self.IS_PREDICATE_PRECEDENCE is IsPredicatePrecedence.{member}:"
            new = old.replace(" is ", " == ")
            with self.subTest(line=line):
                self.assertTrue(self.source_change("sqlglot/parser.py", line, old, new))

    def class_attribute_ranges(self, extra=""):
        source = f"""\
from enum import Enum
class E(Enum):
    A = 1
class C:
    MODE = E.A
    def f(self):
        return self.MODE is E.A
{extra}
"""
        return SemanticProof({"sqlglot/x.py": source})._safe_ranges("sqlglot/x.py")

    def test_closed_class_enum_accepts(self):
        self.assertEqual(self.class_attribute_ranges(), [(7, 7)])

    def test_closed_class_enum_rejects_instance_write(self):
        self.assertEqual(
            self.class_attribute_ranges("def hostile(item):\n    item.MODE = object()"),
            [],
        )

    def test_closed_class_enum_rejects_destructured_instance_write(self):
        self.assertEqual(
            self.class_attribute_ranges(
                "def hostile(item):\n    item.MODE, other = (E.A, None)"
            ),
            [],
        )

    def test_closed_class_enum_rejects_dynamic_setattr(self):
        self.assertEqual(
            self.class_attribute_ranges("def hostile(item, name):\n    setattr(item, name, object())"),
            [],
        )

    def test_closed_class_enum_rejects_namespace_literal(self):
        self.assertEqual(
            self.class_attribute_ranges(
                "def hostile(item):\n    vars(item)['MODE'] = object()"
            ),
            [],
        )

    def test_closed_class_enum_rejects_non_enum_override(self):
        self.assertEqual(
            self.class_attribute_ranges("class D(C):\n    MODE = object()"),
            [],
        )


if __name__ == "__main__":
    unittest.main()
