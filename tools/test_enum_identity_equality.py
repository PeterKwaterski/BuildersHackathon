import tempfile
import unittest
from pathlib import Path

import selector


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


if __name__ == "__main__":
    unittest.main()
