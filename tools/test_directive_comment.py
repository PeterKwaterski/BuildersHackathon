import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
import selector


PATH = "sqlglot/fake_directive.py"


class DirectiveCommentTest(unittest.TestCase):
    def tearDown(self):
        selector._PINNED_SOURCES = None

    def change(self, added: str) -> dict:
        patch = (
            "diff --git a/{0} b/{0}\n"
            "--- a/{0}\n"
            "+++ b/{0}\n"
            "@@ -1,2 +1,3 @@\n"
            " class C:\n"
            "+    {2}\n"
            "     value = 1\n"
        ).format(PATH, 1, added)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "change.patch"
            path.write_text(patch)
            changes = selector.patch_changes(path)
        self.assertEqual(len(changes), 1)
        return changes[0]

    def assert_inert(self, comment: str) -> None:
        selector._PINNED_SOURCES = {PATH: "class C:\n    value = 1\n"}
        self.assertTrue(selector.inert_comment_addition(self.change(comment), PATH))

    def test_noqa_comment_is_runtime_inert(self):
        self.assert_inert("# noqa")

    def test_existing_ordinary_comment_proof_is_preserved(self):
        self.assert_inert("# ordinary comment")

    def test_type_ignore_comment_is_runtime_inert(self):
        self.assert_inert("# type: ignore")

    def test_formatter_and_pragma_comments_remain_rejected(self):
        selector._PINNED_SOURCES = {PATH: "class C:\n    value = 1\n"}
        self.assertFalse(selector.inert_comment_addition(self.change("# fmt: off"), PATH))
        self.assertFalse(
            selector.inert_comment_addition(self.change("# pragma: no cover"), PATH)
        )

    def test_encoding_comment_remains_rejected(self):
        selector._PINNED_SOURCES = {PATH: "class C:\n    value = 1\n"}
        self.assertFalse(
            selector.inert_comment_addition(self.change("# coding: latin-1"), PATH)
        )

    def test_typing_source_remains_rejected(self):
        path = "sqlglot/typing/fake_directive.py"
        selector._PINNED_SOURCES = {path: "class C:\n    value = 1\n"}
        change = self.change("# type: ignore")
        change["old"] = change["new"] = path
        self.assertFalse(selector.inert_comment_addition(change, path))

    def test_directive_suffix_remains_rejected(self):
        selector._PINNED_SOURCES = {PATH: "class C:\n    value = 1\n"}
        self.assertFalse(selector.inert_comment_addition(self.change("# noqa: F401"), PATH))

    def test_executable_ast_change_remains_rejected(self):
        selector._PINNED_SOURCES = {PATH: "class C:\n    value = 1\n"}
        change = self.change("# noqa")
        change["hunks"][0]["lines"].append(("+", "    other = 2"))
        change["added"].append("    other = 2")
        self.assertFalse(selector.inert_comment_addition(change, PATH))

    def test_corrupt_line_mapping_remains_rejected(self):
        selector._PINNED_SOURCES = {PATH: "class C:\n    value = 1\n"}
        change = self.change("# noqa")
        change["added_new_at"] = [(99, "    # noqa")]
        self.assertFalse(selector.inert_comment_addition(change, PATH))


if __name__ == "__main__":
    unittest.main()
