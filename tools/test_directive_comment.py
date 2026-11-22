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
            "index 0000000..1111111 100644\n"
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

    def test_mismatched_paths_and_markers_remain_rejected(self):
        selector._PINNED_SOURCES = {PATH: "class C:\n    value = 1\n"}
        for key, value in (
            ("old", "sqlglot/other.py"),
            ("new", "sqlglot/other.py"),
            ("diff_old", "sqlglot/other.py"),
            ("diff_new", "sqlglot/other.py"),
            ("old_marker_count", 2),
            ("new_marker_count", 2),
            ("index_count", 2),
            ("ordinary_file_index", False),
        ):
            change = self.change("# noqa")
            change[key] = value
            self.assertFalse(selector.inert_comment_addition(change, PATH), key)

    def test_structural_and_file_flags_remain_rejected(self):
        selector._PINNED_SOURCES = {PATH: "class C:\n    value = 1\n"}
        for key, value in (
            ("new_file_mode", "100644"),
            ("new_file_mode_count", 1),
            ("structural_invalid", True),
            ("binary", True),
            ("non_lf", True),
            ("no_newline_marker", True),
        ):
            change = self.change("# type: ignore")
            change[key] = value
            self.assertFalse(selector.inert_comment_addition(change, PATH), key)

    def test_mismatched_hunk_counts_and_coordinates_remain_rejected(self):
        selector._PINNED_SOURCES = {PATH: "class C:\n    value = 1\n"}
        for key, value in (
            ("old_start", 0),
            ("new_start", 2),
            ("old_count", 99),
            ("new_count", 99),
        ):
            change = self.change("# noqa")
            change["hunks"][0][key] = value
            self.assertFalse(selector.inert_comment_addition(change, PATH), key)


if __name__ == "__main__":
    unittest.main()
