import gzip
import json
import tempfile
import unittest
from pathlib import Path
import sys
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent))
import selector


class NewTestModuleProofTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with gzip.open(
            Path(__file__).parent.parent / "new_module_model.json.gz",
            "rt",
            encoding="utf-8",
        ) as profile_file:
            cls.profile = json.load(profile_file)

    def tearDown(self):
        selector._PINNED_SOURCES = None

    def changes(
        self,
        path="tests/test_fresh_kashimo.py",
        body="import unittest\n\nclass TestFresh(unittest.TestCase):\n    pass\n",
        mode="100644",
        extra_metadata=(),
        second_hunk=False,
        terminal_lf=True,
    ):
        lines = body.splitlines()
        patch_lines = [
            f"diff --git a/{path} b/{path}",
            f"new file mode {mode}",
            "index 0000000..1111111",
            *extra_metadata,
            "--- /dev/null",
            f"+++ b/{path}",
            f"@@ -0,0 +1,{len(lines)} @@",
            *(f"+{line}" for line in lines),
        ]
        if second_hunk:
            patch_lines.extend(("@@ -0,0 +10,1 @@", "+VALUE = 1"))
        patch = "\n".join((*patch_lines, ""))
        if not terminal_lf:
            patch = patch.rstrip("\n")
        with tempfile.NamedTemporaryFile("w", delete=False) as patch_file:
            patch_file.write(patch)
            patch_path = Path(patch_file.name)
        try:
            return selector.patch_changes(patch_path)
        finally:
            patch_path.unlink()

    def sources(self, text="VALUE = 1\n"):
        selector._PINNED_SOURCES = {"tests/test_existing.py": text}
        return {"tests/test_existing.py": {0}}

    def test_accepts_fresh_top_level_test_outside_roster(self):
        roster = self.sources()
        self.assertEqual(
            selector.isolated_new_test_indices(
                self.changes(), roster, self.profile
            ),
            set(),
        )

    def test_selected_indices_uses_early_empty_proof(self):
        roster = self.sources()
        changes = self.changes()
        with mock.patch.object(selector, "patch_changes", return_value=changes):
            self.assertEqual(
                selector.selected_indices(
                    Path("unused.patch"),
                    {"t": ["tests/test_existing.py::test_x"]},
                    {0},
                    roster,
                    new_module_model=self.profile,
                ),
                set(),
            )

    def test_rejects_non_test_nested_and_special_paths(self):
        roster = self.sources()
        for path in (
            "tests/helper_new.py",
            "tests/dialects/test_new.py",
            "tests/conftest.py",
            "tests/__init__.py",
        ):
            self.assertIsNone(
                selector.isolated_new_test_indices(
                    self.changes(path=path), roster, self.profile
                )
            )

    def test_rejects_name_or_dotted_name_referenced_by_source(self):
        for reference in (
            "import tests.test_fresh_kashimo\n",
            "NAME = 'test_fresh_kashimo'\n",
            "PATH = 'tests/test_fresh_kashimo.py'\n",
        ):
            roster = self.sources(reference)
            self.assertIsNone(
                selector.isolated_new_test_indices(
                    self.changes(), roster, self.profile
                )
            )

    def test_rejects_existing_roster_path(self):
        path = "tests/test_fresh_kashimo.py"
        selector._PINNED_SOURCES = {path: "VALUE = 1\n"}
        self.assertIsNone(
            selector.isolated_new_test_indices(
                self.changes(), {path: {0}}, self.profile
            )
        )

    def test_rejects_mode_symlink_copy_rename_and_multiple_hunks(self):
        roster = self.sources()
        for changes in (
            self.changes(mode="100755"),
            self.changes(mode="120000"),
            self.changes(extra_metadata=("copy from tests/old.py",)),
            self.changes(extra_metadata=("rename from tests/old.py",)),
            self.changes(second_hunk=True),
        ):
            self.assertIsNone(
                selector.isolated_new_test_indices(changes, roster, self.profile)
            )

    def test_rejects_syntax_plugin_multiple_changes_and_bad_evidence(self):
        roster = self.sources()
        self.assertIsNone(
            selector.isolated_new_test_indices(
                self.changes(body="def broken(:\n    pass\n"), roster, self.profile
            )
        )
        self.assertIsNone(
            selector.isolated_new_test_indices(
                self.changes(body='pytest_plugins = ["plugin"]\n'),
                roster,
                self.profile,
            )
        )
        self.assertIsNone(
            selector.isolated_new_test_indices(
                self.changes(body="VALUE = '" + ("x" * 66_000) + "'\n"),
                roster,
                self.profile,
            )
        )
        changes = self.changes()
        self.assertIsNone(
            selector.isolated_new_test_indices(
                changes + changes, roster, self.profile
            )
        )
        self.assertIsNone(
            selector.isolated_new_test_indices(self.changes(), roster, {})
        )

    def test_rejects_patch_without_terminal_lf(self):
        roster = self.sources()
        changes = self.changes(terminal_lf=False)
        self.assertEqual(len(changes), 1)
        self.assertIs(changes[0].get("terminal_lf"), False)
        self.assertIsNone(
            selector.isolated_new_test_indices(changes, roster, self.profile)
        )


if __name__ == "__main__":
    unittest.main()
