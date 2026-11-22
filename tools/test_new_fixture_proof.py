import gzip
import json
import tempfile
import unittest
from pathlib import Path
import sys
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent))
import selector


class NewFixtureProofTest(unittest.TestCase):
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
        path="tests/fixtures/optimizer/fresh_kashimo.sql",
        body="SELECT 1;\nSELECT 1;\n",
        mode="100644",
        terminal_lf=True,
        second_hunk=False,
    ):
        lines = body.splitlines()
        patch_lines = [
            f"diff --git a/{path} b/{path}",
            f"new file mode {mode}",
            "index 0000000..1111111",
            "--- /dev/null",
            f"+++ b/{path}",
            f"@@ -0,0 +1,{len(lines)} @@",
            *(f"+{line}" for line in lines),
        ]
        if second_hunk:
            patch_lines.extend(("@@ -0,0 +10,1 @@", "+SELECT 2;"))
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

    def test_accepts_fresh_fixture_with_discovery_readers(self):
        self.sources()
        self.assertEqual(
            selector.isolated_new_fixture_indices(self.changes(), self.profile),
            set(self.profile["r"]),
        )

    def test_selected_indices_returns_discovery_readers(self):
        self.sources()
        changes = self.changes()
        with mock.patch.object(selector, "patch_changes", return_value=changes):
            self.assertEqual(
                selector.selected_indices(
                    Path("unused.patch"),
                    {"t": []},
                    set(self.profile["r"]),
                    {},
                    new_module_model=self.profile,
                ),
                set(self.profile["r"]),
            )

    def test_rejects_non_sql_hidden_traversal_and_outside_paths(self):
        self.sources()
        for path in (
            "tests/fixtures/optimizer/fresh.json",
            "tests/fixtures/.hidden/fresh.sql",
            "tests/fixtures/../fresh.sql",
            "tests/fresh.sql",
        ):
            self.assertIsNone(
                selector.isolated_new_fixture_indices(
                    self.changes(path=path), self.profile
                )
            )

    def test_rejects_any_source_reference(self):
        for reference in (
            "fresh_kashimo.sql",
            "optimizer/fresh_kashimo.sql",
            "tests/fixtures/optimizer/fresh_kashimo.sql",
            "optimizer/fresh_kashimo",
            "tests/fixtures/optimizer/fresh_kashimo",
        ):
            self.sources(f"PATH = {reference!r}\n")
            self.assertIsNone(
                selector.isolated_new_fixture_indices(self.changes(), self.profile)
            )

    def test_rejects_bad_mode_terminal_lf_hunks_and_size(self):
        self.sources()
        for changes in (
            self.changes(mode="120000"),
            self.changes(terminal_lf=False),
            self.changes(second_hunk=True),
            self.changes(body="x" * 66_000),
        ):
            self.assertIsNone(
                selector.isolated_new_fixture_indices(changes, self.profile)
            )

    def test_rejects_ambiguous_structure_and_path_metadata(self):
        self.sources()
        for field, value in (
            ("diff_old", "other.sql"),
            ("diff_new", "other.sql"),
            ("old_marker_count", 2),
            ("new_marker_count", 2),
            ("index_count", 2),
            ("new_file_index", False),
            ("ordinary_file_index", True),
            ("structural_invalid", True),
            ("binary", True),
            ("non_lf", True),
            ("no_newline_marker", True),
        ):
            changes = self.changes()
            changes[0][field] = value
            self.assertIsNone(
                selector.isolated_new_fixture_indices(changes, self.profile),
                field,
            )

    def test_complete_authenticated_census_is_required(self):
        self.sources()
        expected_kinds = {
            "dynamic-code",
            "dynamic-import",
            "directory-listing",
            "package-reflection",
            "path-probe",
            "source-reader",
            "subprocess",
        }
        self.assertTrue(expected_kinds.issubset({row[3] for row in self.profile["i"]}))
        for key in ("i", "r", "d"):
            corrupt = dict(self.profile)
            corrupt[key] = [] if key != "d" else "0" * 64
            self.assertIsNone(
                selector.isolated_new_fixture_indices(self.changes(), corrupt), key
            )

    def test_rejects_corrupt_discovery_evidence_and_multiple_files(self):
        self.sources()
        self.assertIsNone(selector.isolated_new_fixture_indices(self.changes(), {}))
        changes = self.changes()
        self.assertIsNone(
            selector.isolated_new_fixture_indices(changes + changes, self.profile)
        )


if __name__ == "__main__":
    unittest.main()
