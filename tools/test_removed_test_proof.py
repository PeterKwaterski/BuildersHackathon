import gzip
import json
import tempfile
import unittest
from pathlib import Path
import sys
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent))
import selector


OLD_PATH = "tests/dialects/test_kashimo.py"
RENAMED_PATH = "tests/dialects/moved_test_kashimo.py"
OLD_SOURCE = "class TestKashimo:\n    pass\n"


class RemovedTestProofTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with gzip.open(
            Path(__file__).parent.parent / "new_module_model.json.gz",
            "rt",
            encoding="utf-8",
        ) as profile_file:
            cls.profile = json.load(profile_file)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        old_file = self.root / OLD_PATH
        old_file.parent.mkdir(parents=True)
        old_file.write_text(OLD_SOURCE, encoding="utf-8")
        self.root_patch = mock.patch.object(selector, "PINNED_SOURCE_ROOT", self.root)
        self.sources_patch = mock.patch.object(
            selector,
            "_PINNED_SOURCES",
            {OLD_PATH: OLD_SOURCE, "tests/test_other.py": "VALUE = 1\n"},
        )
        self.root_patch.start()
        self.sources_patch.start()
        selector._SOURCE_TREES.clear()

    def tearDown(self):
        selector._SOURCE_TREES.clear()
        self.sources_patch.stop()
        self.root_patch.stop()
        self.directory.cleanup()

    def parse_patch(self, lines):
        patch = "\n".join((*lines, ""))
        with tempfile.NamedTemporaryFile("w", delete=False) as patch_file:
            patch_file.write(patch)
            path = Path(patch_file.name)
        try:
            return selector.patch_changes(path)
        finally:
            path.unlink()

    def deletion(self):
        return self.parse_patch(
            (
                f"diff --git a/{OLD_PATH} b/{OLD_PATH}",
                "deleted file mode 100644",
                "index 1111111..0000000",
                f"--- a/{OLD_PATH}",
                "+++ /dev/null",
                "@@ -1,2 +0,0 @@",
                "-class TestKashimo:",
                "-    pass",
            )
        )

    def rename(self, target=RENAMED_PATH):
        return self.parse_patch(
            (
                f"diff --git a/{OLD_PATH} b/{target}",
                "similarity index 100%",
                f"rename from {OLD_PATH}",
                f"rename to {target}",
            )
        )

    def readers(self, changes):
        return selector.isolated_renamed_test_indices(
            changes, {OLD_PATH: {7, 8}}, self.profile
        )

    def test_rejects_deletion(self):
        self.assertIsNone(self.readers(self.deletion()))

    def test_accepts_nondiscoverable_same_directory_rename(self):
        self.assertEqual(self.readers(self.rename()), set(self.profile["r"]) | {7, 8})

    def test_selected_indices_returns_file_and_discovery_readers(self):
        changes = self.rename()
        expected = set(self.profile["r"]) | {7, 8}
        with mock.patch.object(selector, "patch_changes", return_value=changes):
            self.assertEqual(
                selector.selected_indices(
                    Path("unused.patch"),
                    {"t": []},
                    expected,
                    {OLD_PATH: {7, 8}},
                    new_module_model=self.profile,
                ),
                expected,
            )

    def test_rejects_discoverable_cross_directory_and_existing_targets(self):
        self.assertIsNone(self.readers(self.rename("tests/dialects/test_moved.py")))
        self.assertIsNone(self.readers(self.rename("tests/moved_test_kashimo.py")))
        target = self.root / RENAMED_PATH
        target.write_text("collision\n", encoding="utf-8")
        self.assertIsNone(self.readers(self.rename()))

    def test_rejects_static_import_and_string_references(self):
        for reference in (
            "import tests.dialects.test_kashimo\n",
            "from tests.dialects import test_kashimo\n",
            "PLUGIN = 'tests.dialects.test_kashimo'\n",
            "PLUGIN = 'test_kashimo'\n",
            "import tests.dialects.moved_test_kashimo\n",
            "PLUGIN = 'tests.dialects.moved_test_kashimo'\n",
        ):
            selector._PINNED_SOURCES["tests/test_other.py"] = reference
            selector._SOURCE_TREES.clear()
            self.assertIsNone(self.readers(self.rename()), reference)

    def test_rejects_missing_roster_and_corrupt_census(self):
        self.assertIsNone(
            selector.isolated_renamed_test_indices(self.rename(), {}, self.profile)
        )
        corrupt = dict(self.profile)
        corrupt["r"] = []
        self.assertIsNone(
            selector.isolated_renamed_test_indices(
                self.rename(), {OLD_PATH: {7, 8}}, corrupt
            )
        )

    def test_rejects_missing_and_symlink_old_file(self):
        old_file = self.root / OLD_PATH
        old_file.unlink()
        self.assertIsNone(self.readers(self.rename()))
        old_file.symlink_to(self.root / "missing.py")
        self.assertIsNone(self.readers(self.rename()))


if __name__ == "__main__":
    unittest.main()
