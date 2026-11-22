import gzip
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
import sys
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent))
import selector


PINNED_CONFIG = """[mypy]
disallow_untyped_calls = False
no_implicit_optional = True

[mypy-sqlglot.*]
ignore_errors = False

[mypy-sqlglot.dataframe.*]
ignore_errors = False

[mypy-tests.*]
ignore_errors = True

[mypy-tests.dataframe.*]
ignore_errors = False
"""


class MypyConfigProofTest(unittest.TestCase):
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
        (self.root / "setup.cfg").write_text(PINNED_CONFIG, encoding="utf-8")
        self.root_patch = mock.patch.object(selector, "PINNED_SOURCE_ROOT", self.root)
        self.digest_patch = mock.patch.object(
            selector,
            "MYPY_CONFIG_SHA256",
            hashlib.sha256(PINNED_CONFIG.encode()).hexdigest(),
        )
        self.root_patch.start()
        self.digest_patch.start()

    def tearDown(self):
        self.digest_patch.stop()
        self.root_patch.stop()
        self.directory.cleanup()

    def parse_patch(self, lines):
        patch = "\n".join((*lines, ""))
        with tempfile.NamedTemporaryFile("w", delete=False) as patch_file:
            patch_file.write(patch)
            patch_path = Path(patch_file.name)
        try:
            return selector.patch_changes(patch_path)
        finally:
            patch_path.unlink()

    def changes(
        self,
        old="disallow_untyped_calls = False",
        new="disallow_untyped_calls = True",
    ):
        return self.parse_patch(
            (
                "diff --git a/setup.cfg b/setup.cfg",
                "index 0000000..1111111 100644",
                "--- a/setup.cfg",
                "+++ b/setup.cfg",
                "@@ -1,4 +1,4 @@",
                " [mypy]",
                f"-{old}",
                f"+{new}",
                " no_implicit_optional = True",
                " ",
            )
        )

    def header_changes(self):
        return self.parse_patch(
            (
                "diff --git a/setup.cfg b/setup.cfg",
                "index 0000000..1111111 100644",
                "--- a/setup.cfg",
                "+++ b/setup.cfg",
                "@@ -1,2 +1,2 @@",
                "-[mypy]",
                "+[tool:pytest]",
                " disallow_untyped_calls = False",
            )
        )

    def test_accepts_parseable_mypy_only_edit(self):
        self.assertEqual(
            selector.isolated_mypy_config_indices(self.changes(), self.profile), set()
        )

    def test_selected_indices_returns_empty(self):
        changes = self.changes()
        with mock.patch.object(selector, "patch_changes", return_value=changes):
            self.assertEqual(
                selector.selected_indices(
                    Path("unused.patch"),
                    {"t": []},
                    {1, 2},
                    new_module_model=self.profile,
                ),
                set(),
            )

    def test_rejects_non_mypy_section(self):
        changes = self.header_changes()
        self.assertIsNone(selector.isolated_mypy_config_indices(changes, self.profile))

    def test_rejects_malformed_config(self):
        changes = self.changes(new="invalid option")
        self.assertIsNone(selector.isolated_mypy_config_indices(changes, self.profile))

    def test_rejects_ambiguous_indented_section_syntax(self):
        changes = self.changes(new="  [tool:pytest]")
        self.assertIsNone(selector.isolated_mypy_config_indices(changes, self.profile))

    def test_rejects_wrong_path_and_multiple_files(self):
        changes = self.changes()
        changed_path = [dict(changes[0])]
        changed_path[0]["new"] = "tox.ini"
        self.assertIsNone(
            selector.isolated_mypy_config_indices(changed_path, self.profile)
        )
        self.assertIsNone(
            selector.isolated_mypy_config_indices(changes + changes, self.profile)
        )

    def test_rejects_missing_symlink_and_tampered_source(self):
        config = self.root / "setup.cfg"
        config.unlink()
        self.assertIsNone(
            selector.isolated_mypy_config_indices(self.changes(), self.profile)
        )
        config.symlink_to(self.root / "missing.cfg")
        self.assertIsNone(
            selector.isolated_mypy_config_indices(self.changes(), self.profile)
        )
        config.unlink()
        config.write_text(PINNED_CONFIG + "# tampered\n", encoding="utf-8")
        self.assertIsNone(
            selector.isolated_mypy_config_indices(self.changes(), self.profile)
        )

    def test_rejects_corrupt_source_census(self):
        corrupt = dict(self.profile)
        corrupt["r"] = []
        self.assertIsNone(
            selector.isolated_mypy_config_indices(self.changes(), corrupt)
        )


if __name__ == "__main__":
    unittest.main()
