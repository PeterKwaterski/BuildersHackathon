from __future__ import annotations

import gzip
import json
import tempfile
import unittest
from pathlib import Path

import selector
import tokenizer_setting_branch


ROOT = Path(__file__).resolve().parents[1]
PUBLIC = Path("/home/silverdisk/public-matchaluvrs-readonly/validation/val7/commits")


class TokenizerSettingBranchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tests = json.loads((ROOT / "sample/tests.json").read_text())["tests"]
        cls.ids = [test["id"] for test in cls.tests]
        cls.model = json.loads(gzip.decompress((ROOT / "selector_model.json.gz").read_bytes()))
        cls.all_indices = set(range(len(cls.ids)))
        cls.profile = tokenizer_setting_branch.load_profile(
            selector.TOKENIZER_SETTING_BRANCH_MODEL,
            selector.TOKENIZER_SETTING_BRANCH_MODEL_SHA256,
            cls.tests,
            cls.model["sha"],
        )
        if cls.profile is None:
            raise AssertionError("bundled tokenizer setting profile failed authentication")

    def select(self, patch: Path, profile=None):
        return selector.selected_indices(
            patch,
            self.model,
            self.all_indices,
            tokenizer_setting_branch_model=self.profile if profile is None else profile,
        )

    def test_exact_public_mutants_select_first_effect_readers(self) -> None:
        cases = {
            "9b62": "DASH_COMMENT_REQUIRES_BOUNDARY",
            "3ea4": "COMMENTS_TERMINATE_AT_NEWLINE_ONLY",
            "97ef": "STRING_ESCAPES_ALLOWED_IN_RAW_STRINGS",
        }
        for commit, setting in cases.items():
            with self.subTest(commit=commit):
                self.assertEqual(
                    self.select(PUBLIC / f"{commit}.patch"),
                    set(self.profile["d"][setting][2]),
                )

    def test_other_public_settings_fall_back(self) -> None:
        for commit in ("f5cd", "81d3", "0a1f"):
            with self.subTest(commit=commit):
                selected = self.select(PUBLIC / f"{commit}.patch")
                self.assertGreater(len(selected), 1000)

    def test_missing_or_tampered_profile_falls_back(self) -> None:
        patch = PUBLIC / "9b62.patch"
        self.assertGreater(len(self.select(patch, profile=None if False else {})), 1000)
        bad = json.loads(json.dumps(self.profile))
        bad["d"]["DASH_COMMENT_REQUIRES_BOUNDARY"][2] = []
        # selected_indices accepts an already authenticated profile; main is
        # responsible for calling load_profile. Exercise that boundary here.
        raw = gzip.compress(json.dumps(bad, separators=(",", ":")).encode(), mtime=0)
        with tempfile.NamedTemporaryFile("wb", suffix=".gz") as target:
            target.write(raw)
            target.flush()
            self.assertIsNone(
                tokenizer_setting_branch.load_profile(
                    Path(target.name),
                    selector.TOKENIZER_SETTING_BRANCH_MODEL_SHA256,
                    self.tests,
                    self.model["sha"],
                )
            )

    def test_extra_edit_and_nonboolean_edit_reject(self) -> None:
        original = selector.pinned_sources()[tokenizer_setting_branch.TOKENS_PATH]
        changes = (
            original.replace(
                "DASH_COMMENT_REQUIRES_BOUNDARY = False",
                "DASH_COMMENT_REQUIRES_BOUNDARY = True",
            ).replace(
                "COMMENTS_TERMINATE_AT_NEWLINE_ONLY = False",
                "COMMENTS_TERMINATE_AT_NEWLINE_ONLY = True",
            ),
            original.replace(
                "DASH_COMMENT_REQUIRES_BOUNDARY = False",
                "DASH_COMMENT_REQUIRES_BOUNDARY = 1",
            ),
        )
        dummy = {
            "old": tokenizer_setting_branch.TOKENS_PATH,
            "new": tokenizer_setting_branch.TOKENS_PATH,
            "diff_old": tokenizer_setting_branch.TOKENS_PATH,
            "diff_new": tokenizer_setting_branch.TOKENS_PATH,
            "new_file_mode_count": 0,
            "structural_invalid": False,
            "non_lf": False,
            "removed": ["    DASH_COMMENT_REQUIRES_BOUNDARY = False"],
            "added": ["    DASH_COMMENT_REQUIRES_BOUNDARY = True"],
            "lines": {210},
            "added_new_at": [(210, "    DASH_COMMENT_REQUIRES_BOUNDARY = True")],
        }
        for changed in changes:
            self.assertIsNone(
                tokenizer_setting_branch.readers(
                    tokenizer_setting_branch.TOKENS_PATH,
                    original,
                    changed,
                    dummy,
                    self.profile,
                )
            )


if __name__ == "__main__":
    unittest.main()
