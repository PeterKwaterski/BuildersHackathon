import gzip
import json
import unittest
from pathlib import Path

import binary_copy_patch as binary


ROOT = Path(__file__).resolve().parents[1]
MODEL = json.load(gzip.open(ROOT / "selector_model.json.gz", "rt"))
TEST_IDS = MODEL["t"]
PINNED = {
    "tests/fixtures/optimizer/tpc-ds/item.csv.gz": "effacb3a0fcbdd655beba8be45966744e60108ca",
    "tests/fixtures/jsonpath/cts.json": "11af641ad0b17a5ff4554336e470256c623381f6",
    "posts/onboarding_images/lineage_img.png": "0" * 40,
}


def git_binary(path="tests/fixtures/optimizer/tpc-ds/item.csv.gz"):
    old = PINNED.get(path, "1" * 40)
    return f"""diff --git a/{path} b/{path}
index {old}..{'2' * 40} 100644
GIT binary patch
literal 1
KcmZQzKmY&$0RR91

literal 1
KcmZQzKmY&$0RR91
"""


class BinaryCopyPatchTest(unittest.TestCase):
    def test_tpc_binary_replacement_selects_complete_executor_class_and_fixture_owners(self):
        selected = binary.fixture_binary_readers(git_binary(), MODEL, TEST_IDS, PINNED)
        self.assertIsNotNone(selected)
        executor = {
            index for index, test_id in enumerate(TEST_IDS)
            if test_id.startswith("tests/test_executor.py::TestExecutor::")
        }
        fixture = set(MODEL["z"][MODEL["x"]["tests/fixtures/optimizer/tpc-ds/item.csv.gz"]])
        self.assertEqual(selected, executor | fixture)
        self.assertEqual(len(executor), 60)

    def test_binary_files_differ_form_binds_both_paths(self):
        path = "tests/fixtures/jsonpath/cts.json"
        patch = (
            f"diff --git a/{path} b/{path}\n"
            f"index {PINNED[path]}..{'3' * 40} 100644\n"
            f"Binary files a/{path} and b/{path} differ\n"
        )
        self.assertEqual(
            binary.fixture_binary_readers(patch, MODEL, TEST_IDS, PINNED),
            set(MODEL["z"][MODEL["x"][path]]),
        )

    def test_copy_rename_add_delete_and_mode_changes_are_rejected(self):
        additions = (
            "copy from old.bin\ncopy to new.bin",
            "similarity index 100%\nrename from old.bin\nrename to new.bin",
            "new file mode 100644",
            "deleted file mode 100644",
            "old mode 100644\nnew mode 100755",
        )
        for addition in additions:
            with self.subTest(addition=addition):
                self.assertIsNone(binary.parse_existing_binary_replacement(git_binary() + addition + "\n"))

    def test_symlink_gitlink_text_hunk_and_mixed_sections_are_rejected(self):
        for addition in (
            "old mode 100644\nnew mode 120000",
            "index 1111111..2222222 160000",
            "@@ -1 +1 @@\n-old\n+new",
            git_binary("tests/fixtures/jsonpath/cts.json"),
        ):
            with self.subTest(addition=addition[:30]):
                self.assertIsNone(binary.parse_existing_binary_replacement(git_binary() + addition + "\n"))

    def test_quoted_space_traversal_absolute_backslash_and_path_mismatch_rejected(self):
        bad = (
            git_binary("../escape.bin"),
            git_binary("/absolute.bin"),
            git_binary("tests\\fixture.bin"),
            'diff --git "a/x y" "b/x y"\nGIT binary patch\nliteral 1\nabc\n',
            "diff --git a/x.bin b/y.bin\nBinary files a/x.bin and b/y.bin differ\n",
            "diff --git a/x.bin b/x.bin\nBinary files a/y.bin and b/x.bin differ\n",
        )
        for patch in bad:
            with self.subTest(patch=patch.splitlines()[0]):
                self.assertIsNone(binary.parse_existing_binary_replacement(patch))

    def test_unknown_and_inert_unmodeled_assets_are_rejected(self):
        self.assertIsNone(binary.fixture_binary_readers(
            git_binary("posts/onboarding_images/lineage_img.png"), MODEL, TEST_IDS, PINNED
        ))

    def test_preimage_new_blob_mode_and_payload_tamper_fail_closed(self):
        path = "tests/fixtures/jsonpath/cts.json"
        valid = git_binary(path)
        cases = (
            valid.replace(PINNED[path], "f" * 40),
            valid.replace("2" * 40, PINNED[path]),
            valid.replace("100644", "100755"),
            valid.replace("literal 1\nKcmZQzKmY&$0RR91", "not-a-binary-body"),
        )
        for patch in cases:
            with self.subTest(header=patch.splitlines()[1]):
                self.assertIsNone(binary.fixture_binary_readers(
                    patch, MODEL, TEST_IDS, PINNED
                ))
        self.assertIsNone(binary.fixture_binary_readers(
            git_binary("tests/fixtures/not-profiled.bin"), MODEL, TEST_IDS,
            {**PINNED, "tests/fixtures/not-profiled.bin": "1" * 40},
        ))

    def test_model_path_and_identity_tamper_fail_closed(self):
        path = "tests/fixtures/jsonpath/cts.json"
        patch = git_binary(path)
        for changed in (
            {**MODEL, "sha": "0" * 40},
            {**MODEL, "t": TEST_IDS[:-1]},
            {**MODEL, "x": {**MODEL["x"], path: len(MODEL["z"]) + 1}},
        ):
            with self.subTest(keys=changed.keys()):
                self.assertIsNone(binary.fixture_binary_readers(patch, changed, TEST_IDS, PINNED))

    def test_default_off(self):
        self.assertFalse(binary.FEATURE_ENABLED)


if __name__ == "__main__":
    unittest.main()
