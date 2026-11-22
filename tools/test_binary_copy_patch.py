import gzip
import copy
import json
import tempfile
import unittest
import zlib
from pathlib import Path

import binary_copy_patch as binary
import selector


ROOT = Path(__file__).resolve().parents[1]
MODEL = json.load(gzip.open(ROOT / "selector_model.json.gz", "rt"))
TEST_IDS = MODEL["t"]
PREIMAGES = json.load(gzip.open(ROOT / "fixture_binary_preimages.json.gz", "rt"))
PINNED = PREIMAGES["paths"]


ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"


def encoded_chunk(kind="literal", raw=b"\x01"):
    compressed = zlib.compress(raw)
    lines = []
    for offset in range(0, len(compressed), 52):
        block = compressed[offset:offset + 52]
        prefix = chr(64 + len(block)) if len(block) <= 26 else chr(70 + len(block))
        encoded = ""
        padded = block + b"\0" * (-len(block) % 4)
        for group in range(0, len(padded), 4):
            value = int.from_bytes(padded[group:group + 4], "big")
            chars = []
            for _ in range(5):
                chars.append(ALPHABET[value % 85])
                value //= 85
            encoded += "".join(reversed(chars))
        lines.append(prefix + encoded)
    return f"{kind} {len(raw)}\n" + "\n".join(lines)


def git_binary(path="tests/fixtures/optimizer/tpc-ds/item.csv.gz", first=None, second=None):
    old = PINNED.get(path, "1" * 40)
    first = first or encoded_chunk()
    second = second or encoded_chunk(raw=b"\x00")
    return f"""diff --git a/{path} b/{path}
index {old}..{'2' * 40} 100644
GIT binary patch
{first}

{second}
"""


def binary_differ(path="tests/fixtures/optimizer/tpc-ds/item.csv.gz"):
    return (
        f"diff --git a/{path} b/{path}\n"
        f"index {PINNED.get(path, '1' * 40)}..{'3' * 40} 100644\n"
        f"Binary files a/{path} and b/{path} differ\n"
    )


class BinaryCopyPatchTest(unittest.TestCase):
    def test_tpc_binary_replacement_selects_complete_executor_class_and_fixture_owners(self):
        selected = binary.fixture_binary_readers(binary_differ(), MODEL, TEST_IDS, PREIMAGES)
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
        patch = binary_differ(path)
        self.assertEqual(
            binary.fixture_binary_readers(patch, MODEL, TEST_IDS, PREIMAGES),
            set(MODEL["z"][MODEL["x"][path]]),
        )

    def test_literal_and_delta_forward_reverse_chunks_are_admitted(self):
        for first, second in (
            (encoded_chunk(), encoded_chunk(raw=b"\0")),
            (encoded_chunk("delta", b"\x01\x01\x01A"), encoded_chunk(raw=b"\0")),
            (encoded_chunk(), encoded_chunk("delta", b"\x01\x01\x01A")),
        ):
            with self.subTest(first=first.splitlines()[0], second=second.splitlines()[0]):
                self.assertIsNotNone(binary.parse_existing_binary_replacement(
                    git_binary(first=first, second=second)
                ))

    def test_malformed_base85_prefix_alphabet_and_group_length_are_rejected(self):
        line = encoded_chunk().splitlines()[1]
        cases = (
            git_binary().replace(line, "0" + line[1:], 1),
            git_binary().replace(line, line[:6] + "/" + line[7:], 1),
            git_binary().replace(line, line[:-1], 1),
            git_binary().replace(line, line + "2", 1),
            git_binary().replace(line, "z" + line[1:], 1),
        )
        for patch in cases:
            with self.subTest(line=patch.splitlines()[4]):
                self.assertIsNone(binary.parse_existing_binary_replacement(patch))

    def test_chunk_headers_counts_and_separation_fail_closed(self):
        valid = git_binary()
        cases = (
            valid.replace("literal 1", "literal -1", 1),
            valid.replace("literal 1", "literal 01", 1),
            valid.replace("literal 1", "literal", 1),
            valid.replace("literal 1", "literal 99999999999999999999", 1),
            valid.split("\nliteral 1\n", 1)[0] + "\n",
            valid + "\n" + encoded_chunk() + "\n",
            valid.replace("\n\nliteral 1", "\nliteral 1"),
        )
        for patch in cases:
            with self.subTest(size=len(patch)):
                self.assertIsNone(binary.parse_existing_binary_replacement(patch))

    def test_zlib_literal_length_and_delta_instruction_tamper_fail_closed(self):
        valid = git_binary()
        line = encoded_chunk().splitlines()[1]
        self.assertIsNone(binary.parse_existing_binary_replacement(
            valid.replace("literal 1", "literal 2", 1)
        ))
        self.assertIsNone(binary.parse_existing_binary_replacement(
            valid.replace(line, line[:-1] + ("0" if line[-1] != "0" else "1"), 1)
        ))
        for raw in (
            b"",
            b"\x01",
            b"\x01\x01\x00",
            b"\x01\x01\x02A",
            b"\x01\x01\x91\x02\x01",
        ):
            self.assertIsNone(binary._delta_sizes(raw))
        self.assertEqual(binary._delta_sizes(b"\x01\x01\x01A"), (1, 1))

    def test_duplicate_and_late_structural_metadata_are_rejected(self):
        valid = git_binary()
        cases = (
            valid.replace("GIT binary patch", "GIT binary patch\nGIT binary patch"),
            valid + f"index {'1' * 40}..{'2' * 40} 100644\n",
            valid + "copy from x\ncopy to y\n",
            valid + "old mode 100644\nnew mode 100755\n",
            valid + "@@ -1 +1 @@\n-a\n+b\n",
        )
        for patch in cases:
            with self.subTest(tail=patch.splitlines()[-1]):
                self.assertIsNone(binary.parse_existing_binary_replacement(patch))

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
            git_binary().replace("\n", "\r\n"),
        )
        for patch in bad:
            with self.subTest(patch=patch.splitlines()[0]):
                self.assertIsNone(binary.parse_existing_binary_replacement(patch))

    def test_unknown_and_inert_unmodeled_assets_are_rejected(self):
        self.assertIsNone(binary.fixture_binary_readers(
            binary_differ("posts/onboarding_images/lineage_img.png"), MODEL, TEST_IDS, PREIMAGES
        ))

    def test_preimage_new_blob_mode_and_payload_tamper_fail_closed(self):
        path = "tests/fixtures/jsonpath/cts.json"
        valid = binary_differ(path)
        cases = (
            valid.replace(PINNED[path], "f" * 40),
            valid.replace("3" * 40, PINNED[path]),
            valid.replace("100644", "100755"),
            git_binary(path).replace(
                encoded_chunk().splitlines()[1], encoded_chunk().splitlines()[1][:-1] + "3", 1
            ),
        )
        for patch in cases:
            with self.subTest(header=patch.splitlines()[1]):
                self.assertIsNone(binary.fixture_binary_readers(
                    patch, MODEL, TEST_IDS, PREIMAGES
                ))
        self.assertIsNone(binary.fixture_binary_readers(
            binary_differ("tests/fixtures/not-profiled.bin"), MODEL, TEST_IDS,
            {**PREIMAGES, "paths": {**PINNED, "tests/fixtures/not-profiled.bin": "1" * 40}},
        ))

    def test_model_path_and_identity_tamper_fail_closed(self):
        path = "tests/fixtures/jsonpath/cts.json"
        patch = binary_differ(path)
        for changed in (
            {**MODEL, "sha": "0" * 40},
            {**MODEL, "t": TEST_IDS[:-1]},
            {**MODEL, "x": {**MODEL["x"], path: len(MODEL["z"]) + 1}},
        ):
            with self.subTest(keys=changed.keys()):
                self.assertIsNone(binary.fixture_binary_readers(patch, changed, TEST_IDS, PREIMAGES))

    def test_preimage_document_tamper_fails_closed(self):
        path = "tests/fixtures/jsonpath/cts.json"
        patch = binary_differ(path)
        changes = []
        for key, value in (
            ("revision", "0" * 40),
            ("model_sha256", "0" * 64),
            ("test_id_sha256", "0" * 64),
            ("profile_sha256", "0" * 64),
        ):
            document = {**PREIMAGES, key: value}
            changes.append(document)
        document = copy.deepcopy(PREIMAGES)
        document["paths"][path] = "0" * 40
        changes.append(document)
        document = copy.deepcopy(PREIMAGES)
        document["sizes"][path] += 1
        changes.append(document)
        for document in changes:
            self.assertIsNone(binary.fixture_binary_readers(patch, MODEL, TEST_IDS, document))

    def test_union_stacks_distinct_sections_and_rejects_duplicate_or_bad_member(self):
        tpc = binary_differ()
        cts = binary_differ("tests/fixtures/jsonpath/cts.json")
        expected = (
            binary.fixture_binary_readers(tpc, MODEL, TEST_IDS, PREIMAGES)
            | binary.fixture_binary_readers(cts, MODEL, TEST_IDS, PREIMAGES)
        )
        self.assertEqual(binary.fixture_binary_union([tpc, cts], MODEL, TEST_IDS, PREIMAGES), expected)
        self.assertIsNone(binary.fixture_binary_union([tpc, tpc], MODEL, TEST_IDS, PREIMAGES))
        self.assertIsNone(binary.fixture_binary_union([tpc, cts + "copy from x\n"], MODEL, TEST_IDS, PREIMAGES))

    def test_complete_patch_classifier_accepts_binary_only_and_rejects_mixed_or_prefixed(self):
        tpc = binary_differ()
        cts = binary_differ("tests/fixtures/jsonpath/cts.json")
        expected = (
            binary.fixture_binary_readers(tpc, MODEL, TEST_IDS, PREIMAGES)
            | binary.fixture_binary_readers(cts, MODEL, TEST_IDS, PREIMAGES)
        )
        self.assertEqual(binary.binary_patch_readers(tpc + "\n" + cts, MODEL, TEST_IDS, PREIMAGES), expected)
        self.assertIsNone(binary.binary_patch_readers("subject line\n" + tpc, MODEL, TEST_IDS, PREIMAGES))
        self.assertIsNone(binary.binary_patch_readers(tpc + "\n" + "diff --git a/x.py b/x.py\n", MODEL, TEST_IDS, PREIMAGES))

    def test_selector_integration_uses_binary_result_and_mixed_patch_fails_closed(self):
        tpc = binary_differ()
        expected = binary.fixture_binary_readers(tpc, MODEL, TEST_IDS, PREIMAGES)
        all_indices = set(range(len(TEST_IDS)))
        text = (
            "diff --git a/sqlglot/helper.py b/sqlglot/helper.py\n"
            "index 0000000..1111111 100644\n"
            "--- a/sqlglot/helper.py\n+++ b/sqlglot/helper.py\n"
            "@@ -1 +1 @@\n-old\n+new\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            patch = Path(directory) / "change.patch"
            patch.write_text(tpc, encoding="utf-8")
            self.assertEqual(
                selector.selected_indices(
                    patch, MODEL, all_indices, binary_preimages=PREIMAGES
                ),
                expected,
            )
            patch.write_text(tpc + "\n" + text, encoding="utf-8")
            self.assertEqual(
                selector.selected_indices(
                    patch, MODEL, all_indices, binary_preimages=PREIMAGES
                ),
                all_indices,
            )

    def test_pinned_artifact_loader(self):
        self.assertEqual(
            binary.load_preimages(
                ROOT / "fixture_binary_preimages.json.gz",
                ROOT / "selector_model.json.gz",
                MODEL,
                TEST_IDS,
            ),
            PREIMAGES,
        )

    def test_feature_enabled_after_integration(self):
        self.assertTrue(binary.FEATURE_ENABLED)


if __name__ == "__main__":
    unittest.main()
