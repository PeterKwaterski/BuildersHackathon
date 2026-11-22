import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from run_tokenizer_mutant_roster import (
    BASELINE_TOKENS_SHA256,
    PINNED_HEAD,
    authenticate_source,
    normalize_failures,
)


class TokenizerMutantRosterTests(unittest.TestCase):
    def test_exact_and_subfailed_nodeids_map_to_roster_parent(self) -> None:
        ids = [
            "tests/test_x.py::TestX::test_a",
            "tests/test_x.py::TestX::test_a_long",
        ]
        normalized, unmapped = normalize_failures(
            {
                ids[0],
                ids[0] + " (value=1)",
                ids[1] + " (value=2)",
            },
            ids,
        )
        self.assertEqual(normalized, ids)
        self.assertEqual(unmapped, [])

    def test_prefix_without_subtest_separator_and_collect_failure_are_unmapped(self) -> None:
        test_id = "tests/test_x.py::TestX::test_a"
        normalized, unmapped = normalize_failures(
            {test_id + "_suffix", "tests/test_x.py"}, [test_id]
        )
        self.assertEqual(normalized, [])
        self.assertEqual(unmapped, ["tests/test_x.py", test_id + "_suffix"])

    def test_baseline_source_authentication_binds_head_cleanliness_and_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sqlglot").mkdir()
            (root / "sqlglot" / "tokens.py").write_bytes(b"pinned")
            with (
                patch("run_tokenizer_mutant_roster.sha256_file", return_value=BASELINE_TOKENS_SHA256),
                patch(
                    "run_tokenizer_mutant_roster.git",
                    side_effect=[PINNED_HEAD.encode() + b"\n", b""],
                ),
            ):
                source = authenticate_source(root, None, None)
        self.assertEqual(source["head"], PINNED_HEAD)
        self.assertEqual(source["status"], "")
        self.assertIsNone(source["mutant_id"])

    def test_baseline_rejects_dirty_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sqlglot").mkdir()
            (root / "sqlglot" / "tokens.py").write_bytes(b"pinned")
            with (
                patch("run_tokenizer_mutant_roster.sha256_file", return_value=BASELINE_TOKENS_SHA256),
                patch(
                    "run_tokenizer_mutant_roster.git",
                    side_effect=[PINNED_HEAD.encode() + b"\n", b"?? stray\n"],
                ),
                self.assertRaisesRegex(SystemExit, "dirty"),
            ):
                authenticate_source(root, None, None)


if __name__ == "__main__":
    unittest.main()
