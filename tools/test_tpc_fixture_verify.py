import os
import unittest
from unittest import mock

import tpc_fixture_verify as verifier


def change_line(source: str, old: str, new: str, occurrence: int = 0) -> dict:
    matches = [index for index, line in enumerate(source.splitlines()) if line == old]
    line = matches[occurrence] + 1
    return {
        "old": verifier.FIXTURE,
        "new": verifier.FIXTURE,
        "diff_old": verifier.FIXTURE,
        "diff_new": verifier.FIXTURE,
        "structural_invalid": False,
        "binary": False,
        "non_lf": False,
        "no_newline_marker": False,
        "new_file_mode": None,
        "new_file_mode_count": 0,
        "old_marker_count": 1,
        "new_marker_count": 1,
        "index_count": 1,
        "new_file_index": False,
        "hunks": [
            {
                "old_start": line,
                "old_count": 1,
                "new_start": line,
                "new_count": 1,
                "lines": [("-", old), ("+", new)],
            }
        ],
    }


@unittest.skipUnless(verifier.PINNED_FIXTURE.is_file(), "exact image tree required")
class FixtureClassifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = verifier.PINNED_FIXTURE.read_text(encoding="utf-8")

    def test_input_sql_edit_requires_dynamic_verification(self) -> None:
        classified = verifier.classify(change_line(self.source, "LIMIT 100;", "LIMIT 99;", 0))
        self.assertIsNotNone(classified)
        _source, indices, dynamic = classified
        self.assertEqual(indices, [0])
        self.assertTrue(dynamic)

    def test_expected_sql_edit_is_static_for_executor(self) -> None:
        edit = change_line(self.source, "LIMIT 100;", "LIMIT 99;", 1)
        classified = verifier.classify(edit)
        self.assertIsNotNone(classified)
        _source, indices, dynamic = classified
        self.assertEqual(indices, [0])
        self.assertFalse(dynamic)
        passed, cpu, reason = verifier.verify(edit)
        self.assertTrue(passed)
        self.assertGreaterEqual(cpu, 0.0)
        self.assertEqual(reason, "expected-only")

    def test_four_changed_pairs_and_structural_edits_reject(self) -> None:
        lines = self.source.splitlines()
        positions = [index for index, line in enumerate(lines) if line == "# execute: true"][:4]
        hunks = [
            {
                "old_start": position + 1,
                "old_count": 1,
                "new_start": position + 1,
                "new_count": 1,
                "lines": [("-", "# execute: true"), ("+", "-- execute removed")],
            }
            for position in positions
        ]
        edit = change_line(self.source, "LIMIT 100;", "LIMIT 99;", 0)
        edit["hunks"] = hunks
        self.assertIsNone(verifier.classify(edit))
        edit = change_line(self.source, "LIMIT 100;", "LIMIT 99;", 0)
        edit["structural_invalid"] = True
        self.assertIsNone(verifier.classify(edit))

    def test_manifest_child_and_fixture_tampering_fail_closed(self) -> None:
        prior_source, prior_failed = verifier._pinned_source, verifier._pinned_failed
        try:
            verifier._pinned_source = None
            verifier._pinned_failed = False
            with mock.patch.object(verifier, "CHILD_SHA256", "0" * 64):
                self.assertIsNone(verifier._load_pinned_source())
        finally:
            verifier._pinned_source, verifier._pinned_failed = prior_source, prior_failed


@unittest.skipUnless(
    verifier.PINNED_FIXTURE.is_file() and os.environ.get("RUN_TPC_FIXTURE_INTEGRATION") == "1",
    "explicit exact-image integration run required",
)
class FixtureExecutionTests(unittest.TestCase):
    def test_changed_query_matches_spawned_executor_and_duckdb(self) -> None:
        source = verifier.PINNED_FIXTURE.read_text(encoding="utf-8")
        passed, cpu, reason = verifier.verify(change_line(source, "LIMIT 100;", "LIMIT 99;", 0))
        self.assertTrue(passed, reason)
        self.assertEqual(reason, "verified")
        self.assertGreater(cpu, 0.0)
        self.assertLessEqual(cpu, verifier.MAX_CPU_SECONDS)

    def test_execute_metadata_removal_still_parses_then_passes(self) -> None:
        source = verifier.PINNED_FIXTURE.read_text(encoding="utf-8")
        edit = change_line(source, "# execute: true", "-- execute removed", 0)
        passed, cpu, reason = verifier.verify(edit)
        self.assertTrue(passed, reason)
        self.assertEqual(reason, "verified")
        self.assertGreater(cpu, 0.0)

    def test_non_literal_query_shape_change_rejects(self) -> None:
        source = verifier.PINNED_FIXTURE.read_text(encoding="utf-8")
        edit = change_line(source, "LIMIT 100;", "OFFSET 1;", 0)
        passed, _cpu, reason = verifier.verify(edit)
        self.assertFalse(passed)
        self.assertEqual(reason, "child-failure")


if __name__ == "__main__":
    unittest.main()
