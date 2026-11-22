import difflib
import gzip
import json
import tempfile
import unittest
from pathlib import Path

import selector
import tpc_entry_key_access as entry


ROOT = Path(__file__).resolve().parents[1]
MODEL = json.load(gzip.open(ROOT / "selector_model.json.gz", "rt"))
MODEL["h"] = set(MODEL.get("h", ()))
TEST_IDS = MODEL["t"]
SOURCE = selector.pinned_sources()[entry.PATH]
PROVENANCE = entry.load_provenance(
    ROOT / "tpc_entry_reader_provenance.json.gz",
    ROOT / "selector_model.json.gz",
    MODEL,
    TEST_IDS,
)


def diff(original: str, changed: str, path: str = entry.PATH) -> str:
    body = "".join(difflib.unified_diff(
        original.splitlines(keepends=True),
        changed.splitlines(keepends=True),
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
    ))
    return (
        f"diff --git a/{path} b/{path}\n"
        "index 0000000..1111111 100644\n"
        + body
    )


def selection(document: str, provenance=PROVENANCE) -> set[int]:
    with tempfile.TemporaryDirectory() as directory:
        patch = Path(directory) / "change.patch"
        patch.write_text(document, encoding="utf-8")
        return selector.selected_indices(
            patch,
            MODEL,
            set(range(len(TEST_IDS))),
            tpc_entry_provenance=provenance,
        )


class TpcEntryIntegrationTest(unittest.TestCase):
    def test_selected_indices_admits_exact_tpch_and_tpcds_leaf(self):
        for old, new, optimizer in (
            (
                '"l_orderkey": "bigint"',
                '"l_orderkey": "int"',
                "tests/test_optimizer.py::TestOptimizer::test_tpch",
            ),
            (
                '"cs_sold_date_sk": "bigint"',
                '"cs_sold_date_sk": "int"',
                "tests/test_optimizer.py::TestOptimizer::test_tpcds",
            ),
        ):
            with self.subTest(old=old):
                selected = selection(diff(SOURCE, SOURCE.replace(old, new, 1)))
                expected = {
                    index for index, test_id in enumerate(TEST_IDS)
                    if test_id.startswith("tests/test_executor.py::TestExecutor::")
                }
                expected.add(TEST_IDS.index(optimizer))
                self.assertEqual(selected, expected)
                self.assertEqual(len(selected), 61)

    def test_every_other_helpers_edit_and_missing_artifact_select_global(self):
        exact = SOURCE.replace('"l_orderkey": "bigint"', '"l_orderkey": "int"', 1)
        cases = (
            exact.replace('"l_partkey": "bigint"', '"l_partkey": "int"', 1),
            SOURCE.replace('"l_orderkey": "bigint"', '"other": "bigint"', 1),
            SOURCE.replace("TPCH_SCHEMA = {", "# comment\nTPCH_SCHEMA = {", 1),
            SOURCE.replace("import os", "import os\nimport sys", 1),
            SOURCE.replace("def string_to_bool(string):", "def string_to_bool(value):", 1),
        )
        all_indices = set(range(len(TEST_IDS)))
        for changed in cases:
            self.assertEqual(selection(diff(SOURCE, changed)), all_indices)
        self.assertEqual(selection(diff(SOURCE, exact), provenance=None), all_indices)

    def test_mixed_exact_helpers_patch_selects_global(self):
        exact = diff(
            SOURCE,
            SOURCE.replace('"l_orderkey": "bigint"', '"l_orderkey": "int"', 1),
        )
        other = (
            "diff --git a/sqlglot/helper.py b/sqlglot/helper.py\n"
            "--- a/sqlglot/helper.py\n"
            "+++ b/sqlglot/helper.py\n"
            "@@ -1 +1 @@\n"
            "-import os\n"
            "+import sys\n"
        )
        self.assertEqual(selection(exact + other), set(range(len(TEST_IDS))))


if __name__ == "__main__":
    unittest.main()
