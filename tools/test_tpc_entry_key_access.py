import gzip
import hashlib
import json
import unittest

import selector
import tpc_entry_key_access as entry


MODEL = json.load(gzip.open("selector_model.json.gz", "rt"))
TEST_IDS = MODEL["t"]
SOURCE = selector.pinned_sources()[entry.PATH]


def changed(old: str, new: str, count: int = 1) -> str:
    assert SOURCE.count(old) >= count
    return SOURCE.replace(old, new, count)


class TpcEntryKeyAccessTest(unittest.TestCase):
    def test_exact_tpch_leaf_selects_wildcard_executor_class_and_tpch_optimizer(self):
        patched = changed('"l_orderkey": "bigint"', '"l_orderkey": "int"')
        edit = entry.classify(entry.PATH, SOURCE, patched)
        self.assertEqual(
            edit,
            entry.EntryEdit("TPCH_SCHEMA", "lineitem", "l_orderkey", "bigint", "int"),
        )
        selected = entry.readers(entry.PATH, SOURCE, patched, TEST_IDS)
        executor = {
            index for index, test_id in enumerate(TEST_IDS)
            if test_id.startswith("tests/test_executor.py::TestExecutor::")
        }
        optimizer = TEST_IDS.index("tests/test_optimizer.py::TestOptimizer::test_tpch")
        self.assertEqual(selected, executor | {optimizer})
        self.assertEqual(len(selected), 61)

    def test_exact_tpcds_leaf_selects_corresponding_optimizer(self):
        patched = changed('"cs_sold_date_sk": "bigint"', '"cs_sold_date_sk": "int"')
        selected = entry.readers(entry.PATH, SOURCE, patched, TEST_IDS)
        self.assertIn(
            TEST_IDS.index("tests/test_optimizer.py::TestOptimizer::test_tpcds"), selected
        )
        self.assertNotIn(
            TEST_IDS.index("tests/test_optimizer.py::TestOptimizer::test_tpch"), selected
        )
        self.assertEqual(len(selected), 61)

    def test_two_values_key_order_shape_and_table_changes_reject(self):
        cases = (
            changed('"l_orderkey": "bigint"', '"l_orderkey": "int"').replace(
                '"l_partkey": "bigint"', '"l_partkey": "int"', 1
            ),
            changed('"l_orderkey": "bigint"', '"l_otherkey": "bigint"'),
            changed(
                '"l_orderkey": "bigint",\n        "l_partkey": "bigint"',
                '"l_partkey": "bigint",\n        "l_orderkey": "bigint"',
            ),
            changed('"l_orderkey": "bigint"', '"l_orderkey": ["bigint"]'),
            changed('"lineitem": {', '"lineitems": {'),
        )
        for patched in cases:
            self.assertIsNone(entry.classify(entry.PATH, SOURCE, patched))

    def test_nonliteral_alias_call_unpack_and_duplicate_key_reject(self):
        cases = (
            changed('"l_orderkey": "bigint"', '"l_orderkey": TYPE'),
            changed('"l_orderkey": "bigint"', '"l_orderkey": str("int")'),
            changed('"l_orderkey": "bigint"', '"l_orderkey": f"int"'),
            changed('"l_orderkey": "bigint"', "\"l_orderkey\": 'int'"),
            changed('"l_orderkey": "bigint"', '"l_orderkey": "i" "nt"'),
            changed('"l_orderkey": "bigint"', '"l_orderkey": "int",\n        **EXTRA'),
            changed('"l_orderkey": "bigint"', '"l_orderkey": "int",\n        "l_orderkey": "bigint"'),
        )
        for patched in cases:
            self.assertIsNone(entry.classify(entry.PATH, SOURCE, patched))

    def test_comment_import_reassignment_class_and_persistent_side_effect_reject(self):
        base = changed('"l_orderkey": "bigint"', '"l_orderkey": "int"')
        cases = (
            base.replace("TPCH_SCHEMA = {", "# changed\nTPCH_SCHEMA = {", 1),
            base.replace("import os", "import os\nimport sys", 1),
            base + "\nTPCH_SCHEMA = {}\n",
            base + "\nclass Observer:\n    seen = TPCH_SCHEMA\n",
            base + "\nTPCH_SCHEMA.clear()\n",
        )
        for patched in cases:
            self.assertIsNone(entry.classify(entry.PATH, SOURCE, patched))

    def test_path_source_manifest_and_default_off_tamper_reject(self):
        patched = changed('"l_orderkey": "bigint"', '"l_orderkey": "int"')
        self.assertIsNone(entry.classify("tests/other.py", SOURCE, patched))
        self.assertIsNone(entry.classify(entry.PATH, SOURCE + "\n", patched + "\n"))
        self.assertIsNone(entry.readers(entry.PATH, SOURCE, patched, TEST_IDS[:-1]))
        self.assertFalse(entry.FEATURE_ENABLED)

    def test_provenance_closes_import_name_reflection_and_collected_graph(self):
        document = json.load(gzip.open("tpc_entry_reader_provenance.json.gz", "rt"))
        unsigned = {key: document[key] for key in document if key != "profile_sha256"}
        self.assertEqual(
            document["profile_sha256"],
            hashlib.sha256(
                json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        )
        imports = [event for event in document["events"] if event["kind"] == "import"]
        self.assertEqual(
            {
                event["path"] for event in imports
                if event["path"] in document["collected_files"]
            },
            {"tests/test_executor.py", "tests/test_optimizer.py"},
        )
        self.assertFalse(any(
            event["kind"] in {"attribute", "string"} for event in document["events"]
        ))
        self.assertNotIn("tests/gen_fixtures.py", document["collected_files"])
        self.assertNotIn("benchmarks/optimize.py", document["collected_files"])
        self.assertEqual(document["tracked_file_count"], 365)
        self.assertEqual(document["tracked_python_count"], 258)
        self.assertEqual(len(document["source_hashes"]), 258)
        self.assertEqual(
            document["tracked_index_sha256"],
            "a2f99e795d6c15564829485f6e761f28922ba471613097d8c41227dd2bb91ca6",
        )
        self.assertEqual(len(document["text_references"]), 28)
        self.assertEqual(document["uncollected_reader_imports"], [])
        self.assertIn("benchmarks/optimize.py", {event["path"] for event in imports})
        self.assertEqual(
            {name: len(owners) for name, owners in document["owners"].items()},
            {"TPCH_SCHEMA": 61, "TPCDS_SCHEMA": 61},
        )


if __name__ == "__main__":
    unittest.main()
