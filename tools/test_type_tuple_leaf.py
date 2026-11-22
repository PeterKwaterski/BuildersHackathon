from __future__ import annotations

import gzip
import json
import unittest
from pathlib import Path
from unittest import mock

import selector
import type_tuple_leaf


ROOT = Path(__file__).resolve().parents[1]
PUBLIC = Path("/home/silverdisk/public-matchaluvrs-readonly/validation/val11/commits")


class TypeTupleLeafTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with gzip.open(ROOT / "type_tuple_leaf_model.json.gz", "rt") as stream:
            cls.model = json.load(stream)
        cls.tests = json.loads((ROOT / "sample/tests.json").read_text())["tests"]

    def readers(self, patch_name: str):
        patch = PUBLIC / patch_name
        changes = selector.patch_changes(patch)
        self.assertEqual(len(changes), 1)
        change = changes[0]
        path = change["old"]
        original = selector.pinned_sources()[path]
        changed = selector.patched_source(change, path)
        self.assertIsNotNone(changed)
        with mock.patch.object(type_tuple_leaf, "FEATURE_ENABLED", True):
            return type_tuple_leaf.readers(path, original, changed, change, self.model)

    def test_hardened_model_rejects_public_module_escape(self):
        # The permissive census admitted these edits, but the expression module
        # escapes into the executor/serde dynamic lookup paths. The committed
        # model therefore contains no runtime admission for them.
        self.assertIsNone(self.readers("m4bf.patch"))
        self.assertIsNone(self.readers("m4d8.patch"))
        self.assertIsNone(self.readers("md3a.patch"))

    def test_non_tuple_constant_falls_back(self):
        self.assertIsNone(self.readers("m416.patch"))

    def test_model_authentication(self):
        ids = [test["id"] for test in self.tests]
        loaded = type_tuple_leaf.load_model(
            ROOT / "type_tuple_leaf_model.json.gz",
            "eb11aec4be8cb2122afe713a4816662c3f0fb2fa",
            ids,
        )
        self.assertIsNotNone(loaded)
        self.assertIsNone(type_tuple_leaf.load_model(
            ROOT / "type_tuple_leaf_model.json.gz", "wrong", ids
        ))


if __name__ == "__main__":
    unittest.main()
