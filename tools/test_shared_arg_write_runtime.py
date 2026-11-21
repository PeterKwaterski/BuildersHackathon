from __future__ import annotations

import copy
import unittest
from pathlib import Path

import selector
from shared_arg_write_runtime import fresh_receiver_candidate, load_model


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_FVN9 = Path(
    "/home/silverdisk/public-matchaluvrs-readonly/validation/val1/commits/fvn9.patch"
)


class FreshReceiverRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = load_model(ROOT / "shared_arg_write_model.json.gz")
        if cls.model is None:
            raise AssertionError("committed shared-argument model did not validate")

    def test_public_patch_parser_half_is_a_candidate(self):
        changes = selector.patch_changes(PUBLIC_FVN9)
        change = next(item for item in changes if item["old"] == "sqlglot/parser.py")
        source = selector.pinned_sources()["sqlglot/parser.py"]
        changed = selector.patched_source(change, "sqlglot/parser.py")
        self.assertIsNotNone(changed)
        self.assertTrue(
            fresh_receiver_candidate(
                change, "sqlglot/parser.py", source, changed, self.model
            )
        )
        self.assertTrue(
            selector.contained_fresh_receiver_edit(change, "sqlglot/parser.py")
        )

    def test_target_change_and_alias_are_rejected(self):
        path = "sqlglot/example.py"
        original = (
            "def build():\n"
            "    item = Box()\n"
            "    item.set('key', True)\n"
        )
        aliased = (
            "def build():\n"
            "    item = Box()\n"
            "    saved = item\n"
            "    item.set('key', True)\n"
        )
        changed = original.replace("True", "False")
        target_changed = original.replace("set('key', True)", "replace('key', False)")
        record = [
            f"{path}:build:1", path, "build", 1, 3, [], [], [], ["item"], [], [],
            [["item", path, "Box"]], [[3, 4, "item", f"{path}:Box.set:10"]],
            [[3, 4, "item", f"{path}:Box.set:10"]],
        ]
        model = {"functions": [record]}
        change = {"lines": {3}, "removed": [original.splitlines()[2]], "added": [changed.splitlines()[2]]}
        self.assertTrue(fresh_receiver_candidate(change, path, original, changed, model))
        self.assertFalse(
            fresh_receiver_candidate(change, path, original, target_changed, model)
        )
        alias_change = copy.deepcopy(change)
        alias_change["lines"] = {4}
        alias_change["removed"] = [aliased.splitlines()[3]]
        alias_changed = aliased.replace("True", "False")
        alias_model = copy.deepcopy(model)
        alias_model["functions"][0][4] = 4
        alias_model["functions"][0][12][0][0] = 4
        alias_model["functions"][0][12][0][1] = 4
        alias_model["functions"][0][13][0][0] = 4
        alias_model["functions"][0][13][0][1] = 4
        self.assertFalse(
            fresh_receiver_candidate(
                alias_change, path, aliased, alias_changed, alias_model
            )
        )

    def test_model_tamper_fails_closed(self):
        raw = bytearray((ROOT / "shared_arg_write_model.json.gz").read_bytes())
        raw[len(raw) // 2] ^= 1
        temporary = ROOT / ".shared-arg-tamper.tmp"
        try:
            temporary.write_bytes(raw)
            self.assertIsNone(load_model(temporary))
        finally:
            temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
