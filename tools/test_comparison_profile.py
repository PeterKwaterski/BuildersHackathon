from __future__ import annotations

import gzip
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import selector


PATH = "sqlglot/optimizer/simplify.py"
PATCH = """diff --git a/sqlglot/optimizer/simplify.py b/sqlglot/optimizer/simplify.py
--- a/sqlglot/optimizer/simplify.py
+++ b/sqlglot/optimizer/simplify.py
@@ -1032,7 +1032,7 @@
.
                 false = (
                     exp.false()
-                    if left.meta_get("nonnull") is True and right.meta_get("nonnull") is True
+                    if left.meta_get("nonnull") is True and right.meta_get("nonnull") == True
                     else None
                 )
.
""".replace("\n.\n", "\n \n")


class ComparisonProfileTests(unittest.TestCase):
    def patch(self, source: str = PATCH) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "case.patch"
        path.write_text(source, encoding="utf-8")
        return path

    def model(
        self,
        equal: bool = True,
        state: str = "safe",
        domain: str = "bool",
        identity: bool = True,
    ) -> dict:
        observation = [
            ["error", "builtins", "TypeError"]
            for _name in (
                "Lt",
                "LtE",
                "Gt",
                "GtE",
                "Eq",
                "NotEq",
                "Is",
                "IsNot",
                "In",
                "NotIn",
            )
        ]
        observation[4] = ["value", "bool", str(equal)]
        observation[6] = ["value", "bool", str(identity)]
        typed_observation = [
            ["builtins", domain],
            ["builtins", domain],
            observation,
        ]
        return {
            "d": {
                PATH: [
                    [1035, 23, 1035, 55, "Is", state, [typed_observation]],
                    [1035, 60, 1035, 93, "Is", state, [typed_observation]],
                ]
            }
        }

    def check(self, patch: Path, model: dict) -> bool:
        change = selector.patch_changes(patch)[0]
        return selector.profile_equivalent_predicate_edit(change, PATH, model, set())

    def test_equal_profiled_operator_edit_is_accepted(self) -> None:
        self.assertTrue(self.check(self.patch(), self.model()))

    def test_divergent_profiled_operator_edit_is_rejected(self) -> None:
        self.assertFalse(self.check(self.patch(), self.model(equal=False)))

    def test_unsafe_profile_state_is_rejected(self) -> None:
        self.assertFalse(self.check(self.patch(), self.model(state="unsafe")))

    def test_literal_edit_is_rejected(self) -> None:
        patch = self.patch(PATCH.replace("== True", "is False"))
        self.assertFalse(self.check(patch, self.model()))

    def test_identity_value_edit_rejects_allocation_sensitive_domains(self) -> None:
        for domain in ("int", "float", "str", "bytes", "tuple"):
            with self.subTest(domain=domain):
                self.assertFalse(self.check(self.patch(), self.model(domain=domain)))

    def test_fresh_equal_distinct_values_are_rejected(self) -> None:
        for domain in ("int", "str", "bytes", "tuple"):
            with self.subTest(domain=domain):
                self.assertFalse(
                    self.check(
                        self.patch(),
                        self.model(domain=domain, equal=True, identity=False),
                    )
                )

    def test_identity_value_edit_accepts_static_identity_domains(self) -> None:
        for domain in ("NoneType", "bool", "type"):
            with self.subTest(domain=domain):
                self.assertTrue(self.check(self.patch(), self.model(domain=domain)))

    def test_unknown_operand_domain_is_rejected(self) -> None:
        self.assertFalse(self.check(self.patch(), self.model(domain="object")))

    def test_malformed_result_schema_is_rejected(self) -> None:
        model = self.model()
        model["d"][PATH][1][6][0][2][4] = ["value", "int", "1"]
        self.assertFalse(self.check(self.patch(), model))

        model = self.model()
        model["d"][PATH][1][6][0][2][0] = ["error", "", "TypeError"]
        self.assertFalse(self.check(self.patch(), model))

    def test_profile_loader_rejects_raw_append_and_recompressed_tampering(self) -> None:
        document = {
            "d": {PATH: []},
            "n": 2,
            "sha": "source",
            "t": "tests",
            "v": 3,
        }
        encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        raw = gzip.compress(encoded, mtime=0)
        digest = hashlib.sha256(raw).hexdigest()
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "predicate-profile.json.gz"
        path.write_bytes(raw)
        self.assertEqual(selector.load_predicate_profile(path, digest), document)

        for tampered in (
            raw[:-1] + bytes([raw[-1] ^ 1]),
            raw + b"append",
            gzip.compress(encoded, mtime=1),
        ):
            with self.subTest(digest=hashlib.sha256(tampered).hexdigest()):
                self.assertNotEqual(tampered, raw)
                path.write_bytes(tampered)
                self.assertEqual(
                    selector.load_predicate_profile(path, digest), {"d": {}}
                )

    def test_committed_profile_matches_raw_pin(self) -> None:
        document = selector.load_predicate_profile()
        self.assertEqual(document.get("v"), 3)
        self.assertTrue(document.get("d"))


if __name__ == "__main__":
    unittest.main()
