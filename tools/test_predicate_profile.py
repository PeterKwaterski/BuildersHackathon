#!/usr/bin/env python3
from __future__ import annotations

import copy
import gzip
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import selector


class PredicateProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = json.load(gzip.open(ROOT / "predicate_profile.json.gz", "rt"))

    def change(self, path: str, old: str, new: str, *, extra=None, payload=None):
        source = selector.pinned_sources()[path]
        self.assertEqual(source.count(old), 1)
        changed = source.replace(old, new)
        if extra is not None:
            self.assertEqual(changed.count(extra[0]), 1)
            changed = changed.replace(*extra)
        line = source[: source.index(old)].count("\n") + 1
        return {
            "_patched_source": changed,
            "lines": {line},
            "payload": payload if payload is not None else [old, new],
            "removed": [old],
            "added": [new],
            "added_new_at": [(line, new)],
        }

    def accepted(self, path: str, old: str, new: str, **kwargs) -> bool:
        return selector.profile_equivalent_predicate_edit(
            self.change(path, old, new, **kwargs), path, self.model, set()
        )

    def test_existing_profile_exposes_exact_incremental_opportunities(self):
        indices = {"Lt": 0, "LtE": 1, "Gt": 2, "GtE": 3, "Eq": 4, "NotEq": 5}
        adjacent = {
            ("Lt", "LtE"), ("LtE", "Lt"), ("Gt", "GtE"), ("GtE", "Gt")
        }
        pairs = []
        for entries in self.model["d"].values():
            for entry in entries:
                old, state, observations = entry[4:]
                if state != "safe":
                    continue
                for new in indices:
                    if old != new and all(
                        outcome[indices[old]] == outcome[indices[new]]
                        for outcome in observations
                    ):
                        pairs.append((old, new))
        self.assertEqual(len(pairs), 107)
        self.assertEqual(sum(pair in adjacent for pair in pairs), 31)
        self.assertEqual(sum(pair not in adjacent for pair in pairs), 76)
        self.assertEqual(sum(new in {"Eq", "NotEq"} for _old, new in pairs), 70)

    def test_real_nonadjacent_ordering_to_equality_cases(self):
        cases = (
            ("sqlglot/generators/duckdb.py", "num_quantiles <= 0", "num_quantiles == 0"),
            (
                "sqlglot/generator.py",
                "len(args) > 1 and not self.SUPPORTS_MULTI_ARG_CHR",
                "len(args) != 1 and not self.SUPPORTS_MULTI_ARG_CHR",
            ),
            (
                "sqlglot/generator.py",
                "len(expression.expressions) > 1 or tgt_pivot_column_naming",
                "len(expression.expressions) < 1 or tgt_pivot_column_naming",
            ),
        )
        for path, old, new in cases:
            with self.subTest(path=path, old=old, new=new):
                self.assertTrue(self.accepted(path, old, new))

    def test_different_observed_outcome_fails_closed(self):
        self.assertFalse(self.accepted(
            "sqlglot/generators/clickhouse.py",
            "self.dialect.version < (23, 12)",
            "self.dialect.version == (23, 12)",
        ))

    def test_unordered_nan_vector_blocks_cross_fp_operator_class(self):
        path = "sqlglot/generators/duckdb.py"
        change = self.change(path, "num_quantiles <= 0", "num_quantiles == 0")
        model = copy.deepcopy(self.model)
        entry = next(
            item for item in model["d"][path]
            if item[0] == 5049 and item[4] == "LtE"
        )
        entry[6].append([False, False, False, False, False, True])
        self.assertFalse(selector.profile_equivalent_predicate_edit(
            change, path, model, set()
        ))

    def test_identity_operators_remain_excluded(self):
        for replacement in ("is", "is not"):
            with self.subTest(replacement=replacement):
                self.assertFalse(self.accepted(
                    "sqlglot/generator.py",
                    "len(args) > 1 and not self.SUPPORTS_MULTI_ARG_CHR",
                    f"len(args) {replacement} 1 and not self.SUPPORTS_MULTI_ARG_CHR",
                ))

    def test_unsafe_unobserved_and_malformed_evidence_fail_closed(self):
        path = "sqlglot/generators/duckdb.py"
        change = self.change(path, "num_quantiles <= 0", "num_quantiles == 0")
        target = next(
            item for item in self.model["d"][path]
            if item[0] == 5049 and item[4] == "LtE"
        )
        mutations = (
            lambda entry: entry.__setitem__(5, "unsafe"),
            lambda entry: entry.__setitem__(5, "unobserved"),
            lambda entry: entry.__setitem__(4, "UnknownOperator"),
            lambda entry: entry.__setitem__(6, []),
            lambda entry: entry[6][0].__setitem__(4, 1),
            lambda entry: entry[6][0].__setitem__(4, None),
            lambda entry: entry[6][0].pop(),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                model = copy.deepcopy(self.model)
                entry = next(
                    item for item in model["d"][path] if item[:5] == target[:5]
                )
                mutate(entry)
                self.assertFalse(selector.profile_equivalent_predicate_edit(
                    copy.deepcopy(change), path, model, set()
                ))

    def test_operator_only_ast_gate_rejects_every_other_edit(self):
        path = "sqlglot/generators/duckdb.py"
        old = "num_quantiles <= 0"
        attacks = (
            ("num_quantiles == 1", None),
            ("(num_quantiles == 0) or True", None),
            (
                "num_quantiles == 0",
                (
                    "num_quantiles = t.cast(int, num_quantiles_expr.to_py())",
                    "num_quantiles = 0",
                ),
            ),
        )
        for replacement, extra in attacks:
            with self.subTest(replacement=replacement, extra=extra):
                self.assertFalse(self.accepted(path, old, replacement, extra=extra))

    def test_directive_and_process_serialization_gates_remain_closed(self):
        self.assertFalse(self.accepted(
            "sqlglot/generators/duckdb.py",
            "num_quantiles <= 0",
            "num_quantiles == 0",
            payload=["num_quantiles <= 0", "num_quantiles == 0  # noqa"],
        ))
        self.assertFalse(self.accepted(
            "sqlglot/serde.py", "index is not None", "index != None"
        ))


if __name__ == "__main__":
    unittest.main()
