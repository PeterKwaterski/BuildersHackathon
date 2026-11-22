import copy
import unittest
from unittest import mock

import selector
import tpc_rule_fast as fast


class FastRuleTests(unittest.TestCase):
    @staticmethod
    def profile():
        digest = "a" * 64
        owner_id = "b" * 64
        profile = {
            "format": fast.FORMAT,
            "identity": {key: digest for key in (
                "sqlglot_tree", "tests_tree", "fixture_tree", "requirements_lock",
                "builder_source",
            )},
            "capsules": {
                rule: [{
                    "query": 1, "input_dump": [{"c": "Select"}],
                    "input": digest, "output": digest,
                }]
                for rule in fast.RULES
            },
            "owners": {owner_id: {
                "path": "sqlglot/optimizer/unnest_subqueries.py",
                "qualname": "decorrelate", "first_line": 1, "end_line": 2,
                "rule": fast.RULES[1], "source_sha256": "c" * 64,
                "readers": [1],
                "barriers": ["predecessor_state", "process_state"],
                "risk_cpu_s": 1.0,
            }},
        }
        profile["collection_sha256"] = fast.canonical_digest(profile)
        return profile, owner_id

    def test_profile_validates_and_tamper_fails(self):
        profile, _owner_id = self.profile()
        self.assertIs(fast.validate(profile), profile)
        tampered = copy.deepcopy(profile)
        tampered["capsules"][fast.RULES[1]][0]["output"] = "d" * 64
        with self.assertRaises(ValueError):
            fast.validate(tampered)

    def test_plan_has_separate_gate_label_and_barriers(self):
        profile, owner_id = self.profile()
        self.assertIsNone(fast.plan(profile, owner_id, (fast.TARGET,), 10.0))
        plan = fast.plan(profile, owner_id, (fast.TARGET,), 10.0, enabled=True)
        self.assertEqual(plan["tier"], "competition-risk-fast")
        self.assertIs(plan["proof"], False)
        self.assertEqual(plan["readers"], (1,))
        self.assertIn("process_state", plan["barriers"])

    def test_economics_and_target_mismatch_fail_closed(self):
        profile, owner_id = self.profile()
        self.assertIsNone(fast.plan(
            profile, owner_id, (fast.TARGET,), 3.0, enabled=True
        ))
        self.assertIsNone(fast.plan(
            profile, owner_id, ("other",), 10.0, enabled=True
        ))

    def test_selector_pin_loads_and_kill_switch_is_identity(self):
        selected = [{"id": fast.TARGET, "number": 1, "seconds": 18.0}]
        self.assertEqual(
            selector.TPC_RULE_FAST_PROFILE_SHA256,
            "51b2e6cefc9bf1b916e265dae28ab706b1f0a5c053be91018bb9e160b6dedd1d",
        )
        self.assertIsNotNone(selector.load_tpc_rule_fast_profile())
        with mock.patch.object(selector, "TPC_RULE_FAST_ENABLED", False):
            self.assertIs(
                selector.apply_tpc_rule_fast_risk(
                    selected, [], selector.load_tpc_rule_fast_profile()
                ),
                selected,
            )

    def test_expanded_profile_covers_complete_executor_query_roster(self):
        profile = selector.load_tpc_rule_fast_profile()
        self.assertIsNotNone(profile)
        owners = {owner["qualname"]: owner for owner in profile["owners"].values()}
        self.assertEqual(
            set(owners),
            {
                "qualify",
                "qualify_tables",
                "qualify_columns",
                "validate_qualify_columns",
                "_convert_columns_to_dots",
                "isolate_table_selects",
                "unnest_subqueries",
                "decorrelate",
            },
        )
        execute_queries = owners["qualify"]["readers"]
        self.assertEqual(len(execute_queries), 57)
        for name in (
            "qualify",
            "qualify_tables",
            "qualify_columns",
            "validate_qualify_columns",
            "_convert_columns_to_dots",
            "isolate_table_selects",
            "unnest_subqueries",
        ):
            self.assertEqual(owners[name]["readers"], execute_queries)


if __name__ == "__main__":
    unittest.main()
