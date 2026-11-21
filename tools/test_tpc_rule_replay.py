import contextlib
import copy
import io
import unittest

import tpc_rule_replay as replay


class FakeExpression:
    def __init__(self, value, meta=None):
        self.value = value
        self.meta = meta or {}

    def dump(self):
        return [{"c": "Fake", "a": {"this": self.value}, "m": self.meta}]

    def sql(self):
        return str(self.value)


class RuleReplayTests(unittest.TestCase):
    @staticmethod
    def valid_profile():
        digest = "a" * 64
        rows = []
        for target, count in replay.TARGET_COUNTS.items():
            for history in replay.HISTORIES:
                for query in range(1, count + 1):
                    for rule in replay.RULES:
                        rows.append({
                            "target": target, "history": history, "query": query,
                            "rule": rule, "input": digest, "output": digest, "cpu_ns": 1,
                        })
        owner_id = "b" * 64
        profile = {
            "format": replay.PROFILE_FORMAT,
            "identity": {name: digest for name in (
                "sqlglot_tree", "tests_tree", "fixture_tree", "requirements_lock",
                "collector_source",
            )},
            "rule_order": list(replay.RULES),
            "coverage": {target: {"queries": count, "histories": list(replay.HISTORIES)}
                         for target, count in replay.TARGET_COUNTS.items()},
            "boundary_rows_sha256": replay.canonical_digest(rows),
            "boundary_rows": rows,
            "owners": {owner_id: {
                "rule": replay.RULES[3], "source_sha256": "c" * 64,
                "barriers": ["persistent_worker_state"], "state_independent": False,
                "competition_risk": True, "call_graph_sha256": "d" * 64,
            }},
            "spawn_obligations": {name: False for name in (
                "parse", "pickle_roundtrip", "fresh_import", "initializer",
                "persistent_worker_predecessors", "table_reader_state",
                "stdout_warnings_exceptions", "native_state",
            )},
        }
        profile["collection_sha256"] = replay.canonical_digest(profile)
        return profile, owner_id

    def test_boundary_binds_metadata_and_rendering(self):
        left = FakeExpression(1, {"line": 1})
        right = FakeExpression(1, {"line": 2})
        self.assertNotEqual(replay.boundary_digest(left), replay.boundary_digest(right))
        right.meta = {"line": 1}
        right.sql = lambda: "01"
        self.assertNotEqual(replay.boundary_digest(left), replay.boundary_digest(right))

    def test_boundary_rejects_noncanonical_values(self):
        with self.assertRaises(replay.RuleReplayError):
            replay.boundary_digest(FakeExpression(float("nan")))

    def test_rule_composition_mismatch_fails_closed(self):
        def wrong(expression):
            return expression

        with self.assertRaises(replay.RuleReplayError):
            replay.trace_rule_boundaries(FakeExpression(1), [wrong], lambda f, x: f(x))

    def test_default_kill_switch_retains_test(self):
        patch = replay.PatchEvidence("0" * 64, "1" * 64, replay.RULES[0])
        self.assertIsNone(replay.plan_strong_replay({}, patch, list(replay.TARGET_COUNTS), 10, 1))

    def test_malformed_profile_fails_closed_even_when_enabled(self):
        patch = replay.PatchEvidence("0" * 64, "1" * 64, replay.RULES[0])
        self.assertIsNone(
            replay.plan_strong_replay(
                {"format": replay.PROFILE_FORMAT}, patch, list(replay.TARGET_COUNTS), 10, 1,
                enabled=True,
            )
        )

    def test_equal_rule_output_misses_persistent_side_effect(self):
        state = {"calls": 0}

        def changed_rule(expression):
            state["calls"] += 1
            return expression

        before = FakeExpression(1)
        self.assertEqual(replay.boundary_digest(before), replay.boundary_digest(changed_rule(before)))
        self.assertEqual(state["calls"], 1)
        # A later query can observe the write despite exact rule I/O equality.
        self.assertEqual(state["calls"], 1)

    def test_direct_reader_replay_misses_predecessor_write(self):
        state = {"armed": False}

        def predecessor():
            state["armed"] = True

        def changed_reader(expression):
            return FakeExpression(0 if state["armed"] else expression.value)

        isolated = changed_reader(FakeExpression(7))
        predecessor()
        official_history = changed_reader(FakeExpression(7))
        self.assertNotEqual(replay.boundary_digest(isolated), replay.boundary_digest(official_history))

    def test_equal_output_misses_stdout_obligation(self):
        expression = FakeExpression(1)

        def noisy_rule(value):
            print("observable")
            return value

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            returned = noisy_rule(expression)
        self.assertEqual(replay.boundary_digest(expression), replay.boundary_digest(returned))
        self.assertEqual(output.getvalue(), "observable\n")

    def test_risk_plan_is_separately_gated_and_labeled(self):
        profile, owner_id = self.valid_profile()
        patch = replay.PatchEvidence(owner_id, "c" * 64, replay.RULES[3])
        target = next(iter(replay.TARGET_COUNTS))
        self.assertIsNone(replay.plan_competition_risk_replay(
            profile, patch, [target], 18.0, 4.0
        ))
        plan = replay.plan_competition_risk_replay(
            profile, patch, [target], 18.0, 4.0, enabled=True
        )
        self.assertEqual(plan["tier"], "competition-risk")
        self.assertIs(plan["proof"], False)
        self.assertEqual(plan["unclosed_barriers"], ("persistent_worker_state",))

    def test_risk_verifier_requires_complete_exact_slice(self):
        profile, owner_id = self.valid_profile()
        target = next(iter(replay.TARGET_COUNTS))
        patch = replay.PatchEvidence(owner_id, "c" * 64, replay.RULES[3])
        plan = replay.plan_competition_risk_replay(
            profile, patch, [target], 18.0, 4.0, enabled=True
        )
        prospective = [
            {key: row[key] for key in ("target", "history", "query", "rule", "input", "output")}
            for row in profile["boundary_rows"]
            if row["target"] == target and row["rule"] == replay.RULES[3]
        ]
        self.assertTrue(replay.verify_competition_risk_boundaries(profile, plan, prospective))
        self.assertFalse(replay.verify_competition_risk_boundaries(profile, plan, prospective[:-1]))
        tampered = copy.deepcopy(prospective)
        tampered[0]["output"] = "e" * 64
        self.assertFalse(replay.verify_competition_risk_boundaries(profile, plan, tampered))

    def test_risk_tier_can_match_boundaries_despite_hidden_state(self):
        profile, owner_id = self.valid_profile()
        target = next(iter(replay.TARGET_COUNTS))
        patch = replay.PatchEvidence(owner_id, "c" * 64, replay.RULES[3])
        plan = replay.plan_competition_risk_replay(
            profile, patch, [target], 18.0, 4.0, enabled=True
        )
        prospective = [
            {key: row[key] for key in ("target", "history", "query", "rule", "input", "output")}
            for row in profile["boundary_rows"]
            if row["target"] == target and row["rule"] == replay.RULES[3]
        ]
        hidden_state = {"mutations": 1}
        self.assertTrue(replay.verify_competition_risk_boundaries(profile, plan, prospective))
        self.assertEqual(hidden_state["mutations"], 1)
        self.assertIs(plan["proof"], False)


if __name__ == "__main__":
    unittest.main()
