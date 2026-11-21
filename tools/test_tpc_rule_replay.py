import contextlib
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


if __name__ == "__main__":
    unittest.main()
