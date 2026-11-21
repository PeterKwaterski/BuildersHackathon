import unittest
from unittest import mock

import selector
from tpc_rule_replay import PatchEvidence


TARGET = next(iter(selector.TPC_RULE_TARGET_COUNTS))


class RuleReplayPortTests(unittest.TestCase):
    def test_empty_pin_is_identity_without_io(self):
        selected = [{"id": TARGET, "number": 1, "seconds": 20.0}]
        with mock.patch("pathlib.Path.read_bytes") as read:
            self.assertIsNone(selector.load_tpc_rule_replay_profile())
        read.assert_not_called()
        self.assertIs(
            selector.apply_tpc_rule_replay_risk(selected, [], None, None), selected
        )

    def test_profile_api_can_remove_only_verified_target(self):
        owner_id = "a" * 64
        selected = [
            {"id": TARGET, "number": 1, "seconds": 20.0},
            {"id": "tests/test_x.py::T::test_x", "number": 2, "seconds": 2.0},
        ]
        profile = {"owners": {owner_id: {"risk_cpu_s": {TARGET: 1.0}}}}
        evidence = PatchEvidence(owner_id, "b" * 64, "rule")
        result = selector.apply_tpc_rule_replay_risk(
            selected,
            [{"commit": "one"}],
            profile,
            lambda sources, _profile, _plan: sources,
            resolver=lambda _changes, _profile: (evidence, [("x.py", "source")]),
            planner=lambda *_args: {"tier": "competition-risk"},
            verifier=lambda _profile, _plan, rows: rows == [("x.py", "source")],
        )
        self.assertEqual(result, [selected[1]])

    def test_each_commit_collects_fresh_and_failure_is_identity(self):
        owner_id = "a" * 64
        selected = [{"id": TARGET, "number": 1, "seconds": 20.0}]
        profile = {"owners": {owner_id: {"risk_cpu_s": {TARGET: 1.0}}}}
        evidence = PatchEvidence(owner_id, "b" * 64, "rule")
        calls = []

        def collector(sources, _profile, _plan):
            calls.append(sources)
            if len(calls) == 2:
                raise RuntimeError("prospective failure")
            return sources

        kwargs = {
            "resolver": lambda changes, _profile: (evidence, [(changes[0]["path"], "s")]),
            "planner": lambda *_args: {"tier": "competition-risk"},
            "verifier": lambda *_args: True,
        }
        first = selector.apply_tpc_rule_replay_risk(
            selected, [{"path": "one"}], profile, collector, **kwargs
        )
        second = selector.apply_tpc_rule_replay_risk(
            selected, [{"path": "two"}], profile, collector, **kwargs
        )
        self.assertEqual(first, [])
        self.assertIs(second, selected)
        self.assertEqual(calls, [[("one", "s")], [("two", "s")]])


if __name__ == "__main__":
    unittest.main()
