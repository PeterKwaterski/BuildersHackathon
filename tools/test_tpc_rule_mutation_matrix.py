from __future__ import annotations

import unittest

import tpc_rule_replay as replay


class Expression:
    def __init__(self, value):
        self.value = value

    def dump(self):
        return [{"c": "Synthetic", "a": {"this": self.value}}]

    def sql(self):
        return str(self.value)


def rules(replacement=None):
    result = []
    for index, qualified in enumerate(replay.RULES):
        module, name = qualified.rsplit(".", 1)

        def rule(expression, _index=index):
            if replacement is None:
                return expression
            return replacement(_index, expression)

        rule.__module__ = module
        rule.__name__ = name
        result.append(rule)
    return result


def trace(value, candidate_rules):
    _result, rows = replay.trace_rule_boundaries(
        Expression(value), candidate_rules, lambda function, expression: function(expression)
    )
    return [(row["input"], row["output"]) for row in rows]


class MutationMatrixTests(unittest.TestCase):
    def test_known_equal_mutation_matches_every_boundary(self):
        baseline = trace(7, rules())
        equal = trace(7, rules(lambda _index, expression: Expression(expression.value)))
        self.assertEqual(equal, baseline)

    def test_known_qualify_change_diverges_at_first_boundary(self):
        baseline = trace(7, rules())
        changed = trace(
            7,
            rules(lambda index, expression: Expression(8) if index == 0 else expression),
        )
        self.assertEqual(changed[0][0], baseline[0][0])
        self.assertNotEqual(changed[0][1], baseline[0][1])

    def test_known_unnest_change_diverges_at_fourth_boundary(self):
        baseline = trace(7, rules())
        changed = trace(
            7,
            rules(lambda index, expression: Expression(9) if index == 3 else expression),
        )
        self.assertEqual(changed[:3], baseline[:3])
        self.assertNotEqual(changed[3][1], baseline[3][1])

    def test_history_matrix_exposes_first_call_state(self):
        state = {"calls": 0}

        def mutation(index, expression):
            if index == 3:
                state["calls"] += 1
                if state["calls"] == 1:
                    return Expression(0)
            return expression

        candidate = rules(mutation)
        forward = [trace(value, candidate)[3][1] for value in (1, 2)]
        state["calls"] = 0
        reverse = [trace(value, candidate)[3][1] for value in (2, 1)]
        warm = [trace(value, candidate)[3][1] for value in (1, 2)]
        self.assertNotEqual(forward, reverse)
        self.assertNotEqual(forward, warm)


if __name__ == "__main__":
    unittest.main()
