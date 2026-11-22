from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
TREE = Path(os.environ.get("SQLGLOT_TREE", "/home/silverdisk/BuildersHackathon-branch/sqlglot"))
sys.path[:0] = [str(ROOT), str(TREE)]

from sqlglot import exp, parse_one  # noqa: E402

from tpc_graph_digest import GraphEncoder, UnsupportedGraph, graph_digest  # noqa: E402


class TpcGraphDigestTests(unittest.TestCase):
    def expression(self):
        return parse_one("SELECT a, b FROM x WHERE a > 1")

    def test_equal_independent_graphs_have_equal_digest(self) -> None:
        self.assertEqual(graph_digest(self.expression()), graph_digest(self.expression()))

    def test_shared_identity_topology_is_bound(self) -> None:
        shared = self.expression()
        dtype = exp.DataType.build("INT")
        shared.expressions[0]._type = dtype
        shared.expressions[1]._type = dtype

        copied = self.expression()
        copied.expressions[0]._type = exp.DataType.build("INT")
        copied.expressions[1]._type = exp.DataType.build("INT")
        self.assertNotEqual(graph_digest(shared), graph_digest(copied))

    def test_parent_arg_key_and_index_must_be_consistent(self) -> None:
        expression = self.expression()
        expression.expressions[0].arg_key = "wrong"
        with self.assertRaises(UnsupportedGraph):
            graph_digest(expression)

        expression = self.expression()
        expression.expressions[0].index = 9
        with self.assertRaises(UnsupportedGraph):
            graph_digest(expression)

    def test_comments_type_meta_and_cached_hash_are_bound(self) -> None:
        baseline = self.expression()
        mutations = []

        commented = self.expression()
        commented.expressions[0].comments = ["changed"]
        mutations.append(commented)

        typed = self.expression()
        typed.expressions[0]._type = exp.DataType.build("INT")
        mutations.append(typed)

        metadata = self.expression()
        metadata.expressions[0]._meta = {"changed": 1}
        mutations.append(metadata)

        cached = self.expression()
        cached._hash = 1234567
        mutations.append(cached)

        baseline_digest = graph_digest(baseline)
        for mutation in mutations:
            with self.subTest(mutation=type(mutation).__name__):
                self.assertNotEqual(baseline_digest, graph_digest(mutation))

    def test_scalar_types_and_argument_order_are_exact(self) -> None:
        left = exp.Literal(this="1", is_string=False)
        right = exp.Literal(is_string=False, this="1")
        self.assertNotEqual(graph_digest(left), graph_digest(right))

        integer = exp.Literal(this=1, is_string=False)
        string = exp.Literal(this="1", is_string=False)
        self.assertNotEqual(graph_digest(integer), graph_digest(string))

    def test_shared_child_with_inconsistent_single_parent_fails_closed(self) -> None:
        child = exp.column("a")
        expression = exp.select(child, child)
        with self.assertRaises(UnsupportedGraph):
            GraphEncoder().encode(expression)

    def test_backlink_and_nested_arg_expression_fail_closed(self) -> None:
        expression = self.expression()
        child = expression.expressions[0]
        expression.set("orphan", None)
        child.arg_key = "orphan"
        with self.assertRaises(UnsupportedGraph):
            graph_digest(expression)

        nested = exp.Literal(this="root", is_string=True)
        nested.args["nested"] = (exp.column("a"),)
        with self.assertRaises(UnsupportedGraph):
            graph_digest(nested)


if __name__ == "__main__":
    unittest.main()
