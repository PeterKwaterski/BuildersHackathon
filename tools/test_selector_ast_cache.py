import ast
import gc
import unittest
import weakref

import selector


PATH = "sqlglot/fake_index.py"


def follow(root, path):
    node = root
    for field, index in path:
        value = getattr(node, field, None)
        node = value if index is None else value[index]
    return node


class AstCacheTest(unittest.TestCase):
    def tearDown(self):
        selector._PINNED_SOURCES = None
        selector._SOURCE_TREES.clear()
        selector._SOURCE_INDEXES.clear()
        selector._SOURCE_CODE.clear()
        selector._IMPORT_DEFINITION_RANGES.clear()

    def test_order_parents_and_paths_match_ast_walk(self):
        tree = ast.parse(
            "@decorate(x=1)\nclass C(Base):\n"
            "    def f(self, values):\n"
            "        return [item + 1 for item in values if item]\n"
        )
        index = selector._AstIndex(tree)
        self.assertEqual(index.nodes, tuple(ast.walk(tree)))
        expected = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        self.assertEqual(index.parents, expected)
        for child in expected:
            self.assertIs(follow(tree, index.path(child)), child)

    def test_index_rebuilds_when_source_tree_changes(self):
        selector._PINNED_SOURCES = {PATH: "def first():\n    return 1\n"}
        first_tree = selector.source_tree(PATH)
        first_ref = weakref.ref(first_tree)
        first = selector._source_index(PATH)
        selector._PINNED_SOURCES = {PATH: "def second():\n    return 2\n"}
        selector._SOURCE_TREES.clear()
        second = selector._source_index(PATH)
        self.assertIsNot(first, second)
        self.assertEqual([node.name for node in second.functions], ["second"])
        self.assertEqual(len(selector._SOURCE_INDEXES), 1)
        del first, first_tree
        gc.collect()
        self.assertIsNone(first_ref())

    def test_malformed_source_is_cached_fail_closed(self):
        selector._PINNED_SOURCES = {PATH: "def broken("}
        self.assertIsNone(selector.source_tree(PATH))
        self.assertIsNone(selector._source_index(PATH))
        self.assertIsNone(selector._source_index(PATH))

    def test_complete_pinned_inventory_matches_ast_walk(self):
        selector._PINNED_SOURCES = None
        selector._SOURCE_TREES.clear()
        selector._SOURCE_INDEXES.clear()
        for path in selector.pinned_sources():
            tree = selector.source_tree(path)
            if tree is None:
                continue
            index = selector._source_index(path)
            self.assertEqual(index.nodes, tuple(ast.walk(tree)), path)
            self.assertEqual(
                index.parents,
                {
                    child: parent
                    for parent in ast.walk(tree)
                    for child in ast.iter_child_nodes(parent)
                },
                path,
            )


if __name__ == "__main__":
    unittest.main()
