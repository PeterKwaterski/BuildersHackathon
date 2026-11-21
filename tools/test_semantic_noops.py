#!/usr/bin/env python3
"""Adversarial checks for the quarantined semantic no-op families."""

from __future__ import annotations

import ast
import difflib
import gzip
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import selector
from semantic_noops import (
    external_import_reorder,
    local_binding_rename,
    plain_definition_reorder,
)
from collect_code_reflections import unsupported_external_reflection


PATH = "sqlglot/fake_semantic_noops.py"


def change_for(original: str, changed: str) -> dict:
    selector._PINNED_SOURCES = {PATH: original}
    selector._SOURCE_TREES.clear()
    selector._SOURCE_INDEXES.clear()
    patch = "diff --git a/{0} b/{0}\n".format(PATH) + "".join(
        difflib.unified_diff(
            original.splitlines(True),
            changed.splitlines(True),
            fromfile="a/" + PATH,
            tofile="b/" + PATH,
        )
    )
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary, "change.patch")
        path.write_text(patch)
        changes = selector.patch_changes(path)
    assert len(changes) == 1
    return changes[0]


class RuntimeDirectiveCommentTest(unittest.TestCase):
    def setUp(self) -> None:
        selector._PINNED_SOURCES = None
        selector._SOURCE_TREES.clear()
        selector._SOURCE_INDEXES.clear()

    def test_positionless_certificate_accepts_runtime_directives(self) -> None:
        original = "def f(value):\n    return value + 1\n"
        for directive in (
            "    # type: ignore\n",
            "    # noqa: F401\n",
            "    # pragma: no cover\n",
            "    # fmt: off\n",
            "    # pyright: ignore\n",
            "    # mypy: ignore-errors\n",
        ):
            with self.subTest(directive=directive):
                edit = change_for(original, "def f(value):\n" + directive + "    return value + 1\n")
                self.assertTrue(selector.runtime_inert_directive_comment(edit, PATH))

    def test_certificate_rejects_encoding_code_and_non_directive_comments(self) -> None:
        original = "def f(value):\n    return value + 1\n"
        changed_sources = (
            "# coding: utf-8\n" + original,
            "def f(value):\n    # ordinary comment\n    return value + 1\n",
            "def f(value):\n    value += 1  # noqa\n    return value + 1\n",
        )
        for changed in changed_sources:
            with self.subTest(changed=changed):
                edit = change_for(original, changed)
                self.assertFalse(selector.runtime_inert_directive_comment(edit, PATH))

    def test_certificate_rejects_class_firstline_changes(self) -> None:
        original = "class A:\n    pass\n\nclass B:\n    pass\n"
        changed = "class A:\n    # noqa\n    pass\n\nclass B:\n    pass\n"
        edit = change_for(original, changed)
        self.assertFalse(selector.runtime_inert_directive_comment(edit, PATH))

    def test_certificate_rejects_source_observed_typing_package(self) -> None:
        original = "def f(value):\n    return value + 1\n"
        changed = "def f(value):\n    # noqa\n    return value + 1\n"
        edit = change_for(original, changed)
        typing_path = "sqlglot/typing/fake.py"
        edit["old"] = typing_path
        edit["new"] = typing_path
        selector._PINNED_SOURCES = {typing_path: original}
        self.assertFalse(selector.runtime_inert_directive_comment(edit, typing_path))

    def test_type_ignore_changes_only_type_comment_ast(self) -> None:
        original = "def f(value):\n    return value + 1\n"
        changed = "def f(value):\n    # type: ignore\n    return value + 1\n"
        edit = change_for(original, changed)
        self.assertTrue(selector.runtime_inert_directive_comment(edit, PATH))
        self.assertEqual(
            ast.dump(ast.parse(original, type_comments=False), include_attributes=False),
            ast.dump(ast.parse(changed, type_comments=False), include_attributes=False),
        )
        self.assertNotEqual(
            ast.dump(ast.parse(original, type_comments=True), include_attributes=False),
            ast.dump(ast.parse(changed, type_comments=True), include_attributes=False),
        )

    def test_fingerprint_resource_failure_falls_back(self) -> None:
        original = "def f(value):\n    return value + 1\n"
        changed = "def f(value):\n    # noqa\n    return value + 1\n"
        edit = change_for(original, changed)
        with mock.patch.object(
            selector, "positionless_code_fingerprint", side_effect=RecursionError
        ):
            self.assertFalse(selector.runtime_inert_directive_comment(edit, PATH))

    def test_selector_retains_scope_and_reflection_owners_not_global_fallback(self) -> None:
        original = (
            "def f(value):\n    return value + 1\n\n"
            "def g(value):\n    return value - 1\n"
        )
        changed = (
            "def f(value):\n    # type: ignore\n    return value + 1\n\n"
            "def g(value):\n    return value - 1\n"
        )
        selector._PINNED_SOURCES = {PATH: original}
        patch = "diff --git a/{0} b/{0}\n".format(PATH) + "".join(
            difflib.unified_diff(
                original.splitlines(True),
                changed.splitlines(True),
                fromfile="a/" + PATH,
                tofile="b/" + PATH,
            )
        )
        model = {
            "a": {},
            "f": {
                PATH: {
                    "f": 2,
                    "i": [],
                    "l": [[2, 0], [5, 1]],
                    "s": [[1, 2, "f", 0], [4, 5, "f", 1]],
                }
            },
            "h": set(),
            "q": {},
            "r": {},
            "x": {},
            "z": [[9], [10], [7, 9, 10, 11]],
        }
        reflection = {
            "d": {
                PATH: [
                    [1, 2, "f", "observed", [7]],
                    [4, 5, "g", "observed", [10]],
                ]
            }
        }
        with tempfile.TemporaryDirectory() as temporary:
            patch_path = Path(temporary, "change.patch")
            patch_path.write_text(patch)
            self.assertEqual(
                selector.selected_indices(
                    patch_path,
                    model,
                    {7, 9, 10, 11},
                    reflection_model=reflection,
                ),
                {7, 9, 10},
            )
            self.assertEqual(
                selector.selected_indices(
                    patch_path,
                    model,
                    {7, 9, 10, 11},
                    reflection_model=None,
                ),
                {7, 9, 10, 11},
            )

    def tearDown(self) -> None:
        selector._PINNED_SOURCES = None
        selector._SOURCE_TREES.clear()
        selector._SOURCE_INDEXES.clear()


class LocalBindingRenameTest(unittest.TestCase):
    def assertProof(self, original: str, changed: str) -> None:
        self.assertIsNotNone(local_binding_rename(original, changed, PATH))

    def assertReject(self, original: str, changed: str) -> None:
        self.assertIsNone(local_binding_rename(original, changed, PATH))

    def test_straight_line_local(self) -> None:
        self.assertProof(
            "def f():\n    value = 1\n    return value\n",
            "def f():\n    other = 1\n    return other\n",
        )

    def test_test_module_local_rename_is_rejected(self) -> None:
        original = "def test_f():\n    value = 1\n    assert value\n"
        changed = "def test_f():\n    other = 1\n    assert other\n"
        self.assertIsNone(local_binding_rename(original, changed, "tests/test_fake.py"))

    def test_bijective_swap(self) -> None:
        self.assertProof(
            "def f():\n    aa = 1\n    bb = 2\n    return aa - bb\n",
            "def f():\n    bb = 1\n    aa = 2\n    return bb - aa\n",
        )

    def test_nested_closure(self) -> None:
        self.assertProof(
            "def f():\n    value = 1\n    def g():\n        return value\n    return g()\n",
            "def f():\n    other = 1\n    def g():\n        return other\n    return g()\n",
        )

    def test_comprehension_scope(self) -> None:
        self.assertProof(
            "def f(xs):\n    return [value + 1 for value in xs if value]\n",
            "def f(xs):\n    return [other + 1 for other in xs if other]\n",
        )

    def test_except_as_scope(self) -> None:
        self.assertProof(
            "def f():\n    try:\n        1 / 0\n    except Exception as error:\n        return str(error)\n",
            "def f():\n    try:\n        1 / 0\n    except Exception as issue:\n        return str(issue)\n",
        )
        self.assertReject(
            "def f():\n    try:\n        1 / 0\n    except Exception as error:\n        return lambda: error\n",
            "def f():\n    try:\n        1 / 0\n    except Exception as issue:\n        return lambda: issue\n",
        )

    def test_parameter_and_partial_renames_rejected(self) -> None:
        self.assertReject(
            "def f(value):\n    return value\n",
            "def f(other):\n    return other\n",
        )
        self.assertReject(
            "def f():\n    value = 1\n    return value + value\n",
            "def f():\n    other = 1\n    return other + value\n",
        )

    def test_global_nonlocal_and_builtin_rejected(self) -> None:
        self.assertReject(
            "value = 1\ndef f():\n    global value\n    return value\n",
            "value = 1\ndef f():\n    global value\n    return other\n",
        )
        self.assertReject(
            "def f():\n    value = 1\n    def g():\n        nonlocal value\n        return value\n    return g()\n",
            "def f():\n    value = 1\n    def g():\n        nonlocal value\n        return other\n    return g()\n",
        )
        self.assertReject(
            "def f():\n    return len([])\n",
            "def f():\n    return sum([])\n",
        )

    def test_attributes_strings_comments_and_width_rejected(self) -> None:
        self.assertReject(
            "def f(x):\n    return x.value\n",
            "def f(x):\n    return x.other\n",
        )
        self.assertReject(
            "def f():\n    value = 1\n    return 'value', value\n",
            "def f():\n    other = 1\n    return 'other', other\n",
        )
        self.assertReject(
            "def f():\n    value = 1  # value\n    return value\n",
            "def f():\n    other = 1  # other\n    return other\n",
        )
        self.assertReject(
            "def f():\n    x = 1\n    return x\n",
            "def f():\n    longer = 1\n    return longer\n",
        )

    def test_dynamic_frame_code_and_source_observation_rejected(self) -> None:
        for observer in (
            "locals()",
            "vars()",
            "sys._getframe()",
            "f.__code__",
            "inspect.getsource(f)",
        ):
            with self.subTest(observer=observer):
                self.assertReject(
                    "def f():\n    value = 1\n    " + observer + "\n    return value\n",
                    "def f():\n    other = 1\n    " + observer + "\n    return other\n",
                )
        self.assertReject(
            "import sys\nsys.settrace(trace)\ndef f():\n    value = 1\n    return value\n",
            "import sys\nsys.settrace(trace)\ndef f():\n    other = 1\n    return other\n",
        )

    def test_computed_and_aliased_reflection_rejected(self) -> None:
        observers = (
            'getattr(getattr(f, "__" + "code__"), "co_" + "varnames")',
            'builtins.getattr(f, "__" + "code__")',
            'object.__getattribute__(f, "__" + "code__")',
            'operator.attrgetter("__" + "code__")(f)',
            'inspect.getattr_static(f, "__" + "code__")',
            'inspect.getmembers(f)',
            'inspect.getmembers_static(f)',
            'gc.get_referents(f)',
            'globals()["get" + "attr"](f, "__" + "code__")',
            'sys._current_frames()',
            'sys._current_exceptions()',
            'exc.__traceback__.tb_frame.f_locals',
            'traceback.format_exc()',
            'Path(__file__).read_text()',
            'open("/opt/sqlglot/sqlglot/fake.py").read()',
        )
        for observer in observers:
            with self.subTest(observer=observer):
                self.assertReject(
                    "def f():\n    value = 1\n    " + observer + "\n    return value\n",
                    "def f():\n    other = 1\n    " + observer + "\n    return other\n",
                )

        aliases = (
            "from builtins import getattr as g\n",
            "from inspect import getsource as gs\n",
            "from operator import attrgetter as ag\n",
            "from sys import _getframe as gf\n",
            "from ctypes import cast as c\n",
        )
        for statement in aliases:
            with self.subTest(statement=statement):
                self.assertReject(
                    statement + "def f():\n    value = 1\n    return value\n",
                    statement + "def f():\n    other = 1\n    return other\n",
                )

    def test_unknown_getattr_is_fail_closed(self) -> None:
        # Even a currently harmless dynamic lookup is rejected: a later call can
        # feed it the renamed function and a constructed code/frame attribute.
        self.assertReject(
            "def lookup(obj, name):\n    return getattr(obj, name)\n\n"
            "def f():\n    value = 1\n    return value\n",
            "def lookup(obj, name):\n    return getattr(obj, name)\n\n"
            "def f():\n    other = 1\n    return other\n",
        )

    def test_potential_unbound_error_name_rejected(self) -> None:
        self.assertReject(
            "def f(flag):\n    if flag:\n        value = 1\n    return value\n",
            "def f(flag):\n    if flag:\n        other = 1\n    return other\n",
        )
        self.assertReject(
            "def f():\n    value += 1\n    return value\n",
            "def f():\n    other += 1\n    return other\n",
        )
        self.assertReject(
            "def f():\n    value = 1\n    del value\n    return value\n",
            "def f():\n    other = 1\n    del other\n    return other\n",
        )

    def test_public_suspended_frames_rejected(self) -> None:
        self.assertReject(
            "def f():\n    value = 1\n    yield value\n",
            "def f():\n    other = 1\n    yield other\n",
        )
        self.assertReject(
            "def f(xs):\n    return (value for value in xs)\n",
            "def f(xs):\n    return (other for other in xs)\n",
        )

    def test_selector_kill_switch(self) -> None:
        original = "def f():\n    value = 1\n    return value\n"
        changed = "def f():\n    other = 1\n    return other\n"
        edit = change_for(original, changed)
        self.assertEqual(selector.semantic_noop_edit(edit, PATH), "local-binding-rename")
        selector.SEMANTIC_NOOP_LOCAL_RENAME = False
        try:
            self.assertIsNone(selector.semantic_noop_edit(edit, PATH))
        finally:
            selector.SEMANTIC_NOOP_LOCAL_RENAME = True

    def test_selector_retains_reflection_reader_before_skipping_coverage(self) -> None:
        original = "def f():\n    value = 1\n    return value\n"
        changed = "def f():\n    other = 1\n    return other\n"
        selector._PINNED_SOURCES = {PATH: original}
        patch = "diff --git a/{0} b/{0}\n".format(PATH) + "".join(
            difflib.unified_diff(
                original.splitlines(True),
                changed.splitlines(True),
                fromfile="a/" + PATH,
                tofile="b/" + PATH,
            )
        )
        reflection = {"d": {PATH: [[1, 3, "f", "observed", [7]]]}}
        with tempfile.TemporaryDirectory() as temporary:
            patch_path = Path(temporary, "change.patch")
            patch_path.write_text(patch)
            self.assertEqual(
                selector.selected_indices(
                    patch_path,
                    {},
                    {7, 9},
                    reflection_model=reflection,
                ),
                {7},
            )

    def test_bundled_typing_reflection_reader_is_outcome_equivalent(self) -> None:
        path = "sqlglot/typing/__init__.py"
        original = selector.pinned_sources()[path]
        tree = ast.parse(original, filename=path, type_comments=True)
        function = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "annotate_by_numeric_arg"
        )
        lines = original.splitlines(True)
        positions = {}
        for node in ast.walk(function):
            if isinstance(node, ast.Name) and node.id == "this":
                positions.setdefault(node.lineno - 1, []).append(
                    (node.col_offset, node.end_col_offset)
                )
        for index, spans in positions.items():
            for start, end in sorted(spans, reverse=True):
                lines[index] = lines[index][:start] + "that" + lines[index][end:]
        changed = "".join(lines)
        self.assertIsNotNone(local_binding_rename(original, changed, path))
        patch = "diff --git a/{0} b/{0}\n".format(path) + "".join(
            difflib.unified_diff(
                original.splitlines(True),
                changed.splitlines(True),
                fromfile="a/" + path,
                tofile="b/" + path,
            )
        )
        with gzip.open(selector.CODE_REFLECTION_MODEL, "rt", encoding="utf-8") as stream:
            reflection = json.load(stream)
        with tempfile.TemporaryDirectory() as temporary:
            patch_path = Path(temporary, "change.patch")
            patch_path.write_text(patch)
            self.assertEqual(
                selector.selected_indices(
                    patch_path,
                    {},
                    set(range(1620)),
                    reflection_model=reflection,
                ),
                set(),
            )
            self.assertEqual(
                selector.selected_indices(
                    patch_path,
                    {},
                    set(range(1620)),
                    reflection_model=None,
                ),
                set(range(1620)),
            )

    def tearDown(self) -> None:
        selector._PINNED_SOURCES = None
        selector._SOURCE_TREES.clear()
        selector._SOURCE_INDEXES.clear()


class ExternalReflectionAuditTest(unittest.TestCase):
    def audit(self, source: str, path: str = "tests/fake.py") -> None:
        unsupported_external_reflection(
            ast.parse(source, filename=path, type_comments=True),
            Path(path),
        )

    def test_known_non_function_dynamic_lookups_are_accepted(self) -> None:
        self.audit("\n" * 428 + "getattr(schema, method)\n", "tests/test_schema.py")
        self.audit("\n" * 27 + "getattr(logger, level)\n", "tests/helpers.py")
        self.audit("getattr(module, '__file__', '.py')\n")

    def test_computed_code_and_alias_reads_are_rejected(self) -> None:
        rejected = (
            'getattr(f, "__" + "code__")\n',
            'getattr(code, "co_" + "varnames")\n',
            'from builtins import getattr as g\ng(f, "__code__")\n',
            'from inspect import getsource as gs\ngs(f)\n',
            'operator.attrgetter("__code__")(f)\n',
            'gc.get_referents(f)\n',
            'globals()["get" + "attr"](f, "__code__")\n',
            'builtins.__dict__["get" + "attr"](f, "__code__")\n',
            'g = builtins.getattr\ng(f, "__code__")\n',
            'from inspect import getsource\ng = getsource\ng(f)\n',
            'from ctypes import cast\ncast(1, 2)\n',
            'exception.__traceback__.tb_frame.f_locals\n',
            'traceback.format_exc()\n',
            'alias = getattr\n',
        )
        for source in rejected:
            with self.subTest(source=source), self.assertRaises(SystemExit):
                self.audit(source)

    def test_bundled_reflection_readers_are_digest_bound(self) -> None:
        with gzip.open(selector.CODE_REFLECTION_MODEL, "rt", encoding="utf-8") as stream:
            model = json.load(stream)
        self.assertTrue(
            selector.valid_code_reflection_model(
                model, model["sha"], model["t"], model["n"]
            )
        )
        altered = json.loads(json.dumps(model))
        entry = next(
            entry
            for entries in altered["d"].values()
            for entry in entries
            if entry[3] == "observed"
        )
        entry[4] = [0]
        self.assertFalse(
            selector.valid_code_reflection_model(
                altered, altered["sha"], altered["t"], altered["n"]
            )
        )


class ImportReorderTest(unittest.TestCase):
    def test_recognizes_only_isolated_unique_external_run(self) -> None:
        self.assertTrue(
            external_import_reorder("import os\nimport re\nX = 1\n", "import re\nimport os\nX = 1\n", PATH)
        )
        self.assertFalse(
            external_import_reorder("import os\nimport sqlglot\n", "import sqlglot\nimport os\n", PATH)
        )
        self.assertFalse(
            external_import_reorder("from . import x\nimport os\n", "import os\nfrom . import x\n", PATH)
        )
        self.assertFalse(
            external_import_reorder("import os as x\nimport re as x\n", "import re as x\nimport os as x\n", PATH)
        )
        self.assertFalse(
            external_import_reorder("import os\nimport re\nX = sys.modules\n", "import re\nimport os\nX = sys.modules\n", PATH)
        )
        self.assertFalse(
            external_import_reorder("import os\nimport re\n", "import re\nimport os\n", "tests/test_x.py")
        )


class DefinitionReorderTest(unittest.TestCase):
    def test_recognizes_plain_definitions(self) -> None:
        one = "def first():\n    return 1\n\ndef other():\n    return 2\n"
        two = "def other():\n    return 2\n\ndef first():\n    return 1\n"
        self.assertTrue(plain_definition_reorder(one, two, PATH))
        self.assertFalse(plain_definition_reorder(one, two, "tests/test_x.py"))
        self.assertTrue(
            plain_definition_reorder(
                "class C:\n    def first(self):\n        return 1\n    def other(self):\n        return 2\n",
                "class C:\n    def other(self):\n        return 2\n    def first(self):\n        return 1\n",
                PATH,
            )
        )

    def test_rejects_evaluation_and_reflection_channels(self) -> None:
        rejected = [
            ("@d\ndef first():\n    pass\ndef other():\n    pass\n", "def other():\n    pass\n@d\ndef first():\n    pass\n"),
            ("def first(x: T):\n    pass\ndef other():\n    pass\n", "def other():\n    pass\ndef first(x: T):\n    pass\n"),
            ("def first(x=make()):\n    pass\ndef other():\n    pass\n", "def other():\n    pass\ndef first(x=make()):\n    pass\n"),
            ("def first():\n    pass\ndef other():\n    pass\nX = vars()\n", "def other():\n    pass\ndef first():\n    pass\nX = vars()\n"),
        ]
        for one, two in rejected:
            with self.subTest(source=one):
                self.assertFalse(plain_definition_reorder(one, two, PATH))


if __name__ == "__main__":
    unittest.main()
