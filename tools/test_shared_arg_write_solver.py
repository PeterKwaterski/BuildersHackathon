#!/usr/bin/env python3
from __future__ import annotations

import copy
import gzip
import json
import unittest
from pathlib import Path

from tools.shared_arg_write_solver import (
    ESCAPE,
    UNKNOWN,
    WRITE,
    SharedArgumentSolver,
    compact,
    digest,
    load_sources,
)


ROOT = Path(__file__).resolve().parents[1]


class SharedArgumentSolverTests(unittest.TestCase):
    def solve(self, source: str):
        solver = SharedArgumentSolver({"sqlglot/example.py": source})
        document = solver.solve()
        functions = {
            info.qualname: info for info in solver.index.functions.values()
        }
        return solver, document, functions

    def test_safe_shared_argument_and_determinism(self):
        _, document, functions = self.solve(
            "def leaf(value):\n"
            "    pass\n"
            "def caller(shared):\n"
            "    leaf(shared)\n"
            "    leaf(value=shared)\n"
        )
        self.assertEqual(functions["leaf"].summary, [0])
        self.assertEqual(functions["caller"].summary, [0])
        self.assertEqual(document["stats"]["shared_formal_slots"], 1)
        self.assertEqual(document["stats"]["safe_shared_formal_slots"], 1)
        self.assertEqual(compact(document), compact(copy.deepcopy(document)))

    def test_write_and_escape_propagate_to_fixed_point(self):
        _, document, functions = self.solve(
            "def sink(value):\n"
            "    value[0] = 1\n"
            "def middle(item):\n"
            "    sink(item)\n"
            "def outer(root):\n"
            "    middle(root)\n"
            "def escape(value):\n"
            "    return value\n"
            "def escaping(root):\n"
            "    global saved\n"
            "    saved = escape(root)\n"
        )
        self.assertTrue(functions["sink"].summary[0] & WRITE)
        self.assertTrue(functions["middle"].summary[0] & WRITE)
        self.assertTrue(functions["outer"].summary[0] & WRITE)
        self.assertEqual(functions["escape"].summary[0], 0)
        self.assertEqual(functions["escape"].return_alias, {0})
        self.assertTrue(functions["escaping"].summary[0] & ESCAPE)
        self.assertGreaterEqual(document["stats"]["fixed_point_rounds"], 2)

    def test_bound_method_keyword_and_default_binding(self):
        _, _, functions = self.solve(
            "class Example:\n"
            "    def sink(self, value=None):\n"
            "        value[0] = 1\n"
            "    def caller(self, item):\n"
            "        self.sink(value=item)\n"
            "    def omitted(self, item):\n"
            "        self.sink()\n"
        )
        self.assertTrue(functions["Example.caller"].summary[1] & WRITE)
        self.assertEqual(functions["Example.omitted"].summary[1], 0)

    def test_exact_fresh_result_does_not_alias_call_arguments(self):
        _, _, functions = self.solve(
            "class Box:\n"
            "    def __init__(self, value):\n"
            "        pass\n"
            "def caller(argument):\n"
            "    result = Box(argument)\n"
            "    result.attribute = 1\n"
        )
        self.assertEqual(functions["caller"].summary[0], 0)

    def test_immediate_returned_lambda_has_typed_receiver_and_separate_capture(self):
        solver, document, functions = self.solve(
            "from typing import Callable\n"
            "class Generator:\n"
            "    def func(self, name, value):\n"
            "        return 'fixed'\n"
            "def rename(name) -> Callable[[Generator, object], str]:\n"
            "    return lambda self, expression: self.func(name, expression)\n"
            "def render(generator, expression):\n"
            "    return rename('NEW')(generator, expression)\n"
        )
        returned = functions["rename.<lambda>@6"]
        self.assertEqual(returned.parameter_classes[0], ("sqlglot/example.py", "Generator"))
        self.assertEqual(returned.capture_from[2], (functions["rename"].key, 0))
        self.assertEqual(returned.summary[2], 0)
        self.assertEqual(document["stats"]["calls"]["immediate-factory"], 1)
        self.assertTrue(
            any(
                edge.caller == returned.key
                and edge.caller_slot == 2
                and solver.index.functions[edge.callee].qualname == "Generator.func"
                and edge.callee_slot == 1
                for edge in solver.edges
            )
        )

    def test_owned_identity_wrapper_and_adversarial_escapes(self):
        safe = self.solve(
            "class Box:\n"
            "    def __init__(self):\n"
            "        self.value = None\n"
            "    def set(self, key, value):\n"
            "        self.value = value\n"
            "def identity(instance):\n"
            "    return instance\n"
            "def candidate():\n"
            "    item = identity(Box())\n"
            "    item.set('key', True)\n"
        )[1]
        self.assertEqual(safe["stats"]["contained_fresh_receiver_calls"], 1)

        variants = (
            "global saved\n    saved = instance\n",
            "unknown(instance)\n",
            "def nested():\n        return instance\n    nested()\n",
            "saved.append(instance)\n",
            "unknown([instance])\n",
            "getattr(instance, 'value')\n",
            "raise ValueError(instance)\n",
            "try:\n        raise ValueError(instance)\n    except ValueError:\n        raise\n",
            "try:\n        unknown(instance)\n    except Exception:\n        pass\n",
            "alias = instance\n    for _ in ():\n        alias = None\n    unknown(alias)\n",
            "if saved:\n        alias = instance\n    else:\n        alias = None\n    unknown(alias)\n",
        )
        for body in variants:
            with self.subTest(body=body):
                source = (
                    "saved = []\n"
                    "class Box:\n"
                    "    def __init__(self):\n"
                    "        self.value = None\n"
                    "    def set(self, key, value):\n"
                    "        self.value = value\n"
                    "def identity(instance):\n"
                    f"    {body}"
                    "    return instance\n"
                    "def candidate():\n"
                    "    item = identity(Box())\n"
                    "    item.set('key', True)\n"
                )
                document = self.solve(source)[1]
                self.assertEqual(
                    document["stats"]["contained_fresh_receiver_calls"], 0
                )
        descriptor = self.solve(
            "class Box:\n"
            "    def __init__(self):\n"
            "        self.value = None\n"
            "    @property\n"
            "    def callback(self):\n"
            "        return lambda: None\n"
            "    def set(self, key, value):\n"
            "        self.value = value\n"
            "def identity(instance):\n"
            "    instance.callback()\n"
            "    return instance\n"
            "def candidate():\n"
            "    item = identity(Box())\n"
            "    item.set('key', True)\n"
        )[1]
        self.assertEqual(descriptor["stats"]["contained_fresh_receiver_calls"], 0)
        partial_return = self.solve(
            "class Box:\n"
            "    def __init__(self):\n"
            "        self.value = None\n"
            "    def set(self, key, value):\n"
            "        self.value = value\n"
            "def identity(instance, flag):\n"
            "    if flag:\n"
            "        return instance\n"
            "def candidate(flag):\n"
            "    item = identity(Box(), flag)\n"
            "    item.set('key', True)\n"
        )[1]
        self.assertEqual(partial_return["stats"]["contained_fresh_receiver_calls"], 0)

    def test_extended_alias_escape_forms_reject(self):
        bodies = (
            "holder = [instance]\n",
            "holder = [value for value in [instance]]\n",
            "holder = (alias := instance)\n",
            "external.value = instance\n",
            "def nested(value=instance):\n        return value\n",
            "try:\n        return instance\n    finally:\n        saved.append(instance)\n",
            "with manager(instance):\n        pass\n",
            "match instance:\n        case _:\n            pass\n",
        )
        for body in bodies:
            with self.subTest(body=body):
                document = self.solve(
                    "saved = []\n"
                    "class Box:\n"
                    "    def set(self, key, value):\n"
                    "        self.value = value\n"
                    "def identity(instance):\n"
                    f"    {body}"
                    "    return instance\n"
                    "def candidate():\n"
                    "    item = identity(Box())\n"
                    "    item.set('key', True)\n"
                )[1]
                self.assertEqual(
                    document["stats"]["contained_fresh_receiver_calls"], 0
                )

    def test_branch_join_cannot_upgrade_maybe_alias_to_identity(self):
        variants = (
            "saved = Box()\n",
            "saved = None\n",
        )
        for declaration in variants:
            with self.subTest(declaration=declaration):
                document = self.solve(
                    declaration
                    + "class Box:\n"
                    "    def set(self, key, value):\n"
                    "        self.value = value\n"
                    "def identity(instance, flag):\n"
                    "    if flag:\n"
                    "        alias = instance\n"
                    "    else:\n"
                    "        alias = saved\n"
                    "    return alias\n"
                    "def candidate(flag):\n"
                    "    item = identity(Box(), flag)\n"
                    "    item.set('key', True)\n"
                )[1]
                self.assertEqual(
                    document["stats"]["contained_fresh_receiver_calls"], 0
                )

        loop_bodies = (
            "while flag:\n        alias = saved\n        break\n",
            "for _ in (1,):\n        alias = saved\n        continue\n",
        )
        for body in loop_bodies:
            with self.subTest(body=body):
                document = self.solve(
                    "saved = Box()\n"
                    "class Box:\n"
                    "    def set(self, key, value):\n"
                    "        self.value = value\n"
                    "def identity(instance, flag):\n"
                    "    alias = instance\n"
                    f"    {body}"
                    "    return alias\n"
                    "def candidate(flag):\n"
                    "    item = identity(Box(), flag)\n"
                    "    item.set('key', True)\n"
                )[1]
                self.assertEqual(
                    document["stats"]["contained_fresh_receiver_calls"], 0
                )

    def test_conditional_fresh_assignment_does_not_dominate_later_call(self):
        document = self.solve(
            "class Box:\n"
            "    def set(self, key, value):\n"
            "        self.value = value\n"
            "def candidate(shared, flag):\n"
            "    item = shared\n"
            "    if flag:\n"
            "        item = Box()\n"
            "        return\n"
            "    item.set('key', True)\n"
        )[1]
        self.assertEqual(document["stats"]["contained_fresh_receiver_calls"], 0)

    def test_attribute_protocol_and_descriptor_escapes_reject(self):
        variants = (
            "saved = []\n"
            "class Box:\n"
            "    def __getattribute__(self, name):\n"
            "        saved.append(self)\n"
            "        return object.__getattribute__(self, name)\n"
            "    def set(self, key, value):\n"
            "        self.value = value\n",
            "saved = []\n"
            "class Base:\n"
            "    def __getattr__(self, name):\n"
            "        saved.append(self)\n"
            "        return None\n"
            "class Box(Base):\n"
            "    def set(self, key, value):\n"
            "        self.value = value\n",
            "saved = []\n"
            "class Leak:\n"
            "    def __get__(self, instance, owner):\n"
            "        saved.append(instance)\n"
            "        return None\n"
            "class Box:\n"
            "    value = Leak()\n"
            "    def set(self, key, value):\n"
            "        self.value = value\n",
        )
        for classes in variants:
            with self.subTest(classes=classes):
                document = self.solve(
                    classes
                    + "def identity(instance):\n"
                    "    instance.value\n"
                    "    return instance\n"
                    "def candidate():\n"
                    "    item = identity(Box())\n"
                    "    item.set('key', True)\n"
                )[1]
                self.assertEqual(
                    document["stats"]["contained_fresh_receiver_calls"], 0
                )
    def test_alias_and_container_escape(self):
        _, _, functions = self.solve(
            "def sink(value):\n"
            "    value.attr = 1\n"
            "def caller(original, destination):\n"
            "    alias = original\n"
            "    sink(alias)\n"
            "    destination[0] = original\n"
        )
        self.assertTrue(functions["caller"].summary[0] & WRITE)
        self.assertTrue(functions["caller"].summary[0] & ESCAPE)

    def test_star_unknown_property_reflection_and_callable_fall_back(self):
        _, document, functions = self.solve(
            "def target(value):\n"
            "    pass\n"
            "def starred(value):\n"
            "    target(*value)\n"
            "def dynamic(value):\n"
            "    return value.attribute\n"
            "def reflected(value):\n"
            "    return getattr(value, 'x')\n"
            "def callback(function, value):\n"
            "    function(value)\n"
        )
        for name in ("starred", "dynamic", "reflected", "callback"):
            self.assertTrue(any(flags & UNKNOWN for flags in functions[name].summary))
        self.assertEqual(document["stats"]["fallbacks"]["starred-positional"], 1)
        self.assertEqual(document["stats"]["fallbacks"]["reflection-call"], 1)

    def test_closure_global_and_iteration_escape(self):
        _, _, functions = self.solve(
            "saved = None\n"
            "def closure(value):\n"
            "    def inner():\n"
            "        return value\n"
            "    return inner\n"
            "def global_store(value):\n"
            "    global saved\n"
            "    saved = value\n"
            "def iterate(value):\n"
            "    for item in value:\n"
            "        pass\n"
        )
        self.assertTrue(functions["closure"].summary[0] & ESCAPE)
        self.assertTrue(functions["global_store"].summary[0] & ESCAPE)
        self.assertTrue(functions["iterate"].summary[0] & UNKNOWN)

    def test_pinned_source_inventory_is_source_only(self):
        sources = load_sources(ROOT / "semantic_sources.json.gz")
        solver = SharedArgumentSolver(sources)
        document = solver.solve()
        self.assertEqual(document["stats"]["functions"], 5282)
        self.assertGreater(document["stats"]["edges"], 10_000)
        functions = {
            info.qualname: info for info in solver.index.functions.values()
        }
        at_time_zone = functions["Parser._parse_at_time_zone"]
        parser_expression = functions["Parser.expression"]
        rename_lambda = functions["rename_func.<lambda>@1393"]
        self.assertIn("at_time_zone", at_time_zone.fresh_names)
        self.assertEqual(
            at_time_zone.fresh_classes["at_time_zone"],
            ("sqlglot/expressions/core.py", "AtTimeZone"),
        )
        self.assertIn(
            (
                7186,
                12,
                "at_time_zone",
                "sqlglot/expressions/core.py:Expression.set:1084",
            ),
            at_time_zone.fresh_calls,
        )
        self.assertIn(
            (
                7186,
                12,
                "at_time_zone",
                "sqlglot/expressions/core.py:Expression.set:1084",
            ),
            at_time_zone.contained_fresh_calls,
        )
        self.assertEqual(parser_expression.return_alias, {1})
        self.assertEqual(rename_lambda.capture_from[2][1], 0)
        self.assertIn(0, rename_lambda.parameter_classes)
        self.assertNotIn("tests", document)
        raw = gzip.decompress(compact(document))
        self.assertEqual(digest(json.loads(raw)), digest(document))


if __name__ == "__main__":
    unittest.main()
