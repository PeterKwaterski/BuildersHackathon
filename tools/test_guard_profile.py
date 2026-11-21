#!/usr/bin/env python3
from __future__ import annotations

import ast
import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import selector
import build_guard_profile as guard_builder
from collect_guard_observations import (
    INSTRUMENT_SUPPORT,
    Instrumenter,
    NONE_HOOK,
    TRUTH_HOOK,
    canonical_digest,
    copy_tracked_tree,
    exact_roster,
    executed_materialized_digest,
    generated_support_digest,
    generated_support_sources,
    git_tracked_paths,
    materialized_digest,
    sensitive_test_files,
    sensitive_test_owners,
    synchronous_worker_tests,
    test_rosters,
    tracked_inventory_digest,
)
from guard_profile_common import none_comparison, none_comparison_safe, truth_form, truth_state


class GuardProfileTests(unittest.TestCase):
    path = "sqlglot/example.py"

    def setUp(self):
        selector._SOURCE_TREES.clear()
        selector._SOURCE_INDEXES.clear()
        selector._IMPORT_DEFINITION_RANGES.clear()

    def change(self, source: str, old: str, new: str, *, extra=None, payload=None):
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

    def truth_profile(self, source: str):
        tree = ast.parse(source)
        guard = next(node for node in ast.walk(tree) if isinstance(node, ast.If))
        form, operand = truth_form(guard.test)
        position = [guard.test.lineno, guard.test.col_offset, guard.test.end_lineno, guard.test.end_col_offset]
        # One test observed each state, in STATE_NAMES order.
        entry = [
            *position, "truth", form, ast.dump(operand, include_attributes=False),
            None, "safe", "1f", "0", "1", "2", "4", "8", "10",
        ]
        return {"d": {self.path: [entry]}, "n": 5}

    def none_profile(self, source: str):
        tree = ast.parse(source)
        compare = next(node for node in ast.walk(tree) if isinstance(node, ast.Compare))
        operator, operand, side = none_comparison(compare)
        position = [compare.lineno, compare.col_offset, compare.end_lineno, compare.end_col_offset]
        # Test 1 has unsafe equality; test 2 has unsafe inequality.
        entry = [
            *position, "none", operator, ast.dump(operand, include_attributes=False),
            side, "safe", "f", "2", "4",
        ]
        return {"d": {self.path: [entry]}, "n": 4}

    def exemptions(self, source: str, change: dict, profile: dict):
        with patch.object(selector, "_PINNED_SOURCES", {self.path: source}):
            return selector.guard_profile_exemptions(change, self.path, profile, set())

    def test_truth_to_not_none_is_per_test(self):
        source = "def f(value):\n    if value:\n        return 1\n    return 0\n"
        result = self.exemptions(
            source,
            self.change(source, "if value:", "if value is not None:"),
            self.truth_profile(source),
        )
        self.assertEqual(result, {1, 2, 4})

    def test_not_to_is_none_uses_all_state_classes(self):
        source = "def f(value):\n    if not value:\n        return 1\n    return 0\n"
        result = self.exemptions(
            source,
            self.change(source, "if not value:", "if value is None:"),
            self.truth_profile(source),
        )
        # Both forms are false for truthy non-bools and True, and true for None.
        self.assertEqual(result, {1, 2, 4})

    def test_false_identity_to_not_uses_state_specific_results(self):
        source = "def f(value):\n    if value is False:\n        return 1\n    return 0\n"
        result = self.exemptions(
            source,
            self.change(source, "if value is False:", "if not value:"),
            self.truth_profile(source),
        )
        self.assertEqual(result, {1, 3, 4})

    def test_none_identity_to_equality_excludes_only_unsafe_tests(self):
        source = "def f(value):\n    if value is None:\n        return 1\n    return 0\n"
        result = self.exemptions(
            source,
            self.change(source, "value is None", "value == None"),
            self.none_profile(source),
        )
        self.assertEqual(result, {0, 2, 3})

    def test_none_identity_inequality_uses_separate_mask(self):
        source = "def f(value):\n    if value is not None:\n        return 1\n    return 0\n"
        result = self.exemptions(
            source,
            self.change(source, "value is not None", "value != None"),
            self.none_profile(source),
        )
        self.assertEqual(result, {0, 1, 3})

    def test_operand_side_and_syntax_must_be_identical(self):
        source = "def f(value):\n    if value is None:\n        return 1\n    return 0\n"
        profile = self.none_profile(source)
        attacks = (
            ("value is None", "other == None"),
            ("value is None", "None == value"),
            ("value is None", "value is True"),
        )
        for old, new in attacks:
            with self.subTest(new=new):
                self.assertIsNone(self.exemptions(source, self.change(source, old, new), profile))

        truth_source = "def f(obj):\n    if obj.value:\n        return 1\n    return 0\n"
        self.assertIsNone(
            self.exemptions(
                truth_source,
                self.change(truth_source, "if obj.value:", "if obj . value is not None:"),
                self.truth_profile(truth_source),
            )
        )

    def test_whole_tree_and_directive_gates_fail_closed(self):
        source = "def f(value):\n    if value:\n        return 1\n    return 0\n"
        profile = self.truth_profile(source)
        changed = self.change(
            source,
            "if value:",
            "if value is not None:",
            extra=("return 0", "return 2"),
        )
        self.assertIsNone(self.exemptions(source, changed, profile))
        directive = self.change(
            source,
            "if value:",
            "if value is not None:",
            payload=["if value:", "if value is not None:  # noqa"],
        )
        self.assertIsNone(self.exemptions(source, directive, profile))

    def test_unknown_and_malformed_masks_fail_closed(self):
        source = "def f(value):\n    if value:\n        return 1\n    return 0\n"
        change = self.change(source, "if value:", "if value is not None:")
        base = self.truth_profile(source)
        mutations = (
            lambda entry: entry.__setitem__(8, "unattributed"),
            lambda entry: entry.__setitem__(9, "not-hex"),
            lambda entry: entry.__setitem__(10, "20"),
            lambda entry: entry.__setitem__(11, "0"),
            lambda entry: entry.pop(),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                profile = copy.deepcopy(base)
                mutation(profile["d"][self.path][0])
                self.assertIsNone(self.exemptions(source, change, profile))

    def test_unknown_owner_is_retained_while_other_safe_owners_are_exempt(self):
        source = "def f(value):\n    if value:\n        return 1\n    return 0\n"
        profile = self.truth_profile(source)
        profile["d"][self.path][0][10] = "2"
        result = self.exemptions(
            source,
            self.change(source, "if value:", "if value is not None:"),
            profile,
        )
        self.assertEqual(result, {2, 4})

    def test_unseen_tests_are_never_exempted(self):
        source = "def f(value):\n    if value:\n        return 1\n    return 0\n"
        profile = self.truth_profile(source)
        entry = profile["d"][self.path][0]
        entry[9] = "3"  # only tests zero and one reached the site
        entry[11:] = ["1", "2", "0", "0", "0"]
        result = self.exemptions(
            source,
            self.change(source, "if value:", "if value is not None:"),
            profile,
        )
        self.assertEqual(result, {1})

    def test_instrumentation_evaluates_operand_once_and_preserves_identity(self):
        source = "def f(factory):\n    if factory() is None:\n        return 1\n    return 0\n"
        tree = ast.parse(source)
        instrumenter = Instrumenter(self.path)
        tree = ast.fix_missing_locations(instrumenter.visit(tree))
        observed = []
        sentinel = object()
        calls = []

        def factory():
            calls.append(1)
            return sentinel

        def observe(kind):
            def wrapper(_label, value):
                observed.append((kind, value))
                return value
            return wrapper

        namespace = {
            TRUTH_HOOK: observe("truth"),
            NONE_HOOK: observe("none"),
        }
        exec(compile(tree, self.path, "exec"), namespace)
        self.assertEqual(namespace["f"](factory), 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual([kind for kind, _value in observed], ["truth", "none"])
        self.assertTrue(all(value is sentinel for _kind, value in observed))

    def test_runtime_classification_never_invokes_unknown_protocols(self):
        calls = []

        class Hostile:
            def __bool__(self):
                calls.append("bool")
                raise AssertionError("unknown truth protocol was invoked")

            def __eq__(self, other):
                calls.append("eq")
                raise AssertionError("unknown equality protocol was invoked")

        hostile = Hostile()
        self.assertIsNone(truth_state(hostile))
        self.assertFalse(none_comparison_safe(hostile))
        self.assertEqual(calls, [])
        self.assertIsNone(truth_state([]))
        self.assertIsNone(truth_state([1]))
        self.assertTrue(none_comparison_safe(object()))

    def test_mutable_and_native_float_truth_remain_unknown(self):
        for value in ([], [1], {}, {1: 2}, set(), {1}, bytearray(), 0.0, 1.0, 0j, 1j):
            with self.subTest(value=value):
                self.assertIsNone(truth_state(value))
                self.assertTrue(none_comparison_safe(value))

    def test_truth_classifier_ignores_builtin_bool_and_type_monkeypatches(self):
        with patch("builtins.bool", side_effect=AssertionError("patched bool called")), patch(
            "builtins.type", side_effect=AssertionError("patched type called")
        ):
            state = truth_state(1)
            safe = none_comparison_safe(1)
        self.assertEqual(state, "true-nonbool")
        self.assertTrue(safe)

    def test_custom_metaclass_and_reflected_comparisons_are_unknown_without_calls(self):
        calls = []

        class Meta(type):
            def __bool__(cls):
                calls.append("bool")
                return False

            def __eq__(cls, other):
                calls.append("eq")
                return True

        class Hostile(metaclass=Meta):
            pass

        class Reflected:
            def __eq__(self, other):
                calls.append("reflected-eq")
                return NotImplemented

            def __ne__(self, other):
                calls.append("reflected-ne")
                return NotImplemented

        self.assertIsNone(truth_state(Hostile))
        self.assertFalse(none_comparison_safe(Hostile))
        self.assertFalse(none_comparison_safe(Reflected()))
        self.assertEqual(calls, [])

    def test_module_and_class_context_guards_are_not_exempted(self):
        source = "value = None\nif value is None:\n    FLAG = 1\n"
        result = self.exemptions(
            source,
            self.change(source, "value is None", "value == None"),
            self.none_profile(source),
        )
        self.assertIsNone(result)

        source = "class C:\n    value = None\n    if value is None:\n        FLAG = 1\n"
        result = self.exemptions(
            source,
            self.change(source, "value is None", "value == None"),
            self.none_profile(source),
        )
        self.assertIsNone(result)

    def test_generated_import_hook_instrumenter_matches_runtime_contract(self):
        support = (
            INSTRUMENT_SUPPORT.replace("__TRUTH_HOOK__", TRUTH_HOOK)
            .replace("__NONE_HOOK__", NONE_HOOK)
            .replace("__WORK_ROOT__", repr("/tmp/unused-guard-root"))
        )
        namespace = {}
        original = __import__("importlib").machinery.SourceFileLoader.get_code
        sys.modules["_br_guard_common"] = sys.modules["guard_profile_common"]
        try:
            with patch.dict("os.environ", {"GUARD_WORK_ROOT": "/tmp/unused-guard-root"}):
                exec(compile(support, "_br_guard_instrument.py", "exec"), namespace)
        finally:
            __import__("importlib").machinery.SourceFileLoader.get_code = original
            sys.modules.pop("_br_guard_common", None)
        source = "def f(factory):\n    if factory() is None:\n        return 1\n    return 0\n"
        tree = ast.fix_missing_locations(namespace["Instrumenter"](self.path).visit(ast.parse(source)))
        observed = []
        sentinel = object()
        calls = []

        def factory():
            calls.append(1)
            return sentinel

        def observe(kind):
            def wrapper(_label, value):
                observed.append((kind, value))
                return value
            return wrapper

        executed = {TRUTH_HOOK: observe("truth"), NONE_HOOK: observe("none")}
        exec(compile(tree, self.path, "exec"), executed)
        self.assertEqual(executed["f"](factory), 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual([kind for kind, _value in observed], ["truth", "none"])
        self.assertTrue(all(value is sentinel for _kind, value in observed))

    def test_generated_support_digest_binds_every_support_module(self):
        sources = generated_support_sources()
        expected = generated_support_digest(sources)
        self.assertEqual(expected, generated_support_digest())
        changed = dict(sources)
        changed["guard_profile_plugin.py"] += "\n# tampered\n"
        self.assertNotEqual(expected, generated_support_digest(changed))

    def test_runnable_and_skipped_rosters_are_unique_disjoint_and_order_bound(self):
        document = {
            "tests": [{"id": "tests/test_a.py::test_a"}, {"id": "tests/test_b.py::test_b"}],
            "skipped": ["tests/test_c.py::test_c", "tests/test_d.py::test_d"],
        }
        runnable, skipped = test_rosters(document)
        self.assertEqual(runnable, ["tests/test_a.py::test_a", "tests/test_b.py::test_b"])
        self.assertEqual(skipped, ["tests/test_c.py::test_c", "tests/test_d.py::test_d"])
        self.assertNotEqual(canonical_digest(skipped), canonical_digest(list(reversed(skipped))))
        self.assertTrue(exact_roster(sorted(runnable), set(runnable)))
        self.assertFalse(exact_roster(list(reversed(runnable)), set(runnable)))

        attacks = (
            {**document, "extra": []},
            {**document, "tests": [*document["tests"], document["tests"][0]]},
            {**document, "skipped": [document["tests"][0]["id"]]},
            {**document, "skipped": [1]},
        )
        for attack in attacks:
            with self.subTest(attack=attack):
                with self.assertRaises(SystemExit):
                    test_rosters(attack)

    def test_builder_requires_exact_runnable_declared_and_actual_skip_rosters(self):
        runnable = {"tests/test_a.py::test_a"}
        skipped = {"tests/test_b.py::test_b"}
        manifest = {
            "duplicate_protocols": [],
            "tests": sorted(runnable),
            "skipped": sorted(skipped),
            "skipped_protocols": sorted(skipped),
            "xfailed_reports": [],
        }
        guard_builder.require_manifest_rosters(manifest, runnable, skipped, "normal")
        for field, value in (
            ("tests", []),
            ("skipped", []),
            ("skipped_protocols", []),
            ("skipped", [*skipped, "tests/test_extra.py::test_extra"]),
            ("skipped_protocols", [*skipped, *skipped]),
            ("duplicate_protocols", [*runnable]),
            ("xfailed_reports", [*skipped]),
        ):
            with self.subTest(field=field, value=value):
                changed = {**manifest, field: value}
                with self.assertRaisesRegex(SystemExit, "inadmissible normal test rosters"):
                    guard_builder.require_manifest_rosters(changed, runnable, skipped, "normal")

    def test_declared_skip_protocol_is_unowned_and_actual_skip_is_separate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            support = root / "support"
            support.mkdir()
            sources = generated_support_sources()
            for name in (
                "_br_guard_common.py",
                "_br_guard_profile.py",
                "guard_profile_plugin.py",
            ):
                (support / name).write_text(sources[name])
            (support / "pytest.py").write_text(
                "def hookimpl(function=None, **kwargs):\n"
                "    if function is None:\n"
                "        return lambda decorated: decorated\n"
                "    return function\n"
            )
            script = r'''
import os
import guard_profile_plugin as plugin
import _br_guard_profile as tracker

skipped = "tests/test_skip.py::test_skip"
ordinary = "tests/test_ok.py::test_ok"
label = "truth:sqlglot/x.py:1:0:1:1"
tracker.integrity = lambda: True

class Item:
    def __init__(self, nodeid):
        self.nodeid = nodeid

class Report:
    def __init__(self, nodeid, skipped, wasxfail=None):
        self.nodeid = nodeid
        self.skipped = skipped
        if wasxfail is not None:
            self.wasxfail = wasxfail

def protocol(nodeid, body):
    hook = plugin.pytest_runtest_protocol(Item(nodeid), None)
    next(hook)
    body()
    try:
        next(hook)
    except StopIteration:
        pass
    else:
        raise AssertionError("protocol wrapper did not finish")

def skipped_body():
    assert tracker.CURRENT_TEST is None
    assert "BR_PARENT_TEST" not in os.environ
    tracker.observe_truth(label, 1)

def ordinary_body():
    assert tracker.CURRENT_TEST == ordinary
    assert os.environ["BR_PARENT_TEST"] == ordinary
    tracker.observe_truth(label, 1)

protocol(skipped, skipped_body)
plugin.pytest_runtest_logreport(Report(skipped, True))
protocol(ordinary, ordinary_body)
plugin.pytest_runtest_logreport(Report(ordinary, False))

assert plugin.EXECUTED == {ordinary}
assert plugin.SKIPPED_PROTOCOLS == {skipped}
assert plugin.REPORTED_SKIPPED == {skipped}
assert plugin.DUPLICATE_PROTOCOLS == set()
assert plugin.XFAILED_REPORTS == set()
assert tracker.CURRENT_TEST is None
assert "BR_PARENT_TEST" not in os.environ
for owners in tracker.document()[label].values():
    assert skipped not in owners
assert "__NO_TEST__" in tracker.document()[label]["seen"]
assert ordinary in tracker.document()[label]["seen"]

# Duplicate runnable and declared-skip protocols must remain visible rather
# than being collapsed by the set-valued exact rosters.
protocol(ordinary, ordinary_body)
protocol(skipped, skipped_body)
assert plugin.DUPLICATE_PROTOCOLS == {ordinary, skipped}

# XFAIL and XPASS both carry wasxfail and must poison the evidence even when
# their skipped outcomes differ.
plugin.pytest_runtest_logreport(Report(ordinary, True, "expected failure"))
plugin.pytest_runtest_logreport(Report(ordinary, False, "unexpected pass"))
assert plugin.XFAILED_REPORTS == {ordinary}
'''
            environment = os.environ.copy()
            environment.update({
                "BR_PARENT_TEST": "",
                "GUARD_SENSITIVE_OWNERS": "[]",
                "GUARD_SKIPPED_TESTS": json.dumps(["tests/test_skip.py::test_skip"]),
                "PYTHONPATH": str(support),
            })
            result = subprocess.run(
                [sys.executable, "-c", script],
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_sensitive_owner_fast_path_is_inert_and_owner_changes_do_not_leak(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            support = root / "support"
            children = root / "children"
            support.mkdir()
            children.mkdir()
            for stage in ("submitted", "started", "completed", "escaped"):
                (children / "pool" / stage).mkdir(parents=True)
            sources = generated_support_sources()
            for name in ("_br_guard_common.py", "_br_guard_profile.py"):
                (support / name).write_text(sources[name])
            script = r'''
import gc
import _br_guard_profile as tracker

sensitive = "tests/test_memory.py::test_retained_memory"
ordinary = "tests/test_safe.py::test_records"
truth = "truth:sqlglot/x.py:1:0:1:1"
none = "none:sqlglot/x.py:2:0:2:15"
sentinel = object()

tracker.CURRENT_TEST = sensitive
events_before = tracker.document()
escaped_before = set(tracker.ESCAPED)
tracker.tracemalloc.start()
before = tracker.tracemalloc.get_traced_memory()[0]
for _ in range(1000):
    assert tracker.observe_truth(truth, sentinel) is sentinel
    assert tracker.observe_none(none, sentinel) is sentinel
gc.collect()
after = tracker.tracemalloc.get_traced_memory()[0]
tracker.tracemalloc.stop()
assert after - before < 1024, (before, after, after - before)
assert tracker.document() == events_before
assert tracker.ESCAPED == escaped_before

tracker.CURRENT_TEST = ordinary
assert tracker.observe_truth(truth, 1) == 1
assert tracker.observe_none(none, None) is None
assert tracker.document()[truth]["seen"] == [ordinary]
assert tracker.document()[none]["seen"] == [ordinary]

# Exercise real pool-task owner changes.  Quarantine is membership-based, not
# a mutable disabled flag, so a sensitive task cannot suppress the next one.
tracker.run_owned_task(
    sensitive, "a" * 64, tracker.observe_truth, (truth, sentinel), {},
)
tracker.run_owned_task(
    ordinary, "b" * 64, tracker.observe_truth, (truth, 1), {},
)
assert tracker.CURRENT_TEST is None

# Exercise the actual at-fork reset shape: a child inherits a sensitive owner
# before its first persistent-pool task, then transitions to an ordinary task.
# The inherited interval must stay inert and must not suppress later evidence.
tracker.CURRENT_TEST = sensitive
tracker.register_child()
assert tracker.INITIAL_OWNER == sensitive
assert tracker.observe_truth(truth, sentinel) is sentinel
tracker.run_owned_task(
    ordinary, "c" * 64, tracker.observe_truth, (truth, 1), {},
)
assert tracker.CURRENT_TEST is None
for categories in tracker.document().values():
    for owners in categories.values():
        assert sensitive not in owners
assert ordinary in tracker.document()[truth]["seen"]
'''
            environment = os.environ.copy()
            environment.update({
                "BR_PARENT_TEST": "",
                "GUARD_CHILD_DIR": str(children),
                "GUARD_ROOT_PID": "1",
                "GUARD_SENSITIVE_OWNERS": json.dumps(
                    ["tests/test_memory.py::test_retained_memory"]
                ),
                "PYTHONPATH": str(support),
            })
            result = subprocess.run(
                [sys.executable, "-c", script],
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_both_trace_modes_must_retain_every_sensitive_owner(self):
        owners = {"tests/test_memory.py::test_memory", "tests/test_gc.py::test_gc"}
        pairs = {
            "normal": ({}, {"escaped": sorted(owners)}),
            "synchronous-worker": ({}, {"escaped": sorted(owners)}),
        }
        guard_builder.require_sensitive_quarantine(pairs, owners)
        pairs["synchronous-worker"][1]["escaped"].pop()
        with self.assertRaisesRegex(SystemExit, "synchronous-worker trace dropped"):
            guard_builder.require_sensitive_quarantine(pairs, owners)

    def test_pool_task_flushes_before_atexit_and_submitter_is_quarantined(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            support = root / "support"
            children = root / "children"
            support.mkdir()
            children.mkdir()
            for stage in ("submitted", "started", "completed", "escaped"):
                (children / "pool" / stage).mkdir(parents=True)
            sources = generated_support_sources()
            for name in ("_br_guard_common.py", "_br_guard_profile.py"):
                (support / name).write_text(sources[name])
            script = r'''
import json
from pathlib import Path
import _br_guard_profile as tracker

tracker.run_owned_task(
    "tests/test_pool.py::test_task", "a" * 64,
    tracker.observe_truth, ("truth:sqlglot/x.py:1:0:1:1", 1), {},
)
documents = list(Path(tracker.os.environ["GUARD_CHILD_DIR"]).glob("*.json"))
assert len(documents) == 1, documents
payload = json.loads(documents[0].read_text())
assert payload["events"]["truth:sqlglot/x.py:1:0:1:1"]["seen"] == ["tests/test_pool.py::test_task"]

captured = []
tracker._ORIGINAL_SUBMIT = lambda *args: captured.append(args) or object()
tracker.CURRENT_TEST = "tests/test_pool.py::test_submit"
tracker.owned_submit(object(), len, [1])
assert "tests/test_pool.py::test_submit" in tracker.ESCAPED
assert captured
'''
            environment = os.environ.copy()
            environment.update({
                "BR_PARENT_TEST": "",
                "GUARD_CHILD_DIR": str(children),
                "GUARD_ROOT_PID": "1",
                "GUARD_SENSITIVE_OWNERS": "[]",
                "PYTHONPATH": str(support),
            })
            result = subprocess.run(
                [sys.executable, "-c", script],
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_tracked_materialization_excludes_untracked_and_detects_sensitive_tests(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            work = Path(temporary) / "work"
            (source / "sqlglot").mkdir(parents=True)
            (source / "tests").mkdir()
            (source / "sqlglot/__init__.py").write_text("")
            (source / "tests/test_safe.py").write_text("def test_safe():\n    pass\n")
            (source / "tests/test_memory.py").write_text(
                "import gc\nimport weakref\ndef test_memory():\n    gc.collect()\n"
            )
            (source / "sqlglot/untracked.py").write_text("raise AssertionError\n")
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            subprocess.run(
                ["git", "-C", str(source), "add", "sqlglot/__init__.py", "tests"],
                check=True,
            )
            paths = git_tracked_paths(source)
            expected = materialized_digest(source, paths)
            self.assertEqual(copy_tracked_tree(source, work, paths), expected)
            self.assertFalse((work / "sqlglot/untracked.py").exists())
            self.assertEqual(sensitive_test_files(source, paths), ["tests/test_memory.py"])
            self.assertEqual(
                sensitive_test_owners(
                    [
                        "tests/test_safe.py::test_safe",
                        "tests/test_safe.py::test_memory_budget",
                        "tests/test_memory.py::test_other",
                    ],
                    ["tests/test_memory.py"],
                ),
                [
                    "tests/test_memory.py::test_other",
                    "tests/test_safe.py::test_memory_budget",
                ],
            )

    def test_tracked_materialization_binds_gitlink_mode_oid_and_empty_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            work = Path(temporary) / "work"
            source.mkdir()
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            (source / "tracked.py").write_text("VALUE = 1\n")
            subprocess.run(["git", "-C", str(source), "add", "tracked.py"], check=True)
            gitlink_oid = "1" * 40
            subprocess.run(
                [
                    "git", "-C", str(source), "update-index", "--add", "--cacheinfo",
                    f"160000,{gitlink_oid},vendor",
                ],
                check=True,
            )
            (source / "vendor").mkdir()

            entries = git_tracked_paths(source)
            gitlink = next(entry for entry in entries if entry.relative == Path("vendor"))
            self.assertEqual((gitlink.mode, gitlink.oid), ("160000", gitlink_oid))
            self.assertRegex(tracked_inventory_digest(entries), r"^[0-9a-f]{64}$")
            expected = materialized_digest(source, entries)
            self.assertEqual(copy_tracked_tree(source, work, entries), expected)
            self.assertTrue((work / "vendor").is_dir())
            self.assertEqual(list((work / "vendor").iterdir()), [])

            (source / "vendor/content").write_text("initialized\n")
            with self.assertRaisesRegex(SystemExit, "initialized or contentful"):
                materialized_digest(source, entries)
            (source / "vendor/content").unlink()
            (source / "vendor").rmdir()
            with self.assertRaisesRegex(SystemExit, "missing tracked gitlink"):
                materialized_digest(source, entries)
            (source / "vendor").write_text("wrong type\n")
            with self.assertRaisesRegex(SystemExit, "missing tracked gitlink"):
                materialized_digest(source, entries)

    def test_tracked_inventory_rejects_path_collisions(self):
        oid = b"1" * 40
        raw = b"100644 " + oid + b" 0\ta\0" + b"100644 " + oid + b" 0\ta/b\0"
        with patch.object(subprocess, "check_output", return_value=raw):
            with self.assertRaisesRegex(SystemExit, "tracked path collision"):
                git_tracked_paths(Path("/unused"))

    def test_materialized_digest_rejects_index_object_and_mode_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            source.mkdir()
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            path = source / "tracked.py"
            path.write_text("VALUE = 1\n")
            subprocess.run(["git", "-C", str(source), "add", "tracked.py"], check=True)
            entries = git_tracked_paths(source)
            executed_before = executed_materialized_digest(source, entries)

            path.write_text("VALUE = 2\n")
            with self.assertRaisesRegex(SystemExit, "tracked file object mismatch"):
                materialized_digest(source, entries)
            executed_after = executed_materialized_digest(source, entries)
            self.assertNotEqual(executed_after, executed_before)
            path.write_text("VALUE = 1\n")
            path.chmod(0o755)
            with self.assertRaisesRegex(SystemExit, "tracked executable mode mismatch"):
                materialized_digest(source, entries)

    def test_tracked_inventory_rejects_zero_oid_and_noncanonical_path(self):
        with patch.object(
            subprocess,
            "check_output",
            return_value=b"100644 " + b"0" * 40 + b" 0\ttracked.py\0",
        ):
            with self.assertRaisesRegex(SystemExit, "invalid tracked object ID"):
                git_tracked_paths(Path("/unused"))
        with patch.object(
            subprocess,
            "check_output",
            return_value=b"100644 " + b"1" * 40 + b" 0\ta//b\0",
        ):
            with self.assertRaisesRegex(SystemExit, "unsafe tracked path"):
                git_tracked_paths(Path("/unused"))

    def test_tracked_inventory_rejects_unmerged_unsupported_and_duplicate_entries(self):
        oid = b"1" * 40
        cases = (
            (b"100644 " + oid + b" 2\ta\0", "unmerged tracked entry"),
            (b"100664 " + oid + b" 0\ta\0", "unsupported tracked mode"),
            (
                b"100644 " + oid + b" 0\ta\0" + b"100755 " + oid + b" 0\ta\0",
                "duplicate tracked source inventory",
            ),
            (b"100644 " + oid + b" 0\ta", "malformed NUL-delimited"),
            (b"100644 " + oid + b" 0\ta\0\0", "malformed NUL-delimited"),
            (
                b"100644 " + oid + b" 0\ta\0" + b"100644 " + b"2" * 64 + b" 0\tb\0",
                "mixed Git object formats",
            ),
        )
        for raw, message in cases:
            with self.subTest(message=message), patch.object(
                subprocess, "check_output", return_value=raw
            ):
                with self.assertRaisesRegex(SystemExit, message):
                    git_tracked_paths(Path("/unused"))

    def test_materialization_rechecks_gitlink_source_after_copy(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            work = Path(temporary) / "work"
            source.mkdir()
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            oid = "1" * 40
            subprocess.run(
                [
                    "git", "-C", str(source), "update-index", "--add", "--cacheinfo",
                    f"160000,{oid},vendor",
                ],
                check=True,
            )
            gitlink = source / "vendor"
            gitlink.mkdir()
            entries = git_tracked_paths(source)
            pristine = materialized_digest
            source_checks = 0

            def mutate_after_first_source_check(root, checked_entries):
                nonlocal source_checks
                result = pristine(root, checked_entries)
                if root == source and source_checks == 0:
                    source_checks += 1
                    (gitlink / "late-content").write_text("race\n")
                return result

            with patch(
                "collect_guard_observations.materialized_digest",
                side_effect=mutate_after_first_source_check,
            ):
                with self.assertRaisesRegex(SystemExit, "initialized or contentful"):
                    copy_tracked_tree(source, work, entries)

    def test_executed_digest_admits_only_the_bound_synchronous_rewrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            work = Path(temporary) / "work"
            (source / "tests").mkdir(parents=True)
            (source / "tests/test_optimizer.py").write_text(
                "from concurrent.futures import ProcessPoolExecutor, as_completed, wait\n"
                "def parse_and_optimize(func, sql, read_dialect, **kwargs):\n"
                "    return func(sql)\n"
            )
            (source / "tests/test_executor.py").write_text(
                "from concurrent.futures import ProcessPoolExecutor\n"
                "DIR_TPCH = 'tpch'\n"
            )
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            subprocess.run(["git", "-C", str(source), "add", "tests"], check=True)
            entries = git_tracked_paths(source)
            copy_tracked_tree(source, work, entries)
            normal = executed_materialized_digest(work, entries)
            synchronous_worker_tests(work)
            synchronous = executed_materialized_digest(work, entries)
            self.assertNotEqual(normal, synchronous)
            with self.assertRaisesRegex(SystemExit, "tracked file object mismatch"):
                materialized_digest(work, entries)

    def test_line_coverage_is_narrowed_only_by_exemptions(self):
        source = "def f(value):\n    if value:\n        return 1\n    return 0\n"
        change = self.change(source, "if value:", "if value is not None:")
        model = {
            "f": {self.path: {"l": [[2, 0]], "s": [[1, 4, "f", 0]], "f": 0}},
            "z": [[0, 1, 2, 3, 4]],
        }
        with patch.object(selector, "_PINNED_SOURCES", {self.path: source}):
            result = selector.guard_profile_indices(
                change, self.path, self.truth_profile(source), model, set()
            )
        self.assertEqual(result, {0, 3})

    def test_valid_profile_rejects_wrong_inventory_metadata(self):
        valid = {
            "d": {}, "n": 2, "provenance": {}, "sha": "abc", "t": "digest",
            "tree": "tree", "v": 1,
        }
        self.assertTrue(selector.valid_guard_profile(valid, "abc", "digest", 2))
        for key, value in (("v", 2), ("sha", "other"), ("n", 3), ("d", [])):
            with self.subTest(key=key):
                candidate = dict(valid)
                candidate[key] = value
                self.assertFalse(selector.valid_guard_profile(candidate, "abc", "digest", 2))


if __name__ == "__main__":
    unittest.main()
