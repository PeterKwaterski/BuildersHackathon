#!/usr/bin/env python3
from __future__ import annotations

import ast
import copy
import gzip
import hashlib
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from build_module_constant_model import static_unsafe, validated_trace_document
from collect_module_constant_reads import (
    DERIVED_CLASS_ALIASES_ENABLED,
    TRACKER_TEMPLATE,
    collector_code_digest,
    class_alias_labels,
    import_maps,
    instrument_file,
    parsed_files,
    source_candidate_kinds,
    source_candidates,
)
import selector


class ModuleAssignmentPrecisionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.source = Path(self.temporary.name)
        (self.source / "sqlglot").mkdir()
        (self.source / "tests").mkdir()
        (self.source / "tests/__init__.py").write_text("")

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, relative: str, source: str) -> None:
        path = self.source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)

    def test_star_reexport_reaches_module_qualified_reader(self):
        self.write("sqlglot/core.py", "VALUE = ('a', 'b')\n")
        self.write("sqlglot/__init__.py", "from sqlglot.core import *\n")
        self.write("sqlglot/user.py", "import sqlglot as exp\n\ndef read():\n    return exp.VALUE\n")

        candidates = source_candidates(self.source)
        values, modules, qualified = import_maps(parsed_files(self.source), candidates)
        label = candidates[("sqlglot.core", "VALUE")]

        self.assertEqual(qualified[("sqlglot", "VALUE")], label)
        self.assertEqual(modules["sqlglot.user"]["exp"], "sqlglot")
        self.assertNotIn("exp", values["sqlglot.user"])

    def test_public_module_alias_reexport_reaches_qualified_reader(self):
        self.write("sqlglot/expressions.py", "VALUE = ('a', 'b')\n")
        self.write(
            "sqlglot/__init__.py",
            "from sqlglot import expressions as exp\n",
        )
        self.write(
            "sqlglot/user.py",
            "from sqlglot import exp\n\ndef read():\n    return exp.VALUE\n",
        )

        candidates = source_candidates(self.source)
        values, modules, qualified = import_maps(parsed_files(self.source), candidates)
        label = candidates[("sqlglot.expressions", "VALUE")]

        self.assertEqual(modules["sqlglot.user"]["exp"], "sqlglot.expressions")
        self.assertEqual(qualified[("sqlglot.expressions", "VALUE")], label)
        self.assertNotIn("exp", values["sqlglot.user"])

    def test_trace_task_ledger_rejects_missing_or_unattributed_work(self):
        normal = {
            "v": 3,
            "events": {"label": ["tests/test_owner.py::test_owner"]},
            "tasks": {
                "completed": ["task-1"],
                "submitted": ["task-1"],
                "workers": {"task-1": [123]},
            },
        }
        events, tasks = validated_trace_document(normal, "normal")
        self.assertEqual(events, normal["events"])
        self.assertEqual(tasks, normal["tasks"])

        for mutate in (
            lambda value: value["tasks"]["completed"].clear(),
            lambda value: value["tasks"]["workers"].clear(),
            lambda value: value["tasks"]["workers"]["task-1"].clear(),
            lambda value: value.update(v=2),
            lambda value: value.update(extra=True),
        ):
            broken = copy.deepcopy(normal)
            mutate(broken)
            with self.assertRaises(SystemExit):
                validated_trace_document(broken, "normal")

        synchronous = copy.deepcopy(normal)
        synchronous["tasks"] = {"completed": [], "submitted": [], "workers": {}}
        validated_trace_document(synchronous, "synchronous-worker")
        with self.assertRaises(SystemExit):
            validated_trace_document(synchronous, "normal")

    def test_collector_digest_binds_synchronous_rewrite_dependency(self):
        self.write("collect_module_constant_reads.py", "collector-v1\n")
        self.write("collect_dict_access.py", "rewrite-v1\n")
        first = collector_code_digest(self.source)
        self.write("collect_dict_access.py", "rewrite-v2\n")
        self.assertNotEqual(first, collector_code_digest(self.source))

    def test_module_model_recursive_validation_rejects_forged_body(self):
        digest = "a" * 64
        document = {
            "v": 3,
            "sha": "source",
            "n": 2,
            "t": "tests",
            "p": {
                "builder": digest,
                "collector": digest,
                "source_inventory": digest,
                "evidence": {
                    "normal": {
                        "child_logs": 3,
                        "completed_tasks": 2,
                        "manifest": digest,
                        "standalone_child_logs": 1,
                        "task_workers": 2,
                        "trace": digest,
                    },
                    "synchronous-worker": {
                        "child_logs": 1,
                        "completed_tasks": 0,
                        "manifest": digest,
                        "standalone_child_logs": 1,
                        "task_workers": 0,
                        "trace": digest,
                    },
                },
            },
            "d": {
                "sqlglot/executor/env.py": [
                    [182, 182, "FIRST", "Constant(value=0)", "literal", "safe", [0]]
                ]
            },
        }
        self.assertTrue(
            selector.valid_module_constant_model(document, "source", "tests", 2)
        )
        mutations = (
            lambda value: value["d"].update({1: []}),
            lambda value: value["d"].update({"sqlglot/executor/env.py": 1}),
            lambda value: value["d"]["sqlglot/executor/env.py"][0].append("extra"),
            lambda value: value["d"]["sqlglot/executor/env.py"][0][6].append(0),
            lambda value: value["d"]["sqlglot/executor/env.py"][0][6].append("0"),
            lambda value: value["d"]["sqlglot/executor/env.py"][0].__setitem__(4, []),
            lambda value: value["d"]["sqlglot/executor/env.py"][0].__setitem__(5, []),
            lambda value: value["d"]["sqlglot/executor/env.py"][0].__setitem__(5, "bogus"),
            lambda value: value["p"]["evidence"]["normal"].__setitem__(
                "completed_tasks", 0
            ),
            lambda value: value.update(extra=True),
        )
        for mutate in mutations:
            broken = copy.deepcopy(document)
            mutate(broken)
            self.assertFalse(
                selector.valid_module_constant_model(broken, "source", "tests", 2)
            )

    def test_module_model_loader_rejects_raw_and_recompressed_tampering(self):
        document = {"d": {"path": [[1, 1, "NAME", "Constant(value=1)"]]}}
        raw = gzip.compress(
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode(),
            mtime=0,
        )
        path = self.source / "model.json.gz"
        path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        self.assertEqual(selector.load_module_constant_model(path, digest), document)

        for tampered in (
            raw[:-1] + bytes([raw[-1] ^ 1]),
            raw + b"append",
            gzip.compress(b'{"d":{}}', mtime=0),
        ):
            path.write_bytes(tampered)
            self.assertEqual(
                selector.load_module_constant_model(path, digest), {"d": {}}
            )

    def test_star_reexport_honors_static_dunder_all(self):
        self.write(
            "sqlglot/core.py",
            "__all__ = ('PUBLIC',)\nPUBLIC = 1\nHIDDEN_BY_ALL = 2\n_PRIVATE = 3\n",
        )
        self.write("sqlglot/__init__.py", "from sqlglot.core import *\n")

        candidates = source_candidates(self.source)
        _values, _modules, qualified = import_maps(parsed_files(self.source), candidates)

        self.assertIn(("sqlglot", "PUBLIC"), qualified)
        self.assertNotIn(("sqlglot", "HIDDEN_BY_ALL"), qualified)
        self.assertNotIn(("sqlglot", "_PRIVATE"), qualified)

    def test_dynamic_duplicate_or_mutated_dunder_all_is_static_unsafe(self):
        variants = (
            "__all__ = tuple(name for name in ('VALUE',))\nVALUE = 1\n",
            "__all__ = ('VALUE',)\n__all__ = ('VALUE',)\nVALUE = 1\n",
            "__all__ = ['VALUE']\n__all__.append('OTHER')\nVALUE = 1\n",
            "__all__ = ['VALUE']\n__all__[0] = 'OTHER'\nVALUE = 1\n",
            "if True:\n    __all__ = ('VALUE',)\nVALUE = 1\n",
        )
        for index, core in enumerate(variants):
            with self.subTest(index=index):
                self.write("sqlglot/core.py", core)
                self.write("sqlglot/__init__.py", "from sqlglot.core import *\n")
                candidates = source_candidates(self.source)
                label = candidates[("sqlglot.core", "VALUE")]
                self.assertIn(label, static_unsafe(self.source, candidates))

    def test_dynamic_dunder_all_poison_follows_explicit_reexport(self):
        self.write("sqlglot/core.py", "VALUE = 1\n")
        self.write(
            "sqlglot/middle.py",
            "from sqlglot.core import VALUE\n"
            "__all__ = tuple(name for name in ('VALUE',))\n",
        )
        self.write("sqlglot/__init__.py", "from sqlglot.middle import *\n")
        candidates = source_candidates(self.source)

        self.assertIn(
            candidates[("sqlglot.core", "VALUE")], static_unsafe(self.source, candidates)
        )

    def test_absent_dunder_all_has_proved_public_surface(self):
        self.write("sqlglot/core.py", "VALUE = 1\n_PRIVATE = 2\n")
        self.write("sqlglot/__init__.py", "from sqlglot.core import *\n")
        candidates = source_candidates(self.source)

        self.assertNotIn(
            candidates[("sqlglot.core", "VALUE")], static_unsafe(self.source, candidates)
        )

    def test_module_getattr_poison_descendant_candidates(self):
        self.write("sqlglot/lazy/__init__.py", "def __getattr__(name):\n    raise AttributeError(name)\n")
        self.write("sqlglot/lazy/child.py", "VALUE = 1\n")
        self.write("sqlglot/__init__.py", "")
        candidates = source_candidates(self.source)

        self.assertIn(
            candidates[("sqlglot.lazy.child", "VALUE")],
            static_unsafe(self.source, candidates),
        )

    def test_dynamic_module_acquisition_is_static_unsafe(self):
        self.write("sqlglot/core.py", "VALUE = 1\n")
        self.write("sqlglot/__init__.py", "")
        variants = (
            "import importlib\nmodule = importlib.import_module('sqlglot.core')\nRESULT = module.VALUE\n",
            "import sys\nmodule = sys.modules['sqlglot.core']\nRESULT = module.VALUE\n",
            "module = __import__('sqlglot.core', fromlist=['VALUE'])\nRESULT = module.VALUE\n",
        )
        for index, source in enumerate(variants):
            with self.subTest(index=index):
                self.write("sqlglot/user.py", source)
                candidates = source_candidates(self.source)
                self.assertIn(
                    candidates[("sqlglot.core", "VALUE")],
                    static_unsafe(self.source, candidates),
                )

    def test_sys_modules_membership_does_not_observe_module_values(self):
        self.write("sqlglot/core.py", "VALUE = 1\n")
        self.write("sqlglot/__init__.py", "")
        self.write(
            "sqlglot/user.py",
            "import sys\nLOADED = 'sqlglot.core' in sys.modules\n",
        )
        candidates = source_candidates(self.source)

        self.assertNotIn(
            candidates[("sqlglot.core", "VALUE")],
            static_unsafe(self.source, candidates),
        )

        self.write(
            "sqlglot/user.py",
            "import sys\nEQUAL = {} == sys.modules\n",
        )
        candidates = source_candidates(self.source)
        self.assertIn(
            candidates[("sqlglot.core", "VALUE")],
            static_unsafe(self.source, candidates),
        )

    def test_dynamic_import_literal_prefix_poison_is_package_bounded(self):
        self.write("sqlglot/core.py", "CORE_VALUE = 1\n")
        self.write("sqlglot/dialects/a.py", "DIALECT_VALUE = 2\n")
        self.write("sqlglot/__init__.py", "")
        self.write("sqlglot/dialects/__init__.py", "")
        self.write(
            "sqlglot/user.py",
            "import importlib\n"
            "def load(name):\n"
            "    return importlib.import_module(f'sqlglot.dialects.{name}')\n",
        )
        candidates = source_candidates(self.source)
        unsafe = static_unsafe(self.source, candidates)

        self.assertIn(candidates[("sqlglot.dialects.a", "DIALECT_VALUE")], unsafe)
        self.assertNotIn(candidates[("sqlglot.core", "CORE_VALUE")], unsafe)

    def test_dynamic_import_poison_follows_reexport_surface(self):
        self.write("sqlglot/core.py", "VALUE = 1\n")
        self.write("sqlglot/__init__.py", "")
        self.write("sqlglot/dialects/__init__.py", "")
        self.write("sqlglot/dialects/a.py", "from sqlglot.core import VALUE\n")
        self.write(
            "sqlglot/user.py",
            "import importlib\n"
            "def load(name):\n"
            "    return importlib.import_module(f'sqlglot.dialects.{name}')\n",
        )
        candidates = source_candidates(self.source)

        self.assertIn(
            candidates[("sqlglot.core", "VALUE")],
            static_unsafe(self.source, candidates),
        )

    def test_aliased_dynamic_import_fails_closed(self):
        self.write("sqlglot/core.py", "VALUE = 1\n")
        self.write("sqlglot/__init__.py", "")
        self.write(
            "sqlglot/user.py",
            "import importlib as il\n"
            "loader = il.import_module\n"
            "def load(name):\n"
            "    return loader(name)\n",
        )
        candidates = source_candidates(self.source)

        self.assertIn(
            candidates[("sqlglot.core", "VALUE")],
            static_unsafe(self.source, candidates),
        )

    def test_unreachable_unnumbered_test_is_outside_authenticated_threat_surface(self):
        self.write("sqlglot/core.py", "VALUE = 1\n")
        self.write("sqlglot/__init__.py", "")
        self.write(
            "tests/test_docs.py",
            "import importlib\n"
            "def test_docs(name):\n"
            "    return importlib.import_module(name)\n",
        )
        candidates = source_candidates(self.source)
        label = candidates[("sqlglot.core", "VALUE")]

        self.assertIn(label, static_unsafe(self.source, candidates))
        self.assertNotIn(
            label,
            static_unsafe(self.source, candidates, {"tests/test_other.py"}),
        )

    def test_imported_support_module_remains_in_numbered_threat_surface(self):
        self.write("sqlglot/core.py", "VALUE = 1\n")
        self.write("sqlglot/__init__.py", "")
        self.write(
            "tests/helpers.py",
            "import importlib\n"
            "def acquire(name):\n"
            "    return importlib.import_module(name)\n",
        )
        self.write(
            "tests/test_owner.py",
            "from tests.helpers import acquire\n"
            "def test_owner():\n"
            "    return acquire('sqlglot.core')\n",
        )
        candidates = source_candidates(self.source)

        self.assertIn(
            candidates[("sqlglot.core", "VALUE")],
            static_unsafe(
                self.source,
                candidates,
                {"tests/test_owner.py"},
            ),
        )

    def test_test_package_setup_and_nested_conftest_are_in_threat_surface(self):
        self.write("sqlglot/core.py", "VALUE = 1\n")
        self.write("sqlglot/__init__.py", "")
        self.write(
            "tests/dialects/__init__.py",
            "import importlib\nMODULE = importlib.import_module('sqlglot.core')\n",
        )
        self.write(
            "tests/dialects/conftest.py",
            "import sys\nMODULE = sys.modules['sqlglot.core']\n",
        )
        self.write("tests/dialects/test_owner.py", "def test_owner(): pass\n")
        candidates = source_candidates(self.source)

        self.assertIn(
            candidates[("sqlglot.core", "VALUE")],
            static_unsafe(
                self.source,
                candidates,
                {"tests/dialects/test_owner.py"},
            ),
        )

    def test_pinned_exception_shape_mismatch_fails_closed(self):
        self.write("sqlglot/core.py", "VALUE = 1\n")
        self.write("sqlglot/__init__.py", "")
        self.write(
            "sqlglot/serde.py",
            "def _load(name):\n"
            "    module = __import__(name)\n"
            "    return module.VALUE\n",
        )
        candidates = source_candidates(self.source)
        self.assertIn(
            candidates[("sqlglot.core", "VALUE")],
            static_unsafe(self.source, candidates),
        )

        self.write(
            "tests/helpers.py",
            "def is_compiled(module):\n"
            "    return getattr(module, 'VALUE')\n",
        )
        self.write(
            "tests/test_generator.py",
            "from tests.helpers import is_compiled\n"
            "import sqlglot.core as _core_module\n"
            "RESULT = is_compiled(_core_module)\n",
        )
        candidates = source_candidates(self.source)
        self.assertIn(
            candidates[("sqlglot.core", "VALUE")],
            static_unsafe(
                self.source,
                candidates,
                {"tests/test_generator.py"},
            ),
        )

    def test_executor_environment_module_escape_requires_pinned_consumers_and_key(self):
        self.write("sqlglot/__init__.py", "")
        self.write("sqlglot/expressions.py", "VALUE = 1\n")
        sources = {
            "sqlglot/executor/env.py": (
                "import sqlglot.expressions as exp\nENV = {'exp': exp}\n"
            ),
            "sqlglot/executor/python.py": "RESULT = 1\n",
            "sqlglot/executor/context.py": "RESULT = 1\n",
            "sqlglot/generators/python.py": "RESULT = 1\n",
        }
        for relative, text in sources.items():
            self.write(relative, text)

        def tree_digest(text):
            return hashlib.sha256(
                ast.dump(ast.parse(text), include_attributes=False).encode()
            ).hexdigest()

        hashes = {
            "EXECUTOR_ENV_MODULE_AST_SHA256": tree_digest(
                sources["sqlglot/executor/env.py"]
            ),
            "EXECUTOR_PYTHON_MODULE_AST_SHA256": tree_digest(
                sources["sqlglot/executor/python.py"]
            ),
            "EXECUTOR_CONTEXT_MODULE_AST_SHA256": tree_digest(
                sources["sqlglot/executor/context.py"]
            ),
            "PYTHON_GENERATOR_MODULE_AST_SHA256": tree_digest(
                sources["sqlglot/generators/python.py"]
            ),
        }
        with patch.multiple("build_module_constant_model", **hashes):
            candidates = source_candidates(self.source)
            label = candidates[("sqlglot.expressions", "VALUE")]
            self.assertNotIn(label, static_unsafe(self.source, candidates))

            changed = "import sqlglot.expressions as exp\nENV = {'other': exp}\n"
            self.write("sqlglot/executor/env.py", changed)
            hashes["EXECUTOR_ENV_MODULE_AST_SHA256"] = tree_digest(changed)
            with patch.multiple("build_module_constant_model", **hashes):
                candidates = source_candidates(self.source)
                self.assertIn(label, static_unsafe(self.source, candidates))

    def test_patch_object_module_escape_requires_fixed_candidate_name(self):
        self.write("sqlglot/__init__.py", "")
        self.write("sqlglot/expressions.py", "VALUE = 1\n")
        self.write(
            "tests/test_optimizer.py",
            "import sqlglot.expressions as exp\n"
            "from unittest.mock import patch\n"
            "with patch.object(exp, 'column_table_names', None):\n"
            "    pass\n",
        )
        candidates = source_candidates(self.source)
        label = candidates[("sqlglot.expressions", "VALUE")]
        self.assertNotIn(
            label,
            static_unsafe(self.source, candidates, {"tests/test_optimizer.py"}),
        )

        self.write(
            "tests/test_optimizer.py",
            "import sqlglot.expressions as exp\n"
            "from unittest.mock import patch\n"
            "with patch.object(exp, 'VALUE', None):\n"
            "    pass\n",
        )
        candidates = source_candidates(self.source)
        self.assertIn(
            label,
            static_unsafe(self.source, candidates, {"tests/test_optimizer.py"}),
        )

    def test_star_import_cycle_is_static_unsafe(self):
        self.write("sqlglot/a.py", "VALUE = 1\nfrom sqlglot.b import *\n")
        self.write("sqlglot/b.py", "from sqlglot.a import *\n")
        self.write("sqlglot/__init__.py", "")
        candidates = source_candidates(self.source)

        self.assertIn(
            candidates[("sqlglot.a", "VALUE")], static_unsafe(self.source, candidates)
        )

    def test_rebound_or_ambiguous_module_alias_is_not_resolved(self):
        self.write("sqlglot/a.py", "VALUE = 1\n")
        self.write("sqlglot/b.py", "VALUE = 2\n")
        self.write("sqlglot/__init__.py", "")
        variants = (
            "import sqlglot.a as source\nsource = object()\ndef read():\n    return source.VALUE\n",
            "import sqlglot.a as source\nimport sqlglot.b as source\ndef read():\n    return source.VALUE\n",
            "import sqlglot.a as source\ndef read(source):\n    return source.VALUE\n",
        )
        for index, user in enumerate(variants):
            with self.subTest(index=index):
                self.write("sqlglot/user.py", user)
                files = parsed_files(self.source)
                _values, modules, _qualified = import_maps(
                    files, source_candidates(self.source)
                )
                self.assertNotIn("source", modules["sqlglot.user"])

    def test_rebinding_after_star_import_stops_reexport(self):
        self.write("sqlglot/core.py", "VALUE = 1\n")
        self.write(
            "sqlglot/__init__.py",
            "from sqlglot.core import *\nVALUE = 2\n",
        )
        candidates = source_candidates(self.source)
        _values, _modules, qualified = import_maps(parsed_files(self.source), candidates)

        self.assertNotEqual(
            qualified.get(("sqlglot", "VALUE")),
            candidates[("sqlglot.core", "VALUE")],
        )

    def test_star_reexport_no_longer_poisoned_as_static_unsafe(self):
        self.write("sqlglot/core.py", "VALUE = ('a', 'b')\n")
        self.write("sqlglot/__init__.py", "from sqlglot.core import *\n")
        self.write("sqlglot/user.py", "from sqlglot import VALUE\n\ndef read():\n    return VALUE\n")

        candidates = source_candidates(self.source)
        self.assertNotIn(candidates[("sqlglot.core", "VALUE")], static_unsafe(self.source, candidates))

    def test_class_tuple_candidates_require_proved_class_bindings(self):
        self.write(
            "sqlglot/core.py",
            "class Local:\n    pass\n\ndef LooksLikeClass():\n    pass\n\n"
            "CLASSES = (Local,)\nNOT_CLASSES = (LooksLikeClass,)\n",
        )
        self.write("sqlglot/__init__.py", "")

        kinds = source_candidate_kinds(self.source)

        self.assertEqual(kinds[("sqlglot.core", "CLASSES")], "class-tuple")
        self.assertNotIn(("sqlglot.core", "NOT_CLASSES"), kinds)

    def test_imported_class_tuple_and_exact_re_compile_are_candidates(self):
        self.write("sqlglot/core.py", "class First:\n    pass\nclass Second:\n    pass\n")
        self.write(
            "sqlglot/user.py",
            "import re\nfrom sqlglot.core import First, Second\n"
            "KINDS = (First, Second)\nPATTERN = re.compile(r'^x+$')\n",
        )
        self.write("sqlglot/__init__.py", "")

        kinds = source_candidate_kinds(self.source)

        self.assertEqual(kinds[("sqlglot.user", "KINDS")], "class-tuple")
        self.assertEqual(kinds[("sqlglot.user", "PATTERN")], "re-pattern")

    def test_rebound_re_and_new_class_call_are_not_candidates(self):
        self.write(
            "sqlglot/core.py",
            "import re\nre = object()\nPATTERN = re.compile('x')\n"
            "class Real:\n    pass\nCLASSES = (Real(),)\n",
        )
        self.write("sqlglot/__init__.py", "")

        kinds = source_candidate_kinds(self.source)

        self.assertNotIn(("sqlglot.core", "PATTERN"), kinds)
        self.assertNotIn(("sqlglot.core", "CLASSES"), kinds)

    def test_rebound_class_name_is_not_a_proved_class_tuple(self):
        self.write(
            "sqlglot/core.py",
            "class FormerClass:\n    pass\nFormerClass = lambda: None\n"
            "CLASSES = (FormerClass,)\n",
        )
        self.write("sqlglot/__init__.py", "")

        self.assertNotIn(
            ("sqlglot.core", "CLASSES"), source_candidate_kinds(self.source)
        )

    def test_exact_getattr_is_traced_but_dynamic_getattr_is_unsafe(self):
        self.write("sqlglot/core.py", "VALUE = ('a', 'b')\n")
        self.write("sqlglot/__init__.py", "")
        self.write(
            "sqlglot/user.py",
            "import sqlglot.core as core\n"
            "def exact():\n    return getattr(core, 'VALUE'), hasattr(core, 'VALUE')\n",
        )
        candidates = source_candidates(self.source)
        label = candidates[("sqlglot.core", "VALUE")]
        self.assertNotIn(label, static_unsafe(self.source, candidates))

        self.write(
            "sqlglot/user.py",
            "import sqlglot.core as core\n"
            "def exact():\n    return getattr(core, 'VALUE'), hasattr(core, 'VALUE')\n"
            "def dynamic(name):\n    return getattr(core, name)\n",
        )
        files = parsed_files(self.source)
        values, modules, qualified = import_maps(files, candidates)
        user = self.source / "sqlglot/user.py"
        module, _is_package, tree = files[user]

        count = instrument_file(user, tree, values[module], modules[module], qualified)

        self.assertGreaterEqual(count, 1)
        self.assertIn("_br_module_constant_read", user.read_text())
        self.assertIn(label, static_unsafe(self.source, candidates))

    def test_shadowed_reflective_builtin_is_not_rewritten_or_exempted(self):
        self.write("sqlglot/core.py", "VALUE = ('a', 'b')\n")
        self.write("sqlglot/__init__.py", "")
        self.write(
            "sqlglot/user.py",
            "import sqlglot.core as core\n"
            "def read(getattr):\n    return getattr(core, 'VALUE')\n",
        )
        candidates = source_candidates(self.source)
        label = candidates[("sqlglot.core", "VALUE")]
        files = parsed_files(self.source)
        values, modules, qualified = import_maps(files, candidates)
        user = self.source / "sqlglot/user.py"
        module, _is_package, tree = files[user]
        instrument_file(user, tree, values[module], modules[module], qualified)

        self.assertNotIn("_br_module_constant_getattr", user.read_text())
        self.assertIn(label, static_unsafe(self.source, candidates))

    def test_class_alias_binding_is_not_an_import_time_read(self):
        self.write("sqlglot/core.py", "import re\nPATTERN = re.compile('x')\n")
        self.write("sqlglot/__init__.py", "from sqlglot.core import *\n")
        self.write(
            "sqlglot/user.py",
            "import sqlglot as exp\n"
            "class Reader:\n"
            "    ALIAS = exp.PATTERN\n"
            "    def matches(self, text):\n"
            "        return self.ALIAS.match(text)\n",
        )
        candidates = source_candidates(self.source)
        files = parsed_files(self.source)
        values, modules, qualified = import_maps(files, candidates)
        aliases = class_alias_labels(files, values, modules, qualified)
        label = candidates[("sqlglot.core", "PATTERN")]
        self.assertEqual(aliases[("sqlglot.user", "Reader", "ALIAS")], label)

        user = self.source / "sqlglot/user.py"
        module, _is_package, tree = files[user]
        instrument_file(
            user,
            tree,
            values[module],
            modules[module],
            qualified,
            {"ALIAS"},
        )
        transformed = user.read_text()
        self.assertIn("ALIAS = exp.PATTERN", transformed)
        self.assertNotIn(f"_br_module_constant_read('{label}', exp.PATTERN)", transformed)
        self.assertIn("_br_module_constant_class_attr(self, 'ALIAS')", transformed)

    def test_derived_class_aliases_are_production_disabled(self):
        self.assertFalse(DERIVED_CLASS_ALIASES_ENABLED)
        self.write("sqlglot/core.py", "import re\nPATTERN = re.compile('x')\n")
        self.write("sqlglot/__init__.py", "from sqlglot.core import *\n")
        self.write(
            "sqlglot/user.py",
            "import sqlglot as exp\nclass Reader:\n    ALIAS = exp.PATTERN\n",
        )
        candidates = source_candidates(self.source)
        files = parsed_files(self.source)
        values, modules, qualified = import_maps(files, candidates)
        user = self.source / "sqlglot/user.py"
        module, _is_package, tree = files[user]
        instrument_file(user, tree, values[module], modules[module], qualified, set())
        self.assertIn("_br_module_constant_read", user.read_text())

    def test_class_alias_rebind_or_construction_hook_is_rejected(self):
        variants = (
            "class Reader:\n    ALIAS = exp.PATTERN\n    ALIAS = object()\n",
            "class Reader:\n    ALIAS = exp.PATTERN\n    del ALIAS\n",
            "@decorator\nclass Reader:\n    ALIAS = exp.PATTERN\n",
            "class Reader(Base):\n    ALIAS = exp.PATTERN\n",
            "class Reader(metaclass=Meta):\n    ALIAS = exp.PATTERN\n",
            "class Reader:\n    ALIAS = exp.PATTERN\n    COPY = ALIAS\n",
        )
        for index, body in enumerate(variants):
            with self.subTest(index=index):
                self.write("sqlglot/core.py", "import re\nPATTERN = re.compile('x')\n")
                self.write("sqlglot/__init__.py", "from sqlglot.core import *\n")
                self.write("sqlglot/user.py", "import sqlglot as exp\n" + body)
                candidates = source_candidates(self.source)
                files = parsed_files(self.source)
                values, modules, qualified = import_maps(files, candidates)
                aliases = class_alias_labels(files, values, modules, qualified)
                self.assertFalse(aliases)

    def test_class_alias_reflection_sites_are_instrumented(self):
        self.write("sqlglot/core.py", "import re\nPATTERN = re.compile('x')\n")
        self.write("sqlglot/__init__.py", "from sqlglot.core import *\n")
        self.write(
            "sqlglot/user.py",
            "import inspect\nimport sqlglot as exp\n"
            "class Reader:\n"
            "    ALIAS = exp.PATTERN\n"
            "def reflect(owner, name):\n"
            "    a = vars(owner).items()\n"
            "    b = owner.__dict__['ALIAS']\n"
            "    c = getattr(owner, name)\n"
            "    d = inspect.getmembers(owner)\n"
            "    e = hasattr(owner, name)\n"
            "    f = dir(owner)\n"
            "    return a, b, c, d, e, f\n",
        )
        candidates = source_candidates(self.source)
        files = parsed_files(self.source)
        values, modules, qualified = import_maps(files, candidates)
        aliases = class_alias_labels(files, values, modules, qualified)
        user = self.source / "sqlglot/user.py"
        module, _is_package, tree = files[user]

        instrument_file(
            user,
            tree,
            values[module],
            modules[module],
            qualified,
            {name for _module, _qualname, name in aliases},
        )
        transformed = user.read_text()
        self.assertIn("_br_module_constant_vars(owner).items()", transformed)
        self.assertIn("_br_module_constant_class_dict(owner)['ALIAS']", transformed)
        self.assertIn("_br_module_constant_getattr(owner, name)", transformed)
        self.assertIn("_br_module_constant_hasattr(owner, name)", transformed)
        self.assertIn("_br_module_constant_dir(owner)", transformed)
        self.assertIn("_br_module_constant_reflect_call(inspect.getmembers, owner)", transformed)
        compile(
            TRACKER_TEMPLATE.replace("__CLASS_ALIASES__", repr(aliases)),
            "<tracker>",
            "exec",
        )

    def test_reflection_wrappers_preserve_values_and_record_before_errors(self):
        label = "sqlglot/core.py:1:1:VALUE"
        tracker = {}
        exec(
            compile(
                TRACKER_TEMPLATE.replace(
                    "__CLASS_ALIASES__", repr({(__name__, "Reader", "ALIAS"): label})
                ),
                "<tracker>",
                "exec",
            ),
            tracker,
        )

        class Reader:
            ALIAS = object()

        # The synthetic class must match the provenance key embedded above.
        tracker["CLASS_ALIASES"] = {(Reader.__module__, Reader.__qualname__, "ALIAS"): label}
        mapping = tracker["class_vars"](Reader)
        self.assertIsInstance(mapping, types.MappingProxyType)
        self.assertIs(mapping["ALIAS"], Reader.ALIAS)
        self.assertIsInstance(tracker["class_dict"](Reader), types.MappingProxyType)
        self.assertTrue(tracker["class_hasattr"](Reader, "ALIAS"))
        self.assertIn("ALIAS", tracker["class_dir"](Reader))

        def raising(_value):
            raise RuntimeError("after reflection")

        with self.assertRaisesRegex(RuntimeError, "after reflection"):
            tracker["reflect_call"](raising, Reader)
        self.assertIn(label, tracker["EVENTS"])

    def test_direct_attribute_records_before_custom_lookup_raises(self):
        label = "sqlglot/core.py:1:1:VALUE"
        tracker = {}
        exec(
            compile(TRACKER_TEMPLATE.replace("__CLASS_ALIASES__", "{}"), "<tracker>", "exec"),
            tracker,
        )

        class Meta(type):
            def __getattribute__(cls, name):
                if name == "ALIAS":
                    raise RuntimeError("blocked")
                return super().__getattribute__(name)

        class Reader(metaclass=Meta):
            ALIAS = object()

        tracker["CLASS_ALIASES"] = {(Reader.__module__, Reader.__qualname__, "ALIAS"): label}
        with self.assertRaisesRegex(RuntimeError, "blocked"):
            tracker["class_attr"](Reader, "ALIAS")
        self.assertIn(label, tracker["EVENTS"])

    @unittest.skipUnless(DERIVED_CLASS_ALIASES_ENABLED, "derived class aliases disabled")
    def test_opaque_class_receiver_escape_poison_origin(self):
        self.write("sqlglot/core.py", "import re\nPATTERN = re.compile('x')\n")
        self.write("sqlglot/__init__.py", "from sqlglot.core import *\n")
        self.write(
            "sqlglot/user.py",
            "import sqlglot as exp\n"
            "class Reader:\n    ALIAS = exp.PATTERN\n"
            "def opaque(value):\n    return value\n"
            "ESCAPED = opaque(Reader)\n",
        )
        candidates = source_candidates(self.source)
        label = candidates[("sqlglot.core", "PATTERN")]

        self.assertIn(label, static_unsafe(self.source, candidates))

    @unittest.skipUnless(DERIVED_CLASS_ALIASES_ENABLED, "derived class aliases disabled")
    def test_class_alias_owner_construction_or_subclass_is_unsafe(self):
        variants = (
            "INSTANCE = Reader()\n",
            "class Child(Reader):\n    pass\n",
        )
        for index, use in enumerate(variants):
            with self.subTest(index=index):
                self.write("sqlglot/core.py", "import re\nPATTERN = re.compile('x')\n")
                self.write("sqlglot/__init__.py", "from sqlglot.core import *\n")
                self.write(
                    "sqlglot/user.py",
                    "import sqlglot as exp\nclass Reader:\n    ALIAS = exp.PATTERN\n" + use,
                )
                candidates = source_candidates(self.source)
                label = candidates[("sqlglot.core", "PATTERN")]
                self.assertIn(label, static_unsafe(self.source, candidates))

    @unittest.skipUnless(DERIVED_CLASS_ALIASES_ENABLED, "derived class aliases disabled")
    def test_native_uninstrumented_reflection_poison_origin(self):
        self.write("sqlglot/core.py", "import re\nPATTERN = re.compile('x')\n")
        self.write("sqlglot/__init__.py", "from sqlglot.core import *\n")
        self.write(
            "sqlglot/user.py",
            "import inspect\nimport sqlglot as exp\n"
            "class Reader:\n    ALIAS = exp.PATTERN\n"
            "VALUE = inspect.getattr_static(Reader, 'ALIAS')\n",
        )
        candidates = source_candidates(self.source)
        label = candidates[("sqlglot.core", "PATTERN")]

        self.assertIn(label, static_unsafe(self.source, candidates))


if __name__ == "__main__":
    unittest.main()
