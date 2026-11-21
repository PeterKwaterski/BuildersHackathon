#!/usr/bin/env python3
from __future__ import annotations

import copy
import gzip
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import selector
sys.path.insert(0, str(ROOT / "tools"))
import build_tokenizer_setting_flow as builder


class TokenizerSettingFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = json.load(gzip.open(ROOT / "tokenizer_setting_flow_model.json.gz", "rt"))
        cls.tests = json.loads((ROOT / "sample/tests.json").read_text())["tests"]

    def change(self, path: str, old: str, new: str, extra=None):
        source = selector.pinned_sources()[path]
        self.assertEqual(source.count(old), 1)
        changed = source.replace(old, new)
        if extra:
            changed = changed.replace(*extra)
        line = source[: source.index(old)].count("\n") + 1
        return {
            "_patched_source": changed,
            "lines": {line},
            "payload": [old, new],
        }

    def test_bundled_model_and_pin(self):
        digest = selector.hashlib.sha256(
            "\0".join(test["id"] for test in self.tests).encode()
        ).hexdigest()
        self.assertTrue(
            selector.valid_tokenizer_setting_flow_model(
                self.model, "eb11aec4be8cb2122afe713a4816662c3f0fb2fa", digest, len(self.tests)
            )
        )
        self.assertEqual(sum(map(len, self.model["d"].values())), 7)

    def test_exact_base_and_dialect_literal_edits(self):
        cases = (
            (
                "sqlglot/tokens.py",
                "NUMERIC_ESCAPES_ARE_BYTES = False",
                "NUMERIC_ESCAPES_ARE_BYTES = True",
                6,
            ),
            (
                "sqlglot/tokens.py",
                'LONE_SURROGATE_REPLACEMENT = ""',
                'LONE_SURROGATE_REPLACEMENT = "?"',
                0,
            ),
            (
                "sqlglot/dialects/clickhouse.py",
                "NUMERIC_ESCAPES_ARE_BYTES = True",
                "NUMERIC_ESCAPES_ARE_BYTES = False",
                6,
            ),
        )
        for path, old, new, expected in cases:
            with self.subTest(path=path, old=old):
                result = selector.tokenizer_setting_flow_edit(
                    self.change(path, old, new), path, self.model
                )
                self.assertIsNotNone(result)
                self.assertEqual(len(result), expected)

    def test_every_other_change_fails_closed(self):
        path = "sqlglot/tokens.py"
        old = "NUMERIC_ESCAPES_ARE_BYTES = False"
        cases = (
            ("NUMERIC_ESCAPES_ARE_BYTES = bool(1)", None),
            ("OTHER_NAME = True", None),
            (
                "NUMERIC_ESCAPES_ARE_BYTES = True",
                ("DROP_UNKNOWN_ESCAPES = False", "DROP_UNKNOWN_ESCAPES = True"),
            ),
        )
        for new, extra in cases:
            with self.subTest(new=new, extra=extra):
                self.assertIsNone(
                    selector.tokenizer_setting_flow_edit(
                        self.change(path, old, new, extra), path, self.model
                    )
                )

    def test_model_tampering_fails(self):
        digest = selector.hashlib.sha256(
            "\0".join(test["id"] for test in self.tests).encode()
        ).hexdigest()
        for mutate in (
            lambda value: value.update(p="0" * 64),
            lambda value: value.update(s="0" * 64),
            lambda value: value["r"].update(normal="0" * 64),
            lambda value: value["m"].update(normal="0" * 64),
            lambda value: value["d"]["sqlglot/tokens.py"][0][6].append(7),
        ):
            changed = copy.deepcopy(self.model)
            mutate(changed)
            self.assertFalse(
                selector.valid_tokenizer_setting_flow_model(
                    changed, "eb11aec4be8cb2122afe713a4816662c3f0fb2fa", digest, len(self.tests)
                )
            )

    def test_builder_rejects_extra_setting_and_field_observers(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            (source / "sqlglot").mkdir()
            (source / "tests").mkdir()
            tokens = (
                "from __future__ import annotations\n"
                "class _TokenizerBase:\n"
                "    X: int\n"
                "class Tokenizer:\n"
                "    X = 1\n"
                "    def _init_core(self):\n"
                "        return TokenizerCore(field=self.X)\n"
            )
            (source / builder.TOKENS).write_text(tokens)
            core = (
                "class TokenizerCore:\n"
                "    __slots__ = ('field',)\n"
                "    def __init__(self, field):\n"
                "        self.field = field\n"
                "    def use(self):\n"
                "        return self.field\n"
            )
            (source / builder.CORE).write_text(core)
            self.assertEqual(builder.transfer_map(source), {"X": "field"})
            self.assertEqual(builder.audit_setting_mentions(source, {"X"}), {"X"})
            self.assertIn("field", builder.core_uses(source, {"field"}))
            self.assertEqual(
                builder.externally_unobserved_fields(source, {"field"}), {"field"}
            )

            (source / "sqlglot/other.py").write_text("value = object.X\n")
            self.assertEqual(builder.audit_setting_mentions(source, {"X"}), set())
            (source / "sqlglot/other.py").write_text("value = object.field\n")
            self.assertEqual(
                builder.externally_unobserved_fields(source, {"field"}), set()
            )

            (source / "sqlglot/other.py").write_text("value = 'fi' + 'eld'\n")
            self.assertEqual(
                builder.externally_unobserved_fields(source, {"field"}), set()
            )

            (source / "sqlglot/other.py").write_text("")
            invalid_bodies = (
                "self.field = 2\n        return self.field",
                "return vars(self)",
                "alias = self\n        return native(alias)",
                "return self.__dict__",
                "return getattr(self, 'fi' + 'eld')",
            )
            for body in invalid_bodies:
                with self.subTest(body=body):
                    (source / builder.CORE).write_text(
                        core.replace("return self.field", body)
                    )
                    self.assertNotIn("field", builder.core_uses(source, {"field"}))
            (source / builder.CORE).write_text(
                core.replace("self.field = field", "self.field = field\n        sink(field)")
            )
            self.assertNotIn("field", builder.core_uses(source, {"field"}))

    def test_closed_core_lifecycle_rejects_escape_and_override(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            (source / "sqlglot").mkdir()
            (source / "tests").mkdir()
            tokens = (
                "class Tokenizer:\n"
                "    X = 1\n"
                "    def __init__(self):\n"
                "        self._core = self._init_core()\n"
                "    def _init_core(self):\n"
                "        return TokenizerCore(field=self.X)\n"
                "    def tokenize(self, sql):\n"
                "        return self._core.tokenize(sql)\n"
                "    @property\n"
                "    def sql(self):\n"
                "        return self._core.sql\n"
                "    @property\n"
                "    def size(self):\n"
                "        return self._core.size\n"
                "    @property\n"
                "    def tokens(self):\n"
                "        return self._core.tokens\n"
            )
            core = (
                "class TokenizerCore:\n"
                "    def __init__(self, field):\n"
                "        self.field = field\n"
            )
            (source / builder.TOKENS).write_text(tokens)
            (source / builder.CORE).write_text(core)
            other = source / "sqlglot/other.py"
            other.write_text("cached = Tokenizer()\n")
            self.assertTrue(builder.closed_core_lifecycle(source))

            attacks = (
                "value = cached._core\n",
                "class Evil(Tokenizer):\n    def _init_core(self):\n        return object()\n",
                "setattr(Tokenizer, '_init_' + 'core', lambda self: object())\n",
                "def consume(value):\n    return value\nvalue = consume(cached._core)\n",
            )
            for attack in attacks:
                with self.subTest(attack=attack):
                    other.write_text(attack)
                    self.assertFalse(builder.closed_core_lifecycle(source))


if __name__ == "__main__":
    unittest.main()
