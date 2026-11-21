#!/usr/bin/env python3
"""Focused fail-closed tests for Generator.TRANSFORMS runtime gating."""

from __future__ import annotations

import ast
import copy
import gzip
import hashlib
import json
import unittest
from pathlib import Path

import selector
from build_generator_dispatch_model import known_initialization_operation


PATH = "sqlglot/generator.py"


def fixture():
    source = selector.pinned_sources()[PATH]
    tree = ast.parse(source)
    statement = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "TRANSFORMS"
    )
    index = next(
        index for index, value in enumerate(statement.value.values) if isinstance(value, ast.Lambda)
    )
    value = statement.value.values[index]
    entry = [
        statement.lineno,
        statement.end_lineno,
        "Generator",
        index,
        ast.dump(statement.value.keys[index], include_attributes=False),
        ast.dump(value, include_attributes=False),
        "safe",
        [1, 3],
    ]
    return source, tree, statement, index, value, entry


def replace_source(source: str, target: ast.AST, replacement: str) -> str:
    lines = source.splitlines(keepends=True)
    offsets, position = [], 0
    for line in lines:
        offsets.append(position)
        position += len(line)

    def offset(line: int, column: int) -> int:
        prefix = lines[line - 1].encode("utf-8")[:column].decode("utf-8")
        return offsets[line - 1] + len(prefix)

    start = offset(target.lineno, target.col_offset)
    end = offset(target.end_lineno, target.end_col_offset)
    return source[:start] + replacement + source[end:]


def change(patched: str, line: int):
    return {
        "_patched_source": patched,
        "hunks": [{"old_start": line, "old_count": 1, "lines": []}],
        "lines": {line},
        "payload": ["synthetic"],
    }


class GeneratorDispatchGateTest(unittest.TestCase):
    def test_recognizes_only_exact_pinned_dialect_initialization_pop(self):
        self.assertTrue(
            known_initialization_operation(
                "pop", "sqlglot/dialects/dialect.py", 355, "__new__"
            )
        )
        for operation, path, line, owner in (
            ("write", "sqlglot/dialects/dialect.py", 355, "__new__"),
            ("pop", "dialects/dialect.py", 355, "__new__"),
            ("pop", "sqlglot/dialects/dialect.py", 354, "__new__"),
            ("pop", "sqlglot/dialects/dialect.py", 355, "other"),
        ):
            self.assertFalse(known_initialization_operation(operation, path, line, owner))

    def test_accepts_only_body_change(self):
        source, _, _, _, value, entry = fixture()
        patched = replace_source(source, value.body, "'sentinel'")
        self.assertEqual(
            selector.generator_transform_edit(
                change(patched, value.body.lineno), PATH, {"d": {PATH: [entry]}, "n": 10}
            ),
            {1, 3},
        )

    def test_rejects_key_change(self):
        source, _, statement, index, value, entry = fixture()
        patched = replace_source(source, statement.value.keys[index], "exp.Select")
        self.assertIsNone(
            selector.generator_transform_edit(
                change(patched, value.lineno), PATH, {"d": {PATH: [entry]}, "n": 10}
            )
        )

    def test_rejects_signature_change(self):
        source, _, _, _, value, entry = fixture()
        original = ast.get_source_segment(source, value)
        self.assertIsNotNone(original)
        patched = replace_source(source, value, original.replace("lambda self, e:", "lambda self, e, x=1:"))
        self.assertIsNone(
            selector.generator_transform_edit(
                change(patched, value.lineno), PATH, {"d": {PATH: [entry]}, "n": 10}
            )
        )

    def test_rejects_unsafe_state_and_reader(self):
        source, _, _, _, value, entry = fixture()
        patched = replace_source(source, value.body, "'sentinel'")
        unsafe = copy.deepcopy(entry)
        unsafe[6] = "unsafe-observation"
        self.assertIsNone(
            selector.generator_transform_edit(
                change(patched, value.lineno), PATH, {"d": {PATH: [unsafe]}, "n": 10}
            )
        )
        invalid = copy.deepcopy(entry)
        invalid[7] = [10]
        self.assertIsNone(
            selector.generator_transform_edit(
                change(patched, value.lineno), PATH, {"d": {PATH: [invalid]}, "n": 10}
            )
        )

    def test_model_validator_rejects_duplicate_inventory(self):
        source, _, _, _, _, entry = fixture()
        digest = "d" * 64
        model = {"d": {PATH: [entry] * 1350}, "n": 10, "sha": "s", "t": digest, "v": 1}
        self.assertFalse(selector.valid_generator_dispatch_model(model, "s", digest, 10))
        model["d"][PATH][0] = [*entry[:-1], [10]]
        self.assertFalse(selector.valid_generator_dispatch_model(model, "s", digest, 10))
        self.assertIn("TRANSFORMS", source)

    def test_bundled_profile_is_pinned_against_reader_rewrites(self):
        artifact = Path(__file__).parent.parent / "generator_dispatch_model.json.gz"
        with gzip.open(artifact, "rt", encoding="utf-8") as model_file:
            model = json.load(model_file)
        self.assertTrue(
            selector.valid_generator_dispatch_model(
                model, model["sha"], model["t"], model["n"]
            )
        )
        tampered = copy.deepcopy(model)
        entry = next(
            entry
            for entries in tampered["d"].values()
            for entry in entries
            if entry[6] == "safe" and entry[7]
        )
        entry[7] = []
        tampered["p"] = hashlib.sha256(
            json.dumps(tampered["d"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.assertFalse(
            selector.valid_generator_dispatch_model(
                tampered, tampered["sha"], tampered["t"], tampered["n"]
            )
        )


if __name__ == "__main__":
    unittest.main()
