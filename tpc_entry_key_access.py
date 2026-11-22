"""Default-off prospective certificate for one pinned TPC schema leaf edit."""

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass


FEATURE_ENABLED = False
PATH = "tests/helpers.py"
PINNED_REVISION = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"
HELPERS_SHA256 = "c0dc285fccd1b8bee4a451f5962118fe771de005843b56e3af4c7136f74c3ed3"
TEST_IDS_SHA256 = "31a019981e19c3d1b18d929066da7e118fcf3d57696a360f7b9d31ce3a87bc89"
SCHEMAS = {
    "TPCH_SCHEMA": "tests/test_optimizer.py::TestOptimizer::test_tpch",
    "TPCDS_SCHEMA": "tests/test_optimizer.py::TestOptimizer::test_tpcds",
}
STRING_LITERAL = re.compile(r'"(?:[^"\\\n]|\\.)*"\Z')


@dataclass(frozen=True)
class EntryEdit:
    schema: str
    table: str
    column: str
    old_value: str
    new_value: str


def _assignments(tree: ast.Module) -> dict[str, tuple[int, ast.Assign]] | None:
    found: dict[str, tuple[int, ast.Assign]] = {}
    for index, statement in enumerate(tree.body):
        if not (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
        ):
            continue
        name = statement.targets[0].id
        if name in found:
            return None
        found[name] = (index, statement)
    return found


def _literal_dict(node: ast.AST) -> tuple[list[str], list[ast.AST]] | None:
    if not isinstance(node, ast.Dict) or any(key is None for key in node.keys):
        return None
    keys: list[str] = []
    for key in node.keys:
        if not isinstance(key, ast.Constant) or type(key.value) is not str:
            return None
        keys.append(key.value)
    if len(keys) != len(set(keys)):
        return None
    return keys, node.values


def _leaf_changes(
    old: ast.AST, new: ast.AST, path: tuple[str, ...] = ()
) -> list[tuple[tuple[str, ...], ast.Constant, ast.Constant]] | None:
    old_dict = _literal_dict(old)
    new_dict = _literal_dict(new)
    if old_dict is not None or new_dict is not None:
        if old_dict is None or new_dict is None or old_dict[0] != new_dict[0]:
            return None
        changes = []
        for key, old_value, new_value in zip(old_dict[0], old_dict[1], new_dict[1]):
            nested = _leaf_changes(old_value, new_value, (*path, key))
            if nested is None:
                return None
            changes.extend(nested)
        return changes
    if not (
        isinstance(old, ast.Constant)
        and isinstance(new, ast.Constant)
        and type(old.value) is str
        and type(new.value) is str
    ):
        return None
    return [] if old.value == new.value else [(path, old, new)]


def _offset(source: str, line: int, column: int) -> int:
    lines = source.splitlines(keepends=True)
    return sum(len(item) for item in lines[: line - 1]) + column


def classify(path: str, original_source: str, changed_source: str) -> EntryEdit | None:
    """Admit only one double-quoted type leaf under one existing table entry."""
    if (
        path != PATH
        or type(original_source) is not str
        or type(changed_source) is not str
        or hashlib.sha256(original_source.encode()).hexdigest() != HELPERS_SHA256
        or "\r" in original_source
        or "\r" in changed_source
    ):
        return None
    try:
        original = ast.parse(original_source, filename=PATH, type_comments=True)
        changed = ast.parse(changed_source, filename=PATH, type_comments=True)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return None
    original_assignments = _assignments(original)
    changed_assignments = _assignments(changed)
    if original_assignments is None or changed_assignments is None:
        return None
    candidates = []
    for schema in SCHEMAS:
        old_entry = original_assignments.get(schema)
        new_entry = changed_assignments.get(schema)
        if old_entry is None or new_entry is None or old_entry[0] != new_entry[0]:
            return None
        changes = _leaf_changes(old_entry[1].value, new_entry[1].value)
        if changes is None:
            return None
        candidates.extend((schema, *change) for change in changes)
    if len(candidates) != 1:
        return None
    schema, path, old_leaf, new_leaf = candidates[0]
    if len(path) != 2:
        return None

    # Removing the one schema-value change must make the complete modules equal.
    original_dump = [ast.dump(node, include_attributes=False) for node in original.body]
    changed_dump = [ast.dump(node, include_attributes=False) for node in changed.body]
    schema_index = original_assignments[schema][0]
    changed_dump[schema_index] = original_dump[schema_index]
    if original_dump != changed_dump:
        return None

    old_start = _offset(original_source, old_leaf.lineno, old_leaf.col_offset)
    old_end = _offset(original_source, old_leaf.end_lineno, old_leaf.end_col_offset)
    new_segment = ast.get_source_segment(changed_source, new_leaf)
    old_segment = original_source[old_start:old_end]
    if (
        new_segment is None
        or STRING_LITERAL.fullmatch(old_segment) is None
        or STRING_LITERAL.fullmatch(new_segment) is None
        or changed_source != original_source[:old_start] + new_segment + original_source[old_end:]
    ):
        return None
    return EntryEdit(schema, path[0], path[1], old_leaf.value, new_leaf.value)


def readers(
    path: str, original_source: str, changed_source: str, test_ids: list[str]
) -> set[int] | None:
    edit = classify(path, original_source, changed_source)
    if (
        edit is None
        or type(test_ids) is not list
        or any(type(test_id) is not str for test_id in test_ids)
        or hashlib.sha256("\0".join(test_ids).encode()).hexdigest() != TEST_IDS_SHA256
    ):
        return None
    optimizer_id = SCHEMAS[edit.schema]
    if test_ids.count(optimizer_id) != 1:
        return None
    selected = {
        index for index, test_id in enumerate(test_ids)
        if test_id.startswith("tests/test_executor.py::TestExecutor::")
    }
    if len(selected) != 60:
        return None
    selected.add(test_ids.index(optimizer_id))
    return selected
