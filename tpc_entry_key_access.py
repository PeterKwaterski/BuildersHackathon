"""Authenticated certificate for one pinned TPC schema leaf edit."""

from __future__ import annotations

import ast
import gzip
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path


FEATURE_ENABLED = True
PATH = "tests/helpers.py"
PINNED_REVISION = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"
HELPERS_SHA256 = "c0dc285fccd1b8bee4a451f5962118fe771de005843b56e3af4c7136f74c3ed3"
TEST_IDS_SHA256 = "31a019981e19c3d1b18d929066da7e118fcf3d57696a360f7b9d31ce3a87bc89"
SELECTOR_MODEL_SHA256 = "d61c504e9a4a1006217e6702e1c6f05c04846b3dd5a09ec5572523fd8b2cb382"
PROVENANCE_SHA256 = "5e1049132f3c88793fed8d0fed7a12c76e541cd1dce2598b668e1d88ec25eaf4"
PROFILE_SHA256 = "0d3b6fdc2ca925e10528e362e44a38a1232db404d4d429fbe6ca859d0bce5c30"
TRACKED_INDEX_SHA256 = "a2f99e795d6c15564829485f6e761f28922ba471613097d8c41227dd2bb91ca6"
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
    path: str,
    original_source: str,
    changed_source: str,
    test_ids: list[str],
    provenance: dict,
) -> set[int] | None:
    edit = classify(path, original_source, changed_source)
    if (
        edit is None
        or type(test_ids) is not list
        or any(type(test_id) is not str for test_id in test_ids)
        or hashlib.sha256("\0".join(test_ids).encode()).hexdigest() != TEST_IDS_SHA256
        or valid_provenance(provenance, {}, test_ids, check_model=False) is None
    ):
        return None
    optimizer_id = SCHEMAS[edit.schema]
    if test_ids.count(optimizer_id) != 1:
        return None
    expected = {
        index for index, test_id in enumerate(test_ids)
        if test_id.startswith("tests/test_executor.py::TestExecutor::")
    }
    if len(expected) != 60:
        return None
    expected.add(test_ids.index(optimizer_id))
    owners = provenance["owners"].get(edit.schema)
    if owners != sorted(expected):
        return None
    return expected


def valid_provenance(
    document: object,
    model: dict,
    test_ids: list[str],
    *,
    check_model: bool = True,
) -> dict | None:
    expected_keys = {
        "v", "revision", "model_sha256", "test_id_sha256", "source_hashes",
        "tracked_index_sha256", "events", "collected_files", "tracked_file_count",
        "tracked_python_count", "text_references", "uncollected_reader_imports",
        "owners", "fixtures", "profile_sha256",
    }
    if (
        not isinstance(document, dict)
        or set(document) != expected_keys
        or type(test_ids) is not list
        or any(type(test_id) is not str for test_id in test_ids)
        or document.get("v") != 1
        or document.get("revision") != PINNED_REVISION
        or document.get("model_sha256") != SELECTOR_MODEL_SHA256
        or document.get("test_id_sha256") != TEST_IDS_SHA256
        or document.get("profile_sha256") != PROFILE_SHA256
        or document.get("tracked_index_sha256") != TRACKED_INDEX_SHA256
        or document.get("tracked_file_count") != 365
        or document.get("tracked_python_count") != 258
        or document.get("uncollected_reader_imports") != []
        or not isinstance(document.get("source_hashes"), dict)
        or len(document["source_hashes"]) != 258
        or document["source_hashes"].get(PATH) != HELPERS_SHA256
        or hashlib.sha256("\0".join(test_ids).encode()).hexdigest() != TEST_IDS_SHA256
    ):
        return None
    if check_model and (
        not isinstance(model, dict)
        or model.get("sha") != PINNED_REVISION
        or model.get("t") != test_ids
        or not isinstance(model.get("x"), dict)
        or not isinstance(model.get("z"), list)
    ):
        return None
    unsigned = {key: document[key] for key in document if key != "profile_sha256"}
    if hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest() != PROFILE_SHA256:
        return None
    owners = document.get("owners")
    if not isinstance(owners, dict) or set(owners) != set(SCHEMAS):
        return None
    for schema, optimizer_id in SCHEMAS.items():
        expected = {
            index for index, test_id in enumerate(test_ids)
            if test_id.startswith("tests/test_executor.py::TestExecutor::")
        }
        if test_ids.count(optimizer_id) != 1:
            return None
        expected.add(test_ids.index(optimizer_id))
        if owners.get(schema) != sorted(expected):
            return None
    return document


def load_provenance(
    path: Path, model_path: Path, model: dict, test_ids: list[str]
) -> dict | None:
    try:
        if (
            hashlib.sha256(path.read_bytes()).hexdigest() != PROVENANCE_SHA256
            or hashlib.sha256(model_path.read_bytes()).hexdigest() != SELECTOR_MODEL_SHA256
        ):
            return None
        with gzip.open(path, "rt", encoding="utf-8") as stream:
            document = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return document if valid_provenance(document, model, test_ids) is not None else None
