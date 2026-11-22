"""Runtime gate for closed module-level type-tuple leaves.

The build-time model proves that every value-observing read of an assignment is
an ``isinstance`` type-spec operand.  Runtime accepts only deletion/reordering
of the tuple's already-certified names in an otherwise identical module.
"""

from __future__ import annotations

import ast
import gzip
import hashlib
import json
from pathlib import Path


FEATURE_ENABLED = False
MODEL = Path(__file__).with_name("type_tuple_leaf_model.json.gz")


def load_model(path: Path, pinned_sha: str, test_ids: list[str]) -> dict | None:
    try:
        with gzip.open(path, "rt", encoding="utf-8") as stream:
            model = json.load(stream)
    except (OSError, EOFError, UnicodeError, json.JSONDecodeError, ValueError, TypeError):
        return None
    digest = hashlib.sha256("\0".join(test_ids).encode()).hexdigest()
    if (
        not isinstance(model, dict)
        or model.get("v") != 1
        or model.get("sha") != pinned_sha
        or model.get("n") != len(test_ids)
        or model.get("t") != digest
        or not isinstance(model.get("d"), dict)
    ):
        return None
    return model


def _assignment(statement: ast.stmt) -> tuple[str, ast.AST] | None:
    if (
        isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
    ):
        return statement.targets[0].id, statement.value
    if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
        return statement.target.id, statement.value
    return None


def _tuple_names(value: ast.AST) -> tuple[str, ...] | None:
    if not isinstance(value, ast.Tuple) or not value.elts:
        return None
    if not all(isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load) for item in value.elts):
        return None
    names = tuple(item.id for item in value.elts)
    return names if len(set(names)) == len(names) else None


def readers(
    path: str,
    original: str,
    changed: str,
    change: dict,
    model: dict | None,
) -> set[int] | None:
    """Return exact certified readers, or ``None`` for conservative fallback."""
    if not FEATURE_ENABLED or model is None or change.get("structural_invalid"):
        return None
    if any(
        token in line
        for line in change.get("added", ())
        for token in ("# fmt:", "# isort:", "# noqa", "# type: ignore", "# pragma:")
    ):
        return None
    try:
        old_tree = ast.parse(original, filename=path, type_comments=True)
        new_tree = ast.parse(changed, filename=path, type_comments=True)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return None
    entries = model.get("d", {}).get(path)
    if not isinstance(entries, list):
        return None

    matches = []
    changed_lines = change.get("lines")
    if not isinstance(changed_lines, set) or not changed_lines:
        return None
    for entry in entries:
        if (
            not isinstance(entry, list)
            or len(entry) != 6
            or type(entry[0]) is not int
            or type(entry[1]) is not int
            or not isinstance(entry[2], str)
            or not isinstance(entry[3], str)
            or not isinstance(entry[4], list)
            or any(type(index) is not int for index in entry[4])
            or not isinstance(entry[5], list)
        ):
            return None
        start, end, name, old_dump, indices, old_names = entry
        if any(start <= line <= end for line in changed_lines):
            matches.append(entry)
    if len(matches) != 1:
        return None
    start, _end, name, old_dump, indices, old_names = matches[0]

    old_statements = [item for item in old_tree.body if getattr(item, "lineno", -1) == start]
    new_candidates = [
        item
        for item in new_tree.body
        if (pair := _assignment(item)) is not None and pair[0] == name
    ]
    if len(old_statements) != 1 or len(new_candidates) != 1:
        return None
    old_pair = _assignment(old_statements[0])
    new_pair = _assignment(new_candidates[0])
    if old_pair is None or new_pair is None or old_pair[0] != name or new_pair[0] != name:
        return None
    old_value, new_value = old_pair[1], new_pair[1]
    if ast.dump(old_value, include_attributes=False) != old_dump:
        return None
    original_names = _tuple_names(old_value)
    prospective_names = _tuple_names(new_value)
    if (
        original_names is None
        or list(original_names) != old_names
        or prospective_names is None
        or not set(prospective_names).issubset(original_names)
    ):
        return None

    old_value_copy = ast.Constant(value=None)
    new_value_copy = ast.Constant(value=None)
    old_statements[0].value = old_value_copy
    new_candidates[0].value = new_value_copy
    if ast.dump(old_tree, include_attributes=False) != ast.dump(new_tree, include_attributes=False):
        return None
    if indices != sorted(set(indices)) or any(index < 0 or index >= model["n"] for index in indices):
        return None
    return set(indices)
