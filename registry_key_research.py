"""Default-off runtime prototype for inherited parser-registry key renames."""

from __future__ import annotations

import ast
import gzip
import hashlib
import json
import textwrap
from pathlib import Path


FEATURE_ENABLED = True
MODEL = Path(__file__).with_name("registry_key_research_model.json.gz")
MODEL_GZIP_SHA256 = "952b276049efbbdcea47bee9858249b9e08ff9f9341d35c8e7d7baf6ffe94a70"


def load_model(path: Path, pinned_sha: str, test_ids: list[str]) -> dict | None:
    if not isinstance(test_ids, list) or any(type(test_id) is not str for test_id in test_ids):
        return None
    try:
        if hashlib.sha256(path.read_bytes()).hexdigest() != MODEL_GZIP_SHA256:
            return None
        with gzip.open(path, "rt", encoding="utf-8") as stream:
            model = json.load(stream)
    except (OSError, EOFError, UnicodeError, json.JSONDecodeError, ValueError, TypeError):
        return None
    digest = hashlib.sha256("\0".join(test_ids).encode()).hexdigest()
    if (
        not isinstance(model, dict)
        or model.get("v") != 4
        or model.get("sha") != pinned_sha
        or model.get("n") != len(test_ids)
        or model.get("t") != digest
        or model.get("state") != "certified"
        or not isinstance(model.get("d"), dict)
    ):
        return None
    return model


def _class_assignment(tree: ast.Module, owner: str, name: str):
    matches = []
    for statement in tree.body:
        if not isinstance(statement, ast.ClassDef) or statement.name != owner:
            continue
        for item in statement.body:
            if isinstance(item, ast.Assign):
                targets = item.targets
            elif isinstance(item, ast.AnnAssign):
                targets = [item.target]
            else:
                continue
            if len(targets) == 1 and isinstance(targets[0], ast.Name) and targets[0].id == name:
                matches.append(item)
    return matches[0] if len(matches) == 1 else None


def _absolute_offset(source: str, line: int, byte_column: int) -> int:
    lines = source.splitlines(keepends=True)
    if line < 1 or line > len(lines):
        raise ValueError("line outside source")
    prefix = lines[line - 1].encode("utf-8")[:byte_column].decode("utf-8")
    return sum(len(item) for item in lines[: line - 1]) + len(prefix)


def _node_span(source: str, node: ast.AST) -> tuple[int, int]:
    if not all(hasattr(node, name) for name in ("lineno", "col_offset", "end_lineno", "end_col_offset")):
        raise ValueError("node lacks a complete source span")
    return (
        _absolute_offset(source, node.lineno, node.col_offset),
        _absolute_offset(source, node.end_lineno, node.end_col_offset),
    )


def readers(path: str, original: str, changed: str, change: dict, model: dict | None):
    if (
        not FEATURE_ENABLED
        or not isinstance(path, str)
        or not isinstance(original, str)
        or not isinstance(changed, str)
        or not isinstance(change, dict)
        or not isinstance(model, dict)
        or change.get("structural_invalid")
    ):
        return None
    data = model.get("d")
    entries = data.get(path) if isinstance(data, dict) else None
    count = model.get("n")
    if not isinstance(entries, list) or type(count) is not int or count <= 0:
        return None
    added = change.get("added", ())
    if not isinstance(added, (list, tuple, set)) or any(not isinstance(line, str) for line in added):
        return None
    if any(
        marker in line
        for line in added
        for marker in ("# fmt:", "# isort:", "# noqa", "# type: ignore", "# pragma:")
    ):
        return None
    lines = change.get("lines")
    if not isinstance(lines, set) or not lines or any(type(line) is not int for line in lines):
        return None

    valid_entries = []
    for entry in entries:
        if not isinstance(entry, list) or len(entry) != 11:
            return None
        (
            start,
            end,
            owner,
            name,
            old_dump,
            source_digest,
            tree_digest,
            key_readers,
            wildcard,
            safe_keys,
            forbidden_keys,
        ) = entry
        reader_lists = list(key_readers.values()) if isinstance(key_readers, dict) else []
        if (
            type(start) is not int
            or type(end) is not int
            or start < 1
            or end < start
            or not all(
                isinstance(value, str)
                for value in (owner, name, old_dump, source_digest, tree_digest)
            )
            or len(source_digest) != 64
            or len(tree_digest) != 64
            or not isinstance(key_readers, dict)
            or any(type(key) is not str for key in key_readers)
            or any(not isinstance(value, list) for value in reader_lists)
            or not isinstance(wildcard, list)
            or not isinstance(safe_keys, list)
            or not isinstance(forbidden_keys, list)
            or any(type(key) is not str for key in safe_keys + forbidden_keys)
            or safe_keys != sorted(set(safe_keys))
            or forbidden_keys != sorted(set(forbidden_keys))
        ):
            return None
        for values in reader_lists + [wildcard]:
            if (
                any(type(item) is not int or item < 0 or item >= count for item in values)
                or values != sorted(set(values))
            ):
                return None
        valid_entries.append(entry)

    candidates = [
        entry for entry in valid_entries
        if any(entry[0] <= line <= entry[1] for line in lines)
    ]
    if len(candidates) != 1:
        return None
    (
        start,
        end,
        owner,
        name,
        old_dump,
        source_digest,
        tree_digest,
        key_readers,
        wildcard,
        safe_keys,
        forbidden_keys,
    ) = candidates[0]
    try:
        actual_source_digest = hashlib.sha256(original.encode("utf-8")).hexdigest()
    except UnicodeError:
        return None
    if actual_source_digest != source_digest:
        return None

    # The original bytes are authenticated above. Parse only the small pinned
    # assignment to identify the old key and reject unsafe keys before paying
    # for a full changed-module parse.
    original_lines = original.splitlines(keepends=True)
    assignment_source = "".join(original_lines[start - 1:end])
    wrapped_assignment = f"class {owner}:\n" + textwrap.indent(
        textwrap.dedent(assignment_source), "    "
    )
    try:
        assignment_tree = ast.parse(wrapped_assignment, filename=path, type_comments=True)
        old_statement = _class_assignment(assignment_tree, owner, name)
        if old_statement is None or not isinstance(old_statement.value, ast.Dict):
            return None
        old_line_keys = [
            key
            for key in old_statement.value.keys
            if isinstance(key, ast.Constant)
            and type(key.value) is str
            and start + key.lineno - 2 in lines
        ]
        if len(old_line_keys) != 1 or old_line_keys[0].value not in safe_keys:
            return None
        new_tree = ast.parse(changed, filename=path, type_comments=True)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return None
    new_statement = _class_assignment(new_tree, owner, name)
    if old_statement is None or new_statement is None:
        return None
    if ast.dump(old_statement.value, include_attributes=False) != old_dump:
        return None
    old_dict, new_dict = old_statement.value, new_statement.value
    if not isinstance(old_dict, ast.Dict) or not isinstance(new_dict, ast.Dict):
        return None
    if len(old_dict.keys) != len(new_dict.keys) or len(old_dict.values) != len(new_dict.values):
        return None
    differences = []
    for index, (old_key, new_key, old_value, new_value) in enumerate(zip(
        old_dict.keys, new_dict.keys, old_dict.values, new_dict.values
    )):
        if ast.dump(old_value, include_attributes=False) != ast.dump(new_value, include_attributes=False):
            return None
        old_key_dump = ast.dump(old_key, include_attributes=False) if old_key is not None else None
        new_key_dump = ast.dump(new_key, include_attributes=False) if new_key is not None else None
        if old_key_dump != new_key_dump:
            differences.append((index, old_key, new_key))
    if len(differences) != 1:
        return None
    index, old_key, new_key = differences[0]
    if not (
        isinstance(old_key, ast.Constant)
        and isinstance(new_key, ast.Constant)
        and type(old_key.value) is str
        and type(new_key.value) is str
        and old_key.value != new_key.value
    ):
        return None
    old_keys = {
        item.value for item in old_dict.keys if isinstance(item, ast.Constant) and type(item.value) is str
    }
    if new_key.value in old_keys:
        return None
    if old_key.value not in safe_keys or new_key.value in forbidden_keys:
        return None

    # Source bytes, comments, whitespace, quoting outside the one key token,
    # and every directive must be exactly pinned. AST equivalence alone is not
    # sufficient because comments and encoding-sensitive text are observable.
    old_token = ast.get_source_segment(wrapped_assignment, old_key)
    try:
        new_start, new_end = _node_span(changed, new_key)
    except (UnicodeError, ValueError, TypeError):
        return None
    if not isinstance(old_token, str):
        return None
    normalized_source = changed[:new_start] + old_token + changed[new_end:]
    if normalized_source != original:
        return None

    new_dict.keys[index] = ast.Constant(value=old_key.value)
    normalized_tree = ast.dump(new_tree, include_attributes=False)
    if hashlib.sha256(normalized_tree.encode()).hexdigest() != tree_digest:
        return None
    selected = set(wildcard)
    selected.update(key_readers.get(old_key.value, ()))
    selected.update(key_readers.get(new_key.value, ()))
    return selected
