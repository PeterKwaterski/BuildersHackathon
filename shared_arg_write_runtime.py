"""Default-off admission for source-derived fresh-receiver mutations.

This module recognizes candidates only.  Enabling the selector optimization
also requires the model's non-escape/ownership proof; candidates never narrow
selection merely because their spelling matches this recognizer.
"""

from __future__ import annotations

import ast
import hashlib
import json
import gzip
from pathlib import Path


MODEL_VERSION = 2
MODEL_SHA256 = "07c63674343c93c4b53c60f8b0dee38ffc87e48b932206c00514aac039f559e5"
SOURCE_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"


def load_model(path: Path) -> dict | None:
    try:
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != MODEL_SHA256:
            return None
        model = json.loads(gzip.decompress(raw))
    except (
        OSError, EOFError, UnicodeError, json.JSONDecodeError, TypeError,
        ValueError, RecursionError, MemoryError,
    ):
        return None
    if (
        not isinstance(model, dict)
        or model.get("v") != MODEL_VERSION
        or model.get("source_sha") != SOURCE_SHA
        or not isinstance(model.get("functions"), list)
    ):
        return None
    return model


def _nodes(tree: ast.AST):
    pending = [(tree, ())]
    while pending:
        node, path = pending.pop()
        yield node, path
        children = []
        for field, value in ast.iter_fields(node):
            if isinstance(value, ast.AST):
                children.append((value, (*path, (field, None))))
            elif isinstance(value, list):
                children.extend(
                    (item, (*path, (field, index)))
                    for index, item in enumerate(value)
                    if isinstance(item, ast.AST)
                )
        pending.extend(reversed(children))


def _follow(tree: ast.AST, path) -> ast.AST | None:
    node = tree
    for field, index in path:
        value = getattr(node, field, None)
        if index is None:
            node = value
        elif isinstance(value, list) and 0 <= index < len(value):
            node = value[index]
        else:
            return None
        if not isinstance(node, ast.AST):
            return None
    return node


def _replace(tree: ast.AST, path, value: ast.AST):
    if not path:
        return None
    parent = _follow(tree, path[:-1])
    if parent is None:
        return None
    field, index = path[-1]
    target = getattr(parent, field, None)
    if index is None and isinstance(target, ast.AST):
        setattr(parent, field, value)
        return parent, field, index, target
    if isinstance(target, list) and index is not None and index < len(target):
        previous = target[index]
        target[index] = value
        return parent, field, index, previous
    return None


def _restore(state) -> None:
    parent, field, index, value = state
    if index is None:
        setattr(parent, field, value)
    else:
        getattr(parent, field)[index] = value


def _scalar(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and type(node.value) in {
        bool, bytes, complex, float, int, str, type(None),
    }


def _argument_values(call: ast.Call) -> list[tuple[str, ast.AST]] | None:
    if any(isinstance(argument, ast.Starred) for argument in call.args):
        return None
    if any(keyword.arg is None for keyword in call.keywords):
        return None
    return [
        *((f"p:{index}", value) for index, value in enumerate(call.args)),
        *((f"k:{keyword.arg}", keyword.value) for keyword in call.keywords),
    ]


def _single_scalar_argument_edit(original: ast.Call, changed: ast.Call) -> bool:
    if ast.dump(original.func, include_attributes=False) != ast.dump(
        changed.func, include_attributes=False
    ):
        return False
    before = _argument_values(original)
    after = _argument_values(changed)
    if before is None or after is None or [key for key, _ in before] != [key for key, _ in after]:
        return False
    differences = [
        (left, right)
        for (_, left), (_, right) in zip(before, after)
        if ast.dump(left, include_attributes=False) != ast.dump(right, include_attributes=False)
    ]
    return len(differences) == 1 and all(_scalar(node) for node in differences[0])


def _unaliased_before_call(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    receiver: str,
    call: ast.Call,
) -> bool:
    stores = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Name)
        and node.id == receiver
        and isinstance(node.ctx, ast.Store)
        and node.lineno < call.lineno
    ]
    if len(stores) != 1:
        return False
    assignment_line = stores[0].lineno
    loads = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Name)
        and node.id == receiver
        and isinstance(node.ctx, ast.Load)
        and assignment_line < node.lineno <= call.lineno
    ]
    return len(loads) == 1 and loads[0].lineno == call.lineno


def fresh_receiver_candidate(
    change: dict,
    path: str,
    original_source: str,
    changed_source: str,
    model: dict,
) -> bool:
    """Recognize one exact fresh-receiver scalar-argument mutation.

    The result deliberately does not assert non-escape.  The caller must also
    require a separately derived ownership summary for the wrapper and target
    method before suppressing import-owner expansion.
    """
    lines = change.get("lines")
    if (
        not isinstance(lines, set)
        or len(lines) != 1
        or len(change.get("removed", ())) != 1
        or len(change.get("added", ())) != 1
    ):
        return False
    line = next(iter(lines))
    try:
        original_tree = ast.parse(original_source, filename=path, type_comments=True)
        changed_tree = ast.parse(changed_source, filename=path, type_comments=True)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return False

    records = [
        record
        for record in model.get("functions", ())
        if isinstance(record, list)
        and len(record) >= 13
        and record[1] == path
        and isinstance(record[3], int)
        and isinstance(record[4], int)
        and record[3] <= line <= record[4]
    ]
    if not records:
        return False
    record = min(records, key=lambda item: item[4] - item[3])
    calls = [
        item for item in record[12]
        if isinstance(item, list) and len(item) == 4 and item[0] == line
    ]
    if len(calls) != 1:
        return False
    call_line, column, receiver, target_key = calls[0]
    candidates = [
        (node, node_path)
        for node, node_path in _nodes(original_tree)
        if isinstance(node, ast.Call)
        and node.lineno == call_line
        and node.col_offset == column
    ]
    if len(candidates) != 1:
        return False
    original_call, node_path = candidates[0]
    changed_call = _follow(changed_tree, node_path)
    if not isinstance(changed_call, ast.Call):
        return False
    if not (
        isinstance(original_call.func, ast.Attribute)
        and isinstance(original_call.func.value, ast.Name)
        and original_call.func.value.id == receiver
        and target_key.split(":")[-2].rsplit(".", 1)[-1] == original_call.func.attr
        and _single_scalar_argument_edit(original_call, changed_call)
    ):
        return False

    functions = [
        node
        for node in ast.walk(original_tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.lineno <= line <= (node.end_lineno or node.lineno)
    ]
    if not functions or not _unaliased_before_call(
        min(functions, key=lambda node: (node.end_lineno or node.lineno) - node.lineno),
        receiver,
        original_call,
    ):
        return False

    original_state = _replace(original_tree, node_path, ast.Constant("__fresh_call__"))
    changed_state = _replace(changed_tree, node_path, ast.Constant("__fresh_call__"))
    if original_state is None or changed_state is None:
        return False
    try:
        return ast.dump(original_tree, include_attributes=False) == ast.dump(
            changed_tree, include_attributes=False
        )
    finally:
        _restore(original_state)
        _restore(changed_state)
