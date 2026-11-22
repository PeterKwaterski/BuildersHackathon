#!/usr/bin/env python3
"""Build the closed observer model for module-level tuples of types."""

from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path


PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--selector-model", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def assignment(statement: ast.stmt) -> tuple[str, ast.AST] | None:
    if (
        isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
    ):
        return statement.targets[0].id, statement.value
    if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
        return statement.target.id, statement.value
    return None


def tuple_names(value: ast.AST) -> tuple[str, ...] | None:
    if not isinstance(value, ast.Tuple) or len(value.elts) < 2:
        return None
    if not all(isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load) for item in value.elts):
        return None
    names = tuple(item.id for item in value.elts)
    return names if len(set(names)) == len(names) else None


def parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}


def enclosing_call(node: ast.AST, parent: dict[ast.AST, ast.AST]) -> tuple[ast.Call | None, ast.AST]:
    current = node
    while current in parent and isinstance(parent[current], (ast.Starred, ast.Tuple, ast.List)):
        current = parent[current]
    owner = parent.get(current)
    return (owner if isinstance(owner, ast.Call) else None), current


def safe_isinstance_use(node: ast.AST, parent: dict[ast.AST, ast.AST]) -> bool:
    call, contained = enclosing_call(node, parent)
    return bool(
        call
        and isinstance(call.func, ast.Name)
        and call.func.id == "isinstance"
        and len(call.args) >= 2
        and (call.args[1] is contained or (
            isinstance(call.args[1], ast.Tuple) and contained in call.args[1].elts
        ))
    )


def in_runtime_body(node: ast.AST, parent: dict[ast.AST, ast.AST]) -> bool:
    current = node
    while current in parent:
        current = parent[current]
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return True
    return False


def line_readers(selector_model: dict, path: str, start: int, end: int) -> set[int]:
    result: set[int] = set()
    entry = selector_model.get("f", {}).get(path, {})
    for line, set_id in entry.get("l", ()):
        if start <= line <= end:
            result.update(selector_model["z"][set_id])
    return result


def main() -> None:
    args = arguments()
    with gzip.open(args.sources, "rt", encoding="utf-8") as stream:
        sources = json.load(stream)
    with gzip.open(args.selector_model, "rt", encoding="utf-8") as stream:
        selector_model = json.load(stream)
    tests = json.loads(args.tests.read_text())["tests"]
    test_ids = [test["id"] for test in tests]
    if selector_model.get("sha") != PINNED_SHA or selector_model.get("t") != test_ids:
        raise SystemExit("selector model does not match pinned source/test roster")

    trees = {path: ast.parse(text, filename=path, type_comments=True) for path, text in sources.items()}
    parent_maps = {path: parents(tree) for path, tree in trees.items()}
    definitions = Counter(
        node.name
        for tree in trees.values()
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
    )
    candidates = []
    for path, tree in trees.items():
        if not path.startswith("sqlglot/"):
            continue
        for statement in tree.body:
            pair = assignment(statement)
            if pair is None:
                continue
            name, value = pair
            names = tuple_names(value)
            if names and all(definitions[item] == 1 for item in names):
                candidates.append((path, statement, name, value, names))

    entries: dict[str, list[list]] = defaultdict(list)
    rejected = Counter()
    for target_path, statement, name, value, names in candidates:
        uses: list[tuple[str, ast.AST, ast.Call]] = []
        unsafe = None
        for path, tree in trees.items():
            parent = parent_maps[path]
            expression_aliases = set()
            for imported in tree.body:
                if isinstance(imported, ast.Import):
                    for alias in imported.names:
                        if alias.name == "sqlglot.expressions":
                            expression_aliases.add(alias.asname or "sqlglot")
                elif isinstance(imported, ast.ImportFrom) and imported.module == "sqlglot":
                    for alias in imported.names:
                        if alias.name in {"exp", "expressions"}:
                            expression_aliases.add(alias.asname or alias.name)
            for node in ast.walk(tree):
                exact_load = (
                    isinstance(node, ast.Name)
                    and isinstance(node.ctx, ast.Load)
                    and node.id == name
                ) or (
                    isinstance(node, ast.Attribute)
                    and isinstance(node.ctx, ast.Load)
                    and node.attr == name
                )
                if exact_load:
                    # Ignore the defining RHS only; all same-named loads are an
                    # intentional over-approximation of aliases/re-exports.
                    current = node
                    inside_definition = False
                    while current in parent:
                        current = parent[current]
                        if current is value:
                            inside_definition = True
                            break
                    if inside_definition:
                        continue
                    call, _ = enclosing_call(node, parent)
                    if not in_runtime_body(node, parent):
                        unsafe = "import-read"
                    elif not safe_isinstance_use(node, parent) or call is None:
                        unsafe = "non-isinstance-read"
                    else:
                        uses.append((path, node, call))
                if isinstance(node, ast.ImportFrom) and any(
                    alias.name == name and alias.asname not in (None, name) for alias in node.names
                ):
                    unsafe = "renamed-import"
                if isinstance(node, (ast.Assign, ast.AnnAssign)) and node is not statement:
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    if any(isinstance(target, ast.Name) and target.id == name for target in targets):
                        unsafe = "ambiguous-binding"
                if isinstance(node, ast.Constant) and node.value == name:
                    unsafe = "reflective-string"
                # The tuple is re-exported through ``sqlglot.expressions``.
                # Any opaque use of that module object could retrieve the leaf
                # without a source-visible attribute load, so reject it.
                if isinstance(node, ast.Name) and node.id in expression_aliases:
                    owner = parent.get(node)
                    if isinstance(owner, ast.Attribute) and owner.value is node:
                        if owner.attr == "__dict__":
                            unsafe = "module-reflection"
                        continue
                    if isinstance(owner, (ast.Import, ast.ImportFrom)):
                        continue
                    unsafe = "module-escape"
        if unsafe or not uses:
            rejected[unsafe or "unobserved"] += 1
            continue
        readers: set[int] = set()
        for path, _node, call in uses:
            readers.update(line_readers(
                selector_model, path, call.lineno, call.end_lineno or call.lineno
            ))
        entries[target_path].append([
            statement.lineno,
            statement.end_lineno or statement.lineno,
            name,
            ast.dump(value, include_attributes=False),
            sorted(readers),
            list(names),
        ])

    payload = {
        "d": {path: sorted(values) for path, values in sorted(entries.items())},
        "n": len(test_ids),
        "sha": PINNED_SHA,
        "t": hashlib.sha256("\0".join(test_ids).encode()).hexdigest(),
        "v": 1,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    with args.output.open("wb") as raw_stream:
        with gzip.GzipFile(fileobj=raw_stream, mode="wb", mtime=0) as stream:
            stream.write(raw)
    print(json.dumps({
        "admitted": sum(len(values) for values in entries.values()),
        "bytes": args.output.stat().st_size,
        "rejected": dict(sorted(rejected.items())),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
