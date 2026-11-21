#!/usr/bin/env python3
"""Measure source-derived semantic no-op opportunities, without patch answers."""

from __future__ import annotations

import argparse
import ast
import concurrent.futures
import json
import keyword
import string
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import selector
import semantic_noops as proofs


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=4)
    return parser.parse_args()


def defining_scope(node: ast.AST, name: str, parents: dict):
    scope = proofs._nearest_scope(node, parents)
    if scope is None:
        return None
    kind = proofs._binding_kind(scope, name, parents)
    if kind in {"local", "except", "comprehension", "parameter", "global", "nonlocal"}:
        return scope, kind
    if kind != "free":
        return None
    cursor = parents.get(scope)
    while cursor is not None:
        if isinstance(cursor, (proofs._FUNCTIONS, proofs._COMPREHENSIONS)):
            kind = proofs._binding_kind(cursor, name, parents)
            if kind in {"local", "except", "comprehension", "parameter", "global", "nonlocal"}:
                return cursor, kind
        if isinstance(cursor, ast.Module):
            break
        cursor = parents.get(cursor)
    return None


def fresh_name(length: int, used: set[str]) -> str | None:
    alphabet = string.ascii_lowercase + string.ascii_uppercase
    for first in alphabet:
        candidate = first + "z" * (length - 1)
        if candidate not in used and not keyword.iskeyword(candidate):
            return candidate
    return None


def replace_positions(source: str, name: str, replacement: str, positions) -> str | None:
    lines = source.splitlines(True)
    grouped = {}
    for row, start, end in positions:
        grouped.setdefault(row, set()).add((start, end))
    for row, spans in grouped.items():
        line = lines[row]
        for start, end in sorted(spans, reverse=True):
            if line[start:end] != name:
                return None
            line = line[:start] + replacement + line[end:]
        lines[row] = line
    return "".join(lines)


def verify_file(item):
    path, source = item
    try:
        tree = ast.parse(source, filename=path, type_comments=True)
    except (SyntaxError, ValueError):
        return path, [], 0
    parents = proofs._parents(tree)
    if proofs._has_dynamic_observation(tree, parents):
        return path, [], 0
    used = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    candidates = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Name) or not isinstance(node.ctx, ast.Store):
            continue
        resolved = defining_scope(node, node.id, parents)
        if resolved and resolved[1] in {"local", "comprehension"}:
            candidates[(resolved[0], node.id, resolved[1])] = None
    # ExceptHandler.name is a string rather than an ast.Name Store.
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.name:
            scope = proofs._nearest_scope(node, parents)
            if scope is not None:
                candidates[(scope, node.name, "except")] = node

    verified = []
    structural = 0
    for (scope, name, kind), handler in candidates.items():
        if not proofs._safe_definite_binding(scope, name, kind, parents):
            continue
        replacement = fresh_name(len(name), used)
        if replacement is None:
            continue
        structural += 1
        positions = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Name) or node.id != name:
                continue
            resolved = defining_scope(node, name, parents)
            if resolved and resolved[0] is scope:
                positions.append((node.lineno - 1, node.col_offset, node.end_col_offset))
        if handler is not None:
            # Locate the NAME token following ``as`` on the except header.
            line_index = handler.lineno - 1
            line = source.splitlines(True)[line_index]
            marker = " as " + name
            offset = line.find(marker, handler.col_offset)
            if offset < 0:
                continue
            start = offset + len(" as ")
            positions.append((line_index, start, start + len(name)))
        changed = replace_positions(source, name, replacement, positions)
        if changed is None:
            continue
        proof = proofs.local_binding_rename(source, changed, path)
        if proof is not None:
            verified.append(
                {
                    "kind": kind,
                    "line": getattr(scope, "lineno", 0),
                    "name": name,
                    "replacement": replacement,
                    "occurrences": proof.occurrences,
                }
            )
    return path, verified, structural


def import_and_definition_counts(sources: dict[str, str]):
    import_runs = []
    definition_runs = []
    for path, source in sources.items():
        if not path.startswith("sqlglot/") or not path.endswith(".py"):
            continue
        try:
            tree = ast.parse(source, filename=path, type_comments=True)
        except (SyntaxError, ValueError):
            continue
        run = []

        def flush_import():
            if len(run) < 2:
                return
            bindings = []
            for statement in run:
                names = proofs._bound_import_names(statement)
                modules = (
                    [alias.name for alias in statement.names]
                    if isinstance(statement, ast.Import)
                    else [statement.module]
                )
                if names is None or any(
                    module.split(".", 1)[0] in {"sqlglot", "tests"}
                    for module in modules
                ):
                    return
                bindings.extend(names)
            if len(bindings) == len(set(bindings)):
                import_runs.append((path, run[0].lineno, run[-1].end_lineno, len(run)))

        for statement in tree.body:
            if isinstance(statement, (ast.Import, ast.ImportFrom)):
                run.append(statement)
            else:
                flush_import()
                run = []
        flush_import()

        for owner in [tree, *[node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]]:
            run = []

            def flush_definition():
                if (
                    len(run) >= 2
                    and all(proofs._plain_definition(statement) for statement in run)
                    and len({statement.name for statement in run}) == len(run)
                ):
                    definition_runs.append(
                        (path, run[0].lineno, run[-1].end_lineno, len(run), type(owner).__name__)
                    )

            for statement in owner.body:
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    run.append(statement)
                else:
                    flush_definition()
                    run = []
            flush_definition()
    return import_runs, definition_runs


def main() -> None:
    args = arguments()
    sources = {
        path: source
        for path, source in selector.pinned_sources().items()
        if path.startswith("sqlglot/") and path.endswith(".py")
    }
    results = []
    with concurrent.futures.ProcessPoolExecutor(max_workers=args.workers) as executor:
        for result in executor.map(verify_file, sorted(sources.items())):
            results.append(result)
    import_runs, definition_runs = import_and_definition_counts(sources)
    verified = [
        {"path": path, **entry}
        for path, entries, _structural in results
        for entry in entries
    ]
    report = {
        "local_rename": {
            "same_width_proof_pass": len(verified),
            "same_width_occurrences": sum(entry["occurrences"] for entry in verified),
            "structurally_safe_any_width": sum(item[2] for item in results),
            "files": len({entry["path"] for entry in verified}),
            "kinds": {
                kind: sum(entry["kind"] == kind for entry in verified)
                for kind in ("local", "comprehension", "except")
            },
            "examples": verified[:20],
        },
        "external_import_reorder": {
            "runs": len(import_runs),
            "statements": sum(item[3] for item in import_runs),
            "adjacent_swaps": sum(item[3] - 1 for item in import_runs),
            "entries": import_runs,
        },
        "plain_definition_reorder": {
            "runs": len(definition_runs),
            "definitions": sum(item[3] for item in definition_runs),
            "adjacent_swaps": sum(item[3] - 1 for item in definition_runs),
            "entries": definition_runs,
        },
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
