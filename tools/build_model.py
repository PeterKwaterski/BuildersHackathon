#!/usr/bin/env python3
"""Build the compact, answer-independent selector model from pinned sqlglot.

The input coverage databases must use ``dynamic_context = test_function``.
Multiple databases are merged so the ordinary process-pool run can be combined
with the coverage-only synchronous-pool run.
"""

from __future__ import annotations

import argparse
import ast
import gzip
import json
import subprocess
from collections import defaultdict
from pathlib import Path

from coverage import CoverageData


PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--coverage", type=Path, action="append", required=True)
    parser.add_argument("--fixture-access", type=Path, action="append", default=[])
    parser.add_argument("--fixture-map", type=Path, action="append", default=[])
    parser.add_argument("--dependency-map", type=Path, action="append", default=[])
    parser.add_argument("--sources-output", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def context_name(test_id: str) -> str:
    parts = test_id.split("::")
    module = parts[0].removesuffix(".py").replace("/", ".")
    return ".".join((module, *parts[1:]))


def relative_coverage_path(filename: str, source: Path) -> str | None:
    path = Path(filename)
    try:
        return path.resolve().relative_to(source).as_posix()
    except ValueError:
        pass

    # Coverage was collected inside the pinned container at /work.
    marker = "/work/"
    normalized = path.as_posix()
    if marker in normalized:
        return normalized.split(marker, 1)[1]
    return None


def assignment_names(node: ast.AST) -> list[str]:
    targets: list[ast.AST]
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    else:
        return []

    names = []
    for target in targets:
        for child in ast.walk(target):
            if isinstance(child, ast.Name):
                names.append(child.id)
            elif isinstance(child, ast.Attribute):
                names.append(child.attr)
    return sorted(set(names))


def main() -> None:
    args = arguments()
    source = args.source.resolve()
    revision = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    if revision != PINNED_SHA:
        raise SystemExit(f"source is {revision}, expected {PINNED_SHA}")

    runtime_tests = json.loads(args.tests.read_text())["tests"]
    test_ids = [test["id"] for test in runtime_tests]
    test_index = {test_id: index for index, test_id in enumerate(test_ids)}
    context_index = {context_name(test_id): index for index, test_id in enumerate(test_ids)}

    merged = CoverageData(no_disk=True)
    for coverage_path in args.coverage:
        shard = CoverageData(basename=str(coverage_path.resolve()))
        shard.read()
        merged.update(shard)

    sets: list[list[int]] = []
    set_ids: dict[tuple[int, ...], int] = {}

    def intern(numbers) -> int:
        key = tuple(sorted(set(numbers)))
        if key not in set_ids:
            set_ids[key] = len(sets)
            sets.append(list(key))
        return set_ids[key]

    files: dict[str, dict] = {}
    parsed: dict[str, ast.Module] = {}
    line_numbers: dict[str, dict[int, set[int]]] = {}
    empty_context_lines: dict[str, set[int]] = {}
    scopes_by_file: dict[str, list[tuple[int, int, str, set[int]]]] = {}
    definitions: dict[str, list[tuple[int, list[str]]]] = defaultdict(list)
    symbol_references: dict[str, set[int]] = defaultdict(set)

    for measured_file in sorted(merged.measured_files()):
        relative = relative_coverage_path(measured_file, source)
        if relative is None or not relative.endswith(".py"):
            continue
        path = source / relative
        if not path.is_file():
            continue

        contexts = merged.contexts_by_lineno(measured_file)
        empty_context_lines[relative] = {
            line for line, names in contexts.items() if "" in names
        }
        numbered: dict[int, set[int]] = {}
        for line, names in contexts.items():
            indices = {context_index[name] for name in names if name in context_index}
            if indices:
                numbered[line] = indices
        line_numbers[relative] = numbered

        try:
            tree = ast.parse(path.read_text())
        except (SyntaxError, UnicodeDecodeError):
            continue
        parsed[relative] = tree

        scopes = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            start = min(
                [node.lineno, *(decorator.lineno for decorator in node.decorator_list)]
            )
            end = node.end_lineno or node.lineno
            indices: set[int] = set()
            for line in range(start, end + 1):
                indices.update(numbered.get(line, ()))
            if indices:
                kind = "c" if isinstance(node, ast.ClassDef) else "f"
                scopes.append((start, end, kind, indices))
        scopes_by_file[relative] = scopes

        parents: dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent

        for node in ast.walk(tree):
            names = assignment_names(node)
            if names and isinstance(parents.get(node), (ast.Module, ast.ClassDef)):
                definitions[relative].append((node.lineno, names))

            if isinstance(node, ast.Name):
                name = node.id
            elif isinstance(node, ast.Attribute):
                name = node.attr
            else:
                continue

            indices = set(numbered.get(node.lineno, ()))
            # A reference executed in a subprocess can have coverage elsewhere
            # in the enclosing function after ordinary+sync maps are merged.
            containing = [
                scope
                for scope in scopes
                if scope[0] <= node.lineno <= scope[1] and scope[2] == "f"
            ]
            if containing:
                indices.update(min(containing, key=lambda scope: scope[1] - scope[0])[3])
            symbol_references[name].update(indices)

    for relative, numbered in line_numbers.items():
        entry: dict[str, object] = {}
        entry["l"] = [[line, intern(indices)] for line, indices in sorted(numbered.items())]
        scopes = scopes_by_file.get(relative, [])
        entry["s"] = [
            [start, end, kind, intern(indices)]
            for start, end, kind, indices in sorted(scopes, key=lambda item: (item[0], item[1]))
        ]
        all_indices: set[int] = set()
        for indices in numbered.values():
            all_indices.update(indices)
        entry["f"] = intern(all_indices)
        import_ranges = []
        empty_lines = empty_context_lines.get(relative, set())
        scope_ranges = []
        for node in ast.walk(parsed.get(relative, ast.Module(body=[], type_ignores=[]))):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            end = node.end_lineno or node.lineno
            scope_ranges.append((node.lineno, end))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # The full multi-line signature executes at import. Only empty
                # context at the first body statement or later proves that the
                # function itself is called while dependents are importing.
                body_start = min((statement.lineno for statement in node.body), default=end)
                if any(body_start <= line <= end for line in empty_lines):
                    import_ranges.append([node.lineno, end])
                for decorator in node.decorator_list:
                    if decorator.lineno in empty_lines:
                        import_ranges.append([decorator.lineno, decorator.end_lineno or decorator.lineno])
        nested_lines = {
            line
            for start, end in scope_ranges
            for line in empty_lines
            if start <= line <= end
        }
        # Empty-context statements outside functions/classes are genuine
        # module-import execution. Class-body assignments use the narrower
        # assignment/dialect dependency maps instead of all reverse importers.
        import_ranges.extend([line, line] for line in sorted(empty_lines - nested_lines))
        if import_ranges:
            entry["i"] = import_ranges
        files[relative] = entry

    fixtures: dict[str, set[int]] = defaultdict(set)
    for fixture_access in args.fixture_access:
        for relative, owners in json.loads(fixture_access.read_text()).items():
            path = relative if relative.startswith("tests/fixtures/") else f"tests/fixtures/{relative}"
            fixtures[path].update(test_index[owner] for owner in owners if owner in test_index)
    for fixture_map in args.fixture_map:
        for relative, owners in json.loads(fixture_map.read_text()).items():
            path = relative if relative.startswith("tests/fixtures/") else f"tests/fixtures/{relative}"
            fixtures[path].update(test_index[owner] for owner in owners if owner in test_index)

    assignments: dict[str, list[list[int]]] = defaultdict(list)
    reverse_imports: dict[str, set[int]] = defaultdict(set)
    dialects: dict[str, set[int]] = defaultdict(set)
    for dependency_map in args.dependency_map:
        dependencies = json.loads(gzip.decompress(dependency_map.read_bytes()))
        for key, owners in dependencies.get("assignment_reads", {}).items():
            relative, start, end = key.rsplit(":", 2)
            indices = {test_index[owner] for owner in owners if owner in test_index}
            if indices:
                assignments[relative].append([int(start), int(end), intern(indices)])
        for relative, owners in dependencies.get("reverse_imports", {}).items():
            reverse_imports[relative].update(
                test_index[owner] for owner in owners if owner in test_index
            )
        for dialect, owners in dependencies.get("dialects", {}).items():
            dialects[dialect].update(test_index[owner] for owner in owners if owner in test_index)

    init_subclass_attributes: set[str] = set()
    for tree in parsed.values():
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name != "__init_subclass__" or not node.args.args:
                continue
            receiver = node.args.args[0].arg
            init_subclass_attributes.update(
                child.attr
                for child in ast.walk(node)
                if isinstance(child, ast.Attribute)
                and isinstance(child.value, ast.Name)
                and child.value.id == receiver
                and isinstance(child.ctx, ast.Load)
            )

    model = {
        "v": 1,
        "sha": PINNED_SHA,
        "t": test_ids,
        "z": sets,
        "f": files,
        "x": {path: intern(indices) for path, indices in sorted(fixtures.items())},
        "a": {
            path: sorted(entries)
            for path, entries in sorted(assignments.items())
        },
        "r": {
            path: intern(indices) for path, indices in sorted(reverse_imports.items()) if indices
        },
        "q": {
            dialect: intern(indices) for dialect, indices in sorted(dialects.items()) if indices
        },
        "h": sorted(init_subclass_attributes),
    }
    encoded = json.dumps(model, sort_keys=True, separators=(",", ":")).encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("wb") as raw_output:
        with gzip.GzipFile(fileobj=raw_output, mode="wb", mtime=0) as compressed:
            compressed.write(encoded)
    print(
        f"wrote {args.output}: {len(encoded)} raw bytes, "
        f"{args.output.stat().st_size} compressed bytes, {len(sets)} unique test sets"
    )
    if args.sources_output:
        sources = {
            path.relative_to(source).as_posix(): path.read_text()
            for top in ("sqlglot", "tests")
            for path in sorted((source / top).rglob("*.py"))
        }
        source_bytes = json.dumps(sources, sort_keys=True, separators=(",", ":")).encode()
        with args.sources_output.open("wb") as raw_output:
            with gzip.GzipFile(fileobj=raw_output, mode="wb", mtime=0) as compressed:
                compressed.write(source_bytes)
        print(
            f"wrote {args.sources_output}: {len(source_bytes)} raw bytes, "
            f"{args.sources_output.stat().st_size} compressed bytes"
        )


if __name__ == "__main__":
    main()
