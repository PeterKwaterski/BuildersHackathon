#!/usr/bin/env python3
"""Capture target parser lines for every numbered test module imported fresh.

The parent authenticates the package snapshot and roster, then launches one
clean Python process per test module. The union is therefore independent of
pytest collection/module order and includes every module's first-import closure.
"""

from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import importlib
import json
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path


PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"
TARGET_METHODS = ("_parse_case", "_parse_window")
TARGET_PATH = "sqlglot/parser.py"
CHILD_MARKER = "IMPORT_LINE_CHILD="


def capture(tree: Path, module: str) -> tuple[dict[str, list[int]], list]:
    lines: dict[str, set[int]] = defaultdict(set)

    def local_trace(frame, event, _arg):
        if event == "line":
            lines[TARGET_PATH].add(frame.f_lineno)
        return local_trace

    def trace(frame, event, _arg):
        if event != "call":
            return None
        try:
            relative = Path(frame.f_code.co_filename).resolve().relative_to(tree)
        except (OSError, ValueError):
            return None
        return local_trace if relative.as_posix() == TARGET_PATH else None

    os.chdir(tree)
    sys.path.insert(0, str(tree))
    failure = []
    sys.settrace(trace)
    try:
        importlib.import_module(module)
    except BaseException as error:
        failure = [module, type(error).__qualname__, repr(error)]
    finally:
        sys.settrace(None)
    return (
        {path: sorted(numbers) for path, numbers in sorted(lines.items())},
        failure,
    )


def parser_observers(tree: Path, test_files: list[str]) -> list[list]:
    """Find numbered-test reflection channels rooted at ``sqlglot.Parser``."""
    records = []
    reflection_calls = {"vars", "dir", "getattr", "hasattr"}
    for relative in test_files:
        source = (tree / relative).read_text(encoding="utf-8")
        parsed = ast.parse(source, filename=relative, type_comments=True)
        parser_names = {
            alias.asname or alias.name
            for node in parsed.body
            if isinstance(node, ast.ImportFrom)
            and node.module == "sqlglot"
            for alias in node.names
            if alias.name == "Parser"
        }
        for node in ast.walk(parsed):
            if isinstance(node, ast.Attribute):
                root = node.value
                while isinstance(root, ast.Attribute):
                    root = root.value
                if isinstance(root, ast.Name) and root.id in parser_names and (
                    node.attr in TARGET_METHODS or node.attr == "__dict__"
                ):
                    records.append([relative, node.lineno, f"attribute:{node.attr}"])
            if not isinstance(node, ast.Call) or not node.args:
                continue
            first = node.args[0]
            if not isinstance(first, ast.Name) or first.id not in parser_names:
                continue
            if isinstance(node.func, ast.Name) and node.func.id in reflection_calls:
                records.append([relative, node.lineno, f"call:{node.func.id}"])
            elif (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "inspect"
            ):
                records.append([relative, node.lineno, f"inspect:{node.func.attr}"])
    return records


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tree", type=Path, required=True)
    parser.add_argument("--tests", type=Path)
    parser.add_argument("--sources", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--child")
    args = parser.parse_args()
    tree = args.tree.resolve()

    if args.child:
        files, failure = capture(tree, args.child)
        print(CHILD_MARKER + json.dumps({"files": files, "failure": failure}))
        raise SystemExit(bool(failure))

    if args.tests is None or args.sources is None or args.output is None:
        parser.error("--tests, --sources, and --output are required in parent mode")
    with gzip.open(args.sources, "rt", encoding="utf-8") as source_file:
        authenticated_sources = json.load(source_file)
    mismatches = [
        path
        for path, expected in authenticated_sources.items()
        if not (tree / path).is_file()
        or (tree / path).read_text(encoding="utf-8") != expected
    ]
    if mismatches:
        raise SystemExit(f"source snapshot mismatch: {mismatches[:3]}")

    tests = json.loads(args.tests.read_text(encoding="utf-8"))["tests"]
    ids = [test["id"] for test in tests]
    test_files = sorted({test["file"] for test in tests})
    modules = [path.removesuffix(".py").replace("/", ".") for path in test_files]
    target_test_references = [
        [relative, line_number, target]
        for relative in test_files
        for line_number, line in enumerate(
            (tree / relative).read_text(encoding="utf-8").splitlines(), 1
        )
        for target in TARGET_METHODS
        if target in line
    ]
    parser_test_observers = parser_observers(tree, test_files)

    union: dict[str, set[int]] = defaultdict(set)
    failures = []
    for module in modules:
        command = [
            sys.executable,
            str(Path(__file__).resolve()),
            "--tree",
            str(tree),
            "--child",
            module,
        ]
        try:
            result = subprocess.run(
                command,
                cwd=tree,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=180,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            failures.append([module, type(error).__qualname__, repr(error)])
            continue
        records = [
            line.removeprefix(CHILD_MARKER)
            for line in result.stdout.splitlines()
            if line.startswith(CHILD_MARKER)
        ]
        if len(records) != 1:
            failures.append([module, "MissingChildRecord", repr(result.stdout[-1000:])])
            continue
        try:
            record = json.loads(records[0])
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            failures.append([module, type(error).__qualname__, repr(error)])
            continue
        if result.returncode or record.get("failure"):
            failures.append(record.get("failure") or [module, "ChildExit", result.returncode])
            continue
        for path, numbers in record.get("files", {}).items():
            union[path].update(numbers)

    payload = {
        "v": 2,
        "sha": PINNED_SHA,
        "n": len(ids),
        "t": hashlib.sha256("\0".join(ids).encode("utf-8")).hexdigest(),
        "order": "fresh-process-per-module",
        "modules": modules,
        "target_test_references": target_test_references,
        "parser_test_observers": parser_test_observers,
        "files": {path: sorted(numbers) for path, numbers in sorted(union.items())},
        "failures": failures,
    }
    args.output.write_text(json.dumps(payload, separators=(",", ":")) + "\n")
    print(
        f"modules={len(modules)} files={len(union)} "
        f"lines={sum(map(len, union.values()))} failures={len(failures)} "
        f"target_test_references={len(target_test_references)} "
        f"parser_test_observers={len(parser_test_observers)}"
    )
    if failures or target_test_references or parser_test_observers:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
