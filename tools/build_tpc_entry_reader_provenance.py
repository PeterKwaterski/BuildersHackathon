#!/usr/bin/env python3
"""Build a static, answer-free provenance inventory for pinned TPC schemas."""

from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import json
import subprocess
from pathlib import Path


PINNED = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"
NAMES = {"TPCH_SCHEMA", "TPCDS_SCHEMA"}
UNCOLLECTED_READERS = {"benchmarks.optimize", "tests.gen_fixtures"}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def scope(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> list[str]:
    result = []
    while node in parents:
        node = parents[node]
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            result.append(node.name)
    return list(reversed(result))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    revision = subprocess.run(
        ["git", "-C", str(args.source), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    if revision != PINNED:
        raise SystemExit("wrong revision")
    dirty = subprocess.run(
        ["git", "-C", str(args.source), "status", "--porcelain", "--untracked-files=no"],
        check=True, capture_output=True,
    ).stdout
    if dirty:
        raise SystemExit("dirty pinned source")
    model_bytes = args.model.read_bytes()
    model = json.loads(gzip.decompress(model_bytes))
    if model.get("sha") != PINNED:
        raise SystemExit("wrong model")

    events = []
    source_hashes = {}
    tracked = subprocess.run(
        ["git", "-C", str(args.source), "ls-files", "-z", "--", "*.py"],
        check=True, capture_output=True,
    ).stdout.split(b"\0")
    python_paths = [args.source / item.decode() for item in tracked if item]
    all_tracked_result = subprocess.run(
        ["git", "-C", str(args.source), "ls-files", "-z"],
        check=True, capture_output=True,
    ).stdout
    all_tracked = all_tracked_result.split(b"\0")
    tracked_index = subprocess.run(
        ["git", "-C", str(args.source), "ls-files", "-s", "-z"],
        check=True, capture_output=True,
    ).stdout
    all_paths = [args.source / item.decode() for item in all_tracked if item]
    text_references = []
    for path in all_paths:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            if any(name in line for name in (*NAMES, "tests.helpers")):
                text_references.append({
                    "path": path.relative_to(args.source).as_posix(),
                    "line": line_number,
                })
    uncollected_reader_imports = []
    for path in sorted(python_paths):
        relative = path.relative_to(args.source).as_posix()
        data = path.read_bytes()
        source_hashes[relative] = sha(data)
        tree = ast.parse(data, filename=relative, type_comments=True)
        parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        for node in ast.walk(tree):
            event = None
            imported_modules = []
            if isinstance(node, ast.Import):
                imported_modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.append(node.module)
                imported_modules.extend(
                    f"{node.module}.{alias.name}" for alias in node.names
                )
            elif isinstance(node, ast.Constant) and type(node.value) is str:
                imported_modules.append(node.value)
            for module in imported_modules:
                if module in UNCOLLECTED_READERS:
                    uncollected_reader_imports.append({
                        "path": relative, "line": node.lineno, "module": module,
                    })
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id in NAMES
            ):
                event = {"kind": "definition", "name": node.targets[0].id}
            elif isinstance(node, ast.ImportFrom) and node.module == "tests.helpers":
                imported = sorted(alias.name for alias in node.names if alias.name in NAMES or alias.name == "*")
                if imported:
                    event = {"kind": "import", "names": imported}
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in NAMES:
                event = {"kind": "name-load", "name": node.id}
            elif isinstance(node, ast.Attribute) and node.attr in NAMES:
                event = {"kind": "attribute", "name": node.attr}
            elif isinstance(node, ast.Constant) and node.value in NAMES:
                event = {"kind": "string", "name": node.value}
            if event is not None:
                event.update({"path": relative, "line": node.lineno, "scope": scope(node, parents)})
                events.append(event)

    test_ids = model["t"]
    executor = [
        index for index, test_id in enumerate(test_ids)
        if test_id.startswith("tests/test_executor.py::TestExecutor::")
    ]
    owners = {
        name: sorted((*executor, test_ids.index(optimizer)))
        for name, optimizer in {
            "TPCH_SCHEMA": "tests/test_optimizer.py::TestOptimizer::test_tpch",
            "TPCDS_SCHEMA": "tests/test_optimizer.py::TestOptimizer::test_tpcds",
        }.items()
    }
    fixtures = {}
    for name, path in {
        "TPCH_SCHEMA": "tests/fixtures/optimizer/tpc-h/tpc-h.sql",
        "TPCDS_SCHEMA": "tests/fixtures/optimizer/tpc-ds/tpc-ds.sql",
    }.items():
        set_id = model["x"][path]
        fixtures[name] = {"path": path, "model_readers": model["z"][set_id]}
    document = {
        "v": 1,
        "revision": revision,
        "model_sha256": sha(model_bytes),
        "test_id_sha256": sha("\0".join(test_ids).encode()),
        "source_hashes": dict(sorted(source_hashes.items())),
        "tracked_index_sha256": sha(tracked_index),
        "events": events,
        "collected_files": sorted({test_id.split("::", 1)[0] for test_id in test_ids}),
        "tracked_file_count": len(all_paths),
        "tracked_python_count": len(python_paths),
        "text_references": text_references,
        "uncollected_reader_imports": uncollected_reader_imports,
        "owners": owners,
        "fixtures": fixtures,
    }
    document["profile_sha256"] = sha(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    )
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    args.output.write_bytes(gzip.compress(encoded, compresslevel=9, mtime=0))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
