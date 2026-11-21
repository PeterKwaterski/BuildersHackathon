#!/usr/bin/env python3
"""Build a deterministic authenticated TPC-DS rule-boundary profile."""

from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import inspect
import json
import multiprocessing
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tpc_rule_replay import (
    HISTORIES,
    PROFILE_FORMAT,
    RULES,
    TARGET_COUNTS,
    boundary_digest,
    canonical_digest,
    validate_profile,
)


TARGET = "tests/test_executor.py::TestExecutor::test_execute_tpcds"
OWNERS = (
    ("sqlglot/optimizer/qualify_columns.py", "_convert_columns_to_dots", RULES[0]),
    ("sqlglot/optimizer/isolate_table_selects.py", "isolate_table_selects", RULES[0]),
    ("sqlglot/optimizer/unnest_subqueries.py", "decorrelate", RULES[3]),
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tree_digest(root: Path, paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(path for path in paths if path.is_file()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        data = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def _collect_history(tree_text: str, history: str) -> tuple[list[dict], int]:
    tree = Path(tree_text)
    sys.path.insert(0, str(tree))
    from sqlglot import parse_one
    from sqlglot.optimizer import optimizer
    from sqlglot.schema import ensure_schema
    from tests.helpers import TPCDS_SCHEMA, load_sql_fixture_pairs

    rules = optimizer.RULES
    names = tuple(f"{rule.__module__}.{rule.__name__}" for rule in rules)
    if names != RULES:
        raise RuntimeError("optimizer rule identity mismatch")
    fixtures = list(load_sql_fixture_pairs("optimizer/tpc-ds/tpc-ds.sql"))
    if len(fixtures) != TARGET_COUNTS[TARGET]:
        raise RuntimeError("fixture accounting mismatch")
    schema = ensure_schema(TPCDS_SCHEMA)

    def sequence(record: bool, reverse: bool = False) -> list[dict]:
        rows = []
        order = range(len(fixtures) - 1, -1, -1) if reverse else range(len(fixtures))
        for index in order:
            _meta, sql, _expected = fixtures[index]
            expression = parse_one(sql)
            possible = {
                "db": None, "catalog": None, "schema": schema, "dialect": None,
                "sql": None, "isolate_tables": True, "quote_identifiers": False,
            }
            for name, rule in zip(names, rules):
                params = inspect.getfullargspec(rule).args
                kwargs = {key: possible[key] for key in params if key in possible}
                input_digest = boundary_digest(expression)
                expression = rule(expression, **kwargs)
                output_digest = boundary_digest(expression)
                if record:
                    rows.append({
                        "target": TARGET,
                        "history": history,
                        "query": index + 1,
                        "rule": name,
                        "input": input_digest,
                        "output": output_digest,
                        "cpu_ns": 0,
                    })
        return rows

    started = time.process_time_ns()
    if history == "forward":
        rows = sequence(True)
    elif history == "reverse":
        rows = sequence(True, reverse=True)
    elif history == "warm":
        sequence(False)
        rows = sequence(True)
    else:
        raise RuntimeError("unknown history")
    return rows, time.process_time_ns() - started


def collect(tree: Path) -> tuple[list[dict], dict[str, int]]:
    rows = []
    timings = {}
    context = multiprocessing.get_context("spawn")
    for history in HISTORIES:
        with context.Pool(1) as pool:
            history_rows, cpu_ns = pool.starmap(
                _collect_history, [(str(tree.resolve()), history)]
            )[0]
        rows.extend(history_rows)
        timings[history] = cpu_ns
    rows.sort(key=lambda row: (
        row["target"], HISTORIES.index(row["history"]), row["query"],
        RULES.index(row["rule"]),
    ))
    return rows, timings


def owner_profile(tree: Path, qualify_cpu: float, unnest_cpu: float) -> dict:
    owners = {}
    for path, qualname, rule in OWNERS:
        source = (tree / path).read_text(encoding="utf-8")
        module = ast.parse(source, filename=path, type_comments=True)
        matches = [
            node for node in ast.walk(module)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == qualname
        ]
        if len(matches) != 1:
            raise RuntimeError(f"owner mismatch: {path}:{qualname}")
        node = matches[0]
        metadata = {
            "path": path,
            "qualname": qualname,
            "first_line": node.lineno,
            "end_line": node.end_lineno or node.lineno,
            "rule": rule,
            "source_sha256": sha256(source.encode("utf-8")),
        }
        owner_id = canonical_digest(metadata)
        owners[owner_id] = {
            **metadata,
            "barriers": [
                "persistent_worker_predecessors",
                "module_class_native_state",
                "returned_graph_escape",
            ],
            "state_independent": False,
            "competition_risk": True,
            "call_graph_sha256": canonical_digest(
                {"direct_owner_ast": ast.dump(node, include_attributes=False)}
            ),
            "risk_cpu_s": {TARGET: qualify_cpu if rule == RULES[0] else unnest_cpu},
        }
    return owners


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tree", type=Path, required=True)
    parser.add_argument("--requirements", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--timing-out", type=Path, required=True)
    parser.add_argument("--qualify-cpu-s", type=float, required=True)
    parser.add_argument("--unnest-cpu-s", type=float, required=True)
    args = parser.parse_args()
    tree = args.tree.resolve()
    rows, timings = collect(tree)
    profile = {
        "format": PROFILE_FORMAT,
        "identity": {
            "sqlglot_tree": tree_digest(tree, list((tree / "sqlglot").rglob("*.py"))),
            "tests_tree": tree_digest(tree, list((tree / "tests").rglob("*.py"))),
            "fixture_tree": tree_digest(
                tree, list((tree / "tests/fixtures/optimizer/tpc-ds").rglob("*"))
            ),
            "requirements_lock": sha256(args.requirements.read_bytes()),
            "collector_source": sha256(Path(__file__).read_bytes()),
        },
        "rule_order": list(RULES),
        "coverage": {TARGET: {"queries": TARGET_COUNTS[TARGET], "histories": list(HISTORIES)}},
        "boundary_rows_sha256": canonical_digest(rows),
        "boundary_rows": rows,
        "owners": owner_profile(tree, args.qualify_cpu_s, args.unnest_cpu_s),
        "spawn_obligations": {name: False for name in (
            "parse", "pickle_roundtrip", "fresh_import", "initializer",
            "persistent_worker_predecessors", "table_reader_state",
            "stdout_warnings_exceptions", "native_state",
        )},
    }
    profile["collection_sha256"] = canonical_digest(profile)
    validate_profile(profile)
    encoded = json.dumps(profile, sort_keys=True, separators=(",", ":")).encode("utf-8")
    args.out.write_bytes(gzip.compress(encoded, compresslevel=9, mtime=0))
    args.timing_out.write_text(
        json.dumps({
            "format": "tpc-rule-profile-timing-v1",
            "histories_cpu_ns": timings,
            "profile_sha256": sha256(args.out.read_bytes()),
        }, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
