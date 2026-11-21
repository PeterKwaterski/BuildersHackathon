#!/usr/bin/env python3
"""Build deterministic cached rule-input capsules for explicit-risk replay."""

from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import inspect
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tpc_rule_fast import FORMAT, RULES, canonical_digest, validate
from tpc_rule_replay import boundary_digest
from tools.collect_tpc_rule_profile import tree_digest


READERS = {
    "_convert_columns_to_dots": [1, 2, 3, 4, 6, 7, 9, 10, 11, 15, 17, 19, 23, 24,
        25, 26, 29, 31, 33, 34, 35, 38, 42, 43, 45, 46, 48, 50, 52, 54, 55,
        56, 59, 60, 62, 65, 66, 68, 69, 71, 73, 74, 75, 76, 78, 79, 81, 83,
        84, 85, 87, 88, 91, 93, 96, 97, 99],
    "isolate_table_selects": [1, 2, 3, 4, 6, 7, 9, 10, 11, 15, 17, 19, 23, 24,
        25, 26, 29, 31, 33, 34, 35, 38, 42, 43, 45, 46, 48, 50, 52, 54, 55,
        56, 59, 60, 62, 65, 66, 68, 69, 71, 73, 74, 75, 76, 78, 79, 81, 83,
        84, 85, 87, 88, 91, 93, 96, 97, 99],
    "decorrelate": [1, 6, 10, 35, 69, 81],
}
OWNERS = (
    ("sqlglot/optimizer/qualify_columns.py", "_convert_columns_to_dots", RULES[0]),
    ("sqlglot/optimizer/isolate_table_selects.py", "isolate_table_selects", RULES[0]),
    ("sqlglot/optimizer/unnest_subqueries.py", "decorrelate", RULES[1]),
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tree", type=Path, required=True)
    parser.add_argument("--requirements", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--qualify-cpu-s", type=float, required=True)
    parser.add_argument("--unnest-cpu-s", type=float, required=True)
    args = parser.parse_args()
    tree = args.tree.resolve()
    sys.path.insert(0, str(tree))
    from sqlglot import parse_one
    from sqlglot.optimizer import optimizer
    from sqlglot.schema import ensure_schema
    from tests.helpers import TPCDS_SCHEMA, load_sql_fixture_pairs

    names = tuple(f"{rule.__module__}.{rule.__name__}" for rule in optimizer.RULES)
    if names[0] != RULES[0] or names[3] != RULES[1]:
        raise RuntimeError("rule identity mismatch")
    union = {rule: set() for rule in RULES}
    for _path, owner, rule in OWNERS:
        union[rule].update(READERS[owner])
    capsules = {rule: [] for rule in RULES}
    schema = ensure_schema(TPCDS_SCHEMA)
    fixtures = list(load_sql_fixture_pairs("optimizer/tpc-ds/tpc-ds.sql"))
    for query, (_meta, sql, _expected) in enumerate(fixtures, 1):
        expression = parse_one(sql)
        possible = {
            "db": None, "catalog": None, "schema": schema, "dialect": None,
            "sql": None, "isolate_tables": True, "quote_identifiers": False,
        }
        for index, rule in enumerate(optimizer.RULES[:4]):
            name = names[index]
            params = inspect.getfullargspec(rule).args
            kwargs = {key: possible[key] for key in params if key in possible}
            if name in union and query in union[name]:
                input_dump = expression.dump()
                input_digest = boundary_digest(expression)
            expression = rule(expression, **kwargs)
            if name in union and query in union[name]:
                capsules[name].append({
                    "query": query,
                    "input_dump": input_dump,
                    "input": input_digest,
                    "output": boundary_digest(expression),
                })
    owners = {}
    for path, qualname, rule in OWNERS:
        source = (tree / path).read_text(encoding="utf-8")
        nodes = [node for node in ast.walk(ast.parse(source))
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and node.name == qualname]
        if len(nodes) != 1:
            raise RuntimeError("owner mismatch")
        node = nodes[0]
        metadata = {
            "path": path, "qualname": qualname, "first_line": node.lineno,
            "end_line": node.end_lineno or node.lineno, "rule": rule,
            "source_sha256": sha(source.encode("utf-8")),
        }
        owner_id = canonical_digest(metadata)
        owners[owner_id] = {
            **metadata,
            "readers": READERS[qualname],
            "barriers": ["predecessor_state", "process_state", "nonreader_side_effect"],
            "risk_cpu_s": args.qualify_cpu_s if rule == RULES[0] else args.unnest_cpu_s,
        }
    profile = {
        "format": FORMAT,
        "identity": {
            "sqlglot_tree": tree_digest(tree, list((tree / "sqlglot").rglob("*.py"))),
            "tests_tree": tree_digest(tree, list((tree / "tests").rglob("*.py"))),
            "fixture_tree": tree_digest(
                tree, list((tree / "tests/fixtures/optimizer/tpc-ds").rglob("*"))
            ),
            "requirements_lock": sha(args.requirements.read_bytes()),
            "builder_source": sha(Path(__file__).read_bytes()),
        },
        "capsules": capsules,
        "owners": owners,
    }
    profile["collection_sha256"] = canonical_digest(profile)
    validate(profile)
    encoded = json.dumps(profile, sort_keys=True, separators=(",", ":")).encode()
    args.out.write_bytes(gzip.compress(encoded, compresslevel=9, mtime=0))


if __name__ == "__main__":
    main()
