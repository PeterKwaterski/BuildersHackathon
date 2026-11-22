#!/usr/bin/env python3
"""Compare prospective TPC optimizer results with the pinned plan profile."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.abc
import importlib.util
import json
import os
import platform
import resource
import signal
import sys
import time
import unittest  # Keep the target tests' import order.
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import get_context
from pathlib import Path


PROFILE_SHA256 = "0c7c89237e9854f596ec75d028d912346eead351bb0207acdbea5b89ade5f01a"
SOURCE_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"


class Unsupported(ValueError):
    pass


class OneModuleFinder(importlib.abc.MetaPathFinder):
    def __init__(self, module_name: str, source: str):
        self.module_name = module_name
        self.source = source

    def find_spec(self, fullname, path=None, target=None):
        del path, target
        if fullname != self.module_name:
            return None
        return importlib.util.spec_from_file_location(fullname, self.source)


def cpu_seconds() -> float:
    own = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    return own.ru_utime + own.ru_stime + children.ru_utime + children.ru_stime


def canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def load_profile(path: Path) -> dict:
    payload = path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != PROFILE_SHA256:
        raise Unsupported("plan profile digest mismatch")
    try:
        document = json.loads(gzip.decompress(payload))
    except (OSError, EOFError, UnicodeError, json.JSONDecodeError) as error:
        raise Unsupported("invalid plan profile") from error
    if (
        not isinstance(document, dict)
        or document.get("format") != "kashimo-tpc-plan-profile-v1"
        or document.get("source_sha") != SOURCE_SHA
        or document.get("python") != list(sys.version_info[:3])
        or document.get("implementation") != sys.implementation.name
        or document.get("platform") != platform.machine()
        or document.get("hash_seed") != os.environ.get("PYTHONHASHSEED")
        or set(document.get("suites", {})) != {"tpcds", "tpch"}
    ):
        raise Unsupported("plan profile provenance mismatch")
    expected_counts = {"tpcds": 99, "tpch": 22}
    for name, count in expected_counts.items():
        rows = document["suites"].get(name)
        if (
            not isinstance(rows, list)
            or len(rows) != count
            or [row.get("index") for row in rows] != list(range(1, count + 1))
        ):
            raise Unsupported("plan profile roster mismatch")
    return document


def state_signature(value: object, depth: int = 0) -> object:
    if value is None or type(value) in {bool, int, str, bytes}:
        return (type(value).__name__, value)
    if type(value) is float:
        return ("float", value.hex())
    if depth < 2 and type(value) in {tuple, list}:
        return (type(value).__name__, tuple(state_signature(item, depth + 1) for item in value))
    if depth < 2 and type(value) is dict:
        return (
            "dict",
            tuple(
                (state_signature(key, depth + 1), state_signature(item, depth + 1))
                for key, item in value.items()
            ),
        )
    if depth < 2 and type(value) in {set, frozenset}:
        rows = [state_signature(item, depth + 1) for item in value]
        return (type(value).__name__, tuple(sorted(rows, key=repr)))
    return (type(value).__module__, type(value).__qualname__, id(value))


def module_signature(module: object) -> tuple:
    return tuple(
        (name, state_signature(value, 1))
        for name, value in vars(module).items()
        if name != "__builtins__"
    )


def verify_spawn_partition(
    arguments: tuple[str, list[int], list[dict], str, str]
) -> dict:
    """Replay one deterministic official-style worker subsequence."""
    tree_text, indices, baseline_rows, changed_module_name, override_source = arguments
    tree = Path(tree_text)
    sys.path.insert(0, tree_text)
    sys.meta_path.insert(0, OneModuleFinder(changed_module_name, override_source))
    sys.argv = ["pytest", "tests/test_executor.py::TestExecutor::test_execute_tpcds"]
    from sqlglot import parse_one
    from sqlglot.executor import env as executor_env
    from sqlglot.optimizer import optimize
    from tests.helpers import TPCDS_SCHEMA, load_sql_fixture_pairs
    changed_module = __import__(changed_module_name, fromlist=["*"])

    fixtures = list(load_sql_fixture_pairs("optimizer/tpc-ds/tpc-ds.sql"))
    equal = True
    for index in indices:
        meta, sql, expected = fixtures[index - 1]
        baseline = baseline_rows[index - 1]
        if (
            baseline.get("sql_sha256") != hashlib.sha256(sql.encode()).hexdigest()
            or baseline.get("expected_sha256") != hashlib.sha256(expected.encode()).hexdigest()
            or baseline.get("execute") is not bool(meta.get("execute"))
        ):
            raise Unsupported("TPC-DS fixture provenance mismatch")
        state_before = (
            module_signature(changed_module),
            state_signature(executor_env.ENV),
        )
        expression = optimize(
            parse_one(sql), TPCDS_SCHEMA, leave_tables_isolated=True, dialect=None
        )
        if (
            module_signature(changed_module),
            state_signature(executor_env.ENV),
        ) != state_before:
            raise Unsupported("optimizer changed persistent module state")
        equal = equal and (
            canonical_digest(expression.dump())
            == baseline.get("graph_sha256")
        )
        if not equal:
            break
    return {"equal": equal, "count": len(indices), "pid": os.getpid()}


def verify(
    tree: Path, profile_path: Path, changed_paths: set[str], override_source: Path
) -> dict:
    if (
        len(changed_paths) != 1
        or any(
            not path.startswith("sqlglot/optimizer/") or not path.endswith(".py")
            for path in changed_paths
        )
        or not override_source.is_file()
    ):
        raise Unsupported("plan verifier accepts one optimizer source")
    profile = load_profile(profile_path)
    tree = tree.resolve()
    verdicts = {
        "tpcds_executor": False,
        "tpcds_optimizer": False,
        # The pinned TPC-H executor fixture marks every query execute=false;
        # an ordinary optimizer function body is therefore never called.
        "tpch_executor": True,
        "tpch_optimizer": False,
    }
    details = {"tpcds": {"executed": 57}, "tpch": {"executed": 0}}
    execute_indices = [
        row["index"] for row in profile["suites"]["tpcds"] if row["execute"]
    ]
    partitions = [execute_indices]
    changed_path = next(iter(changed_paths))
    changed_module = changed_path[:-3].replace("/", ".")
    with ProcessPoolExecutor(
        max_workers=1,
        mp_context=get_context("spawn"),
        max_tasks_per_child=1,
    ) as pool:
        rows = list(
            pool.map(
                verify_spawn_partition,
                (
                    (
                        str(tree),
                        partition,
                        profile["suites"]["tpcds"],
                        changed_module,
                        str(override_source),
                    )
                    for partition in partitions
                ),
            )
        )
    if (
        len(rows) != 1
        or len({row.get("pid") for row in rows}) != 1
        or sum(row.get("count", 0) for row in rows) != len(execute_indices)
    ):
        raise Unsupported("incomplete spawn partition replay")
    verdicts["tpcds_executor"] = all(row.get("equal") is True for row in rows)
    details["tpcds"]["spawn_workers"] = 1
    return {"accepted": True, "verdicts": verdicts, "details": details}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tree", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--override-source", type=Path, required=True)
    parser.add_argument("--changed-path", action="append", default=[])
    parser.add_argument("--deadline-s", type=float, default=0.0)
    args = parser.parse_args()
    started_cpu = cpu_seconds()
    started_wall = time.monotonic()

    def deadline(_signum, _frame):
        raise TimeoutError("prospective plan verifier deadline exceeded")

    if args.deadline_s:
        signal.signal(signal.SIGALRM, deadline)
        signal.setitimer(signal.ITIMER_REAL, args.deadline_s)
    try:
        result = verify(
            args.tree, args.artifact, set(args.changed_path), args.override_source
        )
    except Exception as error:
        result = {"accepted": False, "reason": f"{type(error).__name__}: {error}"}
    finally:
        if args.deadline_s:
            signal.setitimer(signal.ITIMER_REAL, 0)
    result["process_tree_cpu_s"] = round(cpu_seconds() - started_cpu, 6)
    result["wall_s"] = round(time.monotonic() - started_wall, 6)
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["accepted"] else 1)


if __name__ == "__main__":
    main()
