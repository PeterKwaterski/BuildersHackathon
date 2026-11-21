#!/usr/bin/env python3
"""Collect exact Python 3.13 evidence for the max-nodes certificate."""

from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import json
import platform
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import max_nodes_exact as exact


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def class_method(tree: ast.Module, class_name: str, method_name: str) -> ast.FunctionDef:
    return exact._class_method(tree, class_name, method_name)


def measure(source: Path) -> tuple[list[dict], list[dict]]:
    sys.path.insert(0, str(source))
    from sqlglot import exp, parse_one
    from sqlglot.errors import ErrorLevel, ParseError
    from sqlglot.parser import Parser

    original_validate = Parser.validate_expression
    original_raise = Parser.raise_error
    state = {"calls": 0, "raises": []}

    def validate(self, expression, args=None):
        state["calls"] += 1
        return original_validate(self, expression, args)

    def raise_error(self, message, token=None):
        state["raises"].append(
            {
                "call": state["calls"],
                "message": message,
                "error_level": self.error_level.name,
                "errors_before": len(self.errors),
            }
        )
        return original_raise(self, message, token)

    Parser.validate_expression = validate
    Parser.raise_error = raise_error

    width = 10_000
    depth = 100
    expression = "x" + "=x" * depth
    heavy_sql = f"SELECT {','.join(expression for _ in range(width))}"
    reset_sql = "SELECT " + ",".join(f"x={index}" for index in range(100))

    def run(name, sql, max_nodes, expect_raise, expected_type=None):
        state["calls"] = 0
        state["raises"] = []
        caught = None
        result = None
        try:
            if max_nodes is None:
                result = parse_one(sql)
            else:
                result = parse_one(sql, max_nodes=max_nodes)
        except Exception as error:  # evidence is checked strictly below
            caught = error
        if expect_raise:
            if not isinstance(caught, ParseError):
                raise RuntimeError(f"{name} did not raise ParseError")
        elif caught is not None or (expected_type is not None and not isinstance(result, expected_type)):
            raise RuntimeError(f"{name} did not complete as expected")
        return {
            "name": name,
            "calls": state["calls"],
            "raised": caught is not None,
            "exception": type(caught).__name__ if caught is not None else None,
            "raises": list(state["raises"]),
        }

    try:
        small = run("small-select", "SELECT 1", 1_000_000, False, exp.Select)
        columns = [f"col{index}" for index in range(500)]
        medium = run(
            "five-hundred-columns",
            f"SELECT {','.join(columns)} FROM t",
            1_000_000,
            False,
            exp.Select,
        )
        heavy_full = run("heavy-unbounded", heavy_sql, -1, False, exp.Select)
        heavy_million = run("million-node-limit", heavy_sql, 1_000_000, True)
        heavy_fifty = run("fifty-thousand-limit", heavy_sql, 50_000, True)
        reset_full = run("reset-setup-unbounded", reset_sql, -1, False, exp.Select)
        reset_limited = run("reset-setup-limit", reset_sql, 5, True)
        followup = run("reset-followup", "SELECT 1, 2, 3", None, False, exp.Select)
    finally:
        Parser.validate_expression = original_validate
        Parser.raise_error = original_raise

    if (
        heavy_million["calls"] != 1_000_001
        or heavy_million["calls"] != heavy_full["calls"]
        or heavy_fifty["calls"] != 50_001
        or reset_limited["calls"] != 6
        or any(
            event["error_level"] != ErrorLevel.IMMEDIATE.name
            or event["errors_before"] != 0
            for row in (heavy_million, heavy_fifty, reset_limited)
            for event in row["raises"]
        )
        or len(heavy_million["raises"]) != 1
        or len(heavy_fifty["raises"]) != 1
        or len(reset_limited["raises"]) != 1
    ):
        raise RuntimeError("pinned max-nodes behavior does not match the exact contract")

    scenarios = [
        {
            "name": "small-select",
            "max_nodes": 1_000_000,
            "validation_calls": small["calls"],
            "should_raise": False,
            "required_substring": None,
        },
        {
            "name": "five-hundred-columns",
            "max_nodes": 1_000_000,
            "validation_calls": medium["calls"],
            "should_raise": False,
            "required_substring": None,
        },
        {
            "name": "million-node-limit",
            "max_nodes": 1_000_000,
            "validation_calls": heavy_full["calls"],
            "should_raise": True,
            "required_substring": "Maximum number of AST nodes",
        },
        {
            "name": "fifty-thousand-limit",
            "max_nodes": 50_000,
            "validation_calls": heavy_full["calls"],
            "should_raise": True,
            "required_substring": "(50000)",
        },
        {
            "name": "reset-setup-limit",
            "max_nodes": 5,
            "validation_calls": reset_full["calls"],
            "should_raise": True,
            "required_substring": None,
        },
        {
            "name": "reset-followup",
            "max_nodes": -1,
            "validation_calls": followup["calls"],
            "should_raise": False,
            "required_substring": None,
        },
    ]
    evidence = [
        small,
        medium,
        heavy_full,
        heavy_million,
        heavy_fifty,
        reset_full,
        reset_limited,
        followup,
    ]
    return scenarios, evidence


def main() -> None:
    args = arguments()
    if sys.version_info[:2] != (3, 13):
        raise SystemExit("max-nodes evidence must be collected under Python 3.13")
    source = args.source.resolve()
    parser_raw = (source / exact.PARSER_PATH).read_bytes()
    test_raw = (source / exact.TEST_PATH).read_bytes()
    tests_document = json.loads(args.tests.read_bytes())
    tests = tests_document.get("tests")
    if not isinstance(tests, list):
        raise SystemExit("invalid test manifest")
    target = [test for test in tests if test.get("id") == exact.TARGET_TEST]
    if len(target) != 1:
        raise SystemExit("target test is not unique")

    parser_tree = ast.parse(parser_raw, filename=exact.PARSER_PATH, type_comments=True)
    test_tree = ast.parse(test_raw, filename=exact.TEST_PATH, type_comments=True)
    validate = class_method(parser_tree, "Parser", "validate_expression")
    raise_error = class_method(parser_tree, "Parser", "raise_error")
    test_method = class_method(test_tree, "TestParser", "test_max_nodes")
    scenarios, evidence = measure(source)
    profile = {
        "format": exact.FORMAT_VERSION,
        "implementation_version": exact.IMPLEMENTATION_VERSION,
        "source_revision": exact.PINNED_SOURCE_SHA,
        "python": platform.python_implementation() + " " + platform.python_version(),
        "implementation_sha256": exact.implementation_digest(),
        "collector_sha256": sha(Path(__file__).read_bytes()),
        "parser_sha256": sha(parser_raw),
        "test_sha256": sha(test_raw),
        "test_manifest_sha256": exact._manifest_digest(tests),
        "validate_expression_sha256": exact._sha_ast(validate),
        "raise_error_sha256": exact._sha_ast(raise_error),
        "test_method_sha256": exact._sha_ast(test_method),
        "state_accesses": exact._state_accesses(parser_tree),
        "target_test": target[0],
        "scenarios": scenarios,
        "immediate_raise_verified": True,
        "evidence": evidence,
        "evidence_sha256": sha(exact._json_bytes(evidence)),
    }
    raw = exact._json_bytes(profile)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("wb") as output:
        with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as stream:
            stream.write(raw)
    print(f"profile {sha(raw)}")
    print(f"scenarios {scenarios}")


if __name__ == "__main__":
    main()
