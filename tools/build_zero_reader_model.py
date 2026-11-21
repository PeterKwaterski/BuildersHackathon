#!/usr/bin/env python3
"""Build a conservative zero-reader dictionary-key certificate.

The input traces are answer-independent observations from the complete pinned
test suite.  A dictionary is admitted only when static taint proves its object
identity reaches keyed reads or key/shape-only operations and no value-wide or
opaque consumer.  The runtime selector still re-proves the exact patch shape.
"""

from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import json
import subprocess
from collections import defaultdict
from pathlib import Path


PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"
VALUE_WILDCARD = repr(("__BR_WILDCARD__", "values"))


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument(
        "--suite-nodeids",
        type=Path,
        required=True,
        help="nodeids captured by the successful unfiltered instrumented run",
    )
    parser.add_argument("--trace", type=Path, action="append", required=True)
    parser.add_argument("--child-trace", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def trace_files(paths: list[Path]) -> list[Path]:
    result = []
    for path in paths:
        if path.is_dir():
            result.extend(sorted(path.glob("*.json")))
        else:
            result.append(path)
    return result


def merge_traces(paths: list[Path]) -> dict[str, dict[str, set[str]]]:
    merged: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for path in paths:
        for label, events in json.loads(path.read_text()).items():
            for key, owners in events.items():
                merged[label][key].update(owners)
    return merged


def final_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def target_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def is_reference(node: ast.AST, names: set[str]) -> bool:
    return (
        isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Load)
        and node.id in names
    ) or (
        isinstance(node, ast.Attribute)
        and isinstance(node.ctx, ast.Load)
        and node.attr in names
    )


def callable_parameters(
    call: ast.Call, definitions: dict[str, list[ast.AST]]
) -> tuple[list[str], set[str]] | None:
    name = final_name(call.func)
    candidates = definitions.get(name or "", [])
    if len(candidates) != 1:
        return None
    definition = candidates[0]
    if isinstance(definition, ast.ClassDef):
        initializers = [
            item
            for item in definition.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            and item.name == "__init__"
        ]
        if len(initializers) != 1:
            return None
        function = initializers[0]
        positional = [*function.args.posonlyargs, *function.args.args][1:]
    elif isinstance(definition, (ast.FunctionDef, ast.AsyncFunctionDef)):
        function = definition
        positional = [*function.args.posonlyargs, *function.args.args]
    else:
        return None
    return [argument.arg for argument in positional], {
        argument.arg for argument in function.args.kwonlyargs
    }


def build_flow_model(
    modules: list[tuple[ast.Module, dict[ast.AST, ast.AST]]],
    definitions: dict[str, list[ast.AST]],
) -> tuple[dict[str, set[str]], set[str]]:
    """Index identity-preserving name flow and every unsafe value sink."""
    edges: dict[str, set[str]] = defaultdict(set)
    unsafe = set()
    keyed_methods = {"get", "__getitem__", "__contains__"}
    key_methods = {"keys"}
    for tree, parents in modules:
        def truth_only(node: ast.AST) -> bool:
            parent = parents.get(node)
            if isinstance(parent, (ast.If, ast.While)) and parent.test is node:
                return True
            if isinstance(parent, ast.IfExp) and parent.test is node:
                return True
            if isinstance(parent, ast.UnaryOp) and isinstance(parent.op, ast.Not):
                return truth_only(parent)
            if isinstance(parent, ast.BoolOp):
                return truth_only(parent)
            return (
                isinstance(parent, ast.Call)
                and isinstance(parent.func, ast.Name)
                and parent.func.id == "bool"
                and node in parent.args
            )

        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                name = node.id
            elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
                name = node.attr
            else:
                continue
            parent = parents.get(node)
            if isinstance(parent, (ast.Assign, ast.AnnAssign)) and parent.value is node:
                targets = parent.targets if isinstance(parent, ast.Assign) else [parent.target]
                target_names = [target_name(item) for item in targets]
                if any(target is None for target in target_names):
                    unsafe.add(name)
                else:
                    edges[name].update(target_names)
                continue
            if isinstance(parent, ast.Attribute) and parent.value is node:
                call = parents.get(parent)
                if (
                    parent.attr in keyed_methods | key_methods
                    and isinstance(call, ast.Call)
                    and call.func is parent
                ):
                    continue
                unsafe.add(name)
                continue
            if isinstance(parent, ast.Subscript) and parent.value is node:
                continue
            if isinstance(parent, ast.Compare):
                membership = any(
                    comparator is node and isinstance(operator, (ast.In, ast.NotIn))
                    for operator, comparator in zip(parent.ops, parent.comparators)
                )
                if membership:
                    continue
                unsafe.add(name)
                continue
            if isinstance(parent, ast.Call):
                if (
                    isinstance(parent.func, ast.Name)
                    and parent.func.id in {"bool", "len"}
                    and node in parent.args
                ):
                    continue
                parameters = callable_parameters(parent, definitions)
                if parameters is None:
                    unsafe.add(name)
                    continue
                positional, keyword_only = parameters
                if node in parent.args:
                    index = parent.args.index(node)
                    if index < len(positional):
                        edges[name].add(positional[index])
                        continue
                unsafe.add(name)
                continue
            if isinstance(parent, ast.keyword) and parent.value is node:
                call = parents.get(parent)
                if not isinstance(call, ast.Call):
                    unsafe.add(name)
                    continue
                parameters = callable_parameters(call, definitions)
                if parameters is None:
                    unsafe.add(name)
                    continue
                positional, keyword_only = parameters
                if parent.arg and parent.arg in set(positional) | keyword_only:
                    edges[name].add(parent.arg)
                    continue
                unsafe.add(name)
                continue
            if isinstance(parent, (ast.If, ast.While)) and parent.test is node:
                continue
            if isinstance(parent, ast.BoolOp):
                if truth_only(parent):
                    continue
                unsafe.add(name)
                continue
            if isinstance(parent, ast.IfExp) and parent.test is node:
                continue
            if isinstance(parent, ast.UnaryOp) and isinstance(parent.op, ast.Not):
                continue
            if isinstance(parent, (ast.For, ast.AsyncFor)) and parent.iter is node:
                continue
            if isinstance(parent, ast.comprehension) and parent.iter is node:
                continue
            unsafe.add(name)
    return edges, unsafe


def certified_target(seed: str, edges: dict[str, set[str]], unsafe: set[str]) -> bool:
    pending = [seed]
    reached = set()
    while pending:
        name = pending.pop()
        if name in reached:
            continue
        reached.add(name)
        if name in unsafe:
            return False
        pending.extend(edges.get(name, ()))
    return True


def main() -> None:
    args = arguments()
    source = args.source.resolve()
    revision = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    if revision != PINNED_SHA:
        raise SystemExit(f"source is {revision}, expected {PINNED_SHA}")

    test_ids = [
        test["id"] for test in json.loads(args.tests.read_text())["tests"]
    ]
    expected_tests = set(test_ids)
    completed_value = json.loads(args.suite_nodeids.read_text())
    if isinstance(completed_value, dict) and completed_value.get("exitstatus") != 0:
        raise SystemExit("instrumented suite manifest records a nonzero exit status")
    completed_tests = set(
        completed_value.get("tests", ())
        if isinstance(completed_value, dict)
        else completed_value
    )
    missing_tests = expected_tests - completed_tests
    if missing_tests:
        raise SystemExit(
            f"instrumented suite manifest is missing {len(missing_tests)} tests"
        )
    traces = merge_traces([*args.trace, *trace_files(args.child_trace)])
    unknown_owners = {
        owner
        for events in traces.values()
        for owners in events.values()
        for owner in owners
        if owner != "__NO_TEST__" and owner not in expected_tests
    }
    if unknown_owners:
        raise SystemExit(f"trace contains {len(unknown_owners)} unknown tests")

    modules = []
    definitions: dict[str, list[ast.AST]] = defaultdict(list)
    assignments = []
    for path in sorted((source / "sqlglot").rglob("*.py")):
        relative = path.relative_to(source).as_posix()
        tree = ast.parse(path.read_text(), filename=relative, type_comments=True)
        parents = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent
        modules.append((tree, parents))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                definitions[node.name].append(node)
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            if not isinstance(value, ast.Dict):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if len(targets) != 1 or not isinstance(targets[0], ast.Name):
                continue
            if not isinstance(parents.get(node), (ast.Module, ast.ClassDef)):
                continue
            target = targets[0].id
            label = f"{relative}:{node.lineno}:{node.end_lineno or node.lineno}:{target}"
            assignments.append((relative, node, target, label))

    flow_edges, unsafe_names = build_flow_model(modules, definitions)
    certificate_cache = {}
    certified: dict[str, list[list[object]]] = defaultdict(list)
    for relative, node, target, label in assignments:
        events = traces.get(label)
        if not events or VALUE_WILDCARD in events:
            continue
        if target not in certificate_cache:
            certificate_cache[target] = certified_target(
                target, flow_edges, unsafe_names
            )
        if not certificate_cache[target]:
            continue
        if any(key is None for key in node.value.keys):
            continue

        runtime_keys = []
        key_dumps = []
        valid = True
        for key in node.value.keys:
            try:
                runtime_key = ast.literal_eval(key)
                hash(runtime_key)
            except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                valid = False
                break
            if runtime_key in runtime_keys:
                valid = False
                break
            runtime_keys.append(runtime_key)
            if repr(runtime_key) not in events:
                key_dumps.append(ast.dump(key, include_attributes=False))
        if valid and key_dumps:
            certified[relative].append(
                [node.lineno, node.end_lineno or node.lineno, target, key_dumps]
            )

    output = {
        "v": 1,
        "sha": PINNED_SHA,
        "n": len(expected_tests),
        "t": hashlib.sha256("\0".join(test_ids).encode("utf-8")).hexdigest(),
        "d": {path: entries for path, entries in sorted(certified.items())},
    }
    payload = json.dumps(
        output, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    args.output.write_bytes(gzip.compress(payload, compresslevel=9, mtime=0))
    print(
        f"certified {sum(len(entries) for entries in certified.values())} dictionaries "
        f"across {len(certified)} files"
    )


if __name__ == "__main__":
    main()
