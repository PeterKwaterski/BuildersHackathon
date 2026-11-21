#!/usr/bin/env python3
"""Build the complete owner-aware literal class-attribute reader profile."""

from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import json
import subprocess
import types
from collections import defaultdict
from pathlib import Path

from collect_class_attribute_reads import SAFE, safe_literal, source_labels


PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, action="append", required=True)
    parser.add_argument("--trace", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def entries(source: Path):
    labels = source_labels(source)
    by_label = {label: key for key, label in labels.items()}
    result = []
    for path in sorted((source / "sqlglot").rglob("*.py")):
        relative = path.relative_to(source).as_posix()
        module = relative.removesuffix("/__init__.py").removesuffix(".py").replace("/", ".")
        tree = ast.parse(path.read_text(), filename=relative, type_comments=True)

        def visit(body: list[ast.stmt], owners: tuple[str, ...]):
            for statement in body:
                if not isinstance(statement, ast.ClassDef):
                    continue
                qualname = ".".join((*owners, statement.name))
                for item in statement.body:
                    if isinstance(item, ast.Assign):
                        targets = item.targets
                    elif isinstance(item, ast.AnnAssign):
                        targets = [item.target]
                    else:
                        continue
                    if len(targets) != 1 or not isinstance(targets[0], ast.Name):
                        continue
                    name = targets[0].id
                    key = (module, qualname, name)
                    label = labels.get(key)
                    if label is None or by_label.get(label) != key:
                        continue
                    value_node = getattr(item, "value", None)
                    try:
                        value = ast.literal_eval(value_node)
                    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                        continue
                    if safe_literal(value):
                        result.append((relative, item, qualname, name, label))
                visit(statement.body, (*owners, statement.name))

        visit(tree.body, ())
    return result


def static_unsafe_names(source: Path, candidate_names: set[str]) -> set[str]:
    unsafe = set()
    for root_name in ("sqlglot", "tests"):
        for path in sorted((source / root_name).rglob("*.py")):
            text = path.read_text()
            tree = ast.parse(text, filename=path.as_posix(), type_comments=True)

            # ``ast.literal_eval`` deliberately does not evaluate expressions
            # such as ``"WEEK_" + "OFFSET"``, while CPython folds those into
            # a single runtime string. Inspect code constants, but not
            # ``co_names`` (which includes ordinary direct attribute loads),
            # so folded names passed to an alias or native reflector reject
            # every candidate with that name.
            def compiled_strings(code: types.CodeType):
                for constant in code.co_consts:
                    if type(constant) is str:
                        yield constant
                    elif isinstance(constant, types.CodeType):
                        yield from compiled_strings(constant)

            code = compile(text, path.as_posix(), "exec", dont_inherit=True, optimize=0)
            unsafe.update(candidate_names.intersection(compiled_strings(code)))
            for node in ast.walk(tree):
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    value = node.value
                    if isinstance(value, ast.Name) and value.id in {
                        "getattr", "hasattr", "setattr", "delattr", "vars", "dir",
                    }:
                        raise SystemExit(f"aliased reflective builtin at {path}:{node.lineno}")
                if isinstance(node, ast.ImportFrom) and node.module == "builtins":
                    if any(alias.name in {
                        "getattr", "hasattr", "setattr", "delattr", "vars", "dir",
                    } for alias in node.names):
                        raise SystemExit(f"imported reflective builtin at {path}:{node.lineno}")
                if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
                    unsafe.add(node.attr)
                # An exact attribute-name value can feed an alias, native API,
                # or computed reflector that source rewriting cannot identify.
                # Direct ``obj.NAME`` loads contain no string node and remain
                # eligible for owner-aware tracing.
                try:
                    literal = ast.literal_eval(node)
                except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                    literal = None
                if type(literal) is str and literal in candidate_names:
                    unsafe.add(literal)
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                    continue
                if node.func.attr not in {
                    "__getattribute__", "__setattr__", "__delattr__",
                    "getattr_static", "attrgetter",
                }:
                    continue
                for argument in node.args:
                    if isinstance(argument, ast.Constant) and type(argument.value) is str:
                        unsafe.add(argument.value)
                    else:
                        # No such dynamic opaque operation exists in the pinned
                        # tree. Preserve that invariant rather than guessing.
                        raise SystemExit(
                            f"dynamic opaque attribute access at {path}:{node.lineno}"
                        )
    return unsafe


def main() -> None:
    args = arguments()
    if len(args.manifest) < 2 or len(args.trace) < 2:
        raise SystemExit("normal and synchronous-worker traces are required")
    source = args.source.resolve()
    revision = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    if revision != PINNED_SHA:
        raise SystemExit(f"source is {revision}, expected {PINNED_SHA}")
    tests = json.loads(args.tests.read_text())["tests"]
    test_ids = [test["id"] for test in tests]
    test_index = {test_id: index for index, test_id in enumerate(test_ids)}
    expected = set(test_ids)
    manifests = [json.loads(path.read_text()) for path in args.manifest]
    if not {"normal", "synchronous-worker"}.issubset(
        {manifest.get("mode") for manifest in manifests}
    ):
        raise SystemExit("both trace modes are required")
    for path, manifest in zip(args.manifest, manifests):
        missing = expected - set(manifest.get("tests", ()))
        if manifest.get("exitstatus") != 0 or missing:
            raise SystemExit(f"inadmissible manifest {path}: {len(missing)} tests missing")
        if not isinstance(manifest.get("child_logs"), int) or manifest["child_logs"] <= 0:
            raise SystemExit(f"manifest {path} lacks subprocess accounting")

    documents = [json.loads(path.read_text()) for path in args.trace]
    unknown = {
        owner
        for document in documents
        for events in document.values()
        for owners in events.values()
        for owner in owners
        if owner != "__NO_TEST__" and owner not in expected
    }
    if unknown:
        raise SystemExit(f"trace contains {len(unknown)} unknown test owners")
    source_entries = entries(source)
    unsafe_names = static_unsafe_names(
        source, {name for _, _, _, name, _ in source_entries}
    )
    profile: dict[str, list[list]] = defaultdict(list)
    states = defaultdict(int)
    for relative, statement, qualname, name, label in source_entries:
        observations = [document.get(label) for document in documents]
        owners = set()
        kinds = set()
        for events in observations:
            if not events:
                continue
            kinds.update(events)
            for values in events.values():
                owners.update(values)
        if name in unsafe_names:
            state = "static-unsafe"
        elif any(events is None for events in observations):
            state = "incomplete" if owners else "unobserved"
        elif "__NO_TEST__" in owners:
            state = "import-read"
        elif "mutation" in kinds:
            state = "mutated"
        elif not owners:
            state = "unobserved"
        else:
            state = "safe"
        readers = sorted(test_index[owner] for owner in owners if owner in test_index)
        profile[relative].append([
            statement.lineno,
            statement.end_lineno or statement.lineno,
            qualname,
            name,
            ast.dump(statement.value, include_attributes=False),
            state,
            readers,
        ])
        states[state] += 1

    ordered = {
        path: sorted(values, key=lambda entry: (entry[0], entry[2], entry[3]))
        for path, values in sorted(profile.items())
    }
    payload = {
        "d": ordered,
        "n": len(test_ids),
        "sha": revision,
        "t": hashlib.sha256("\0".join(test_ids).encode()).hexdigest(),
        "v": 1,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    args.output.write_bytes(gzip.compress(raw, compresslevel=9, mtime=0))
    print(
        f"wrote {sum(map(len, ordered.values()))} class-attribute profile entries: "
        + ", ".join(f"{key}={value}" for key, value in sorted(states.items()))
    )


if __name__ == "__main__":
    main()
