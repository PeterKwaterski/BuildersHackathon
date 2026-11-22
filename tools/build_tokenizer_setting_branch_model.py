#!/usr/bin/env python3
"""Build the exact first-effect reader certificate for three Tokenizer settings."""

from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import json
import re
import subprocess
from pathlib import Path


PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"
TOKENS = "sqlglot/tokens.py"
CORE = "sqlglot/tokenizer_core.py"
TOKENS_SHA256 = "93ea4dd996a6ffb9b61f77cc7900658351ca1d9b1d6cd40efddd233720d8e2be"
CORE_SHA256 = "142463b972f35299140172de19eb72bf0c32742867eb251e06c5592413f8083c"
MODEL_SHA256 = "d61c504e9a4a1006217e6702e1c6f05c04846b3dd5a09ec5572523fd8b2cb382"
SETTINGS = {
    "DASH_COMMENT_REQUIRES_BOUNDARY": ("dash_comment_requires_boundary", 908),
    "COMMENTS_TERMINATE_AT_NEWLINE_ONLY": ("comments_terminate_at_newline_only", 950),
    "STRING_ESCAPES_ALLOWED_IN_RAW_STRINGS": (
        "string_escapes_allowed_in_raw_strings",
        1405,
    ),
}
TRACE_SHA256 = {
    "normal": "4afe4afc075b26f4e947de92cfb5a9598ab1bea22c30f137d76ada1cc7c35ecf",
    "synchronous-worker": "709a17acaf46f8516553f94577dac156e04f17ad0a5e7f88ab7bffa77f749868",
}
MANIFEST_SHA256 = {
    "normal": "ac04ff11895a8eaa24979d5bcddd83845c0aff961beff50b31548b72bb70f9ca",
    "synchronous-worker": "63107844c3db71a3befb864fa2f34fbeff918604a835042fa31e7cea9eceef31",
}
CLASS_COLLECTOR_SHA256 = "5a37f6ae830a6bd7a9d3647f8b746264fd6ad274bfa5eb22005c07042d60d6be"
COLLECTOR_SHA256 = "21f618281b27ae6567a22d4f24e4b0514d64a4c8be30037212c52a8c74753677"
EXPECTED_RUNTIME = {
    "cache_tag": "cpython-313",
    "compiler": "GCC 14.2.0",
    "environment": "49497bc3ebd9b53a764db3de05a75fc08d320ff50465756d1258121fd2a080e7",
    "executable": "73efccb6aa17a74869ef6f11e0a0118b0f27693ea85f36c7a3758c307fd8914f",
    "hexversion": 51188464,
    "implementation": "cpython",
    "machine": "x86_64",
    "platform": "Linux",
    "pytest": "9.2.0",
    "version": "3.13.18 (main, Nov  5 2026, 07:59:38) [GCC 14.2.0]",
    "version_info": [3, 13, 18, "final", 0],
}
IMPLEMENTATION_SHA256 = "1884907391a10f7a655b5e0e95b6b888e0c80431911c078db570db0f63b308ba"
IMPLEMENTATION_PATTERN = re.compile(
    rb'(?m)^IMPLEMENTATION_SHA256\s*=\s*"[^"]*"'
)


def implementation_digest() -> str:
    source = Path(__file__).read_bytes()
    normalized, count = IMPLEMENTATION_PATTERN.subn(
        b'IMPLEMENTATION_SHA256 = "<normalized>"', source
    )
    if count != 1:
        raise SystemExit("builder implementation sentinel is missing")
    return hashlib.sha256(normalized).hexdigest()


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--selector-model", type=Path, required=True)
    parser.add_argument("--collection", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, action="append", required=True)
    parser.add_argument("--trace", type=Path, action="append", required=True)
    parser.add_argument("--class-collector", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def unique_class(tree: ast.Module, name: str) -> ast.ClassDef:
    values = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == name]
    if len(values) != 1:
        raise SystemExit(f"expected one {name}")
    return values[0]


def source_contract(source: Path) -> None:
    tokens_text = (source / TOKENS).read_text(encoding="utf-8")
    core_text = (source / CORE).read_text(encoding="utf-8")
    if hashlib.sha256(tokens_text.encode()).hexdigest() != TOKENS_SHA256:
        raise SystemExit("tokens source mismatch")
    if hashlib.sha256(core_text.encode()).hexdigest() != CORE_SHA256:
        raise SystemExit("core source mismatch")
    tokens = ast.parse(tokens_text, filename=TOKENS, type_comments=True)
    core = ast.parse(core_text, filename=CORE, type_comments=True)
    tokenizer = unique_class(tokens, "Tokenizer")
    base = unique_class(tokens, "_TokenizerBase")
    core_cls = unique_class(core, "TokenizerCore")
    annotations = {
        item.target.id
        for item in base.body
        if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name)
    }
    assignments = {
        item.targets[0].id: item
        for item in tokenizer.body
        if isinstance(item, ast.Assign)
        and len(item.targets) == 1
        and isinstance(item.targets[0], ast.Name)
        and item.targets[0].id in SETTINGS
    }
    if set(assignments) != set(SETTINGS) or not set(SETTINGS) <= annotations:
        raise SystemExit("setting definitions are not canonical")
    if any(
        not isinstance(item.value, ast.Constant) or type(item.value.value) is not bool
        for item in assignments.values()
    ):
        raise SystemExit("setting defaults are not booleans")
    init_core = [
        item
        for item in tokenizer.body
        if isinstance(item, ast.FunctionDef) and item.name == "_init_core"
    ]
    if len(init_core) != 1:
        raise SystemExit("Tokenizer._init_core is not unique")
    if (
        init_core[0].decorator_list
        or len(init_core[0].body) != 1
        or not isinstance(init_core[0].body[0], ast.Return)
    ):
        raise SystemExit("Tokenizer._init_core body is not the exact handoff")
    calls = [
        node
        for node in ast.walk(init_core[0])
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "TokenizerCore"
    ]
    if len(calls) != 1:
        raise SystemExit("TokenizerCore handoff is not unique")
    all_core_loads = [
        node
        for node in ast.walk(tokens)
        if isinstance(node, ast.Name)
        and node.id == "TokenizerCore"
        and isinstance(node.ctx, ast.Load)
    ]
    if (
        init_core[0].body[0].value is not calls[0]
        or sorted(node.lineno for node in all_core_loads) != [576, 577]
        or not isinstance(init_core[0].returns, ast.Name)
        or init_core[0].returns.id != "TokenizerCore"
    ):
        raise SystemExit("TokenizerCore has another construction or escape")
    keywords = {item.arg: item.value for item in calls[0].keywords if item.arg}
    for setting, (field, _line) in SETTINGS.items():
        value = keywords.get(field)
        if not (
            isinstance(value, ast.Attribute)
            and isinstance(value.value, ast.Name)
            and value.value.id == "self"
            and value.attr == setting
        ):
            raise SystemExit(f"invalid handoff for {setting}")

    # Exact field stores and first-effect loads. The raw-string setting's
    # earlier self-field load only copies an immutable bool into the local;
    # line 1405 is its sole local load and therefore its first effect.
    parents = {child: node for node in ast.walk(core_cls) for child in ast.iter_child_nodes(node)}
    expected_loads = {
        "dash_comment_requires_boundary": [908],
        "comments_terminate_at_newline_only": [950],
        "string_escapes_allowed_in_raw_strings": [1325],
    }
    for field, loads in expected_loads.items():
        observed = sorted(
            node.lineno
            for node in ast.walk(core_cls)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "self"
            and node.attr == field
            and isinstance(node.ctx, ast.Load)
        )
        if observed != loads:
            raise SystemExit(f"field load mismatch for {field}: {observed}")
        stores = [
            node
            for node in ast.walk(core_cls)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "self"
            and node.attr == field
            and isinstance(node.ctx, ast.Store)
        ]
        assignment = parents.get(stores[0]) if len(stores) == 1 else None
        if not (
            isinstance(assignment, ast.Assign)
            and len(assignment.targets) == 1
            and assignment.targets[0] is stores[0]
            and isinstance(assignment.value, ast.Name)
            and assignment.value.id == field
        ):
            raise SystemExit(f"field store mismatch for {field}")
        string_mentions = [
            node
            for node in ast.walk(core_cls)
            if isinstance(node, ast.Constant) and node.value == field
        ]
        if len(string_mentions) != 1:
            raise SystemExit(f"field string/reflection mismatch for {field}")
        cursor = string_mentions[0]
        while cursor in parents and not isinstance(cursor, ast.Assign):
            cursor = parents[cursor]
        if not (
            isinstance(cursor, ast.Assign)
            and len(cursor.targets) == 1
            and isinstance(cursor.targets[0], ast.Name)
            and cursor.targets[0].id == "__slots__"
        ):
            raise SystemExit(f"field name escapes __slots__ for {field}")
    raw_names = [
        node
        for node in ast.walk(core_cls)
        if isinstance(node, ast.Name)
        and node.id == "string_escapes_allowed_in_raw_strings"
        and isinstance(node.ctx, ast.Load)
    ]
    if sorted(node.lineno for node in raw_names) != [649, 1405]:
        raise SystemExit("raw-string local flow changed")
    raw_stores = [
        node
        for node in ast.walk(core_cls)
        if isinstance(node, ast.Name)
        and node.id == "string_escapes_allowed_in_raw_strings"
        and isinstance(node.ctx, ast.Store)
    ]
    if len(raw_stores) != 1 or raw_stores[0].lineno != 1325:
        raise SystemExit("raw-string local has another definition")

    # The core object never crosses the Tokenizer facade. Reject whole-object
    # aliasing/reflection inside TokenizerCore, any external construction or
    # `_core` observation, and computed factory lookup. This also closes native
    # calls because passing `self` is not an attribute access.
    opaque_self_attributes = {
        "__class__", "__dict__", "__getattr__", "__getattribute__",
        "__getstate__", "__reduce__", "__reduce_ex__", "__slots__",
        "copy", "items", "values",
    }
    for node in ast.walk(core_cls):
        if not (isinstance(node, ast.Name) and node.id == "self" and isinstance(node.ctx, ast.Load)):
            continue
        parent = parents.get(node)
        if not (
            isinstance(parent, ast.Attribute)
            and parent.value is node
            and parent.attr not in opaque_self_attributes
        ):
            raise SystemExit(f"TokenizerCore self escapes at line {node.lineno}")
    for root in ("sqlglot", "tests"):
        for path in sorted((source / root).rglob("*.py")):
            relative = path.relative_to(source).as_posix()
            parsed = ast.parse(path.read_text(encoding="utf-8"), filename=relative, type_comments=True)
            if relative != TOKENS and any(
                isinstance(node, ast.Attribute) and node.attr == "_core"
                for node in ast.walk(parsed)
            ):
                raise SystemExit(f"external _core observer at {relative}")
            if relative != TOKENS and any(
                isinstance(node, ast.Name)
                and node.id == "TokenizerCore"
                and isinstance(node.ctx, ast.Load)
                for node in ast.walk(parsed)
            ):
                raise SystemExit(f"external TokenizerCore construction at {relative}")
            if any(
                isinstance(node, ast.Name)
                and node.id == "_init_core"
                and isinstance(node.ctx, ast.Load)
                for node in ast.walk(parsed)
            ):
                raise SystemExit(f"aliased _init_core at {relative}")

    # Exact-name audit across package and tests. The only runtime attribute
    # loads are the certified self-setting handoffs; string constants with a
    # setting name would enable computed/native reflection and are forbidden.
    for root in ("sqlglot", "tests"):
        for path in sorted((source / root).rglob("*.py")):
            relative = path.relative_to(source).as_posix()
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative, type_comments=True)
            local_parents = {
                child: parent
                for parent in ast.walk(tree)
                for child in ast.iter_child_nodes(parent)
            }
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and node.value in SETTINGS:
                    raise SystemExit(f"computed setting observer at {relative}:{node.lineno}")
                if isinstance(node, ast.Attribute) and node.attr in SETTINGS:
                    cursor = node
                    function = None
                    owner = None
                    while cursor in local_parents:
                        cursor = local_parents[cursor]
                        if function is None and isinstance(cursor, ast.FunctionDef):
                            function = cursor
                        if isinstance(cursor, ast.ClassDef):
                            owner = cursor
                            break
                    if not (
                        relative == TOKENS
                        and isinstance(node.ctx, ast.Load)
                        and isinstance(node.value, ast.Name)
                        and node.value.id == "self"
                        and function is not None
                        and function.name == "_init_core"
                        and owner is not None
                        and owner.name == "Tokenizer"
                    ):
                        raise SystemExit(f"setting observer at {relative}:{node.lineno}")


def main() -> None:
    args = arguments()
    if implementation_digest() != IMPLEMENTATION_SHA256:
        raise SystemExit("builder implementation digest mismatch")
    source = args.source.resolve()
    revision = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    if revision != PINNED_SHA or subprocess.check_output(
        ["git", "-C", str(source), "status", "--porcelain"], text=True
    ):
        raise SystemExit("source checkout is not the clean pinned revision")
    source_contract(source)
    tests = json.loads(args.tests.read_text(encoding="utf-8"))["tests"]
    test_ids = [test["id"] for test in tests]
    raw_model = args.selector_model.read_bytes()
    if hashlib.sha256(raw_model).hexdigest() != MODEL_SHA256:
        raise SystemExit("selector model bytes mismatch")
    model = json.loads(gzip.decompress(raw_model))
    if model.get("sha") != revision or model.get("t") != test_ids:
        raise SystemExit("selector model provenance mismatch")
    if len(args.manifest) != 2 or len(args.trace) != 2:
        raise SystemExit("exactly two manifests and traces are required")
    if hashlib.sha256(args.class_collector.read_bytes()).hexdigest() != CLASS_COLLECTOR_SHA256:
        raise SystemExit("class reflection collector bytes mismatch")
    manifests = [json.loads(path.read_text(encoding="utf-8")) for path in args.manifest]
    manifest_digests = {
        manifest.get("mode"): hashlib.sha256(path.read_bytes()).hexdigest()
        for path, manifest in zip(args.manifest, manifests)
    }
    if manifest_digests != MANIFEST_SHA256 or any(
        manifest.get("exitstatus") != 0
        or not set(test_ids).issubset(manifest.get("tests", ()))
        or type(manifest.get("child_logs")) is not int
        or manifest["child_logs"] <= 0
        for manifest in manifests
    ):
        raise SystemExit("normal/synchronous manifests are incomplete")
    traces = [json.loads(path.read_text(encoding="utf-8")) for path in args.trace]
    trace_by_mode = {
        manifest["mode"]: trace for manifest, trace in zip(manifests, traces)
    }
    trace_digests = {
        manifest["mode"]: hashlib.sha256(path.read_bytes()).hexdigest()
        for path, manifest in zip(args.trace, manifests)
    }
    if trace_digests != TRACE_SHA256:
        raise SystemExit("normal/synchronous trace bytes mismatch")
    token_tree = ast.parse((source / TOKENS).read_text(encoding="utf-8"))
    token_owner = unique_class(token_tree, "Tokenizer")
    setting_lines = {
        item.targets[0].id: item.lineno
        for item in token_owner.body
        if isinstance(item, ast.Assign)
        and len(item.targets) == 1
        and isinstance(item.targets[0], ast.Name)
        and item.targets[0].id in SETTINGS
    }
    for setting, line in setting_lines.items():
        label = f"{TOKENS}:{line}:{line}:Tokenizer:{setting}"
        observations = [trace_by_mode[mode].get(label) for mode in sorted(TRACE_SHA256)]
        if any(
            not isinstance(events, dict)
            or set(events) != {"read"}
            or not isinstance(events["read"], list)
            or events["read"] != sorted(set(events["read"]))
            or "__NO_TEST__" not in events["read"]
            for events in observations
        ) or observations[0] != observations[1]:
            raise SystemExit(f"setting trace mismatch for {setting}")
    collection_raw = args.collection.read_bytes()
    collection = json.loads(collection_raw)
    modules = sorted({test["file"].removesuffix(".py").replace("/", ".") for test in tests})
    if not (
        collection.get("sha") == revision
        and collection.get("modules") == modules
        and collection.get("failures") == []
        and collection.get("owners") == {}
        and collection.get("collection_lines") == []
        and collection.get("collection_exit") == 0
        and collection.get("collector") == COLLECTOR_SHA256
        and collection.get("runtime") == EXPECTED_RUNTIME
    ):
        raise SystemExit("collection branch profile is not empty and complete")
    line_sets = dict(model["f"][CORE]["l"])
    data = {}
    for setting, (field, line) in SETTINGS.items():
        set_id = line_sets.get(line)
        if set_id is None:
            raise SystemExit(f"missing line coverage for {line}")
        data[setting] = [field, line, model["z"][set_id]]
    payload = {
        "v": 1,
        "sha": revision,
        "n": len(test_ids),
        "t": hashlib.sha256("\0".join(test_ids).encode()).hexdigest(),
        "m": MODEL_SHA256,
        "tokens": TOKENS_SHA256,
        "core": CORE_SHA256,
        "a": CLASS_COLLECTOR_SHA256,
        "b": IMPLEMENTATION_SHA256,
        "collector": COLLECTOR_SHA256,
        "runtime": EXPECTED_RUNTIME,
        "collection": hashlib.sha256(collection_raw).hexdigest(),
        "reflection": "normal+sync:no-reflect-or-mutation",
        "r": TRACE_SHA256,
        "p": MANIFEST_SHA256,
        "modules": modules,
        "c": [],
        "d": data,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    args.output.write_bytes(gzip.compress(raw, compresslevel=9, mtime=0))
    print({setting: len(entry[2]) for setting, entry in data.items()})


if __name__ == "__main__":
    main()
