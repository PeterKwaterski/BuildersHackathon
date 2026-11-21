#!/usr/bin/env python3
"""Build a narrow Tokenizer setting -> TokenizerCore field reader proof."""

from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import json
import re
import subprocess
import types
from collections import defaultdict
from pathlib import Path

from collect_class_attribute_reads import source_labels


PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"
TOKENS = "sqlglot/tokens.py"
CORE = "sqlglot/tokenizer_core.py"
TRACE_SHA256 = {
    "normal": "4afe4afc075b26f4e947de92cfb5a9598ab1bea22c30f137d76ada1cc7c35ecf",
    "synchronous-worker": "709a17acaf46f8516553f94577dac156e04f17ad0a5e7f88ab7bffa77f749868",
}
MANIFEST_SHA256 = {
    "normal": "ac04ff11895a8eaa24979d5bcddd83845c0aff961beff50b31548b72bb70f9ca",
    "synchronous-worker": "63107844c3db71a3befb864fa2f34fbeff918604a835042fa31e7cea9eceef31",
}
IMPLEMENTATION_SHA256 = "cd45fe8eace881ac34ade5b5ceb26b2fd5a684c10d330d3ed438e2cdd3517e7a"
IMPLEMENTATION_PATTERN = re.compile(
    rb'(?m)^IMPLEMENTATION_SHA256\s*=\s*"[^"]+"'
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
    parser.add_argument("--class-model", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, action="append", required=True)
    parser.add_argument("--trace", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def read_gzip(path: Path) -> tuple[dict, str]:
    raw = path.read_bytes()
    return json.loads(gzip.decompress(raw)), hashlib.sha256(raw).hexdigest()


def unique_class(tree: ast.Module, name: str) -> ast.ClassDef:
    matches = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == name]
    if len(matches) != 1:
        raise SystemExit(f"expected one class {name}")
    return matches[0]


def transfer_map(source: Path) -> dict[str, str]:
    tree = ast.parse((source / TOKENS).read_text(), filename=TOKENS, type_comments=True)
    owner = unique_class(tree, "Tokenizer")
    methods = [
        node for node in owner.body
        if isinstance(node, ast.FunctionDef) and node.name == "_init_core"
    ]
    if len(methods) != 1 or methods[0].decorator_list:
        raise SystemExit("Tokenizer._init_core is not canonical")
    calls = [
        node for node in ast.walk(methods[0])
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "TokenizerCore"
    ]
    if len(calls) != 1 or any(keyword.arg is None for keyword in calls[0].keywords):
        raise SystemExit("TokenizerCore handoff is not canonical")
    if (
        len(methods[0].body) != 1
        or not isinstance(methods[0].body[0], ast.Return)
        or methods[0].body[0].value is not calls[0]
    ):
        raise SystemExit("Tokenizer._init_core has behavior outside the handoff")
    result = {}
    for keyword in calls[0].keywords:
        value = keyword.value
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "bool"
            and len(value.args) == 1
            and not value.keywords
        ):
            value = value.args[0]
        if (
            isinstance(value, ast.Attribute)
            and isinstance(value.value, ast.Name)
            and value.value.id == "self"
            and keyword.arg
        ):
            if value.attr in result:
                raise SystemExit(f"duplicate Tokenizer setting handoff {value.attr}")
            result[value.attr] = keyword.arg
    for setting in result:
        mentions = [
            node
            for node in ast.walk(methods[0])
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "self"
            and node.attr == setting
        ]
        if len(mentions) != 1:
            raise SystemExit(f"Tokenizer setting {setting} has extra _init_core uses")
    return result


def core_uses(source: Path, fields: set[str]) -> dict[str, set[int]]:
    tree = ast.parse((source / CORE).read_text(), filename=CORE, type_comments=True)
    core = unique_class(tree, "TokenizerCore")
    init = [
        node for node in core.body
        if isinstance(node, ast.FunctionDef) and node.name == "__init__"
    ]
    if len(init) != 1:
        raise SystemExit("TokenizerCore.__init__ is not unique")
    parents = {
        child: parent for parent in ast.walk(core) for child in ast.iter_child_nodes(parent)
    }
    opaque_self_attributes = {
        "__class__",
        "__dict__",
        "__getattr__",
        "__getattribute__",
        "__getstate__",
        "__reduce__",
        "__reduce_ex__",
        "__slots__",
        "copy",
        "items",
        "values",
    }
    for node in ast.walk(core):
        if not (
            isinstance(node, ast.Name)
            and node.id == "self"
            and isinstance(node.ctx, ast.Load)
        ):
            continue
        parent = parents.get(node)
        if (
            not isinstance(parent, ast.Attribute)
            or parent.value is not node
            or parent.attr in opaque_self_attributes
        ):
            # Passing/aliasing the whole object (including vars, repr, pickle,
            # inspect, native calls, and object.__getattribute__) defeats a
            # field-by-field line-coverage proof.
            return {}
    result = {}
    for field in sorted(fields):
        stores = []
        uses = set()
        invalid = False
        for node in ast.walk(core):
            if isinstance(node, ast.Attribute) and node.attr == field:
                if not (isinstance(node.value, ast.Name) and node.value.id == "self"):
                    invalid = True
                    break
                if isinstance(node.ctx, ast.Load):
                    uses.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
                elif isinstance(node.ctx, ast.Store):
                    stores.append(node)
                else:
                    invalid = True
                    break
            if isinstance(node, ast.Constant) and node.value == field:
                # The one string occurrence is the exact __slots__ entry.
                cursor = node
                while cursor in parents and not isinstance(cursor, ast.Assign):
                    cursor = parents[cursor]
                if not (
                    isinstance(cursor, ast.Assign)
                    and len(cursor.targets) == 1
                    and isinstance(cursor.targets[0], ast.Name)
                    and cursor.targets[0].id == "__slots__"
                ):
                    invalid = True
                    break
        if invalid or len(stores) != 1:
            continue
        store = stores[0]
        assignment = next(
            (node for node in ast.walk(init[0]) if isinstance(node, ast.Assign) and store in node.targets),
            None,
        )
        if not (
            isinstance(assignment, ast.Assign)
            and len(assignment.targets) == 1
            and assignment.targets[0] is store
            and isinstance(assignment.value, ast.Name)
            and assignment.value.id == field
        ):
            continue
        parameter_loads = [
            node
            for node in ast.walk(init[0])
            if isinstance(node, ast.Name)
            and node.id == field
            and isinstance(node.ctx, ast.Load)
        ]
        if parameter_loads != [assignment.value]:
            continue
        result[field] = uses
    return result


def audit_setting_mentions(source: Path, settings: set[str]) -> set[str]:
    """Return settings whose only runtime load is the exact _init_core handoff."""
    eligible = set(settings)
    compiled = defaultdict(list)
    for root_name in ("sqlglot", "tests"):
        for path in sorted((source / root_name).rglob("*.py")):
            relative = path.relative_to(source).as_posix()
            text = path.read_text()
            tree = ast.parse(text, filename=relative, type_comments=True)
            parents = {
                child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)
            }
            code = compile(text, relative, "exec", dont_inherit=True, optimize=0)

            def strings(value: types.CodeType):
                for constant in value.co_consts:
                    if type(constant) is str:
                        yield constant, value.co_qualname
                    elif isinstance(constant, types.CodeType):
                        yield from strings(constant)

            for value, qualname in strings(code):
                if value in settings:
                    compiled[value].append((relative, qualname))
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr in settings:
                    ok = False
                    if relative == TOKENS and isinstance(node.ctx, ast.Load):
                        cursor = node
                        fn = None
                        while cursor in parents:
                            cursor = parents[cursor]
                            if isinstance(cursor, ast.FunctionDef):
                                fn = cursor
                                break
                        ok = (
                            fn is not None
                            and fn.name == "_init_core"
                            and isinstance(node.value, ast.Name)
                            and node.value.id == "self"
                        )
                    if not ok:
                        eligible.discard(node.attr)
                elif isinstance(node, ast.Name) and node.id in settings and isinstance(node.ctx, ast.Load):
                    eligible.discard(node.id)
                elif isinstance(node, ast.Constant) and node.value in settings:
                    eligible.discard(node.value)

    # CPython stores annotated class-member names in the protocol class code.
    # Any other compiled-string occurrence could feed opaque reflection.
    for setting in tuple(eligible):
        if compiled[setting] != [(TOKENS, "_TokenizerBase")]:
            eligible.discard(setting)
    return eligible


def externally_unobserved_fields(source: Path, fields: set[str]) -> set[str]:
    """Fields with no exact-name observer outside TokenizerCore itself."""
    eligible = set(fields)
    compiled = defaultdict(list)
    for root_name in ("sqlglot", "tests"):
        for path in sorted((source / root_name).rglob("*.py")):
            relative = path.relative_to(source).as_posix()
            if relative == CORE:
                continue
            text = path.read_text()
            tree = ast.parse(text, filename=relative, type_comments=True)
            code = compile(text, relative, "exec", dont_inherit=True, optimize=0)

            def strings(value: types.CodeType):
                for constant in value.co_consts:
                    if type(constant) is str:
                        yield constant, value.co_qualname
                    elif isinstance(constant, types.CodeType):
                        yield from strings(constant)

            for value, qualname in strings(code):
                if value in fields:
                    compiled[value].append((relative, qualname))
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr in eligible:
                    eligible.discard(node.attr)
                elif isinstance(node, ast.Constant) and node.value in eligible:
                    eligible.discard(node.value)
    # Keyword names are constants in the one exact constructor call. The
    # transfer-map shape proof establishes that method contains nothing else.
    # CPython emits small KW_NAMES groups as a tuple (not individual strings),
    # so zero exact string constants is also the canonical representation.
    for field in tuple(eligible):
        if compiled[field] not in ([], [(TOKENS, "Tokenizer._init_core")]):
            eligible.discard(field)
    return eligible


def closed_core_lifecycle(source: Path) -> bool:
    """Prove TokenizerCore instances remain behind the narrow Tokenizer facade."""
    init_definitions = []
    init_attributes = []
    for root_name in ("sqlglot", "tests"):
        for path in sorted((source / root_name).rglob("*.py")):
            relative = path.relative_to(source).as_posix()
            text = path.read_text()
            tree = ast.parse(text, filename=relative, type_comments=True)
            if relative != TOKENS and any(
                isinstance(node, ast.Attribute) and node.attr == "_core"
                for node in ast.walk(tree)
            ):
                return False
            if relative != TOKENS and any(
                isinstance(node, ast.Name)
                and node.id == "TokenizerCore"
                and isinstance(node.ctx, ast.Load)
                for node in ast.walk(tree)
            ):
                return False
            init_definitions.extend(
                (relative, node)
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == "_init_core"
            )
            init_attributes.extend(
                (relative, node)
                for node in ast.walk(tree)
                if isinstance(node, ast.Attribute) and node.attr == "_init_core"
            )
            if any(
                isinstance(node, ast.Name)
                and node.id == "_init_core"
                and isinstance(node.ctx, ast.Load)
                for node in ast.walk(tree)
            ):
                return False
            code = compile(text, relative, "exec", dont_inherit=True, optimize=0)

            def strings(value: types.CodeType):
                for constant in value.co_consts:
                    if type(constant) is str:
                        yield constant
                    elif isinstance(constant, types.CodeType):
                        yield from strings(constant)

            # Catches computed getattr/setattr and monkeypatch names because
            # CPython folds adjacent and constant-concatenated strings.
            if "_init_core" in strings(code):
                return False
    tree = ast.parse((source / TOKENS).read_text(), filename=TOKENS, type_comments=True)
    tokenizer = unique_class(tree, "Tokenizer")
    parents = {
        child: parent for parent in ast.walk(tokenizer) for child in ast.iter_child_nodes(parent)
    }
    stores = []
    loads = []
    for node in ast.walk(tokenizer):
        if not (
            isinstance(node, ast.Attribute)
            and node.attr == "_core"
            and isinstance(node.value, ast.Name)
            and node.value.id == "self"
        ):
            continue
        if isinstance(node.ctx, ast.Store):
            stores.append(node)
        elif isinstance(node.ctx, ast.Load):
            loads.append(node)
        else:
            return False
    if len(stores) != 1 or len(loads) != 4:
        return False
    store_parent = parents.get(stores[0])
    if not (
        isinstance(store_parent, ast.Assign)
        and len(store_parent.targets) == 1
        and store_parent.targets[0] is stores[0]
        and isinstance(store_parent.value, ast.Call)
        and isinstance(store_parent.value.func, ast.Attribute)
        and isinstance(store_parent.value.func.value, ast.Name)
        and store_parent.value.func.value.id == "self"
        and store_parent.value.func.attr == "_init_core"
        and not store_parent.value.args
        and not store_parent.value.keywords
    ):
        return False
    observed = {}
    for node in loads:
        attribute = parents.get(node)
        if not (
            isinstance(attribute, ast.Attribute)
            and attribute.value is node
            and attribute.attr in {"tokenize", "sql", "size", "tokens"}
        ):
            return False
        cursor = attribute
        method = None
        while cursor in parents:
            cursor = parents[cursor]
            if isinstance(cursor, ast.FunctionDef):
                method = cursor.name
                break
        if method != attribute.attr or method in observed:
            return False
        observed[method] = attribute
    if set(observed) != {"tokenize", "sql", "size", "tokens"}:
        return False
    token_call = parents.get(observed["tokenize"])
    if not (
        isinstance(token_call, ast.Call)
        and token_call.func is observed["tokenize"]
        and len(token_call.args) == 1
        and isinstance(token_call.args[0], ast.Name)
        and token_call.args[0].id == "sql"
        and not token_call.keywords
    ):
        return False
    if any(not isinstance(parents.get(observed[name]), ast.Return) for name in ("sql", "size", "tokens")):
        return False
    canonical_definition = next(
        (
            node
            for node in tokenizer.body
            if isinstance(node, ast.FunctionDef) and node.name == "_init_core"
        ),
        None,
    )
    definition = init_definitions[0][1] if len(init_definitions) == 1 else None
    lookup = init_attributes[0][1] if len(init_attributes) == 1 else None
    # The sole factory definition and sole lookup are the canonical pair above.
    # Compare source locations because the repository-wide scan and the local
    # shape proof deliberately parse independent ASTs.
    return (
        len(init_definitions) == 1
        and init_definitions[0][0] == TOKENS
        and isinstance(canonical_definition, ast.FunctionDef)
        and isinstance(definition, ast.FunctionDef)
        and (definition.lineno, definition.end_lineno)
        == (canonical_definition.lineno, canonical_definition.end_lineno)
        and len(init_attributes) == 1
        and init_attributes[0][0] == TOKENS
        and isinstance(lookup, ast.Attribute)
        and (lookup.lineno, lookup.col_offset, lookup.end_lineno, lookup.end_col_offset)
        == (
            store_parent.value.func.lineno,
            store_parent.value.func.col_offset,
            store_parent.value.func.end_lineno,
            store_parent.value.func.end_col_offset,
        )
    )


def main() -> None:
    args = arguments()
    if implementation_digest() != IMPLEMENTATION_SHA256:
        raise SystemExit("builder implementation digest is not pinned")
    if len(args.manifest) < 2 or len(args.trace) < 2:
        raise SystemExit("normal and synchronous traces are required")
    source = args.source.resolve()
    revision = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    if revision != PINNED_SHA:
        raise SystemExit(f"source is {revision}, expected {PINNED_SHA}")
    if subprocess.check_output(
        ["git", "-C", str(source), "status", "--porcelain"], text=True
    ):
        raise SystemExit("source tree has tracked or untracked modifications")
    tests_payload = json.loads(args.tests.read_text())
    tests = tests_payload["tests"]
    test_ids = [test["id"] for test in tests]
    test_digest = hashlib.sha256("\0".join(test_ids).encode()).hexdigest()
    selector_model, selector_sha = read_gzip(args.selector_model)
    class_model, class_sha = read_gzip(args.class_model)
    if (
        selector_model.get("sha") != revision
        or class_model.get("sha") != revision
        or class_model.get("n") != len(test_ids)
        or class_model.get("t") != test_digest
    ):
        raise SystemExit("input model provenance mismatch")
    manifests = [json.loads(path.read_text()) for path in args.manifest]
    if not {"normal", "synchronous-worker"}.issubset(
        {manifest.get("mode") for manifest in manifests}
    ) or any(
        manifest.get("exitstatus") != 0
        or not set(test_ids).issubset(manifest.get("tests", ()))
        or not isinstance(manifest.get("child_logs"), int)
        or manifest["child_logs"] <= 0
        for manifest in manifests
    ):
        raise SystemExit("inadmissible class trace manifest")
    if {
        manifest["mode"]: hashlib.sha256(path.read_bytes()).hexdigest()
        for path, manifest in zip(args.manifest, manifests)
    } != MANIFEST_SHA256:
        raise SystemExit("class manifest bytes do not match the audited traces")
    if len(args.trace) != len(manifests):
        raise SystemExit("trace/manifest count mismatch")
    documents = [json.loads(path.read_text()) for path in args.trace]
    if {
        manifest["mode"]: hashlib.sha256(path.read_bytes()).hexdigest()
        for path, manifest in zip(args.trace, manifests)
    } != TRACE_SHA256:
        raise SystemExit("class trace bytes do not match the audited traces")

    transfers = transfer_map(source)
    permitted = audit_setting_mentions(source, set(transfers))
    uses = core_uses(source, {transfers[name] for name in permitted})
    unobserved_fields = externally_unobserved_fields(source, set(uses))
    if not closed_core_lifecycle(source):
        raise SystemExit("TokenizerCore object lifecycle is not closed")
    entry = selector_model["f"][CORE]
    import_lines = {
        line for start, end in entry.get("i", ()) for line in range(start, end + 1)
    }
    line_sets = {line: set(selector_model["z"][set_id]) for line, set_id in entry["l"]}
    labels = source_labels(source)
    output = defaultdict(list)
    for path, entries in class_model["d"].items():
        module = path.removesuffix("/__init__.py").removesuffix(".py").replace("/", ".")
        for start, end, qualname, name, value_dump, _state, _readers in entries:
            field = transfers.get(name)
            if (
                name not in permitted
                or field not in unobserved_fields
                or uses[field] & import_lines
            ):
                continue
            label = labels.get((module, qualname, name))
            observations = [document.get(label) for document in documents]
            if (
                label is None
                or any(
                    not isinstance(events, dict)
                    or set(events) != {"read"}
                    or not isinstance(events["read"], list)
                    or not events["read"]
                    or events["read"] != sorted(set(events["read"]))
                    or any(
                        type(owner) is not str
                        or (owner != "__NO_TEST__" and owner not in test_ids)
                        for owner in events["read"]
                    )
                    for events in observations
                )
            ):
                continue
            readers = sorted(set().union(*(line_sets.get(line, set()) for line in uses[field])))
            output[path].append(
                [start, end, qualname, name, value_dump, field, readers]
            )
    ordered = {
        path: sorted(entries, key=lambda item: (item[0], item[2], item[3]))
        for path, entries in sorted(output.items())
    }
    profile = hashlib.sha256(
        json.dumps(ordered, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    payload = {
        "b": IMPLEMENTATION_SHA256,
        "c": class_sha,
        "d": ordered,
        "m": MANIFEST_SHA256,
        "n": len(test_ids),
        "p": profile,
        "r": TRACE_SHA256,
        "s": selector_sha,
        "sha": revision,
        "t": test_digest,
        "v": 1,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    with args.output.open("wb") as raw_output:
        with gzip.GzipFile(filename="", fileobj=raw_output, mode="wb", compresslevel=9, mtime=0) as stream:
            stream.write(raw)
    print(
        f"wrote {sum(map(len, ordered.values()))} tokenizer setting flows: "
        f"settings={sorted({entry[3] for entries in ordered.values() for entry in entries})} "
        f"profile={profile}"
    )


if __name__ == "__main__":
    main()
