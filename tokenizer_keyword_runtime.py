"""Disconnected runtime gate for proven Tokenizer ``KEYWORDS`` value edits.

The collector and model builder live outside the submission runtime.  This
module consumes only their immutable, exact-hash output plus the already-pinned
semantic source archive.  It deliberately does not import ``selector`` and is
not wired into test selection yet.
"""

from __future__ import annotations

import ast
import gzip
import hashlib
import json
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


PINNED_SOURCE_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"
PINNED_TEST_COUNT = 1620
PINNED_TEST_DIGEST = "31a019981e19c3d1b18d929066da7e118fcf3d57696a360f7b9d31ce3a87bc89"
PINNED_SEMANTIC_SOURCES_SHA256 = "f453c6266c20edcc9ba7127ebedde0bdf45d44633279352c2daafe1fa123da5f"
PINNED_INVENTORY_SHA256 = "07d7909c5a70a3f07e316af0a552d50b515878a4f0aef8bb91219d2f2302b535"
PINNED_STATIC_SHA256 = "ecdd75f46a76164924b4168180ea352c6679ee8d88aebadfe397720aa063ff51"
PINNED_OPERATIONS_SHA256 = "9fc0f92f7726c53b37b4e7a77334a65e77af0502d53ee17989ebae349e2f4655"

MODEL_KEYS = {
    "builder_sha256",
    "d",
    "evidence",
    "inventory",
    "n",
    "operations",
    "safe_keys",
    "sha",
    "static",
    "status",
    "t",
    "v",
}
STATIC_KEYS = {
    "core_assignments",
    "hazards",
    "init_core",
    "pops",
    "reads",
    "reflection_calls",
    "reserved_hits",
    "token_type_bindings",
    "tokenizer_lineage",
}
EVIDENCE_KEYS = {
    "common",
    "event_maps_sha256",
    "evidence_index_sha256",
    "global_poison",
    "modes",
    "purpose",
    "python_environment",
    "python_environment_sha256",
}
MODE_KEYS = {
    "bundle_sha256",
    "child_starts",
    "child_tokens_sha256",
    "instrumented_tree_sha256",
    "manifest_sha256",
    "trace_sha256",
}
PYTHON_ENVIRONMENT_KEYS = {
    "base_prefix",
    "distributions",
    "entry_points",
    "executable",
    "implementation",
    "prefix",
    "pytest_environment",
    "runtime_environment",
    "toolchain",
    "version",
}

# These are the stable, independently audited collection pins.  Per-run trace,
# bundle, evidence-index and final model hashes remain bound by the caller's
# exact compressed-model SHA-256.
EXPECTED_COMMON = {
    "base_image": "python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90",
    "base_materialized_tree_sha256": "ecf5daaf891c20bbca197895fa43e3e10c00421fc783c9679a755a8ebb66a4e1",
    "builder_sha256": "7ed48b7e8f62bab76bb80e58bc35dff7f550294e7074c45b8d83d2e896d49e5d",
    "class_attribute_dependency_sha256": "5a37f6ae830a6bd7a9d3647f8b746264fd6ad274bfa5eb22005c07042d60d6be",
    "collector_sha256": "27a3a1590e764cd0a8cf23520286af35a2820812f4ce12f94eb9a4aba8bb9a27",
    "core_origin_verified": True,
    "core_sha256": "142463b972f35299140172de19eb72bf0c32742867eb251e06c5592413f8083c",
    "dependency_sha256": "14416f4ea2d132d012c1d1db4883fd2e6cc8d09e75962216c59465095daebfbd",
    "dockerfile_sha256": "90cd31d98e08c01e05c2bd3a551d28893c2149af943fa405ad5e4e2d25128758",
    "finalizer_sha256": "6503d0181d4057b10af99d1776d16f2dac420273d30c83bfaf5e8a6e06c971d0",
    "image_id": "sha256:736857c2a387ff1be1d4331e0cfa5d2a0a40b43eb98ce80119868ff280d2bdcb",
    "inventory_sha256": PINNED_INVENTORY_SHA256,
    "lifecycle_dependency_sha256": "584ce48f7fbdf4ff038bb45d81ec2a83ebd3cd9b6ddbf5d72dc48a49cb324f4f",
    "materialized_manifest_sha256": "ecf5daaf891c20bbca197895fa43e3e10c00421fc783c9679a755a8ebb66a4e1",
    "operations_sha256": PINNED_OPERATIONS_SHA256,
    "reflection_sha256": "8891bd314a2d4eab581c1cad979af7fab828cbda254f84dc57dbc73bfd16a200",
    "requirements_sha256": "3c752cfa352064043d55ea97d874ed2b11c5860f8f089783c832d6a4e0d63e60",
    "review_public_key_sha256": "f0f956bbebd967a450e025fb1c18a52562ac123554024770d84e28a2d125b4c4",
    "selector_model_sha256": "d61c504e9a4a1006217e6702e1c6f05c04846b3dd5a09ec5572523fd8b2cb382",
    "signature_module_sha256": "27c83b825ba699b89b921351693ae5020ed18b253169b84defb294e600cce8da",
    "signer_sha256": "b9e6fa862f50bbb5cab393f7129920a98c686110f56acba188a151a1f304a80a",
    "source_archive_sha256": "578d90b1a8e1130094aaf0746117a596e6d94b63c9e4d38aa74f0fea61a37395",
    "source_sha": PINNED_SOURCE_SHA,
    "source_tree_sha256": "d004c83c8491d811813c3852237b15eef6546331fecaa684f1cb35a3b14e3ab1",
    "static_sha256": PINNED_STATIC_SHA256,
    "support_sha256": "da23ddbf17e1919b982b68d45b248375636c64d7eb0e1e70222e14de5e990851",
    "test_digest": PINNED_TEST_DIGEST,
    "tests_sha256": "21257a93c58f4b0646c5122586d2141b4b340ad85b2f0bb251af3746de3f0dc2",
    "tracked_entries": 365,
    "tracker_version": 2,
}

HEX64 = re.compile(r"[0-9a-f]{64}\Z")
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
COMMENT_DIRECTIVE = re.compile(r"(?i)(coding\s*[:=]|type:|noqa|pragma|fmt:|pyright|mypy)")
MAX_MODEL_BYTES = 8 * 1024 * 1024
MAX_SOURCES_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class KeywordEntry:
    path: str
    owner: str
    start: int
    end: int
    index: int
    key: str
    token: str
    token_dump: str
    state: str


@dataclass(frozen=True, slots=True)
class TokenizerKeywordContext:
    model_sha256: str
    sources_sha256: str
    entries_by_path: Mapping[str, tuple[KeywordEntry, ...]]
    bindings_by_path: Mapping[str, str]
    sources: Mapping[str, str]
    token_types: frozenset[str]


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _is_hex64(value: object) -> bool:
    return type(value) is str and HEX64.fullmatch(value) is not None


def _decompress(raw: bytes, limit: int) -> bytes:
    value = gzip.decompress(raw)
    if len(value) > limit:
        raise ValueError("decompressed artifact is too large")
    return value


def _valid_environment(value: object, expected_digest: object) -> bool:
    if (
        not isinstance(value, dict)
        or set(value) != PYTHON_ENVIRONMENT_KEYS
        or not _is_hex64(expected_digest)
        or _digest(value) != expected_digest
        or value.get("implementation") != "CPython"
        or type(value.get("version")) is not str
        or not value["version"].startswith("3.13.")
        or any(
            type(value.get(field)) is not str or not value[field].startswith("/")
            for field in ("executable", "prefix", "base_prefix")
        )
    ):
        return False
    distributions = value.get("distributions")
    entry_points = value.get("entry_points")
    if (
        not isinstance(distributions, list)
        or distributions != sorted(distributions)
        or len({tuple(item) for item in distributions if isinstance(item, list)})
        != len(distributions)
        or any(
            not isinstance(item, list)
            or len(item) != 2
            or any(type(part) is not str or not part for part in item)
            for item in distributions
        )
        or not isinstance(entry_points, list)
        or entry_points != sorted(entry_points)
        or len({tuple(item) for item in entry_points if isinstance(item, list)})
        != len(entry_points)
        or any(
            not isinstance(item, list)
            or len(item) != 4
            or any(type(part) is not str for part in item)
            for item in entry_points
        )
    ):
        return False
    if value.get("pytest_environment") != {
        "PYTEST_ADDOPTS": None,
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "PYTEST_PLUGINS": None,
    } or value.get("runtime_environment") != {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONPATH": "/work/tools",
        "PYTHONSAFEPATH": "1",
        "PYTHONWARNINGS": None,
        "TZ": "UTC",
    }:
        return False
    tools = value.get("toolchain")
    return (
        isinstance(tools, dict)
        and set(tools) == {"git", "openssl"}
        and all(
            isinstance(item, dict)
            and set(item) == {"package", "path", "sha256", "version"}
            and type(item["package"]) is str
            and type(item["path"]) is str
            and item["path"].startswith("/")
            and _is_hex64(item["sha256"])
            and type(item["version"]) is str
            for item in tools.values()
        )
    )


def _model_entries(model: dict) -> tuple[list[KeywordEntry], list[list[object]]] | None:
    records = model.get("d")
    if not isinstance(records, list) or len(records) != 716:
        return None
    entries: list[KeywordEntry] = []
    inventory: list[list[object]] = []
    states: dict[str, str] = {}
    for record in records:
        if not isinstance(record, list) or len(record) != 9:
            return None
        path, owner, start, end, index, key, token, token_dump, state = record
        expected_dump = (
            "Attribute(value=Name(id='TokenType', ctx=Load()), "
            f"attr='{token}', ctx=Load())"
        )
        if (
            type(path) is not str
            or not path.startswith("sqlglot/")
            or not path.endswith(".py")
            or path.startswith("/")
            or ".." in path.split("/")
            or type(owner) is not str
            or not owner
            or any(IDENTIFIER.fullmatch(part) is None for part in owner.split("."))
            or type(start) is not int
            or type(end) is not int
            or start <= 0
            or end < start
            or type(index) is not int
            or index < 0
            or type(key) is not str
            or not key
            or type(token) is not str
            or IDENTIFIER.fullmatch(token) is None
            or token_dump != expected_dump
            or state not in {"observed", "poison", "safe-zero"}
            or (key in states and states[key] != state)
        ):
            return None
        states[key] = state
        inventory_record = record[:8]
        inventory.append(inventory_record)
        entries.append(KeywordEntry(*record))
    if (
        inventory != sorted(inventory)
        or len({entry.key for entry in entries}) != 616
        or len({tuple(item) for item in inventory}) != 716
        or _digest(inventory) != PINNED_INVENTORY_SHA256
        or model.get("inventory") != PINNED_INVENTORY_SHA256
    ):
        return None
    safe_keys = model.get("safe_keys")
    expected_safe = sorted(key for key, state in states.items() if state == "safe-zero")
    if safe_keys != expected_safe or not isinstance(safe_keys, list):
        return None
    return entries, inventory


def _valid_model(model: object) -> tuple[list[KeywordEntry], dict] | None:
    if (
        not isinstance(model, dict)
        or set(model) != MODEL_KEYS
        or type(model.get("v")) is not int
        or model.get("v") != 0
        or model.get("status") != "READY-FOR-AUDIT/NO-SHIP"
        or model.get("sha") != PINNED_SOURCE_SHA
        or type(model.get("n")) is not int
        or model.get("n") != PINNED_TEST_COUNT
        or model.get("t") != PINNED_TEST_DIGEST
        or model.get("builder_sha256") != EXPECTED_COMMON["builder_sha256"]
    ):
        return None
    entry_result = _model_entries(model)
    if entry_result is None:
        return None
    entries, _inventory = entry_result
    static = model.get("static")
    operations = model.get("operations")
    if (
        not isinstance(static, dict)
        or set(static) != {"document", "sha256"}
        or static.get("sha256") != PINNED_STATIC_SHA256
        or not isinstance(static.get("document"), dict)
        or set(static["document"]) != STATIC_KEYS
        or _digest(static["document"]) != PINNED_STATIC_SHA256
        or static["document"].get("hazards") != []
        or static["document"].get("reserved_hits") != []
        or not isinstance(operations, dict)
        or set(operations) != {"document", "sha256"}
        or operations.get("sha256") != PINNED_OPERATIONS_SHA256
        or _digest(operations.get("document")) != PINNED_OPERATIONS_SHA256
    ):
        return None
    evidence = model.get("evidence")
    if (
        not isinstance(evidence, dict)
        or set(evidence) != EVIDENCE_KEYS
        or evidence.get("purpose") != "full"
        or not _is_hex64(evidence.get("event_maps_sha256"))
        or not _is_hex64(evidence.get("evidence_index_sha256"))
        or type(evidence.get("global_poison")) is not bool
        or evidence.get("common") != EXPECTED_COMMON
        or model["builder_sha256"] != evidence["common"]["builder_sha256"]
    ):
        return None
    if evidence["global_poison"] and any(entry.state != "poison" for entry in entries):
        return None
    modes = evidence.get("modes")
    if not isinstance(modes, dict) or set(modes) != {"normal", "synchronous-worker"}:
        return None
    for value in modes.values():
        if (
            not isinstance(value, dict)
            or set(value) != MODE_KEYS
            or type(value.get("child_starts")) is not int
            or value["child_starts"] <= 0
            or any(not _is_hex64(value.get(field)) for field in MODE_KEYS - {"child_starts"})
        ):
            return None
    if not _valid_environment(
        evidence.get("python_environment"), evidence.get("python_environment_sha256")
    ):
        return None
    return entries, static["document"]


def _source_inventory(sources: Mapping[str, str]) -> tuple[list[list[object]], dict[str, ast.Module]]:
    records: list[list[object]] = []
    trees: dict[str, ast.Module] = {}
    for path in sorted(sources):
        if not path.startswith("sqlglot/") or not path.endswith(".py"):
            continue
        source = sources[path]
        tree = ast.parse(source, filename=path, type_comments=True)
        trees[path] = tree

        def visit(body: list[ast.stmt], owners: tuple[str, ...] = ()) -> None:
            for statement in body:
                if not isinstance(statement, ast.ClassDef):
                    continue
                owner = (*owners, statement.name)
                for item in statement.body:
                    targets = item.targets if isinstance(item, ast.Assign) else (
                        [item.target] if isinstance(item, ast.AnnAssign) else []
                    )
                    value = getattr(item, "value", None)
                    if (
                        len(targets) != 1
                        or not isinstance(targets[0], ast.Name)
                        or targets[0].id != "KEYWORDS"
                        or not isinstance(value, ast.Dict)
                    ):
                        continue
                    seen: set[str] = set()
                    for index, (key, token) in enumerate(zip(value.keys, value.values)):
                        if (
                            not isinstance(key, ast.Constant)
                            or type(key.value) is not str
                            or not isinstance(token, ast.Attribute)
                            or not isinstance(token.value, ast.Name)
                            or token.value.id != "TokenType"
                        ):
                            continue
                        if key.value in seen:
                            raise ValueError("duplicate explicit keyword")
                        seen.add(key.value)
                        records.append([
                            path,
                            ".".join(owner),
                            item.lineno,
                            item.end_lineno or item.lineno,
                            index,
                            key.value,
                            token.attr,
                            ast.dump(token, include_attributes=False),
                        ])
                visit(statement.body, owner)

        visit(tree.body)
    return sorted(records), trees


def _token_type_members(tree: ast.Module) -> frozenset[str]:
    classes = [
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "TokenType"
    ]
    if len(classes) != 1:
        raise ValueError("ambiguous TokenType")
    members: set[str] = set()
    for statement in classes[0].body:
        if (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
            and IDENTIFIER.fullmatch(statement.targets[0].id)
            and isinstance(statement.value, ast.Call)
            and isinstance(statement.value.func, ast.Name)
            and statement.value.func.id == "auto"
            and not statement.value.args
            and not statement.value.keywords
        ):
            members.add(statement.targets[0].id)
    if len(members) < 100:
        raise ValueError("incomplete TokenType census")
    return frozenset(members)


def _certified_bindings(entries: list[KeywordEntry], static: dict) -> dict[str, str]:
    inventory_paths = {entry.path for entry in entries}
    bindings = static.get("token_type_bindings")
    if not isinstance(bindings, list):
        raise ValueError("missing binding census")
    by_path: dict[str, list[list[object]]] = {}
    for binding in bindings:
        if (
            not isinstance(binding, list)
            or len(binding) != 4
            or any(type(part) is not str for part in binding[:3])
            or binding[2] != "TokenType"
            or binding[3] is not None
        ):
            raise ValueError("malformed binding")
        by_path.setdefault(binding[0], []).append(binding)
    result = {}
    for path in inventory_paths:
        records = by_path.get(path)
        if not records or len(records) != 1:
            raise ValueError("unbound inventory path")
        result[path] = records[0][1]
    if set(by_path) != inventory_paths:
        raise ValueError("binding census differs from inventory paths")
    return result


def _valid_runtime_binding(tree: ast.Module, module: str) -> bool:
    imports = [
        alias
        for statement in tree.body
        if isinstance(statement, ast.ImportFrom) and statement.module == module
        for alias in statement.names
        if alias.name == "TokenType" and alias.asname is None
    ]
    return len(imports) == 1


def load_context(
    model_raw: bytes,
    expected_model_sha256: str,
    sources_raw: bytes,
    expected_sources_sha256: str,
) -> TokenizerKeywordContext | None:
    """Load and freeze an exact full evidence model and semantic source archive."""
    try:
        if (
            not _is_hex64(expected_model_sha256)
            or not _is_hex64(expected_sources_sha256)
            or expected_sources_sha256 != PINNED_SEMANTIC_SOURCES_SHA256
            or len(model_raw) > MAX_MODEL_BYTES
            or hashlib.sha256(model_raw).hexdigest() != expected_model_sha256
            or hashlib.sha256(sources_raw).hexdigest() != expected_sources_sha256
        ):
            return None
        model = json.loads(_decompress(model_raw, MAX_MODEL_BYTES))
        validated = _valid_model(model)
        if validated is None:
            return None
        entries, static = validated
        sources_document = json.loads(_decompress(sources_raw, MAX_SOURCES_BYTES))
        if (
            not isinstance(sources_document, dict)
            or not sources_document
            or any(
                type(path) is not str
                or type(source) is not str
                or path.startswith("/")
                or ".." in path.split("/")
                for path, source in sources_document.items()
            )
        ):
            return None
        sources = dict(sources_document)
        core_source = sources.get("sqlglot/tokenizer_core.py")
        if core_source is None:
            return None
        core = ast.parse(
            core_source, filename="sqlglot/tokenizer_core.py", type_comments=True
        )
        token_types = _token_type_members(core)
        if any(entry.token not in token_types for entry in entries):
            return None
        bindings = _certified_bindings(entries, static)
        grouped: dict[str, list[KeywordEntry]] = {}
        for entry in entries:
            grouped.setdefault(entry.path, []).append(entry)
        return TokenizerKeywordContext(
            model_sha256=expected_model_sha256,
            sources_sha256=expected_sources_sha256,
            entries_by_path=MappingProxyType(
                {path: tuple(values) for path, values in grouped.items()}
            ),
            bindings_by_path=MappingProxyType(bindings),
            sources=MappingProxyType(sources),
            token_types=token_types,
        )
    except (
        OSError,
        EOFError,
        UnicodeError,
        json.JSONDecodeError,
        SyntaxError,
        ValueError,
        TypeError,
        KeyError,
        OverflowError,
        MemoryError,
        RecursionError,
    ):
        return None


def _apply_single_hunk(change: Mapping[str, object], path: str, source: str) -> tuple[str, str, str] | None:
    if (
        change.get("old") != path
        or change.get("new") != path
        or change.get("diff_old") != path
        or change.get("diff_new") != path
        or change.get("new_file_mode") is not None
        or change.get("binary") is not False
        or change.get("non_lf") is not False
        or change.get("no_newline_marker") is not False
        or "\r" in source
        or not source.endswith("\n")
    ):
        return None
    hunks = change.get("hunks")
    if not isinstance(hunks, list) or len(hunks) != 1:
        return None
    hunk = hunks[0]
    if not isinstance(hunk, dict) or set(hunk) != {
        "old_start", "old_count", "new_start", "new_count", "lines"
    }:
        return None
    old_start = hunk.get("old_start")
    old_count = hunk.get("old_count")
    new_start = hunk.get("new_start")
    new_count = hunk.get("new_count")
    lines = hunk.get("lines")
    if (
        type(old_start) is not int
        or type(old_count) is not int
        or type(new_start) is not int
        or type(new_count) is not int
        or old_start <= 0
        or new_start != old_start
        or old_count <= 0
        or new_count <= 0
        or old_count != new_count
        or not isinstance(lines, list)
    ):
        return None
    removed = [text for tag, text in lines if tag == "-"] if all(
        isinstance(item, tuple) and len(item) == 2
        and item[0] in {" ", "+", "-"} and type(item[1]) is str
        for item in lines for tag, text in [item]
    ) else []
    added = [text for tag, text in lines if tag == "+"] if lines else []
    if (
        len(removed) != 1
        or len(added) != 1
        or change.get("removed") != removed
        or change.get("added") != added
        or change.get("payload") != [*removed, *added]
        or any(COMMENT_DIRECTIVE.search(text) for text in (*removed, *added))
    ):
        return None
    original = source.splitlines()
    cursor = old_start - 1
    if cursor > len(original):
        return None
    output = original[:cursor]
    consumed = emitted = 0
    removed_old_line = None
    added_old_line = None
    added_new_line = None
    for tag, text in lines:
        if tag in {" ", "-"}:
            if cursor >= len(original) or original[cursor] != text:
                return None
            if tag == "-":
                removed_old_line = cursor + 1
            cursor += 1
            consumed += 1
        if tag in {" ", "+"}:
            if tag == "+":
                added_old_line = old_start + consumed
                added_new_line = new_start + emitted
            output.append(text)
            emitted += 1
    if (
        consumed != old_count
        or emitted != new_count
        or removed_old_line is None
        or added_old_line is None
        or added_new_line is None
        or change.get("lines") != {removed_old_line}
        or change.get("added_at") != [(added_old_line, added[0])]
        or change.get("added_new_at") != [(added_new_line, added[0])]
    ):
        return None
    output.extend(original[cursor:])
    return "\n".join(output) + "\n", removed[0], added[0]


def _keyword_assignments(tree: ast.Module) -> dict[tuple[str, int, int], ast.Dict] | None:
    result: dict[tuple[str, int, int], ast.Dict] = {}

    def visit(body: list[ast.stmt], owners: tuple[str, ...] = ()) -> bool:
        for statement in body:
            if not isinstance(statement, ast.ClassDef):
                continue
            owner = (*owners, statement.name)
            for item in statement.body:
                targets = item.targets if isinstance(item, ast.Assign) else (
                    [item.target] if isinstance(item, ast.AnnAssign) else []
                )
                value = getattr(item, "value", None)
                if (
                    len(targets) == 1
                    and isinstance(targets[0], ast.Name)
                    and targets[0].id == "KEYWORDS"
                    and isinstance(value, ast.Dict)
                ):
                    key = (
                        ".".join(owner), item.lineno,
                        item.end_lineno or item.lineno,
                    )
                    if key in result:
                        return False
                    result[key] = value
            if not visit(statement.body, owner):
                return False
        return True

    return result if visit(tree.body) else None


def tokenizer_keyword_patch(
    changes: object, context: TokenizerKeywordContext
) -> set[int] | None:
    """Return an empty reader set only for one exact safe-zero value edit."""
    try:
        if not isinstance(changes, list) or len(changes) != 1:
            return None
        change = changes[0]
        if not isinstance(change, dict):
            return None
        path = change.get("old")
        if type(path) is not str:
            return None
        source = context.sources.get(path)
        entries = context.entries_by_path.get(path)
        if source is None or not entries:
            return None
        applied = _apply_single_hunk(change, path, source)
        if applied is None:
            return None
        changed_source, removed_line, added_line = applied
        original_tree = ast.parse(source, filename=path, type_comments=True)
        changed_tree = ast.parse(changed_source, filename=path, type_comments=True)
        runtime_inventory, _runtime_trees = _source_inventory({path: source})
        expected_inventory = [
            [
                entry.path, entry.owner, entry.start, entry.end, entry.index,
                entry.key, entry.token, entry.token_dump,
            ]
            for entry in entries
        ]
        if (
            runtime_inventory != expected_inventory
            or not _valid_runtime_binding(
                original_tree, context.bindings_by_path.get(path, "")
            )
        ):
            return None
        original_assignments = _keyword_assignments(original_tree)
        changed_assignments = _keyword_assignments(changed_tree)
        if original_assignments is None or changed_assignments is None:
            return None
        candidates: list[tuple[KeywordEntry, ast.AST, ast.AST]] = []
        for entry in entries:
            if entry.state != "safe-zero":
                continue
            assignment_key = (entry.owner, entry.start, entry.end)
            original = original_assignments.get(assignment_key)
            changed = changed_assignments.get(assignment_key)
            if (
                original is None
                or changed is None
                or entry.index >= len(original.keys)
                or entry.index >= len(changed.keys)
                or entry.index >= len(original.values)
                or entry.index >= len(changed.values)
            ):
                continue
            old_key = original.keys[entry.index]
            new_key = changed.keys[entry.index]
            old_value = original.values[entry.index]
            new_value = changed.values[entry.index]
            if (
                not isinstance(old_key, ast.Constant)
                or type(old_key.value) is not str
                or old_key.value != entry.key
                or not isinstance(new_key, ast.Constant)
                or type(new_key.value) is not str
                or new_key.value != entry.key
                or not isinstance(old_value, ast.Attribute)
                or not isinstance(old_value.value, ast.Name)
                or old_value.value.id != "TokenType"
                or old_value.attr != entry.token
                or ast.dump(old_value, include_attributes=False) != entry.token_dump
                or not isinstance(new_value, ast.Attribute)
                or not isinstance(new_value.value, ast.Name)
                or new_value.value.id != "TokenType"
                or new_value.attr == entry.token
                or new_value.attr not in context.token_types
            ):
                continue
            old_text = f"TokenType.{entry.token}"
            new_text = f"TokenType.{new_value.attr}"
            if (
                removed_line.count(old_text) != 1
                or added_line.count(new_text) != 1
                or removed_line.replace(old_text, "__TOKEN__", 1)
                != added_line.replace(new_text, "__TOKEN__", 1)
            ):
                continue
            old_segment = ast.get_source_segment(source, old_value)
            new_segment = ast.get_source_segment(changed_source, new_value)
            if old_segment != old_text or new_segment != new_text:
                continue
            candidates.append((entry, old_value, new_value))
        if len(candidates) != 1:
            return None
        _entry, old_value, new_value = candidates[0]
        sentinel = ast.Name(id="__blast_radius_token_type__", ctx=ast.Load())
        old_parent = None
        new_parent = None
        # Values are held directly by the assignment dictionaries found above.
        for dictionary in original_assignments.values():
            for index, value in enumerate(dictionary.values):
                if value is old_value:
                    old_parent = (dictionary, index)
        for dictionary in changed_assignments.values():
            for index, value in enumerate(dictionary.values):
                if value is new_value:
                    new_parent = (dictionary, index)
        if old_parent is None or new_parent is None:
            return None
        old_parent[0].values[old_parent[1]] = sentinel
        new_parent[0].values[new_parent[1]] = sentinel
        if ast.dump(original_tree, include_attributes=False) != ast.dump(
            changed_tree, include_attributes=False
        ):
            return None
        return set()
    except (
        SyntaxError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        OverflowError,
        MemoryError,
        RecursionError,
    ):
        return None
