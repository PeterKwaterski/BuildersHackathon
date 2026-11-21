"""Fail-closed runtime gate for proven single-word ``KEYWORDS`` key renames."""

from __future__ import annotations

import ast
import gzip
import hashlib
import json
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from tokenizer_keyword_runtime import (
    PINNED_INVENTORY_SHA256,
    PINNED_SEMANTIC_SOURCES_SHA256,
    PINNED_SOURCE_SHA,
    PINNED_STATIC_SHA256,
    PINNED_TEST_COUNT,
    PINNED_TEST_DIGEST,
    KeywordEntry,
    _apply_single_hunk,
    _digest,
    _is_hex64,
    _keyword_assignments,
    _source_inventory,
    _valid_runtime_binding,
)


MODEL_SHA256 = "5c3548e4d558d2dfe9f93fa0d8443b320097bfaa0329467c4c7d4224711626a6"
BUILDER_SHA256 = "e2898f26980a78b7cb58d8021831b17c3d2344039605d593c537650f017048d9"
BASE_MODEL_SHA256 = "28a5241f3d8006f075f283ac8e59f46793be482457bece67de97a4ecdd3db230"
EVENT_MAPS_SHA256 = "83adb952e7190bc46363428e5501378d4e06c924a13648fd8b2e40f536e42c32"
MODE_EVENT_SHA256 = "bfe44c58880c57ec7413d02d045a48f3871f83afff615ba365da60843fe032c6"
EVIDENCE_INDEX_SHA256 = "34bc68bda69c402cefc51f835f724d0a7f03a47da37763c6448ee6430d14884d"
SIGNATURE_SHA256 = "cc7de24f63be775681c0c1239f8f8b2ce2d7ad4d9262e660da4299f05b17b05e"
POPS_SHA256 = "f5e9364a2aa0df9439df4d82bde2dede8022b74c376328238b5900f521a1cdaa"
READS_SHA256 = "4c507f08a5f09abd9ae0f6e7524f6d19c4fe929c41aca038b0f5c6e4ee896b48"
KEY_IDENTIFIER = re.compile(r"[A-Z_][A-Z0-9_]*\Z")
MAX_MODEL_BYTES = 8 * 1024 * 1024
MAX_SOURCES_BYTES = 64 * 1024 * 1024

EXPECTED_TRACES = {
    "normal": {
        "bundle_sha256": "ed84487dfbd26d4ef853ce3ab2060ce251bd2554cd60d006c1261d35371ff700",
        "child_starts": 22,
        "child_tokens_sha256": "4021e57fd67e8d0035dfb38082c83877714498f1f1ad708af05de87170404293",
        "manifest_sha256": "44347a9d3500ebd4a4537ce7d9b132da1d3b9c8e1f7cbbe9062d961add932493",
        "trace_sha256": "0dbe327359f086d57d317db2dd36d575182c391411fe91ceb2e77f329f48aedb",
    },
    "synchronous-worker": {
        "bundle_sha256": "340939ee026743e6eb1d466cbcc6de23949d6878bea293ee62b0eb81639558c5",
        "child_starts": 1,
        "child_tokens_sha256": "5ea5c1b049534bcae857322355f5089d43322f184f7d465a0f64d0c693f7aec8",
        "manifest_sha256": "7bbffdeafb0c6eab89096453922781d2de33b5bca182a1ce311cb1801102931e",
        "trace_sha256": "6b59b928632538e6ef7bd37ff8f1fda46fad62a22980cd1a2502e969f0f7ceb2",
    },
}


@dataclass(frozen=True, slots=True)
class TokenizerKeyRenameContext:
    entries_by_path: Mapping[str, tuple[KeywordEntry, ...]]
    events: Mapping[str, frozenset[int]]
    poison_keys: frozenset[str]
    pop_keys: frozenset[str]
    bindings_by_path: Mapping[str, str]
    sources: Mapping[str, str]


def _entries(records: object) -> list[KeywordEntry] | None:
    if not isinstance(records, list) or len(records) != 716:
        return None
    entries = []
    inventory = []
    for record in records:
        if not isinstance(record, list) or len(record) != 9:
            return None
        path, owner, start, end, index, key, token, token_dump, state = record
        if (
            type(path) is not str
            or not path.startswith("sqlglot/")
            or not path.endswith(".py")
            or type(owner) is not str
            or type(start) is not int
            or type(end) is not int
            or type(index) is not int
            or type(key) is not str
            or type(token) is not str
            or type(token_dump) is not str
            or state not in {"observed", "poison", "safe-zero"}
        ):
            return None
        entries.append(KeywordEntry(*record))
        inventory.append(record[:8])
    if (
        inventory != sorted(inventory)
        or len({tuple(row) for row in inventory}) != 716
        or len({entry.key for entry in entries}) != 616
        or _digest(inventory) != PINNED_INVENTORY_SHA256
    ):
        return None
    return entries


def _model(model: object) -> tuple[list[KeywordEntry], dict[str, frozenset[int]], frozenset[str], frozenset[str]] | None:
    if (
        not isinstance(model, dict)
        or set(model) != {
            "audit", "builder_sha256", "events", "evidence", "global_poison",
            "inventory", "n", "poison_keys", "sha", "status", "t", "v",
        }
        or model.get("v") != 1
        or model.get("status") != "READY-FOR-SHIP"
        or model.get("sha") != PINNED_SOURCE_SHA
        or model.get("n") != PINNED_TEST_COUNT
        or model.get("t") != PINNED_TEST_DIGEST
        or model.get("builder_sha256") != BUILDER_SHA256
        or model.get("global_poison") is not False
    ):
        return None
    entries = _entries(model.get("inventory"))
    if entries is None:
        return None
    events_raw = model.get("events")
    poison_raw = model.get("poison_keys")
    if (
        not isinstance(events_raw, dict)
        or len(events_raw) != 8275
        or not isinstance(poison_raw, list)
        or poison_raw != sorted(set(poison_raw))
        or any(type(key) is not str for key in poison_raw)
        or not {entry.key for entry in entries if entry.state == "poison"} <= set(poison_raw)
    ):
        return None
    events: dict[str, frozenset[int]] = {}
    for key, owners in events_raw.items():
        if (
            type(key) is not str
            or not isinstance(owners, list)
            or owners != sorted(set(owners))
            or any(type(owner) is not int or not 0 <= owner < PINNED_TEST_COUNT for owner in owners)
        ):
            return None
        events[key] = frozenset(owners)
    audit = model.get("audit")
    if (
        not isinstance(audit, dict)
        or set(audit) != {
            "base_static_sha256", "pop_keys", "pops_sha256", "reads_sha256",
            "relevant_source_sha256", "theorem", "whole_map_observers",
        }
        or audit.get("base_static_sha256") != PINNED_STATIC_SHA256
        or audit.get("pops_sha256") != POPS_SHA256
        or audit.get("reads_sha256") != READS_SHA256
        or audit.get("theorem") != "single-word-old-prefix-terminal-closure-v3"
        or audit.get("whole_map_observers") != []
        or not isinstance(audit.get("pop_keys"), list)
        or audit["pop_keys"] != sorted(set(audit["pop_keys"]))
        or any(type(key) is not str for key in audit["pop_keys"])
    ):
        return None
    evidence = model.get("evidence")
    if (
        not isinstance(evidence, dict)
        or set(evidence) != {
            "base_model_sha256", "event_maps_sha256", "index_sha256",
            "mode_event_sha256", "pins", "signature_sha256", "sources_sha256", "traces",
        }
        or evidence.get("base_model_sha256") != BASE_MODEL_SHA256
        or evidence.get("event_maps_sha256") != EVENT_MAPS_SHA256
        or evidence.get("mode_event_sha256") != MODE_EVENT_SHA256
        or evidence.get("index_sha256") != EVIDENCE_INDEX_SHA256
        or evidence.get("signature_sha256") != SIGNATURE_SHA256
        or evidence.get("sources_sha256") != PINNED_SEMANTIC_SOURCES_SHA256
        or evidence.get("traces") != EXPECTED_TRACES
        or not isinstance(evidence.get("pins"), dict)
        or evidence["pins"].get("source_sha") != PINNED_SOURCE_SHA
        or evidence["pins"].get("test_digest") != PINNED_TEST_DIGEST
        or evidence["pins"].get("inventory_sha256") != PINNED_INVENTORY_SHA256
        or evidence["pins"].get("static_sha256") != PINNED_STATIC_SHA256
    ):
        return None
    relevant = audit.get("relevant_source_sha256")
    if not isinstance(relevant, dict) or set(relevant) != {
        "sqlglot/dialects/dialect.py", "sqlglot/tokenizer_core.py", "sqlglot/tokens.py"
    } or any(not _is_hex64(value) for value in relevant.values()):
        return None
    return entries, events, frozenset(poison_raw), frozenset(audit["pop_keys"])


def load_key_rename_context(
    model_raw: bytes,
    expected_model_sha256: str,
    sources_raw: bytes,
    expected_sources_sha256: str,
) -> TokenizerKeyRenameContext | None:
    try:
        if (
            expected_model_sha256 != MODEL_SHA256
            or expected_sources_sha256 != PINNED_SEMANTIC_SOURCES_SHA256
            or hashlib.sha256(model_raw).hexdigest() != expected_model_sha256
            or hashlib.sha256(sources_raw).hexdigest() != expected_sources_sha256
            or len(model_raw) > MAX_MODEL_BYTES
            or len(sources_raw) > MAX_SOURCES_BYTES
        ):
            return None
        model = json.loads(gzip.decompress(model_raw))
        validated = _model(model)
        if validated is None:
            return None
        entries, events, poison, pop_keys = validated
        sources = json.loads(gzip.decompress(sources_raw))
        if not isinstance(sources, dict) or any(
            type(path) is not str or type(source) is not str
            for path, source in sources.items()
        ):
            return None
        runtime_inventory, trees = _source_inventory(sources)
        if runtime_inventory != [record[:8] for record in model["inventory"]]:
            return None
        audit_sources = model["audit"]["relevant_source_sha256"]
        if any(
            path not in sources
            or hashlib.sha256(sources[path].encode()).hexdigest() != expected
            for path, expected in audit_sources.items()
        ):
            return None
        grouped: dict[str, list[KeywordEntry]] = {}
        for entry in entries:
            grouped.setdefault(entry.path, []).append(entry)
        bindings = {}
        for path in grouped:
            tree = trees.get(path)
            if tree is None:
                return None
            modules = {
                statement.module
                for statement in tree.body
                if isinstance(statement, ast.ImportFrom)
                for alias in statement.names
                if alias.name == "TokenType" and alias.asname is None
            }
            if len(modules) != 1:
                return None
            module = modules.pop()
            if module is None or not _valid_runtime_binding(tree, module):
                return None
            bindings[path] = module
        return TokenizerKeyRenameContext(
            entries_by_path=MappingProxyType({path: tuple(rows) for path, rows in grouped.items()}),
            events=MappingProxyType(events),
            poison_keys=poison,
            pop_keys=pop_keys,
            bindings_by_path=MappingProxyType(bindings),
            sources=MappingProxyType(dict(sources)),
        )
    except (OSError, EOFError, UnicodeError, json.JSONDecodeError, SyntaxError,
            ValueError, TypeError, KeyError, IndexError, OverflowError, MemoryError,
            RecursionError):
        return None


def tokenizer_key_rename_patch(
    changes: object, context: TokenizerKeyRenameContext
) -> set[int] | None:
    """Return the complete OLD/NEW attempted-key owner union, else fail closed."""
    try:
        if not isinstance(changes, list) or len(changes) != 1:
            return None
        change = changes[0]
        if not isinstance(change, dict) or type(change.get("old")) is not str:
            return None
        path = change["old"]
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
        runtime_inventory, _ = _source_inventory({path: source})
        expected_inventory = [[
            entry.path, entry.owner, entry.start, entry.end, entry.index,
            entry.key, entry.token, entry.token_dump,
        ] for entry in entries]
        if (
            runtime_inventory != expected_inventory
            or not _valid_runtime_binding(original_tree, context.bindings_by_path[path])
        ):
            return None
        original_assignments = _keyword_assignments(original_tree)
        changed_assignments = _keyword_assignments(changed_tree)
        if original_assignments is None or changed_assignments is None:
            return None
        candidates = []
        for entry in entries:
            assignment_id = (entry.owner, entry.start, entry.end)
            old_dict = original_assignments.get(assignment_id)
            new_dict = changed_assignments.get(assignment_id)
            if old_dict is None or new_dict is None or entry.index >= len(old_dict.keys) or entry.index >= len(new_dict.keys):
                continue
            old_key = old_dict.keys[entry.index]
            new_key = new_dict.keys[entry.index]
            old_value = old_dict.values[entry.index]
            new_value = new_dict.values[entry.index]
            if (
                not isinstance(old_key, ast.Constant) or type(old_key.value) is not str
                or old_key.value != entry.key
                or not isinstance(new_key, ast.Constant) or type(new_key.value) is not str
                or new_key.value == entry.key
                or KEY_IDENTIFIER.fullmatch(entry.key) is None
                or KEY_IDENTIFIER.fullmatch(new_key.value) is None
                or not new_key.value.startswith(entry.key)
                or entry.key not in context.events
                or entry.key in context.poison_keys
                or new_key.value in context.poison_keys
                or entry.key in context.pop_keys
                or new_key.value in context.pop_keys
                or new_key.value in {
                    key.value for key in old_dict.keys
                    if isinstance(key, ast.Constant) and type(key.value) is str
                }
                # This stricter global literal collision rule closes inherited
                # and dialect-spread maps without reconstructing their MRO.
                or new_key.value in {
                    candidate.key
                    for rows in context.entries_by_path.values()
                    for candidate in rows
                }
                or ast.dump(old_value, include_attributes=False) != entry.token_dump
                or ast.dump(new_value, include_attributes=False) != entry.token_dump
            ):
                continue
            old_segment = ast.get_source_segment(source, old_key)
            new_segment = ast.get_source_segment(changed_source, new_key)
            if (
                type(old_segment) is not str or type(new_segment) is not str
                or removed_line.count(old_segment) != 1
                or added_line.count(new_segment) != 1
                or removed_line.replace(old_segment, "__KEY__", 1)
                != added_line.replace(new_segment, "__KEY__", 1)
            ):
                continue
            candidates.append((entry, new_key.value, old_dict, new_dict, old_key, new_key))
        if len(candidates) != 1:
            return None
        entry, new_name, old_dict, new_dict, old_key, new_key = candidates[0]
        sentinel = ast.Name(id="__blast_radius_keyword_key__", ctx=ast.Load())
        old_dict.keys[entry.index] = sentinel
        new_dict.keys[entry.index] = sentinel
        if ast.dump(original_tree, include_attributes=False) != ast.dump(changed_tree, include_attributes=False):
            return None
        # Before the final .get(NEW), the trie may terminate at any existing
        # literal keyword prefix of NEW.  Retain every such terminal's owners;
        # an absent event remains zero only after this prefix closure.
        terminal_prefixes = {
            candidate.key
            for rows in context.entries_by_path.values()
            for candidate in rows
            if KEY_IDENTIFIER.fullmatch(candidate.key) is not None
            and new_name.startswith(candidate.key)
            and len(candidate.key) >= len(entry.key)
        }
        terminal_prefixes.add(new_name)
        if terminal_prefixes & context.poison_keys:
            return None
        owners = set(context.events[entry.key])
        for prefix in terminal_prefixes:
            owners.update(context.events.get(prefix, ()))
        return owners
    except (SyntaxError, ValueError, TypeError, KeyError, IndexError, OverflowError,
            MemoryError, RecursionError):
        return None
