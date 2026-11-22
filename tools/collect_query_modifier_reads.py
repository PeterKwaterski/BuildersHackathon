#!/usr/bin/env python3
"""Collect key-sensitive reads for ``QUERY_MODIFIERS`` deletion research.

This composes the authenticated dictionary collector with three exact pinned
consumer rewrites.  The helper records a modifier only when its value is
truthy, which is the conservative condition under which removing that key can
change the parser/generator result.  All ordinary ``arg_types`` membership and
shape observations remain recorded by the base dictionary tracker.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import collect_dict_access as base


SENSITIVE_LABEL = "__QUERY_MODIFIER_EFFECT__"
BASE_INSTRUMENT_SOURCE = base.instrument_source


def collector_bundle_digest() -> str:
    digest = hashlib.sha256()
    for path in (Path(__file__), Path(base.__file__)):
        raw = path.read_bytes()
        name = path.name.encode()
        digest.update(len(name).to_bytes(4, "big"))
        digest.update(name)
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()

TRACKER_EXTENSION = r'''
def sensitive_keys(label, mapping):
    if type(mapping) is TrackingDict:
        # These three loops are authenticated by exact source rewrites below.
        # Bypass only the generic iteration hook: their semantic effect is
        # recorded by the paired value helper, while unrelated iteration,
        # reflection and mutation of QUERY_MODIFIERS remain visible.
        return dict.__iter__(mapping)
    record(label, ("__BR_WILDCARD__", "keys"))
    return iter(mapping)

def sensitive_unpack(label, mapping):
    if type(mapping) is TrackingDict:
        return {
            key: dict.__getitem__(mapping, key)
            for key in dict.__iter__(mapping)
        }
    record(label, ("__BR_WILDCARD__", "values"))
    return mapping

def sensitive_required_items(label, mapping):
    if type(mapping) is TrackingDict:
        return dict.items(mapping)
    # A non-tracker belongs to a dynamically created class that defines or
    # overrides its own arg_types. It cannot be one of the three authenticated
    # dictionaries derived from QUERY_MODIFIERS; the pinned static census also
    # rejects attribute rebinding of those dictionaries.
    return mapping.items()

def sensitive_pair_get(label, mapping, key):
    if type(mapping) is not dict:
        record(label, ("__BR_WILDCARD__", "values"))
    value = mapping.get(key)
    truth = bool(value)
    if truth:
        record(label, key)
    return value, truth

def sensitive_bool_get(label, mapping, key):
    if type(mapping) is not dict:
        record(label, ("__BR_WILDCARD__", "values"))
    value = mapping.get(key)
    truth = bool(value)
    if truth:
        record(label, key)
    return truth

def sensitive_unmerge(label, mapping, keys):
    if type(mapping) is not dict or type(keys) is not set:
        record(label, ("__BR_WILDCARD__", "values"))
    for key, value in mapping.items():
        if key in keys and value:
            record(label, key)
            return True
    return False

builtins._br_sensitive_pair_get = sensitive_pair_get
builtins._br_sensitive_bool_get = sensitive_bool_get
builtins._br_sensitive_unmerge = sensitive_unmerge
builtins._br_sensitive_keys = sensitive_keys
builtins._br_sensitive_unpack = sensitive_unpack
builtins._br_sensitive_required_items = sensitive_required_items
'''


def replace_once(path: Path, old: str, new: str) -> None:
    source = path.read_text()
    if source.count(old) != 1:
        raise SystemExit(f"expected one pinned query-modifier consumer in {path}: {old!r}")
    path.write_text(source.replace(old, new))


def instrument_source(source: Path) -> int:
    injected_names = {
        "_br_modifier_truth",
        "_br_sensitive_pair_get",
        "_br_sensitive_bool_get",
        "_br_sensitive_unmerge",
        "_br_sensitive_keys",
        "_br_sensitive_unpack",
        "_br_sensitive_required_items",
    }
    collisions = {
        name
        for root_name in ("sqlglot", "tests")
        for path in (source / root_name).rglob("*.py")
        for name in injected_names
        if name in path.read_text()
    }
    if collisions:
        raise SystemExit(f"query-modifier helper collision: {sorted(collisions)}")
    count = BASE_INSTRUMENT_SOURCE(source)
    query_path = source / "sqlglot/expressions/query.py"
    query_source = query_path.read_text()
    if query_source.count("**QUERY_MODIFIERS") != 3:
        raise SystemExit("expected three pinned QUERY_MODIFIERS unpacks")
    query_path.write_text(
        query_source.replace(
            "**QUERY_MODIFIERS",
            f"**_br_sensitive_unpack({SENSITIVE_LABEL!r}, QUERY_MODIFIERS)",
        )
    )
    replace_once(
        source / "sqlglot/expressions/core.py",
        "cls.required_args = {k for k, v in cls.arg_types.items() if v}",
        f"cls.required_args = {{k for k, v in _br_sensitive_required_items("
        f"{SENSITIVE_LABEL!r}, cls.arg_types) if v}}",
    )
    replace_once(
        source / "sqlglot/optimizer/merge_subqueries.py",
        "UNMERGABLE_ARGS = set(exp.Select.arg_types) - {",
        f"UNMERGABLE_ARGS = set(_br_sensitive_keys("
        f"{SENSITIVE_LABEL!r}, exp.Select.arg_types)) - {{",
    )
    replace_once(
        source / "sqlglot/parser.py",
        "        for key in exp.QUERY_MODIFIERS:\n"
        "            if modifier := values.args.get(key):",
        f"        for key in _br_sensitive_keys({SENSITIVE_LABEL!r}, exp.QUERY_MODIFIERS):\n"
        f"            modifier, _br_modifier_truth = _br_sensitive_pair_get("
        f"{SENSITIVE_LABEL!r}, values.args, key)\n"
        "            if _br_modifier_truth:",
    )
    replace_once(
        source / "sqlglot/generator.py",
        "inner.args.get(key) for key in exp.QUERY_MODIFIERS",
        f"_br_sensitive_bool_get({SENSITIVE_LABEL!r}, inner.args, key) "
        f"for key in _br_sensitive_keys({SENSITIVE_LABEL!r}, exp.QUERY_MODIFIERS)",
    )
    replace_once(
        source / "sqlglot/generator.py",
        "left.this.args.get(key) for key in exp.QUERY_MODIFIERS",
        f"_br_sensitive_bool_get({SENSITIVE_LABEL!r}, left.this.args, key) "
        f"for key in _br_sensitive_keys({SENSITIVE_LABEL!r}, exp.QUERY_MODIFIERS)",
    )
    replace_once(
        source / "sqlglot/optimizer/merge_subqueries.py",
        "any(v for k, v in inner_select.args.items() if k in UNMERGABLE_ARGS)",
        f"_br_sensitive_unmerge({SENSITIVE_LABEL!r}, inner_select.args, UNMERGABLE_ARGS)",
    )
    return count


def main() -> None:
    args = base.arguments()
    marker = "builtins._br_trace_dict = trace_dict\n"
    if base.TRACKER.count(marker) != 1:
        raise SystemExit("base tracker injection marker changed")
    membership = '''    def __contains__(self, key):
        # Membership observes only key presence, which the runtime gate proves
        # unchanged for a value-only edit.
        record(self._br_label, ("__BR_WILDCARD__", "keys"))
        return super().__contains__(key)
'''
    exact_membership = '''    def __contains__(self, key):
        # QUERY_MODIFIERS research includes key deletion, so retain the exact
        # membership key.  Other artifact builders remain on the base tracker.
        record(self._br_label, key)
        return super().__contains__(key)
'''
    if base.TRACKER.count(membership) != 1:
        raise SystemExit("base membership tracker shape changed")
    base.TRACKER = base.TRACKER.replace(membership, exact_membership)
    import_record = '''    if event_owner == "__NO_TEST__":
        filename, line, function = site or import_site()
        IMPORT_EVENTS.add((label, raw_key, kind, filename, line, function))
'''
    complete_import_record = '''    if not CURRENT_TEST:
        # Retain the exact call site even when collection imported sqlglot
        # through a tests.* frame.  The query-modifier builder authenticates
        # harmless class-dictionary derivations and fails closed on every
        # other unnumbered consumer.
        filename, line, function = site or import_site()
        IMPORT_EVENTS.add((label, raw_key, kind, filename, line, function))
'''
    if base.TRACKER.count(import_record) != 1:
        raise SystemExit("base import-event tracker shape changed")
    base.TRACKER = base.TRACKER.replace(import_record, complete_import_record)
    base.TRACKER = base.TRACKER.replace(marker, TRACKER_EXTENSION + marker)
    base.instrument_source = instrument_source
    base.main()
    output = args.output.resolve()
    manifest_path = (args.manifest or output.with_suffix(".manifest.json")).resolve()
    manifest = json.loads(manifest_path.read_text())
    manifest["collector_bundle_sha256"] = collector_bundle_digest()
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
