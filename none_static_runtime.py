"""Fail-closed runtime matcher for the trace-free None-domain profile."""

from __future__ import annotations

import ast
import gzip
import hashlib
import json
from pathlib import Path


PROFILE_GZIP_SHA256 = "3332998e622431ed753891f1dcf176570c0320150e370b19dd59dad226316d1f"
PROFILE_PATH = Path(__file__).with_name("none_static_profile.json.gz")
PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"
PINNED_TREE = "6606fc5229c882bd0cf8f9ba79503e9e10d084f7"
MAX_GZIP_BYTES = 32_000
MAX_JSON_BYTES = 128_000


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_profile(test_digest: str, test_count: int) -> dict | None:
    """Load the exact artifact; any byte/schema/identity drift disables it."""

    try:
        raw = PROFILE_PATH.read_bytes()
        if len(raw) > MAX_GZIP_BYTES or _sha(raw) != PROFILE_GZIP_SHA256:
            return None
        decoded = gzip.decompress(raw)
        if len(decoded) > MAX_JSON_BYTES:
            return None
        profile = json.loads(decoded)
    except (OSError, EOFError, UnicodeError, json.JSONDecodeError, ValueError, TypeError):
        return None
    expected_top = {
        "builder_sha256", "envelope_sha256", "format", "policy",
        "proof_sha256", "reflection_sha256", "sites", "skipped_sha256",
        "source_sha", "source_tree", "test_count", "tests_sha256", "version",
    }
    if (
        not isinstance(profile, dict)
        or set(profile) != expected_top
        or profile.get("format") != "none-static-profile-v3"
        or profile.get("version") != 3
        or profile.get("source_sha") != PINNED_SHA
        or profile.get("source_tree") != PINNED_TREE
        or profile.get("tests_sha256") != test_digest
        or profile.get("test_count") != test_count
        or profile.get("policy") != {
            "admit": "closed-fixed-tree-exact-builtin-domain",
            "mutation": "one-file-one-hunk-one-line-IsNot-to-NotEq",
            "reflection": "retain-all-authenticated-source-readers",
        }
        or not isinstance(profile.get("sites"), list)
        or len(profile["sites"]) != 2
    ):
        return None
    expected_site = {
        "added", "domain", "line", "path", "prospective_sha256",
        "reflection_retain", "removed", "source_sha256",
    }
    keys = set()
    for site in profile["sites"]:
        if (
            not isinstance(site, dict)
            or set(site) != expected_site
            or type(site.get("path")) is not str
            or type(site.get("line")) is not int
            or site.get("domain") not in {"exact-list-or-none", "exact-tuple-or-none"}
            or type(site.get("removed")) is not str
            or type(site.get("added")) is not str
            or not isinstance(site.get("reflection_retain"), list)
            or any(type(index) is not int or not 0 <= index < test_count for index in site["reflection_retain"])
            or site["reflection_retain"] != sorted(set(site["reflection_retain"]))
            or any(
                type(site.get(name)) is not str
                or len(site[name]) != 64
                or any(character not in "0123456789abcdef" for character in site[name])
                for name in ("source_sha256", "prospective_sha256")
            )
        ):
            return None
        keys.add((site["path"], site["line"]))
    if keys != {
        ("sqlglot/executor/table.py", 109),
        ("sqlglot/optimizer/pushdown_projections.py", 496),
    }:
        return None
    return profile


def _normalized_operator_ast(original: str, prospective: str, line: int) -> bool:
    try:
        before = ast.parse(original, type_comments=True)
        after = ast.parse(prospective, type_comments=True)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return False
    before_nodes = [
        node for node in ast.walk(before)
        if isinstance(node, ast.Compare) and node.lineno == line
    ]
    after_nodes = [
        node for node in ast.walk(after)
        if isinstance(node, ast.Compare) and node.lineno == line
    ]
    if (
        len(before_nodes) != 1
        or len(after_nodes) != 1
        or len(before_nodes[0].ops) != 1
        or len(after_nodes[0].ops) != 1
        or not isinstance(before_nodes[0].ops[0], ast.IsNot)
        or not isinstance(after_nodes[0].ops[0], ast.NotEq)
    ):
        return False
    before_nodes[0].ops[0] = ast.NotEq()
    return ast.dump(before, include_attributes=False) == ast.dump(
        after, include_attributes=False
    )


def _exact_hunk(change: dict, site: dict) -> bool:
    """Accept exactly one coherent hunk with one removed and one added line."""

    if (
        change.get("old") != site["path"]
        or change.get("new") != site["path"]
        or change.get("diff_old") != site["path"]
        or change.get("diff_new") != site["path"]
        or change.get("binary") is not False
        or change.get("non_lf") is not False
        or change.get("no_newline_marker") is not False
        or change.get("new_file_mode") is not None
        or change.get("removed") != [site["removed"]]
        or change.get("added") != [site["added"]]
        or change.get("payload") != [site["removed"], site["added"]]
        or len(change.get("hunks", ())) != 1
    ):
        return False
    hunk = change["hunks"][0]
    if not isinstance(hunk, dict) or set(hunk) != {
        "old_start", "old_count", "new_start", "new_count", "lines"
    }:
        return False
    lines = hunk["lines"]
    if (
        not isinstance(lines, list)
        or sum(prefix == "-" for prefix, _line in lines) != 1
        or sum(prefix == "+" for prefix, _line in lines) != 1
        or any(prefix not in {" ", "-", "+"} for prefix, _line in lines)
        or hunk["old_count"] != sum(prefix != "+" for prefix, _line in lines)
        or hunk["new_count"] != sum(prefix != "-" for prefix, _line in lines)
        or not hunk["old_start"] <= site["line"] < hunk["old_start"] + hunk["old_count"]
    ):
        return False
    return True


def match(
    changes: list[dict],
    profile: dict | None,
    original: str | None,
    prospective: str | None,
) -> set[int] | None:
    """Return authenticated source readers to retain, or ``None`` on rejection."""

    if profile is None or len(changes) != 1 or original is None or prospective is None:
        return None
    change = changes[0]
    path = change.get("old")
    sites = [site for site in profile["sites"] if site["path"] == path]
    if len(sites) != 1:
        return None
    site = sites[0]
    if not _exact_hunk(change, site):
        return None
    if (
        _sha(original.encode()) != site["source_sha256"]
        or _sha(prospective.encode()) != site["prospective_sha256"]
    ):
        return None
    before = original.splitlines()
    after = prospective.splitlines()
    line = site["line"]
    if (
        len(before) != len(after)
        or before[line - 1] != site["removed"]
        or after[line - 1] != site["added"]
        or before[: line - 1] != after[: line - 1]
        or before[line:] != after[line:]
        or not _normalized_operator_ast(original, prospective, line)
    ):
        return None
    return set(site["reflection_retain"])
