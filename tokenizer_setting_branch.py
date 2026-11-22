"""Certified Tokenizer setting edits narrowed to their first effectful branches."""

from __future__ import annotations

import ast
import gzip
import hashlib
import json
from pathlib import Path


TOKENS_PATH = "sqlglot/tokens.py"
CORE_PATH = "sqlglot/tokenizer_core.py"
TOKENS_SHA256 = "93ea4dd996a6ffb9b61f77cc7900658351ca1d9b1d6cd40efddd233720d8e2be"
CORE_SHA256 = "142463b972f35299140172de19eb72bf0c32742867eb251e06c5592413f8083c"
MODEL_SHA256 = "d61c504e9a4a1006217e6702e1c6f05c04846b3dd5a09ec5572523fd8b2cb382"
PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"
TRACE_SHA256 = {
    "normal": "4afe4afc075b26f4e947de92cfb5a9598ab1bea22c30f137d76ada1cc7c35ecf",
    "synchronous-worker": "709a17acaf46f8516553f94577dac156e04f17ad0a5e7f88ab7bffa77f749868",
}
MANIFEST_SHA256 = {
    "normal": "ac04ff11895a8eaa24979d5bcddd83845c0aff961beff50b31548b72bb70f9ca",
    "synchronous-worker": "63107844c3db71a3befb864fa2f34fbeff918604a835042fa31e7cea9eceef31",
}
COLLECTOR_SHA256 = "21f618281b27ae6567a22d4f24e4b0514d64a4c8be30037212c52a8c74753677"
BUILDER_SHA256 = "1884907391a10f7a655b5e0e95b6b888e0c80431911c078db570db0f63b308ba"
CLASS_COLLECTOR_SHA256 = "5a37f6ae830a6bd7a9d3647f8b746264fd6ad274bfa5eb22005c07042d60d6be"
COLLECTION_SHA256 = "61acd6e4693afd48623101e27519ad604b453f6326c92c158f3ea7bf4c50a928"
COLLECTION_RUNTIME = {
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
SETTINGS = {
    "DASH_COMMENT_REQUIRES_BOUNDARY": ("dash_comment_requires_boundary", 908),
    "COMMENTS_TERMINATE_AT_NEWLINE_ONLY": ("comments_terminate_at_newline_only", 950),
    "STRING_ESCAPES_ALLOWED_IN_RAW_STRINGS": (
        "string_escapes_allowed_in_raw_strings",
        1405,
    ),
}


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_profile(
    path: Path,
    expected_digest: str,
    tests: list[dict],
    source_sha: object,
) -> dict | None:
    try:
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected_digest:
            return None
        profile = json.loads(gzip.decompress(raw))
    except (
        OSError,
        EOFError,
        UnicodeError,
        json.JSONDecodeError,
        ValueError,
        TypeError,
        RecursionError,
        MemoryError,
    ):
        return None
    test_ids = [test.get("id") for test in tests]
    test_digest = hashlib.sha256("\0".join(test_ids).encode("utf-8")).hexdigest()
    if not (
        isinstance(profile, dict)
        and set(profile)
        == {
            "v", "sha", "n", "t", "m", "tokens", "core", "modules", "c", "d",
            "r", "p", "b", "collector", "collection", "runtime",
            "a", "reflection",
        }
        and profile.get("v") == 1
        and profile.get("sha") == source_sha == PINNED_SHA
        and profile.get("n") == len(test_ids)
        and profile.get("t") == test_digest
        and profile.get("m") == MODEL_SHA256
        and profile.get("tokens") == TOKENS_SHA256
        and profile.get("core") == CORE_SHA256
        and profile.get("r") == TRACE_SHA256
        and profile.get("p") == MANIFEST_SHA256
        and profile.get("b") == BUILDER_SHA256
        and profile.get("collector") == COLLECTOR_SHA256
        and profile.get("collection") == COLLECTION_SHA256
        and profile.get("runtime") == COLLECTION_RUNTIME
        and profile.get("a") == CLASS_COLLECTOR_SHA256
        and profile.get("reflection") == "normal+sync:no-reflect-or-mutation"
        and isinstance(profile.get("modules"), list)
        and profile["modules"]
        and profile["modules"] == sorted(set(profile["modules"]))
        and all(type(module) is str for module in profile["modules"])
        and profile.get("c") == []
        and isinstance(profile.get("d"), dict)
        and set(profile["d"]) == set(SETTINGS)
    ):
        return None
    for setting, (field, line) in SETTINGS.items():
        entry = profile["d"].get(setting)
        if not (
            isinstance(entry, list)
            and len(entry) == 3
            and entry[0] == field
            and entry[1] == line
            and isinstance(entry[2], list)
            and entry[2] == sorted(set(entry[2]))
            and all(type(index) is int and 0 <= index < len(test_ids) for index in entry[2])
        ):
            return None
    expected_modules = sorted(
        {test["file"].removesuffix(".py").replace("/", ".") for test in tests}
    )
    return profile if profile["modules"] == expected_modules else None


def _class(tree: ast.Module, name: str) -> ast.ClassDef | None:
    matches = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == name]
    return matches[0] if len(matches) == 1 else None


def _changed_setting(
    original: str, prospective: str
) -> tuple[str, ast.Module, ast.Module] | None:
    if _digest(original) != TOKENS_SHA256:
        return None
    try:
        old_tree = ast.parse(original, filename=TOKENS_PATH, type_comments=True)
        new_tree = ast.parse(prospective, filename=TOKENS_PATH, type_comments=True)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return None
    old_owner = _class(old_tree, "Tokenizer")
    new_owner = _class(new_tree, "Tokenizer")
    if old_owner is None or new_owner is None:
        return None

    def assignments(owner: ast.ClassDef) -> dict[str, ast.Assign]:
        result = {}
        for statement in owner.body:
            if (
                isinstance(statement, ast.Assign)
                and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name)
                and statement.targets[0].id in SETTINGS
            ):
                result[statement.targets[0].id] = statement
        return result

    old = assignments(old_owner)
    new = assignments(new_owner)
    if set(old) != set(SETTINGS) or set(new) != set(SETTINGS):
        return None
    changed = []
    for setting in SETTINGS:
        before = old[setting].value
        after = new[setting].value
        if not (
            isinstance(before, ast.Constant)
            and isinstance(after, ast.Constant)
            and type(before.value) is bool
            and type(after.value) is bool
        ):
            return None
        if before.value != after.value:
            changed.append(setting)
        after.value = before.value
    if len(changed) != 1:
        return None
    if ast.dump(old_tree, include_attributes=False) != ast.dump(
        new_tree, include_attributes=False
    ):
        return None
    return changed[0], old_tree, new_tree


def readers(
    path: str,
    original: str,
    prospective: str,
    change: dict,
    profile: dict | None,
) -> set[int] | None:
    """Return the authenticated first-effect branch readers, else fall back."""
    if profile is None or path != TOKENS_PATH:
        return None
    if (
        change.get("old") != TOKENS_PATH
        or change.get("new") != TOKENS_PATH
        or change.get("diff_old") != TOKENS_PATH
        or change.get("diff_new") != TOKENS_PATH
        or change.get("new_file_mode_count")
        or change.get("structural_invalid")
        or change.get("non_lf")
        or len(change.get("removed", ())) != 1
        or len(change.get("added", ())) != 1
        or len(change.get("lines", ())) != 1
        or len(change.get("added_new_at", ())) != 1
    ):
        return None
    result = _changed_setting(original, prospective)
    if result is None:
        return None
    setting, old_tree, _new_tree = result
    entry = profile.get("d", {}).get(setting) if isinstance(profile, dict) else None
    if not (
        isinstance(entry, list)
        and len(entry) == 3
        and entry[:2] == list(SETTINGS[setting])
        and isinstance(entry[2], list)
        and entry[2] == sorted(set(entry[2]))
        and all(type(index) is int and index >= 0 for index in entry[2])
    ):
        return None
    assignment = next(
        node
        for node in ast.walk(old_tree)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == setting
        and isinstance(node.value, ast.Constant)
        and type(node.value.value) is bool
    )
    line = next(iter(change["lines"]))
    if (
        line != assignment.lineno
        or change["added_new_at"][0][0] != line
        or change["removed"][0].strip()
        != f"{setting} = {assignment.value.value}"
        or change["added"][0].strip()
        != f"{setting} = {not assignment.value.value}"
    ):
        return None
    return set(entry[2])
