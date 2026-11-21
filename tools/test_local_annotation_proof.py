#!/usr/bin/env python3
"""Adversarial synthetic checks for local-annotation identity proofs."""

from __future__ import annotations

import difflib
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import selector


PATH = "sqlglot/fake.py"


def parsed_change(original: str, changed: str) -> dict:
    selector._PINNED_SOURCES = {PATH: original}
    selector._SOURCE_TREES.clear()
    selector._SOURCE_CODE.clear()
    patch = "diff --git a/sqlglot/fake.py b/sqlglot/fake.py\n" + "".join(
        difflib.unified_diff(
            original.splitlines(True),
            changed.splitlines(True),
            fromfile="a/sqlglot/fake.py",
            tofile="b/sqlglot/fake.py",
        )
    )
    with tempfile.TemporaryDirectory() as temporary:
        patch_path = Path(temporary, "change.patch")
        patch_path.write_text(patch)
        changes = selector.patch_changes(patch_path)
    assert len(changes) == 1
    return changes[0]


def proof(original: str, changed: str) -> bool:
    return selector.local_annotation_only_edit(parsed_change(original, changed), PATH)


def main() -> None:
    assert proof(
        "def f():\n    value: int = 1\n    return value\n",
        "def f():\n    value: str = 1\n    return value\n",
    )
    assert proof(
        "def f(obj):\n    obj.value: int = 1\n",
        "def f(obj):\n    obj.value: str = 1\n",
    )
    assert proof(
        "def f():\n    value: int\n    return 1\n",
        "def f():\n    value: OtherType\n    return 1\n",
    )
    assert proof(
        "def outer():\n    def inner():\n        value: int = 1\n",
        "def outer():\n    def inner():\n        value: str = 1\n",
    )

    # Executable source positions move when a valued annotation changes width.
    assert not proof(
        "def f():\n    value: int = call()\n",
        "def f():\n    value: OtherType = call()\n",
    )
    assert not proof("value: int = 1\n", "value: str = 1\n")
    assert not proof(
        "class C:\n    value: int = 1\n",
        "class C:\n    value: str = 1\n",
    )
    assert not proof(
        "def f(value: int):\n    return value\n",
        "def f(value: str):\n    return value\n",
    )
    assert not proof(
        "def f():\n    value: int = 1\n",
        "def f():\n    value: str = 2\n",
    )
    assert not proof(
        "def f():\n    value: int = 1\n",
        "def f():\n    other: str = 1\n",
    )
    assert not proof(
        "def f():\n    class C:\n        value: int = 1\n",
        "def f():\n    class C:\n        value: str = 1\n",
    )

    # Two distant edits create separate hunks and must take the fallback path.
    padding = "".join(f"    x{i} = {i}\n" for i in range(12))
    assert not proof(
        "def f():\n    value: int = 1\n" + padding + "    return 1\n",
        "def f():\n    value: str = 1\n" + padding + "    return 2\n",
    )

    # A malformed context line cannot be applied to the pinned source.
    original = "def f():\n    value: int = 1\n    return value\n"
    change = parsed_change(
        original, "def f():\n    value: str = 1\n    return value\n"
    )
    marker, _text = change["hunks"][0]["lines"][0]
    assert marker == " "
    change["hunks"][0]["lines"][0] = (" ", "def wrong():")
    assert not selector.local_annotation_only_edit(change, PATH)
    print("local annotation proof synthetic regressions passed")


if __name__ == "__main__":
    main()
