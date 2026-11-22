#!/usr/bin/env python3
"""Construct an isolated patched tree and invoke the bounded memo verifier."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath


HUNK = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class PatchRejected(ValueError):
    pass


def safe_path(raw: str) -> str | None:
    if raw == "/dev/null":
        return None
    value = raw[2:] if raw.startswith(("a/", "b/")) else raw
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in value
        or "\0" in value
        or path.as_posix() != value
    ):
        raise PatchRejected(f"unsafe patch path {raw!r}")
    return value


def parse_patch(path: Path) -> list[dict]:
    lines = path.read_text(encoding="utf-8").splitlines()
    changes = []
    change = None
    hunk = None
    for line in lines:
        if line.startswith("diff --git "):
            change = {"old": None, "new": None, "hunks": []}
            changes.append(change)
            hunk = None
        elif change is None:
            if line:
                raise PatchRejected("content before first diff header")
        elif line.startswith("--- "):
            change["old"] = safe_path(line[4:].split("\t", 1)[0])
        elif line.startswith("+++ "):
            change["new"] = safe_path(line[4:].split("\t", 1)[0])
        elif match := HUNK.match(line):
            hunk = {
                "old_start": int(match.group(1)),
                "old_count": int(match.group(2) or 1),
                "new_count": int(match.group(4) or 1),
                "lines": [],
            }
            change["hunks"].append(hunk)
        elif hunk is not None and line[:1] in {" ", "+", "-"}:
            hunk["lines"].append((line[0], line[1:]))
        elif line == "\\ No newline at end of file":
            raise PatchRejected("no-newline patches are outside the closed applier")
        elif line.startswith(("index ", "new file mode ", "deleted file mode ")):
            continue
        elif line.startswith(("rename ", "copy ", "GIT binary patch", "Binary files ")):
            raise PatchRejected("rename/copy/binary patch is outside the closed applier")
        elif line:
            raise PatchRejected(f"unsupported patch directive {line!r}")
    if not changes or any(change["old"] is None and change["new"] is None for change in changes):
        raise PatchRejected("patch has no usable file changes")
    return changes


def apply_change(
    root: Path, base_tree: Path | dict, change: dict | None = None
) -> str:
    if change is None:
        change = base_tree
        base_tree = root
    assert isinstance(base_tree, Path) and isinstance(change, dict)
    old_name, new_name = change["old"], change["new"]
    if old_name is not None and new_name is not None and old_name != new_name:
        raise PatchRejected("renames are outside the closed applier")
    relative = new_name or old_name
    assert relative is not None
    target = root / relative
    if target.is_symlink():
        try:
            target.resolve(strict=True).relative_to(base_tree.resolve(strict=True))
        except (OSError, ValueError):
            raise PatchRejected("symlink target escapes the pinned tree") from None
    if old_name is None:
        original = []
        trailing_newline = True
        if target.exists():
            raise PatchRejected("new-file target already exists")
    else:
        try:
            source = target.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise PatchRejected(f"cannot read target: {error}") from error
        original = source.splitlines()
        trailing_newline = source.endswith("\n")

    output = []
    cursor = 0
    for hunk in change["hunks"]:
        start = hunk["old_start"] if hunk["old_count"] == 0 else hunk["old_start"] - 1
        if start < cursor or start > len(original):
            raise PatchRejected("hunk offset outside target")
        output.extend(original[cursor:start])
        cursor = start
        old_seen = new_seen = 0
        for marker, text in hunk["lines"]:
            if marker in {" ", "-"}:
                if cursor >= len(original) or original[cursor] != text:
                    raise PatchRejected("hunk context/removal mismatch")
                cursor += 1
                old_seen += 1
            if marker in {" ", "+"}:
                output.append(text)
                new_seen += 1
        if old_seen != hunk["old_count"] or new_seen != hunk["new_count"]:
            raise PatchRejected("hunk count mismatch")
    output.extend(original[cursor:])

    if new_name is None:
        if output:
            raise PatchRejected("deleted file still has content")
        target.unlink()
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_symlink():
            target.unlink()
        target.write_text("\n".join(output) + ("\n" if trailing_newline or old_name is None else ""), encoding="utf-8")
    return relative


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-tree", type=Path, required=True)
    parser.add_argument("--patch", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--deadline-s", type=float, default=170.0)
    args = parser.parse_args()
    started = time.monotonic()
    try:
        changes = parse_patch(args.patch)
        with tempfile.TemporaryDirectory(prefix="tpc-memo-") as directory:
            prospective = Path(directory) / "overlay"
            prospective.mkdir()
            for change in changes:
                relative = change.get("new") or change.get("old")
                if relative is None:
                    raise PatchRejected("patch has no materialized target")
                source = args.base_tree / relative
                destination = prospective / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                if not source.is_file():
                    raise PatchRejected("patch target is absent from pinned tree")
                destination.symlink_to(source)
            changed_paths = [
                apply_change(prospective, args.base_tree, change) for change in changes
            ]
            if len(changed_paths) != 1:
                raise PatchRejected("prospective verifier accepts one changed source")
            verifier = Path(__file__).with_name("verify_prospective_executor_memo.py")
            command = [
                sys.executable,
                str(verifier),
                "--tree",
                str(args.base_tree),
                "--override-source",
                str(prospective / changed_paths[0]),
                "--artifact",
                str(args.artifact),
                "--deadline-s",
                str(max(1.0, args.deadline_s - (time.monotonic() - started))),
            ]
            for path in changed_paths:
                command.extend(("--changed-path", path))
            completed = subprocess.run(
                command,
                env={**os.environ, "PYTHONPATH": os.pathsep.join((str(args.base_tree), str(Path(__file__).parent)))},
                text=True,
                capture_output=True,
                timeout=max(1.0, args.deadline_s - (time.monotonic() - started) + 2.0),
            )
            if completed.stderr:
                print(completed.stderr, file=sys.stderr, end="")
            if not completed.stdout:
                raise PatchRejected("prospective verifier returned no result")
            print(completed.stdout, end="")
            raise SystemExit(completed.returncode)
    except SystemExit:
        raise
    except Exception as error:
        print(
            json.dumps(
                {
                    "accepted": False,
                    "reason": f"{type(error).__name__}: {error}",
                    "wall_s": round(time.monotonic() - started, 6),
                },
                sort_keys=True,
            )
        )
        raise SystemExit(1)


if __name__ == "__main__":
    main()
