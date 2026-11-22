"""Default-off research classifier for binary fixture replacements.

The admitted language is intentionally much narrower than Git's patch format:
one existing, same-path, same-mode binary replacement of an authenticated
fixture. Copies, renames, additions, deletions, mode changes and mixed patches
remain unsupported because path/name observers are not yet certified.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath


FEATURE_ENABLED = False
PINNED_REVISION = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"
SAFE_PATH = re.compile(r"[A-Za-z0-9._@+/-]+\Z")
DIFF = re.compile(r"diff --git a/([^ ]+) b/([^ ]+)\Z")
BINARY_DIFFER = re.compile(r"Binary files a/([^ ]+) and b/([^ ]+) differ\Z")
INDEX = re.compile(r"index ([0-9a-f]{40})\.\.([0-9a-f]{40})(?: (100644|100755))?\Z")
STRUCTURAL_PREFIXES = (
    "copy from ", "copy to ", "rename from ", "rename to ",
    "old mode ", "new mode ", "new file mode ", "deleted file mode ",
    "similarity index ", "dissimilarity index ", "--- ", "+++ ", "@@ ",
)


@dataclass(frozen=True)
class BinaryReplacement:
    path: str
    encoding: str
    old_blob: str
    new_blob: str
    mode: str


def _safe_path(value: str) -> bool:
    path = PurePosixPath(value)
    return bool(
        value
        and SAFE_PATH.fullmatch(value)
        and not path.is_absolute()
        and ".." not in path.parts
        and str(path) == value
        and "//" not in value
    )


def parse_existing_binary_replacement(document: str) -> BinaryReplacement | None:
    """Recognize one same-path binary body with no namespace/mode operation."""
    if type(document) is not str or "\x00" in document:
        return None
    lines = document.splitlines()
    diffs = [index for index, line in enumerate(lines) if line.startswith("diff --git ")]
    if diffs != [0]:
        return None
    match = DIFF.fullmatch(lines[0])
    if match is None or match.group(1) != match.group(2) or not _safe_path(match.group(1)):
        return None
    path = match.group(1)
    structural = [line for line in lines[1:] if line.startswith(STRUCTURAL_PREFIXES)]
    if structural:
        return None
    git_markers = [index for index, line in enumerate(lines) if line == "GIT binary patch"]
    differ_markers = [
        (index, BINARY_DIFFER.fullmatch(line))
        for index, line in enumerate(lines)
        if line.startswith("Binary files ")
    ]
    if git_markers and differ_markers:
        return None
    if len(git_markers) == 1:
        marker = git_markers[0]
        # A Git binary body has at least one literal/delta header and payload.
        if marker < 1 or marker + 2 >= len(lines):
            return None
        index_match = INDEX.fullmatch(lines[1]) if len(lines[1:marker]) == 1 else None
        if index_match is None or index_match.group(3) is None:
            return None
        if any(line.startswith("index ") for line in lines[marker + 1 :]):
            return None
        if not any(
            re.fullmatch(r"(?:literal|delta) [0-9]+", line)
            for line in lines[marker + 1 :]
        ):
            return None
        return BinaryReplacement(
            path, "git-binary-patch", index_match.group(1), index_match.group(2), index_match.group(3)
        )
    if len(differ_markers) == 1:
        marker_index, marker = differ_markers[0]
        if marker is None or marker.group(1) != path or marker.group(2) != path:
            return None
        prefix = lines[1:marker_index]
        index_match = INDEX.fullmatch(prefix[0]) if len(prefix) == 1 else None
        if index_match is None or index_match.group(3) is None:
            return None
        if marker_index != len(lines) - 1:
            return None
        return BinaryReplacement(
            path, "binary-files-differ", index_match.group(1), index_match.group(2), index_match.group(3)
        )
    return None


def fixture_binary_readers(
    document: str,
    model: dict,
    test_ids: list[str],
    pinned_blobs: dict[str, str],
) -> set[int] | None:
    """Return manifest indices for a certified existing fixture replacement."""
    replacement = parse_existing_binary_replacement(document)
    if (
        replacement is None
        or pinned_blobs.get(replacement.path) != replacement.old_blob
        or replacement.old_blob == replacement.new_blob
        or replacement.mode != "100644"
        or not replacement.path.startswith("tests/fixtures/")
        or replacement.path.endswith((".py", ".pyi"))
        or not isinstance(model, dict)
        or model.get("sha") != PINNED_REVISION
        or model.get("t") != test_ids
        or not isinstance(model.get("x"), dict)
        or not isinstance(model.get("z"), list)
    ):
        return None
    set_id = model["x"].get(replacement.path)
    if type(set_id) is not int or not 0 <= set_id < len(model["z"]):
        return None
    readers = model["z"][set_id]
    if (
        not isinstance(readers, list)
        or readers != sorted(set(readers))
        or any(type(index) is not int or not 0 <= index < len(test_ids) for index in readers)
    ):
        return None
    selected = set(readers)
    if replacement.path.endswith(".csv.gz") and replacement.path.startswith(
        ("tests/fixtures/optimizer/tpc-h/", "tests/fixtures/optimizer/tpc-ds/")
    ):
        selected.update(
            index
            for index, test_id in enumerate(test_ids)
            if test_id.startswith("tests/test_executor.py::TestExecutor::")
        )
    return selected
