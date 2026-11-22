"""Default-off research classifier for binary fixture replacements.

The admitted language is intentionally much narrower than Git's patch format:
one existing, same-path, same-mode binary replacement of an authenticated
fixture. Copies, renames, additions, deletions, mode changes and mixed patches
remain unsupported because path/name observers are not yet certified.
"""

from __future__ import annotations

import re
import hashlib
import json
import zlib
from dataclasses import dataclass
from pathlib import PurePosixPath


FEATURE_ENABLED = False
PINNED_REVISION = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"
SELECTOR_MODEL_SHA256 = "d61c504e9a4a1006217e6702e1c6f05c04846b3dd5a09ec5572523fd8b2cb382"
SAFE_PATH = re.compile(r"[A-Za-z0-9._@+/-]+\Z")
DIFF = re.compile(r"diff --git a/([^ ]+) b/([^ ]+)\Z")
BINARY_DIFFER = re.compile(r"Binary files a/([^ ]+) and b/([^ ]+) differ\Z")
INDEX = re.compile(r"index ([0-9a-f]{40})\.\.([0-9a-f]{40})(?: (100644|100755))?\Z")
BINARY_HEADER = re.compile(r"(literal|delta) (0|[1-9][0-9]*)\Z")
BASE85 = frozenset(
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "!#$%&()*+-;<=>?@^_`{|}~"
)
MAX_BINARY_BYTES = 64 * 1024 * 1024
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
    chunks: tuple["BinaryChunk", "BinaryChunk"]


@dataclass(frozen=True)
class BinaryChunk:
    kind: str
    data: bytes


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


def _decoded_line_size(prefix: str) -> int | None:
    if "A" <= prefix <= "Z":
        return ord(prefix) - ord("A") + 1
    if "a" <= prefix <= "z":
        return ord(prefix) - ord("a") + 27
    return None


def _decode_binary_chunk(lines: list[str]) -> BinaryChunk | None:
    if not lines or BINARY_HEADER.fullmatch(lines[0]) is None or len(lines) < 2:
        return None
    header = BINARY_HEADER.fullmatch(lines[0])
    assert header is not None
    if len(header.group(2)) > 8:
        return None
    declared_size = int(header.group(2))
    if declared_size > MAX_BINARY_BYTES:
        return None
    compressed = bytearray()
    for line_index, line in enumerate(lines[1:]):
        if not line:
            return None
        decoded = _decoded_line_size(line[0])
        encoded = line[1:]
        if (
            decoded is None
            or (line_index < len(lines[1:]) - 1 and decoded != 52)
            or len(encoded) != 5 * ((decoded + 3) // 4)
            or any(character not in BASE85 for character in encoded)
        ):
            return None
        decoded_line = bytearray()
        for offset in range(0, len(encoded), 5):
            value = 0
            for character in encoded[offset : offset + 5]:
                value = value * 85 + (
                    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    "!#$%&()*+-;<=>?@^_`{|}~"
                ).index(character)
            if value > 0xFFFFFFFF:
                return None
            decoded_line.extend(value.to_bytes(4, "big"))
        compressed.extend(decoded_line[:decoded])
    try:
        decompressor = zlib.decompressobj()
        raw = decompressor.decompress(bytes(compressed), declared_size + 1)
        if decompressor.unconsumed_tail:
            return None
        raw += decompressor.flush()
    except zlib.error:
        return None
    if not decompressor.eof or decompressor.unused_data or decompressor.unconsumed_tail:
        return None
    if len(raw) != declared_size:
        return None
    return BinaryChunk(header.group(1), raw)


def _decode_git_binary_body(lines: list[str]) -> tuple[BinaryChunk, BinaryChunk] | None:
    """Validate the two forward/reverse chunks of an in-place Git binary edit."""
    while lines and not lines[-1]:
        lines.pop()
    chunks: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        if not line:
            if current:
                chunks.append(current)
                current = []
            continue
        current.append(line)
    if current:
        chunks.append(current)
    if len(chunks) != 2:
        return None
    decoded = tuple(_decode_binary_chunk(chunk) for chunk in chunks)
    if any(chunk is None for chunk in decoded):
        return None
    return decoded  # type: ignore[return-value]


def _delta_sizes(data: bytes) -> tuple[int, int] | None:
    """Validate Git delta instructions and return (base size, result size)."""
    offset = 0

    def varint() -> int | None:
        nonlocal offset
        value = 0
        shift = 0
        for _ in range(10):
            if offset >= len(data):
                return None
            byte = data[offset]
            offset += 1
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value
            shift += 7
        return None

    base_size = varint()
    result_size = varint()
    if base_size is None or result_size is None:
        return None
    produced = 0
    while offset < len(data):
        opcode = data[offset]
        offset += 1
        if opcode & 0x80:
            copy_offset = 0
            copy_size = 0
            for bit, shift in ((0x01, 0), (0x02, 8), (0x04, 16), (0x08, 24)):
                if opcode & bit:
                    if offset >= len(data):
                        return None
                    copy_offset |= data[offset] << shift
                    offset += 1
            for bit, shift in ((0x10, 0), (0x20, 8), (0x40, 16)):
                if opcode & bit:
                    if offset >= len(data):
                        return None
                    copy_size |= data[offset] << shift
                    offset += 1
            if copy_size == 0:
                copy_size = 0x10000
            if copy_offset + copy_size > base_size:
                return None
            produced += copy_size
        elif opcode:
            if offset + opcode > len(data):
                return None
            offset += opcode
            produced += opcode
        else:
            return None
        if produced > result_size:
            return None
    return (base_size, result_size) if produced == result_size else None


def _binary_sizes(chunks: tuple[BinaryChunk, BinaryChunk], old_size: int) -> bool:
    forward, reverse = chunks
    forward_delta = _delta_sizes(forward.data) if forward.kind == "delta" else None
    reverse_delta = _delta_sizes(reverse.data) if reverse.kind == "delta" else None
    if (forward.kind == "delta" and forward_delta is None) or (
        reverse.kind == "delta" and reverse_delta is None
    ):
        return False
    new_size = (
        len(forward.data) if forward.kind == "literal" else forward_delta[1]  # type: ignore[index]
    )
    reverse_old_size = (
        len(reverse.data) if reverse.kind == "literal" else reverse_delta[1]  # type: ignore[index]
    )
    if reverse_old_size != old_size:
        return False
    if forward_delta is not None and forward_delta[0] != old_size:
        return False
    if reverse_delta is not None and reverse_delta[0] != new_size:
        return False
    return True


def _git_blob(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()


def _literal_hashes(replacement: BinaryReplacement) -> bool:
    forward, reverse = replacement.chunks
    return (
        (forward.kind != "literal" or _git_blob(forward.data) == replacement.new_blob)
        and (reverse.kind != "literal" or _git_blob(reverse.data) == replacement.old_blob)
    )


def parse_existing_binary_replacement(document: str) -> BinaryReplacement | None:
    """Recognize one same-path binary body with no namespace/mode operation."""
    if type(document) is not str or "\x00" in document or "\r" in document:
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
        chunks = _decode_git_binary_body(lines[marker + 1 :])
        if chunks is None:
            return None
        return BinaryReplacement(
            path, "git-binary-patch", index_match.group(1), index_match.group(2),
            index_match.group(3), chunks,
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
            path, "binary-files-differ", index_match.group(1), index_match.group(2),
            index_match.group(3),
            (BinaryChunk("literal", b""), BinaryChunk("literal", b"")),
        )
    return None


def fixture_binary_readers(
    document: str,
    model: dict,
    test_ids: list[str],
    preimages: dict,
) -> set[int] | None:
    """Return manifest indices for a certified existing fixture replacement."""
    replacement = parse_existing_binary_replacement(document)
    pinned_blobs = valid_preimages(preimages, model, test_ids)
    if (
        replacement is None
        or pinned_blobs is None
        or pinned_blobs.get(replacement.path) != replacement.old_blob
        or replacement.old_blob == replacement.new_blob
        or replacement.mode != "100644"
        or (replacement.encoding == "git-binary-patch" and not _binary_sizes(
            replacement.chunks, preimages["sizes"].get(replacement.path, -1)
        ))
        or (
            replacement.encoding == "git-binary-patch"
            and not _literal_hashes(replacement)
        )
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


def fixture_binary_union(
    documents: list[str], model: dict, test_ids: list[str], preimages: dict
) -> set[int] | None:
    """Compose independently certified sections, rejecting duplicates or partial failure."""
    if type(documents) is not list or not documents:
        return None
    selected: set[int] = set()
    paths: set[str] = set()
    for document in documents:
        replacement = parse_existing_binary_replacement(document)
        readers = fixture_binary_readers(document, model, test_ids, preimages)
        if replacement is None or readers is None or replacement.path in paths:
            return None
        paths.add(replacement.path)
        selected.update(readers)
    return selected


def valid_preimages(document: object, model: dict, test_ids: list[str]) -> dict[str, str] | None:
    if (
        not isinstance(document, dict)
        or not isinstance(model, dict)
        or type(test_ids) is not list
        or any(type(test_id) is not str for test_id in test_ids)
        or set(document) != {
            "v", "revision", "model_sha256", "test_id_sha256", "paths",
            "sizes", "profile_sha256",
        }
    ):
        return None
    paths = document.get("paths")
    sizes = document.get("sizes")
    if (
        document.get("v") != 1
        or document.get("revision") != PINNED_REVISION
        or document.get("model_sha256") != SELECTOR_MODEL_SHA256
        or not isinstance(paths, dict)
        or not isinstance(sizes, dict)
        or set(paths) != set(model.get("x", {}))
        or set(sizes) != set(paths)
        or any(
            type(path) is not str
            or not _safe_path(path)
            or type(blob) is not str
            or re.fullmatch(r"[0-9a-f]{40}", blob) is None
            for path, blob in paths.items()
        )
        or any(
            type(path) is not str or type(size) is not int or size < 0
            for path, size in sizes.items()
        )
    ):
        return None
    test_digest = hashlib.sha256("\0".join(test_ids).encode()).hexdigest()
    if document.get("test_id_sha256") != test_digest:
        return None
    unsigned = {key: document[key] for key in document if key != "profile_sha256"}
    digest = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if document.get("profile_sha256") != digest:
        return None
    return paths
