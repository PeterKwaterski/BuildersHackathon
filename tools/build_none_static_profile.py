#!/usr/bin/env python3
"""Build the trace-free exact-domain certificate for two None comparisons."""

from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from none_comparison_envelopes import SITES, validate


PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"
PINNED_TREE = "6606fc5229c882bd0cf8f9ba79503e9e10d084f7"
REFLECTION_GZIP_SHA256 = "8891bd314a2d4eab581c1cad979af7fab828cbda254f84dc57dbc73bfd16a200"
REPLACEMENTS = {
    ("sqlglot/optimizer/pushdown_projections.py", 496): (
        "        if journal is not None:",
        "        if journal != None:",
    ),
    ("sqlglot/executor/table.py", 109): (
        "            if columns is not None",
        "            if columns != None",
    ),
}


def test_rosters(document: object) -> tuple[list[str], list[str]]:
    if not isinstance(document, dict) or set(document) != {"tests", "skipped"}:
        raise SystemExit("test manifest schema mismatch")
    tests = document["tests"]
    skipped = document["skipped"]
    if (
        not isinstance(tests, list)
        or any(not isinstance(row, dict) or type(row.get("id")) is not str for row in tests)
        or not isinstance(skipped, list)
        or any(type(test_id) is not str for test_id in skipped)
    ):
        raise SystemExit("test manifest roster mismatch")
    test_ids = [row["id"] for row in tests]
    if len(test_ids) != len(set(test_ids)) or len(skipped) != len(set(skipped)) or set(test_ids) & set(skipped):
        raise SystemExit("test manifest rosters are not disjoint and unique")
    return test_ids, skipped


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--reflection", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _reflection_readers(document: dict, path: str, line: int, count: int) -> list[int]:
    result: set[int] = set()
    for entry in document.get("d", {}).get(path, ()):
        if (
            isinstance(entry, list)
            and len(entry) == 5
            and entry[3] in {"observed", "import-read"}
            and type(entry[0]) is int
            and type(entry[1]) is int
            and entry[0] <= line <= entry[1]
            and isinstance(entry[4], list)
        ):
            result.update(entry[4])
    if any(type(index) is not int or not 0 <= index < count for index in result):
        raise SystemExit("invalid reflection-reader index")
    return sorted(result)


def _operator_only(original: str, prospective: str, line: int) -> None:
    """Require exactly one IsNot -> NotEq AST mutation at the pinned line."""

    before = ast.parse(original, type_comments=True)
    after = ast.parse(prospective, type_comments=True)
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
        raise SystemExit("comparison operator shape mismatch")
    before_nodes[0].ops[0] = ast.NotEq()
    if ast.dump(before, include_attributes=False) != ast.dump(after, include_attributes=False):
        raise SystemExit("prospective source changes more than the operator")


def build(source: Path, tests_path: Path, reflection_path: Path) -> dict:
    source = source.resolve()
    revision = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    tree = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD^{tree}"], text=True
    ).strip()
    dirty = subprocess.check_output(
        ["git", "-C", str(source), "status", "--porcelain=v1", "--untracked-files=no"],
        text=True,
    )
    if revision != PINNED_SHA or tree != PINNED_TREE or dirty:
        raise SystemExit("pinned source identity mismatch")

    proof = validate(source)
    tests, skipped = test_rosters(json.loads(tests_path.read_text()))
    test_digest = _sha_bytes("\0".join(tests).encode())
    reflection_raw = reflection_path.read_bytes()
    if _sha_bytes(reflection_raw) != REFLECTION_GZIP_SHA256:
        raise SystemExit("reflection artifact digest mismatch")
    reflection = json.loads(gzip.decompress(reflection_raw))
    if (
        set(reflection) != {"d", "n", "p", "sha", "t", "v"}
        or reflection["v"] != 1
        or reflection["sha"] != revision
        or reflection["n"] != len(tests)
        or reflection["t"] != test_digest
    ):
        raise SystemExit("reflection artifact identity mismatch")

    sites = []
    for path, line in sorted(SITES):
        if (path, line) not in REPLACEMENTS:
            raise SystemExit("unrecognized static-domain site")
        original_line, added_line = REPLACEMENTS[(path, line)]
        raw = (source / path).read_bytes()
        text = raw.decode("utf-8")
        lines = text.splitlines()
        if line > len(lines) or lines[line - 1] != original_line:
            raise SystemExit("pinned source line mismatch")
        prospective_lines = list(lines)
        prospective_lines[line - 1] = added_line
        prospective = "\n".join(prospective_lines) + ("\n" if text.endswith("\n") else "")
        _operator_only(text, prospective, line)
        readers = _reflection_readers(reflection, path, line, len(tests))
        sites.append(
            {
                "added": added_line,
                "domain": SITES[(path, line)],
                "line": line,
                "path": path,
                "prospective_sha256": _sha_bytes(prospective.encode()),
                "reflection_retain": readers,
                "removed": original_line,
                "source_sha256": _sha_bytes(raw),
            }
        )

    builder = Path(__file__).read_bytes()
    envelope = Path(__file__).parents[1] / "none_comparison_envelopes.py"
    return {
        "builder_sha256": _sha_bytes(builder),
        "envelope_sha256": _sha_bytes(envelope.read_bytes()),
        "format": "none-static-profile-v3",
        "policy": {
            "admit": "closed-fixed-tree-exact-builtin-domain",
            "mutation": "one-file-one-hunk-one-line-IsNot-to-NotEq",
            "reflection": "retain-all-authenticated-source-readers",
        },
        "proof_sha256": proof,
        "reflection_sha256": REFLECTION_GZIP_SHA256,
        "sites": sites,
        "skipped_sha256": _sha_bytes("\0".join(skipped).encode()),
        "source_sha": revision,
        "source_tree": tree,
        "test_count": len(tests),
        "tests_sha256": test_digest,
        "version": 3,
    }


def main() -> None:
    args = _arguments()
    payload = build(args.source, args.tests, args.reflection)
    raw = _json_bytes(payload)
    args.output.write_bytes(gzip.compress(raw, compresslevel=9, mtime=0))
    print(
        json.dumps(
            {
                "artifact_sha256": _sha_bytes(args.output.read_bytes()),
                "proof_sha256": payload["proof_sha256"],
                "sites": len(payload["sites"]),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
