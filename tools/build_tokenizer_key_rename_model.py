#!/usr/bin/env python3
"""Build a compact attempted-key model from authenticated full KEYWORDS traces."""

from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from build_tokenizer_keyword_model import load_signed_index
from tokenizer_keyword_runtime import load_context


BASE_MODEL_SHA256 = "28a5241f3d8006f075f283ac8e59f46793be482457bece67de97a4ecdd3db230"
SOURCES_SHA256 = "f453c6266c20edcc9ba7127ebedde0bdf45d44633279352c2daafe1fa123da5f"
TEST_DIGEST = "31a019981e19c3d1b18d929066da7e118fcf3d57696a360f7b9d31ce3a87bc89"
SOURCE_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compact_bytes(document: dict) -> bytes:
    return gzip.compress(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode(),
        compresslevel=9,
        mtime=0,
    )


def key_static_audit(sources: dict[str, str], base_model: dict) -> dict:
    """Bind every key-set observer and reject unclassified KEYWORDS use."""
    expected_reads = base_model["static"]["document"]["reads"]
    expected_pops = base_model["static"]["document"]["pops"]
    reads = []
    pops = []
    pop_keys = set()
    whole_map = []

    def chain(node: ast.AST) -> str | None:
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
            return ".".join(reversed(parts))
        return None

    for path, source in sorted(sources.items()):
        if not path.endswith(".py") or not path.startswith(("sqlglot/", "tests/")):
            continue
        tree = ast.parse(source, filename=path, type_comments=True)
        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        for node in ast.walk(tree):
            is_attr = isinstance(node, ast.Attribute) and node.attr == "KEYWORDS"
            is_name = isinstance(node, ast.Name) and node.id == "KEYWORDS"
            if not (is_attr or is_name):
                continue
            parent = parents.get(node)
            node_chain = chain(node) or "KEYWORDS"
            pop_attr = (
                parent
                if isinstance(parent, ast.Attribute)
                and parent.value is node
                and parent.attr == "pop"
                else None
            )
            pop_call = parents.get(pop_attr) if pop_attr is not None else None
            if isinstance(pop_call, ast.Call) and pop_call.func is pop_attr:
                record = [path, node.lineno, node.col_offset, node_chain, "pop"]
                pops.append(record)
                if (
                    len(pop_call.args) != 1
                    or pop_call.keywords
                    or not isinstance(pop_call.args[0], ast.Constant)
                    or type(pop_call.args[0].value) is not str
                ):
                    whole_map.append([path, node.lineno, "nonliteral-pop"])
                else:
                    pop_keys.add(pop_call.args[0].value)
                continue
            # Bare KEYWORDS names are assignment targets in the class bodies.
            # The reviewed static contract records Attribute reads only.
            if is_name:
                continue
            kind = type(parent).__name__ if parent is not None else "None"
            reads.append([path, node.lineno, node.col_offset, node_chain, kind])

            allowed = False
            if isinstance(parent, ast.Starred) and isinstance(parents.get(parent), (ast.List, ast.Tuple, ast.Set)):
                allowed = path == "sqlglot/tokens.py" and node_chain == "cls.KEYWORDS"
            elif isinstance(parent, ast.keyword):
                allowed = (
                    path == "sqlglot/tokens.py"
                    and parent.arg == "keywords"
                    and node_chain == "self.KEYWORDS"
                )
            elif isinstance(parent, ast.Compare):
                constants = {
                    value.value
                    for value in ast.walk(parent)
                    if isinstance(value, ast.Constant) and type(value.value) is str
                }
                hint_start = any(
                    isinstance(value, ast.Attribute)
                    and value.attr == "HINT_START"
                    for value in ast.walk(parent)
                )
                allowed = (constants <= {"/*+", "(+)"} and bool(constants)) or (
                    path == "sqlglot/tokens.py"
                    and node_chain == "cls.KEYWORDS"
                    and hint_start
                )
            elif isinstance(parent, ast.Dict):
                allowed = node in parent.values and any(
                    key is None and value is node
                    for key, value in zip(parent.keys, parent.values)
                )
            elif isinstance(parent, ast.Attribute) and parent.value is node and parent.attr == "copy":
                call = parents.get(parent)
                allowed = isinstance(call, ast.Call) and call.func is parent and not call.args and not call.keywords
            if not allowed:
                whole_map.append([path, node.lineno, node_chain, kind])

    if sorted(reads) != expected_reads or sorted(pops) != expected_pops or whole_map:
        raise SystemExit(
            f"KEYWORDS key-observer closure changed: reads={len(reads)} "
            f"pops={len(pops)} whole={whole_map[:2]}"
        )
    relevant = {
        path: hashlib.sha256(sources[path].encode()).hexdigest()
        for path in (
            "sqlglot/tokens.py",
            "sqlglot/tokenizer_core.py",
            "sqlglot/dialects/dialect.py",
        )
    }
    return {
        "reads_sha256": digest(sorted(reads)),
        "pops_sha256": digest(sorted(pops)),
        "pop_keys": sorted(pop_keys),
        "whole_map_observers": whole_map,
        "relevant_source_sha256": relevant,
        "base_static_sha256": base_model["static"]["sha256"],
        "theorem": "single-word-old-prefix-terminal-closure-v3",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--base-model", type=Path, required=True)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    evidence = args.evidence_dir
    index_path = evidence / "evidence-index.json"
    signature_path = evidence / "evidence-index.signature.json"
    index = load_signed_index(index_path, signature_path, targeted_smoke=False)
    base_raw = args.base_model.read_bytes()
    sources_raw = args.sources.read_bytes()
    if file_digest(args.base_model) != BASE_MODEL_SHA256 or file_digest(args.sources) != SOURCES_SHA256:
        raise SystemExit("wrong base model or semantic source archive")
    base_context = load_context(base_raw, BASE_MODEL_SHA256, sources_raw, SOURCES_SHA256)
    if base_context is None:
        raise SystemExit("authenticated base KEYWORDS model failed validation")
    base_model = json.loads(gzip.decompress(base_raw))
    sources = json.loads(gzip.decompress(sources_raw))

    tests_document = json.loads(args.tests.read_text())
    tests = tests_document.get("tests")
    skipped = tests_document.get("skipped")
    if (
        not isinstance(tests, list)
        or len(tests) != 1620
        or not isinstance(skipped, list)
        or len(skipped) != 1
    ):
        raise SystemExit("wrong test roster")
    test_ids = [test["id"] for test in tests]
    if digest(test_ids) == TEST_DIGEST:
        raise AssertionError("NUL digest must not be confused with JSON digest")
    if hashlib.sha256("\0".join(test_ids).encode()).hexdigest() != TEST_DIGEST:
        raise SystemExit("wrong ordered test roster")
    test_number = {test["id"]: test["number"] for test in tests}
    if len(test_number) != 1620 or set(test_number.values()) != set(range(1620)):
        raise SystemExit("test numbering is not canonical")

    documents = {}
    manifests = {}
    names = {
        "normal": ("normal.trace.json", "normal.manifest.json"),
        "synchronous-worker": ("sync.trace.json", "sync.manifest.json"),
    }
    for mode, (trace_name, manifest_name) in names.items():
        trace_path = evidence / trace_name
        manifest_path = evidence / manifest_name
        artifact = index["artifacts"][mode]
        if (
            file_digest(trace_path) != artifact["trace_sha256"]
            or trace_path.stat().st_size != artifact["trace_size"]
            or file_digest(manifest_path) != artifact["manifest_sha256"]
            or manifest_path.stat().st_size != artifact["manifest_size"]
        ):
            raise SystemExit(f"{mode} trace/manifest differs from signed index")
        trace = json.loads(trace_path.read_text())
        manifest = json.loads(manifest_path.read_text())
        if trace.get("mode") != mode or manifest.get("mode") != mode:
            raise SystemExit("mode mismatch")
        if (
            manifest.get("exitstatus") != 0
            or manifest.get("child_complete") is not True
            or manifest.get("child_starts") != manifest.get("child_logs")
            or manifest.get("child_starts") != manifest.get("child_completions")
            or manifest.get("tests") != sorted([*test_ids, *skipped])
            or trace.get("test_digest") != TEST_DIGEST
            or trace.get("source_sha") != SOURCE_SHA
            or trace.get("tests_sha256") != index["pins"]["tests_sha256"]
            or trace.get("python_environment_sha256")
            != index["pins"]["python_environment_sha256"]
            or trace.get("inventory_sha256") != base_model["inventory"]
            or trace.get("static_sha256") != base_model["static"]["sha256"]
            or trace.get("operations_sha256") != base_model["operations"]["sha256"]
        ):
            raise SystemExit(f"{mode} provenance mismatch")
        documents[mode] = trace.get("events")
        manifests[mode] = manifest

    normal = documents["normal"]
    synchronous = documents["synchronous-worker"]
    if not isinstance(normal, dict) or normal != synchronous or len(normal) != 8275:
        raise SystemExit("attempted-key maps are not complete and mode-identical")

    event_indices = {}
    poison_keys = set()
    for key, owners in sorted(normal.items()):
        if type(key) is not str or not isinstance(owners, list) or owners != sorted(set(owners)):
            raise SystemExit("malformed attempted-key event")
        indices = []
        for owner in owners:
            if owner in {"__IMPORT__", "__NO_TEST__"} or owner in skipped:
                poison_keys.add(key)
            elif owner not in test_number:
                raise SystemExit(f"unknown event owner for {key!r}")
            else:
                indices.append(test_number[owner])
        event_indices[key] = sorted(indices)
    global_poison = "__NON_STRING__" in normal
    if global_poison:
        poison_keys.update(event_indices)

    audit = key_static_audit(sources, base_model)
    model = {
        "v": 1,
        "status": "READY-FOR-SHIP",
        "sha": SOURCE_SHA,
        "n": 1620,
        "t": TEST_DIGEST,
        "inventory": base_model["d"],
        "events": event_indices,
        "poison_keys": sorted(poison_keys),
        "global_poison": global_poison,
        "audit": audit,
        "evidence": {
            "index_sha256": file_digest(index_path),
            "signature_sha256": file_digest(signature_path),
            "event_maps_sha256": digest(documents),
            "mode_event_sha256": digest(normal),
            "base_model_sha256": BASE_MODEL_SHA256,
            "sources_sha256": SOURCES_SHA256,
            "traces": {
                mode: {
                    "trace_sha256": index["artifacts"][mode]["trace_sha256"],
                    "manifest_sha256": index["artifacts"][mode]["manifest_sha256"],
                    "bundle_sha256": index["artifacts"][mode]["bundle_sha256"],
                    "child_starts": manifests[mode]["child_starts"],
                    "child_tokens_sha256": manifests[mode]["child_tokens_sha256"],
                }
                for mode in names
            },
            "pins": index["pins"],
        },
        "builder_sha256": file_digest(Path(__file__)),
    }
    args.output.write_bytes(compact_bytes(model))
    print(
        f"wrote {args.output}: {len(event_indices)} keys, "
        f"{len(poison_keys)} poisoned, {args.output.stat().st_size} bytes"
    )


if __name__ == "__main__":
    main()
