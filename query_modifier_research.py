"""Certified runtime gate for the public ``QUERY_MODIFIERS['where']`` deletion."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path


FEATURE_ENABLED = True
MODEL = Path(__file__).with_name("query_modifier_model.json.gz")
MODEL_GZIP_SHA256 = "cd800758e5768d595534f956f2ef499fa62fd7c39f9eefa125fa09c2b7604230"
TARGET_PATH = "sqlglot/expressions/core.py"
ALLOWED_KEYS = frozenset({"where"})


def load_model(
    path: Path,
    artifact_sha256: str,
    source_sha: str,
    test_ids: list[str],
) -> dict | None:
    if (
        type(artifact_sha256) is not str
        or len(artifact_sha256) != 64
        or type(source_sha) is not str
        or not isinstance(test_ids, list)
        or any(type(test_id) is not str for test_id in test_ids)
    ):
        return None
    try:
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != artifact_sha256:
            return None
        model = json.loads(gzip.decompress(raw).decode("utf-8"))
    except (
        OSError, EOFError, UnicodeError, json.JSONDecodeError, ValueError,
        TypeError, MemoryError, RecursionError,
    ):
        return None
    roster_digest = hashlib.sha256("\0".join(test_ids).encode()).hexdigest()
    def digest(value: object) -> bool:
        return (
            type(value) is str
            and len(value) == 64
            and all(character in "0123456789abcdef" for character in value)
        )

    if (
        not isinstance(model, dict)
        or set(model) != {"d", "n", "p", "s", "sha", "t", "v"}
        or model.get("v") != 1
        or model.get("sha") != source_sha
        or model.get("n") != len(test_ids)
        or model.get("t") != roster_digest
        or not digest(model.get("s"))
        or not isinstance(model.get("p"), dict)
        or not isinstance(model.get("d"), dict)
        or not model["d"]
    ):
        return None
    provenance = model["p"]
    if (
        set(provenance) != {"builder", "collector", "manifests", "traces"}
        or not digest(provenance.get("builder"))
        or not digest(provenance.get("collector"))
        or any(
            not isinstance(provenance.get(name), list)
            or len(provenance[name]) != 2
            or any(not digest(value) for value in provenance[name])
            or provenance[name] != sorted(set(provenance[name]))
            for name in ("manifests", "traces")
        )
    ):
        return None
    seen_digests = set()
    for key, entry in model["d"].items():
        if (
            type(key) is not str
            or not isinstance(entry, list)
            or len(entry) != 2
            or type(entry[0]) is not str
            or not digest(entry[0])
            or entry[0] in seen_digests
            or not isinstance(entry[1], list)
            or any(type(index) is not int or index < 0 or index >= len(test_ids) for index in entry[1])
            or entry[1] != sorted(set(entry[1]))
        ):
            return None
        seen_digests.add(entry[0])
    return model


def readers(path: str, original: str, changed: str, model: dict | None) -> set[int] | None:
    if (
        not FEATURE_ENABLED
        or path != TARGET_PATH
        or type(original) is not str
        or type(changed) is not str
        or not isinstance(model, dict)
        or hashlib.sha256(original.encode()).hexdigest() != model.get("s")
    ):
        return None
    changed_digest = hashlib.sha256(changed.encode()).hexdigest()
    data = model.get("d")
    if not isinstance(data, dict):
        return None
    matches = [
        entry for key, entry in data.items()
        if key in ALLOWED_KEYS
        and isinstance(entry, list)
        and len(entry) == 2
        and entry[0] == changed_digest
    ]
    if len(matches) != 1:
        return None
    return set(matches[0][1])
