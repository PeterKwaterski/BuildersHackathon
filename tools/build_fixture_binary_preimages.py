#!/usr/bin/env python3
"""Build exact Git-blob preimages for authenticated fixture paths."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import subprocess
from pathlib import Path


PINNED = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def blob(value: bytes) -> str:
    return hashlib.sha1(f"blob {len(value)}\0".encode() + value).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    revision = subprocess.run(
        ["git", "-C", str(args.source), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    if revision != PINNED:
        raise SystemExit("wrong source revision")
    model_bytes = args.model.read_bytes()
    model = json.loads(gzip.decompress(model_bytes))
    if model.get("sha") != PINNED or not isinstance(model.get("x"), dict):
        raise SystemExit("wrong model")
    paths = {}
    sizes = {}
    for relative in sorted(model["x"]):
        path = args.source / relative
        if not path.is_file():
            raise SystemExit(f"missing fixture: {relative}")
        data = path.read_bytes()
        paths[relative] = blob(data)
        sizes[relative] = len(data)
    document = {
        "v": 1,
        "revision": revision,
        "model_sha256": sha(model_bytes),
        "test_id_sha256": sha("\0".join(model["t"]).encode()),
        "paths": paths,
        "sizes": sizes,
    }
    document["profile_sha256"] = sha(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    )
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    args.output.write_bytes(gzip.compress(encoded, compresslevel=9, mtime=0))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
