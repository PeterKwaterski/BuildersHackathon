#!/usr/bin/env python3
"""Freeze a captured import-line JSON document as deterministic gzip bytes."""

from __future__ import annotations

import argparse
import gzip
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw = args.input.read_bytes()
    payload = json.loads(raw)
    if not (
        payload.get("v") == 2
        and payload.get("order") == "fresh-process-per-module"
        and payload.get("failures") == []
        and payload.get("target_test_references") == []
        and payload.get("parser_test_observers") == []
    ):
        raise SystemExit("capture is not a clean fresh-process profile")
    args.output.write_bytes(gzip.compress(raw, compresslevel=9, mtime=0))


if __name__ == "__main__":
    main()
