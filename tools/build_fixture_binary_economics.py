#!/usr/bin/env python3
"""Build answer-free per-fixture owner and packed-cost economics."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path


WORKER_COST_MS = 2_000


def packed(indices: set[int], tests: list[dict], ids: list[str]) -> int:
    by_id = {test["id"]: test for test in tests}
    selected = [by_id[ids[index]] for index in indices]
    best = None
    for count in range(1, 9):
        loads = [0] * count
        for test in sorted(selected, key=lambda item: item["seconds"], reverse=True):
            lightest = loads.index(min(loads))
            loads[lightest] += round(test["seconds"] * 1_000)
        cost = max(loads, default=0) + WORKER_COST_MS * count
        best = cost if best is None else min(best, cost)
    return best or 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    model = json.loads(gzip.decompress(args.model.read_bytes()))
    tests = json.loads(args.tests.read_text())["tests"]
    if [test["id"] for test in tests] != model["t"]:
        raise SystemExit("test manifest/model order mismatch")
    all_cost = packed(set(range(len(tests))), tests, model["t"])
    paths = {}
    executor = {
        index for index, test_id in enumerate(model["t"])
        if test_id.startswith("tests/test_executor.py::TestExecutor::")
    }
    for path, set_id in sorted(model["x"].items()):
        owners = set(model["z"][set_id])
        if path.endswith(".csv.gz") and path.startswith(
            ("tests/fixtures/optimizer/tpc-h/", "tests/fixtures/optimizer/tpc-ds/")
        ):
            owners.update(executor)
        cost = packed(owners, tests, model["t"])
        paths[path] = {
            "owners": sorted(owners),
            "owner_ids": [model["t"][index] for index in sorted(owners)],
            "owner_count": len(owners),
            "packed_ms": cost,
            "saving_ms": all_cost - cost,
        }
    document = {"v": 1, "all_packed_ms": all_cost, "paths": paths}
    unsigned = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    document["profile_sha256"] = hashlib.sha256(unsigned).hexdigest()
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    args.output.write_bytes(gzip.compress(encoded, compresslevel=9, mtime=0))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
