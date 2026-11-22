"""Rank answer-free selector output by packed test cost."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def packed_cost(tests: list[dict], workers: int) -> float:
    loads = [0.0] * workers
    for test in sorted(tests, key=lambda item: item["seconds"], reverse=True):
        index = loads.index(min(loads))
        loads[index] += test["seconds"]
    return max(loads, default=0.0) + 2.0 * workers


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--set", required=True)
    args = parser.parse_args()
    tests = json.loads(args.tests.read_text())["tests"]
    by_number = {test["number"]: test for test in tests}
    rows = []
    for line in sys.stdin:
        document = json.loads(line)
        selected = [
            by_number[number]
            for worker in document["workers"]
            for number in worker
        ]
        cost = (
            min(packed_cost(selected, workers) for workers in range(1, 9))
            if selected
            else 0.0
        )
        rows.append((cost, len(selected), document["commit"]))
    for cost, count, commit in sorted(rows, reverse=True):
        print(f"{cost:09.3f}\t{count:04d}\t{args.set}\t{commit}")


if __name__ == "__main__":
    main()
