"""The starter selector: run every test on every commit.

It never misses a failing test and it is slow. Everything you do from here
is deciding which tests a change cannot break.
"""

import json
import sys
from pathlib import Path

DATA = Path("/data")
MAX_WORKERS = 8
WORKER_COST_MS = 2_000


def split(tests: list[dict], worker_count: int) -> tuple[list[list[int]], int]:
    """Longest test first, each onto the worker with the least to do so far."""
    workers: list[list[int]] = [[] for _ in range(worker_count)]
    loads = [0] * worker_count
    for test in sorted(tests, key=lambda test: test["seconds"], reverse=True):
        lightest = loads.index(min(loads))
        workers[lightest].append(test["number"])
        loads[lightest] += round(test["seconds"] * 1_000)
    return workers, max(loads, default=0) + WORKER_COST_MS * worker_count


def best_split(tests: list[dict]) -> list[list[int]]:
    """Choose the worker count with the lowest simulated cost."""
    if not tests:
        return []

    candidates = (split(tests, count) for count in range(1, MAX_WORKERS + 1))
    return min(candidates, key=lambda candidate: candidate[1])[0]


def main() -> None:
    tests = json.loads((DATA / "tests.json").read_text())["tests"]
    workers = best_split(tests)
    for patch in sorted((DATA / "commits").glob("*.patch")):
        print(json.dumps({"commit": patch.stem, "workers": workers}))
    print(f"selected {len(tests)} tests on every commit", file=sys.stderr)


if __name__ == "__main__":
    main()
