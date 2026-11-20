"""Select tests from answer-independent coverage, fixture, and symbol maps."""

import gzip
import json
import re
import sys
from pathlib import Path

DATA = Path("/data")
MODEL = Path(__file__).with_name("selector_model.json.gz")
MAX_WORKERS = 8
WORKER_COST_MS = 2_000
HUNK = re.compile(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
COMMENT_DIRECTIVE = re.compile(r"(?i)(coding\s*[:=]|type:|noqa|pragma|fmt:|pyright|mypy)")
PROCESS_SERIALIZATION_FILES = {"sqlglot/serde.py"}


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


def patch_changes(patch: Path) -> list[dict]:
    """Return each changed path and its affected line anchors in the base tree."""
    changes: list[dict] = []
    change = None
    old_line = 0
    addition_anchor = None
    for line in patch.read_text().splitlines():
        if line.startswith("diff --git "):
            change = {
                "old": None,
                "new": None,
                "lines": set(),
                "payload": [],
                "removed": [],
                "added": [],
            }
            changes.append(change)
        elif change is None:
            continue
        elif line.startswith("--- "):
            name = line[4:].split("\t", 1)[0]
            change["old"] = name[2:] if name.startswith("a/") else name
        elif line.startswith("+++ "):
            name = line[4:].split("\t", 1)[0]
            change["new"] = name[2:] if name.startswith("b/") else name
        elif match := HUNK.match(line):
            old_line = int(match.group(1))
            addition_anchor = None
        elif line.startswith("-") and not line.startswith("---"):
            if addition_anchor is None:
                addition_anchor = old_line
            change["lines"].add(max(1, old_line))
            change["payload"].append(line[1:])
            change["removed"].append(line[1:])
            old_line += 1
        elif line.startswith("+") and not line.startswith("+++"):
            change["lines"].add(max(1, addition_anchor or old_line))
            change["payload"].append(line[1:])
            change["added"].append(line[1:])
        elif line.startswith(" "):
            old_line += 1
            addition_anchor = None
    return changes


def safe_python_comments(change: dict, path: str) -> bool:
    """Recognize comments with no Python decoding or tooling semantics."""
    payload = [line.strip() for line in change["payload"] if line.strip()]
    return (
        path.endswith(".py")
        and payload
        and min(change["lines"], default=0) > 2
        and all(line.startswith("#") for line in payload)
        and not any(COMMENT_DIRECTIVE.search(line) for line in payload)
    )


def mapped_set(model: dict, set_id: int) -> set[int]:
    return set(model["z"][set_id])


def selected_indices(patch: Path, model: dict, all_indices: set[int]) -> set[int]:
    selected: set[int] = set()
    for change in patch_changes(patch):
        old_path = change["old"]
        new_path = change["new"]
        path = old_path if old_path not in (None, "/dev/null") else new_path
        if path in (None, "/dev/null"):
            selected.update(all_indices)
            continue
        if safe_python_comments(change, path):
            continue

        fixture_set = model["x"].get(path)
        if fixture_set is not None:
            selected.update(mapped_set(model, fixture_set))
            continue
        if path.startswith("tests/fixtures/"):
            # An unseen fixture can be shared or loaded during class setup.
            selected.update(all_indices)
            continue

        entry = model["f"].get(path)
        if entry is None and new_path not in (None, "/dev/null"):
            entry = model["f"].get(new_path)
        if entry is None:
            selected.update(all_indices)
            continue

        changed_lines = change["lines"]
        line_sets = {line: set_id for line, set_id in entry.get("l", ())}
        scopes = entry.get("s", ())
        for line in changed_lines:
            containing = [scope for scope in scopes if scope[0] <= line <= scope[1]]
            if containing:
                scope = min(containing, key=lambda item: item[1] - item[0])
                selected.update(mapped_set(model, scope[3]))
                continue

            nearby = [line_sets[near] for near in (line - 1, line, line + 1) if near in line_sets]
            if nearby:
                for set_id in nearby:
                    selected.update(mapped_set(model, set_id))
            else:
                # Import-time statements and uncovered module code have no
                # per-test context, so retain the conservative file fallback.
                selected.update(mapped_set(model, entry["f"]))

        if not changed_lines or path in PROCESS_SERIALIZATION_FILES:
            selected.update(mapped_set(model, entry["f"]))

        if any(
            start <= line <= end
            for start, end in entry.get("i", ())
            for line in changed_lines
        ):
            importer_set = model.get("r", {}).get(path)
            if importer_set is not None:
                selected.update(mapped_set(model, importer_set))

        matched_assignment = False
        for start, end, set_id in model.get("a", {}).get(path, ()):
            if any(start <= line <= end for line in changed_lines):
                selected.update(mapped_set(model, set_id))
                matched_assignment = True

        parts = Path(path).parts
        if (
            not matched_assignment
            and len(parts) >= 3
            and parts[0] == "sqlglot"
            and parts[1] in {"dialects", "parsers", "generators", "typing"}
            and not any(scope[0] <= line <= scope[1] for scope in scopes for line in changed_lines)
        ):
            dialect_set = model.get("q", {}).get(Path(path).stem.lower())
            if dialect_set is not None:
                selected.update(mapped_set(model, dialect_set))
    return selected


def main() -> None:
    tests = json.loads((DATA / "tests.json").read_text())["tests"]
    tests_by_id = {test["id"]: test for test in tests}
    with gzip.open(MODEL, "rt", encoding="utf-8") as model_file:
        model = json.load(model_file)
    mapped_tests = [tests_by_id.get(test_id) for test_id in model["t"]]
    all_indices = {index for index, test in enumerate(mapped_tests) if test is not None}

    selection_count = 0
    for patch in sorted((DATA / "commits").glob("*.patch")):
        indices = selected_indices(patch, model, all_indices)
        selected = [mapped_tests[index] for index in indices if mapped_tests[index] is not None]
        selection_count += len(selected)
        workers = best_split(selected)
        print(
            json.dumps(
                {"commit": patch.stem, "workers": workers},
                separators=(",", ":"),
            )
        )
    print(
        f"selected {selection_count} tests across "
        f"{len(list((DATA / 'commits').glob('*.patch')))} commits",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
