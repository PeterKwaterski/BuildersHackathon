"""Select tests from answer-independent coverage, fixture, and symbol maps."""

import ast
import gzip
import json
import re
import sys
from pathlib import Path

from semantic import SemanticProof

DATA = Path("/data")
MODEL = Path(__file__).with_name("selector_model.json.gz")
SEMANTIC_SOURCES = Path(__file__).with_name("semantic_sources.json.gz")
MAX_WORKERS = 8
WORKER_COST_MS = 2_000
HUNK = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
COMPARISON_OPERATOR = re.compile(r"\bis\s+not\b|\bis\b|==|!=")
COMMENT_DIRECTIVE = re.compile(r"(?i)(coding\s*[:=]|type:|noqa|pragma|fmt:|pyright|mypy)")
PROCESS_SERIALIZATION_FILES = {"sqlglot/serde.py"}
_SEMANTIC_PROOF = None
_PINNED_SOURCES = None


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
    hunk = None
    old_line = 0
    addition_anchor = None
    in_hunk = False
    for line in patch.read_text().splitlines():
        if line.startswith("diff --git "):
            change = {
                "old": None,
                "new": None,
                "lines": set(),
                "payload": [],
                "removed": [],
                "added": [],
                "added_at": [],
                "hunks": [],
            }
            changes.append(change)
            hunk = None
            in_hunk = False
        elif change is None:
            continue
        elif match := HUNK.match(line):
            old_start = int(match.group(1))
            old_count = int(match.group(2) or 1)
            old_line = old_start + (old_count == 0)
            addition_anchor = None
            hunk = {"old_start": old_start, "old_count": old_count, "lines": []}
            change["hunks"].append(hunk)
            in_hunk = True
        elif not in_hunk and line.startswith("--- "):
            name = line[4:].split("\t", 1)[0]
            change["old"] = name[2:] if name.startswith("a/") else name
        elif not in_hunk and line.startswith("+++ "):
            name = line[4:].split("\t", 1)[0]
            change["new"] = name[2:] if name.startswith("b/") else name
        elif line.startswith("-"):
            hunk["lines"].append(("-", line[1:]))
            if addition_anchor is None:
                addition_anchor = old_line
            change["lines"].add(max(1, old_line))
            change["payload"].append(line[1:])
            change["removed"].append(line[1:])
            old_line += 1
        elif line.startswith("+"):
            hunk["lines"].append(("+", line[1:]))
            if addition_anchor is None:
                change["lines"].update((max(1, old_line - 1), max(1, old_line)))
            else:
                change["lines"].add(max(1, addition_anchor))
            change["payload"].append(line[1:])
            change["added"].append(line[1:])
            change["added_at"].append((old_line, line[1:]))
        elif line.startswith(" "):
            hunk["lines"].append((" ", line[1:]))
            old_line += 1
            addition_anchor = None
    return changes


def pinned_sources() -> dict[str, str]:
    global _PINNED_SOURCES
    if _PINNED_SOURCES is None:
        with gzip.open(SEMANTIC_SOURCES, "rt", encoding="utf-8") as source_file:
            _PINNED_SOURCES = json.load(source_file)
    return _PINNED_SOURCES


def comment_only_addition(change: dict) -> bool:
    return (
        bool(change["added"])
        and not change["removed"]
        and all(line.strip().startswith("#") for line in change["added"] if line.strip())
    )


def patched_source(change: dict, path: str) -> str | None:
    """Apply one file's unified hunks to its pinned source."""
    source = pinned_sources().get(path)
    if source is None:
        return None
    original = source.splitlines()
    result = []
    cursor = 0
    for hunk in change["hunks"]:
        start = max(
            0,
            hunk["old_start"] if hunk["old_count"] == 0 else hunk["old_start"] - 1,
        )
        if start < cursor or start > len(original):
            return None
        result.extend(original[cursor:start])
        cursor = start
        for marker, text in hunk["lines"]:
            if marker == "+":
                result.append(text)
                continue
            if cursor >= len(original) or original[cursor] != text:
                return None
            if marker == " ":
                result.append(original[cursor])
            cursor += 1
    result.extend(original[cursor:])
    ending = "\n" if source.endswith("\n") else ""
    return "\n".join(result) + ending


def invalid_python_patch(change: dict, path: str) -> bool:
    if not path.endswith(".py") or path not in pinned_sources():
        return False
    changed = patched_source(change, path)
    if changed is None:
        return True
    try:
        compile(changed, path, "exec", dont_inherit=True)
    except (SyntaxError, ValueError, OverflowError):
        return True
    return False


def inert_comment_addition(change: dict, path: str) -> bool:
    """Prove an added comment leaves the complete executable AST unchanged."""
    if not comment_only_addition(change) or any(
        COMMENT_DIRECTIVE.search(line) for line in change["added"]
    ):
        return False
    source = pinned_sources().get(path)
    changed = patched_source(change, path)
    if source is None or changed is None:
        return False
    try:
        original_tree = ast.parse(source, filename=path, type_comments=True)
        changed_tree = ast.parse(changed, filename=path, type_comments=True)
    except (SyntaxError, ValueError):
        return False
    return ast.dump(original_tree, include_attributes=False) == ast.dump(
        changed_tree, include_attributes=False
    )


def proven_identity_equality(change: dict, path: str, model: dict) -> bool:
    """Use source-derived proofs where identity and equality coincide."""
    if len(change["removed"]) != 1 or len(change["added"]) != 1:
        return False
    old, new = change["removed"][0], change["added"][0]
    old_operators = COMPARISON_OPERATOR.findall(old)
    new_operators = COMPARISON_OPERATOR.findall(new)
    if len(old_operators) != 1 or len(new_operators) != 1:
        return False
    positive = {"is", "=="}
    if (old_operators[0] in positive) != (new_operators[0] in positive):
        return False
    if COMPARISON_OPERATOR.sub("<comparison>", old) != COMPARISON_OPERATOR.sub(
        "<comparison>", new
    ):
        return False
    global _SEMANTIC_PROOF
    if _SEMANTIC_PROOF is None:
        _SEMANTIC_PROOF = SemanticProof(pinned_sources())
    return _SEMANTIC_PROOF.covers(path, change["lines"])


def mapped_set(model: dict, set_id: int) -> set[int]:
    return set(model["z"][set_id])


def selected_indices(patch: Path, model: dict, all_indices: set[int]) -> set[int]:
    selected: set[int] = set()
    changes = patch_changes(patch)
    if not changes:
        return set(all_indices)
    for change in changes:
        old_path = change["old"]
        new_path = change["new"]
        path = old_path if old_path not in (None, "/dev/null") else new_path
        if path in (None, "/dev/null"):
            selected.update(all_indices)
            continue
        if old_path != new_path:
            # New/deleted/renamed modules can invalidate imports independently
            # of any covered line in the old file.
            selected.update(all_indices)
            continue
        if invalid_python_patch(change, path):
            # Python parses the whole module before any test can import it.
            selected.update(all_indices)
            continue
        if comment_only_addition(change) and any(
            COMMENT_DIRECTIVE.search(line) for line in change["added"]
        ):
            selected.update(all_indices)
            continue
        if inert_comment_addition(change, path):
            continue
        if proven_identity_equality(change, path, model):
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

        if change["added"] and not change["removed"]:
            anchor_scopes = []
            for line in changed_lines:
                containing = [scope for scope in scopes if scope[0] <= line <= scope[1]]
                scope = min(containing, key=lambda item: item[1] - item[0]) if containing else None
                anchor_scopes.append(tuple(scope[:3]) if scope else None)
            if len(set(anchor_scopes)) > 1 and not comment_only_addition(change):
                # The insertion sits on a scope boundary. It can be module/class
                # code that prevents import, so neighboring function coverage is
                # not evidence of safety.
                selected.update(all_indices)
                continue

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
