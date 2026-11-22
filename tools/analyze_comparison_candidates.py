#!/usr/bin/env python3
"""Answer-free census of patches isolated to one comparison expression."""

from __future__ import annotations

import ast
import argparse
import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import selector


VALIDATION = Path("/home/silverdisk/public-matchaluvrs-readonly/validation")
def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--selection-output", type=Path)
    parser.add_argument("--tests", type=Path, default=ROOT / "sample" / "tests.json")
    parser.add_argument("--trace", type=Path, action="append", default=[])
    return parser.parse_args()


def nodes_with_paths(tree: ast.AST):
    pending = [(tree, ())]
    while pending:
        node, path = pending.pop()
        yield node, path
        children = []
        for field, value in ast.iter_fields(node):
            if isinstance(value, ast.AST):
                children.append((value, (*path, (field, None))))
            elif isinstance(value, list):
                children.extend(
                    (item, (*path, (field, index)))
                    for index, item in enumerate(value)
                    if isinstance(item, ast.AST)
                )
        pending.extend(reversed(children))


def follow(tree: ast.AST, path):
    node = tree
    for field, index in path:
        value = getattr(node, field, None)
        if index is None:
            node = value
        elif isinstance(value, list) and index < len(value):
            node = value[index]
        else:
            return None
        if not isinstance(node, ast.AST):
            return None
    return node


def replace(tree: ast.AST, path, value: ast.AST) -> None:
    parent = tree
    for field, index in path[:-1]:
        child = getattr(parent, field)
        parent = child if index is None else child[index]
    field, index = path[-1]
    if index is None:
        setattr(parent, field, value)
    else:
        getattr(parent, field)[index] = value


def literal(node: ast.AST) -> bool:
    try:
        ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return False
    return True


def main() -> None:
    args = arguments()
    outputs = {}
    if args.selection_output:
        outputs = {
            row["commit"]: row
            for line in args.selection_output.read_text().splitlines()
            if line.startswith("{")
            for row in [json.loads(line)]
        }
    tests = json.loads(args.tests.read_text())["tests"]
    durations = {test["number"]: test["seconds"] for test in tests}

    def cost(row):
        workers = [worker for worker in row.get("workers", ()) if worker]
        return max(
            (sum(durations[number] for number in worker) for worker in workers),
            default=0,
        ) + 2 * len(workers)

    candidates = []
    for group in sorted(path for path in VALIDATION.iterdir() if path.is_dir()):
        for patch in sorted((group / "commits").glob("*.patch")):
            key = f"{group.name}__{patch.stem}"
            row = outputs.get(key, {})
            try:
                changes = selector.patch_changes(patch)
            except (OSError, UnicodeError, ValueError, TypeError):
                continue
            if len(changes) != 1:
                continue
            change = changes[0]
            relative = change.get("old")
            if (
                not isinstance(relative, str)
                or change.get("new") != relative
                or not relative.startswith("sqlglot/")
                or not relative.endswith(".py")
            ):
                continue
            original = selector.pinned_sources().get(relative)
            prospective = selector.patched_source(change, relative)
            if original is None or prospective is None:
                continue
            try:
                old_tree = ast.parse(original, type_comments=True)
                new_tree = ast.parse(prospective, type_comments=True)
            except (SyntaxError, ValueError):
                continue

            for compare, path in nodes_with_paths(old_tree):
                if not isinstance(compare, ast.Compare):
                    continue
                if not any(
                    compare.lineno <= line <= (compare.end_lineno or compare.lineno)
                    for line in change.get("lines", ())
                ):
                    continue
                changed_compare = follow(new_tree, path)
                if not isinstance(changed_compare, ast.Compare):
                    continue

                old_without = copy.deepcopy(old_tree)
                new_without = copy.deepcopy(new_tree)
                replace(old_without, path, ast.Constant(value="__COMPARE__"))
                replace(new_without, path, ast.Constant(value="__COMPARE__"))
                if ast.dump(old_without, include_attributes=False) != ast.dump(
                    new_without, include_attributes=False
                ):
                    continue

                old_ops = [type(operator).__name__ for operator in compare.ops]
                new_ops = [type(operator).__name__ for operator in changed_compare.ops]
                op_tree = copy.deepcopy(old_tree)
                changed_op_tree = copy.deepcopy(new_tree)
                old_compare = follow(op_tree, path)
                new_compare = follow(changed_op_tree, path)
                assert isinstance(old_compare, ast.Compare)
                assert isinstance(new_compare, ast.Compare)
                if len(old_compare.ops) == len(new_compare.ops):
                    old_compare.ops = [ast.Eq() for _ in old_compare.ops]
                    new_compare.ops = [ast.Eq() for _ in new_compare.ops]
                op_only = old_ops != new_ops and ast.dump(
                    op_tree, include_attributes=False
                ) == ast.dump(changed_op_tree, include_attributes=False)

                combined_tree = copy.deepcopy(old_tree)
                changed_combined_tree = copy.deepcopy(new_tree)
                old_compare = follow(combined_tree, path)
                new_compare = follow(changed_combined_tree, path)
                assert isinstance(old_compare, ast.Compare)
                assert isinstance(new_compare, ast.Compare)
                old_operands = [old_compare.left, *old_compare.comparators]
                new_operands = [new_compare.left, *new_compare.comparators]
                changed_literals = []
                if len(old_operands) == len(new_operands):
                    for index, (left, right) in enumerate(
                        zip(old_operands, new_operands)
                    ):
                        if (
                            ast.dump(left, include_attributes=False)
                            != ast.dump(right, include_attributes=False)
                            and literal(left)
                            and literal(right)
                        ):
                            changed_literals.append(index)
                            sentinel = ast.Constant(value="__LITERAL__")
                            if index == 0:
                                old_compare.left = sentinel
                                new_compare.left = copy.deepcopy(sentinel)
                            else:
                                old_compare.comparators[index - 1] = sentinel
                                new_compare.comparators[index - 1] = copy.deepcopy(
                                    sentinel
                                )
                if len(old_compare.ops) == len(new_compare.ops):
                    old_compare.ops = [ast.Eq() for _ in old_compare.ops]
                    new_compare.ops = [ast.Eq() for _ in new_compare.ops]
                combined = bool(old_ops != new_ops or changed_literals) and ast.dump(
                    combined_tree, include_attributes=False
                ) == ast.dump(changed_combined_tree, include_attributes=False)

                candidates.append(
                    {
                        "commit": key,
                        "cost": cost(row),
                        "path": relative,
                        "line": compare.lineno,
                        "coordinates": [
                            compare.lineno,
                            compare.col_offset,
                            compare.end_lineno,
                            compare.end_col_offset,
                        ],
                        "old_ops": old_ops,
                        "new_ops": new_ops,
                        "changed_literals": changed_literals,
                        "op_only": op_only,
                        "combined": combined,
                        "old": ast.get_source_segment(original, compare),
                        "new": ast.get_source_segment(prospective, changed_compare),
                    }
                )
                break

    traces = [json.loads(path.read_text()) for path in args.trace]
    operator_order = (
        "Lt", "LtE", "Gt", "GtE", "Eq", "NotEq", "Is", "IsNot", "In", "NotIn"
    )
    identity_pairs = {
        ("Is", "Eq"),
        ("Eq", "Is"),
        ("IsNot", "NotEq"),
        ("NotEq", "IsNot"),
    }
    for candidate in candidates:
        candidate["admitted"] = False
        if (
            not traces
            or not candidate["op_only"]
            or len(candidate["old_ops"]) != 1
            or len(candidate["new_ops"]) != 1
        ):
            continue
        old_operator = candidate["old_ops"][0]
        new_operator = candidate["new_ops"][0]
        if old_operator not in operator_order or new_operator not in operator_order:
            continue
        label = f"{candidate['path']}:{':'.join(map(str, candidate['coordinates']))}"
        if any(label not in trace for trace in traces):
            continue
        observations = []
        safe = True
        for trace in traces:
            for signature, ownership in trace[label].items():
                if (
                    not isinstance(ownership, list)
                    or len(ownership) != 3
                    or ownership[0] == "0"
                    or ownership[1]
                    or ownership[2]
                ):
                    safe = False
                try:
                    document = json.loads(signature)
                except (json.JSONDecodeError, TypeError):
                    safe = False
                    continue
                if signature == "__UNSAFE__" or set(document) != {
                    "left", "right", "outcomes"
                }:
                    safe = False
                    continue
                observations.append(document)
        old_index = old_operator
        if (
            not safe
            or not observations
            or any(
                observation["outcomes"][old_index][:2] != ["value", "bool"]
                or observation["outcomes"][old_operator]
                != observation["outcomes"][new_operator]
                for observation in observations
            )
        ):
            continue
        if "Is" in {old_operator, new_operator} or "IsNot" in {
            old_operator,
            new_operator,
        }:
            if (old_operator, new_operator) not in identity_pairs:
                continue
            if any(
                not (
                    "NoneType" in {observation["left"][1], observation["right"][1]}
                    or "type" in {observation["left"][1], observation["right"][1]}
                    or observation["left"][1] == observation["right"][1] == "bool"
                )
                for observation in observations
            ):
                continue
        candidate["admitted"] = True

    print(
        json.dumps(
            {
                "count": len(candidates),
                "total_cost": sum(item["cost"] for item in candidates),
                "op_only_count": sum(item["op_only"] for item in candidates),
                "op_only_cost": sum(
                    item["cost"] for item in candidates if item["op_only"]
                ),
                "combined_count": sum(item["combined"] for item in candidates),
                "combined_cost": sum(
                    item["cost"] for item in candidates if item["combined"]
                ),
                "admitted_count": sum(item["admitted"] for item in candidates),
                "admitted_cost": sum(
                    item["cost"] for item in candidates if item["admitted"]
                ),
            },
            sort_keys=True,
        )
    )
    for item in sorted(candidates, key=lambda item: item["cost"], reverse=True):
        print(json.dumps(item, sort_keys=True))


if __name__ == "__main__":
    main()
