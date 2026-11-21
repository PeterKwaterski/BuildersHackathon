"""Leader-scale cached-input TPC rule replay, explicitly competition-risk."""

from __future__ import annotations

import inspect
import multiprocessing
import os
import shutil
import sys
import tempfile
from pathlib import Path

from tpc_rule_fast import RULES, validate
from tpc_rule_replay import boundary_digest


PINNED_TREE = Path("/opt/sqlglot")
TIMEOUT_SECONDS = 20.0


def _safe_path(path: str) -> Path | None:
    candidate = Path(path)
    if (
        candidate.is_absolute()
        or ".." in candidate.parts
        or len(candidate.parts) < 3
        or candidate.parts[0:2] != ("sqlglot", "optimizer")
        or candidate.suffix != ".py"
    ):
        return None
    return candidate


def _verify_child(tree_text: str, profile: dict, plan: dict) -> bool:
    sys.path.insert(0, tree_text)
    from sqlglot import exp
    from sqlglot.optimizer import optimizer
    from sqlglot.schema import ensure_schema
    from tests.helpers import TPCDS_SCHEMA

    names = tuple(f"{rule.__module__}.{rule.__name__}" for rule in optimizer.RULES)
    if plan["rule"] not in RULES or plan["rule"] not in names:
        return False
    rule = optimizer.RULES[names.index(plan["rule"])]
    capsules = {row["query"]: row for row in profile["capsules"][plan["rule"]]}
    schema = ensure_schema(TPCDS_SCHEMA)
    possible = {
        "db": None, "catalog": None, "schema": schema, "dialect": None,
        "sql": None, "isolate_tables": True, "quote_identifiers": False,
    }
    params = inspect.getfullargspec(rule).args
    kwargs = {key: possible[key] for key in params if key in possible}
    for query in plan["readers"]:
        row = capsules.get(query)
        if row is None:
            return False
        expression = exp.Expression.load(row["input_dump"])
        if boundary_digest(expression) != row["input"]:
            return False
        if boundary_digest(rule(expression, **kwargs)) != row["output"]:
            return False
    return True


def verify_fast_boundaries(
    sources: list[tuple[str, str]], profile: dict, plan: dict, *,
    pinned_tree: Path = PINNED_TREE,
) -> bool:
    try:
        checked = validate(profile)
        if (
            len(sources) != 1
            or plan.get("tier") != "competition-risk-fast"
            or plan.get("proof") is not False
            or plan.get("profile") != checked["collection_sha256"]
            or not pinned_tree.is_dir()
        ):
            return False
        path, changed = sources[0]
        relative = _safe_path(path)
        owner = checked["owners"].get(plan.get("owner_id"))
        if (
            relative is None
            or type(changed) is not str
            or owner is None
            or owner["path"] != path
            or owner["rule"] != plan.get("rule")
            or tuple(owner["readers"]) != tuple(plan.get("readers", ()))
        ):
            return False
        original = pinned_tree / relative
        with tempfile.TemporaryDirectory(prefix="blast-radius-tpc-fast-") as temporary:
            overlay = Path(temporary) / "sqlglot"
            shutil.copytree(pinned_tree, overlay, copy_function=os.symlink)
            destination = overlay / relative
            if not destination.is_symlink() or destination.resolve() != original.resolve():
                return False
            destination.unlink()
            destination.write_text(changed, encoding="utf-8")
            context = multiprocessing.get_context("spawn")
            with context.Pool(1) as pool:
                pending = pool.apply_async(
                    _verify_child, (str(overlay), checked, plan)
                )
                return pending.get(timeout=TIMEOUT_SECONDS) is True
    except Exception:
        return False
