"""Explicit-risk cached-input replay for two TPC-DS optimizer rules."""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any


FORMAT = "tpc-rule-fast-risk-v1"
ENABLE_ENV = "BR_TPC_RULE_FAST_RISK"
TARGET = "tests/test_executor.py::TestExecutor::test_execute_tpcds"
RULES = (
    "sqlglot.optimizer.qualify.qualify",
    "sqlglot.optimizer.unnest_subqueries.unnest_subqueries",
)


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")).hexdigest()


def _digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def validate(profile: object) -> dict:
    if not isinstance(profile, dict) or set(profile) != {
        "format", "identity", "capsules", "owners", "collection_sha256"
    }:
        raise ValueError("fast profile shape mismatch")
    if profile["format"] != FORMAT:
        raise ValueError("fast profile format mismatch")
    identity = profile["identity"]
    if not isinstance(identity, dict) or set(identity) != {
        "sqlglot_tree", "tests_tree", "fixture_tree", "requirements_lock", "builder_source"
    } or not all(_digest(value) for value in identity.values()):
        raise ValueError("fast identity mismatch")
    capsules = profile["capsules"]
    if not isinstance(capsules, dict) or set(capsules) != set(RULES):
        raise ValueError("fast capsule rule mismatch")
    for rule, rows in capsules.items():
        if not isinstance(rows, list) or not rows:
            raise ValueError("fast capsule rows missing")
        seen = set()
        for row in rows:
            if not isinstance(row, dict) or set(row) != {
                "query", "input_dump", "input", "output"
            } or type(row["query"]) is not int or not 1 <= row["query"] <= 99:
                raise ValueError("fast capsule row mismatch")
            if row["query"] in seen or not isinstance(row["input_dump"], list):
                raise ValueError("fast capsule duplicate/dump mismatch")
            if not _digest(row["input"]) or not _digest(row["output"]):
                raise ValueError("fast capsule digest mismatch")
            seen.add(row["query"])
    owners = profile["owners"]
    if not isinstance(owners, dict) or not owners:
        raise ValueError("fast owners missing")
    for owner_id, owner in owners.items():
        if not _digest(owner_id) or not isinstance(owner, dict) or set(owner) != {
            "path", "qualname", "first_line", "end_line", "rule", "source_sha256",
            "readers", "barriers", "risk_cpu_s",
        }:
            raise ValueError("fast owner shape mismatch")
        readers = owner["readers"]
        capsule_queries = {row["query"] for row in capsules.get(owner["rule"], ())}
        if (
            owner["rule"] not in RULES
            or not _digest(owner["source_sha256"])
            or not isinstance(readers, list)
            or readers != sorted(set(readers))
            or not readers
            or not set(readers) <= capsule_queries
            or not isinstance(owner["barriers"], list)
            or not owner["barriers"]
            or type(owner["risk_cpu_s"]) not in (int, float)
            or owner["risk_cpu_s"] < 0
        ):
            raise ValueError("fast owner evidence mismatch")
    supplied = profile["collection_sha256"]
    unsigned = dict(profile)
    unsigned.pop("collection_sha256")
    if not _digest(supplied) or canonical_digest(unsigned) != supplied:
        raise ValueError("fast collection digest mismatch")
    return profile


def plan(
    profile: object,
    owner_id: str,
    selected_ids: tuple[str, ...],
    packed_saving: float,
    *,
    minimum_margin: float = 2.0,
    enabled: bool | None = None,
) -> dict | None:
    if enabled is None:
        enabled = os.environ.get(ENABLE_ENV) == "1"
    if not enabled:
        return None
    try:
        checked = validate(profile)
        owner = checked["owners"][owner_id]
        if (
            selected_ids != (TARGET,)
            or packed_saving <= owner["risk_cpu_s"] + minimum_margin
        ):
            return None
        return {
            "tier": "competition-risk-fast",
            "proof": False,
            "owner_id": owner_id,
            "rule": owner["rule"],
            "target": TARGET,
            "readers": tuple(owner["readers"]),
            "barriers": tuple(owner["barriers"]),
            "profile": checked["collection_sha256"],
        }
    except Exception:
        return None
