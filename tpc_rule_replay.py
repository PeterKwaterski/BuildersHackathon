"""Research-only, fail-closed optimizer rule replay primitives.

This module is deliberately not imported by ``selector.py``.  It describes
the evidence a future per-rule TPC replay would have to authenticate before it
could remove a test.  No evidence artifact is shipped, and the runtime switch
defaults to off.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any


PROFILE_FORMAT = "tpc-rule-replay-v1"
ENABLE_ENV = "BR_TPC_RULE_REPLAY"

RULES = (
    "sqlglot.optimizer.qualify.qualify",
    "sqlglot.optimizer.pushdown_projections.pushdown_projections",
    "sqlglot.optimizer.normalize.normalize",
    "sqlglot.optimizer.unnest_subqueries.unnest_subqueries",
    "sqlglot.optimizer.pushdown_predicates.pushdown_predicates",
    "sqlglot.optimizer.optimize_joins.optimize_joins",
    "sqlglot.optimizer.eliminate_subqueries.eliminate_subqueries",
    "sqlglot.optimizer.merge_subqueries.merge_subqueries",
    "sqlglot.optimizer.eliminate_joins.eliminate_joins",
    "sqlglot.optimizer.eliminate_ctes.eliminate_ctes",
    "sqlglot.optimizer.qualify_columns.quote_identifiers",
    "sqlglot.optimizer.annotate_types.annotate_types",
    "sqlglot.optimizer.canonicalize.canonicalize",
    "sqlglot.optimizer.simplify.simplify",
)

TARGET_COUNTS = {
    "tests/test_executor.py::TestExecutor::test_execute_tpcds": 99,
    "tests/test_executor.py::TestExecutor::test_execute_tpch": 22,
    "tests/test_executor.py::TestExecutor::test_optimized_tpch": 22,
}

# A singleton history finds query-local differences.  The other histories are
# evidence against ordering bugs, not a proof of arbitrary spawn partitions.
HISTORIES = ("singleton", "forward", "reverse", "warm", "official_spawn")
HEX_CHARS = frozenset("0123456789abcdef")


class RuleReplayError(ValueError):
    """Malformed or incomplete evidence."""


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= HEX_CHARS


def canonical_digest(value: Any) -> str:
    """Hash a JSON-only value with a single, version-independent encoding."""

    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise RuleReplayError("non-canonical boundary value") from error
    return _sha256(encoded)


def expression_boundary(expression: Any) -> dict[str, Any]:
    """Return the complete portable state used at a rule boundary.

    SQLGlot's serde dump carries node types, ordered argument edges, comments,
    types, and metadata.  We also bind the rendered SQL and root class as
    independent composition checks.  Parent/arg/index links are derivable from
    the ordered dump; a collector must reject a dump that cannot round-trip.
    """

    dump = getattr(expression, "dump", None)
    sql = getattr(expression, "sql", None)
    if not callable(dump) or not callable(sql):
        raise RuleReplayError("expression lacks pinned dump/sql APIs")
    try:
        serialized = dump()
        rendered = sql()
    except Exception as error:
        raise RuleReplayError("expression serialization failed") from error
    if not isinstance(serialized, list) or not isinstance(rendered, str):
        raise RuleReplayError("invalid expression serialization")
    root = f"{type(expression).__module__}.{type(expression).__qualname__}"
    state = {"root": root, "dump": serialized, "sql": rendered}
    # Force canonicalizability here rather than at a later trust boundary.
    canonical_digest(state)
    return state


def boundary_digest(expression: Any) -> str:
    return canonical_digest(expression_boundary(expression))


def trace_rule_boundaries(
    expression: Any,
    rules: Sequence[Callable[..., Any]],
    invoke: Callable[[Callable[..., Any], Any], Any],
) -> tuple[Any, list[dict[str, str]]]:
    """Trace exact rule inputs/outputs without changing rule composition.

    ``invoke`` owns the pinned optimizer's argument binding.  Rule exceptions
    propagate and therefore cannot be converted into passing evidence.
    """

    names = tuple(f"{rule.__module__}.{rule.__name__}" for rule in rules)
    if names != RULES:
        raise RuleReplayError("optimizer rule order/identity mismatch")
    rows: list[dict[str, str]] = []
    current = expression
    for name, rule in zip(names, rules):
        before = boundary_digest(current)
        current = invoke(rule, current)
        after = boundary_digest(current)
        rows.append({"rule": name, "input": before, "output": after})
    return current, rows


def _validate_identity(identity: object) -> None:
    required = {
        "sqlglot_tree",
        "tests_tree",
        "fixture_tree",
        "requirements_lock",
        "collector_source",
    }
    if not isinstance(identity, dict) or set(identity) != required:
        raise RuleReplayError("identity shape mismatch")
    if not all(_is_digest(value) for value in identity.values()):
        raise RuleReplayError("identity digest mismatch")


def validate_profile(profile: object) -> dict[str, Any]:
    """Authenticate structural completeness; reject unknown composition."""

    if not isinstance(profile, dict) or set(profile) != {
        "format",
        "identity",
        "rule_order",
        "coverage",
        "boundary_rows_sha256",
        "boundary_rows",
        "owners",
        "spawn_obligations",
        "collection_sha256",
    }:
        raise RuleReplayError("profile shape mismatch")
    if profile["format"] != PROFILE_FORMAT or tuple(profile["rule_order"]) != RULES:
        raise RuleReplayError("profile format/rule mismatch")
    _validate_identity(profile["identity"])
    coverage = profile["coverage"]
    if not isinstance(coverage, dict) or set(coverage) != set(TARGET_COUNTS):
        raise RuleReplayError("target coverage mismatch")
    for target, count in TARGET_COUNTS.items():
        if coverage[target] != {"queries": count, "histories": list(HISTORIES)}:
            raise RuleReplayError("query/history coverage mismatch")

    rows = profile["boundary_rows"]
    if not isinstance(rows, list) or not _is_digest(profile["boundary_rows_sha256"]):
        raise RuleReplayError("boundary rows missing")
    if canonical_digest(rows) != profile["boundary_rows_sha256"]:
        raise RuleReplayError("boundary rows digest mismatch")
    expected = sum(TARGET_COUNTS.values()) * len(HISTORIES) * len(RULES)
    if len(rows) != expected:
        raise RuleReplayError("incomplete boundary census")
    seen: set[tuple[str, str, int, str]] = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "target",
            "history",
            "query",
            "rule",
            "input",
            "output",
            "cpu_ns",
        }:
            raise RuleReplayError("boundary row shape mismatch")
        target = row["target"]
        key = (target, row["history"], row["query"], row["rule"])
        if (
            target not in TARGET_COUNTS
            or row["history"] not in HISTORIES
            or type(row["query"]) is not int
            or not 1 <= row["query"] <= TARGET_COUNTS[target]
            or row["rule"] not in RULES
            or not _is_digest(row["input"])
            or not _is_digest(row["output"])
            or type(row["cpu_ns"]) is not int
            or row["cpu_ns"] < 0
            or key in seen
        ):
            raise RuleReplayError("invalid/duplicate boundary row")
        seen.add(key)

    owners = profile["owners"]
    if not isinstance(owners, dict):
        raise RuleReplayError("owner census missing")
    for owner_id, owner in owners.items():
        if not _is_digest(owner_id) or not isinstance(owner, dict) or set(owner) != {
            "rule",
            "source_sha256",
            "barriers",
            "state_independent",
            "call_graph_sha256",
        }:
            raise RuleReplayError("owner certificate shape mismatch")
        if (
            owner["rule"] not in RULES
            or not _is_digest(owner["source_sha256"])
            or not _is_digest(owner["call_graph_sha256"])
            or not isinstance(owner["barriers"], list)
            or not all(isinstance(x, str) and x for x in owner["barriers"])
            or type(owner["state_independent"]) is not bool
        ):
            raise RuleReplayError("owner certificate invalid")

    obligations = profile["spawn_obligations"]
    required_obligations = {
        "parse",
        "pickle_roundtrip",
        "fresh_import",
        "initializer",
        "persistent_worker_predecessors",
        "table_reader_state",
        "stdout_warnings_exceptions",
        "native_state",
    }
    if not isinstance(obligations, dict) or set(obligations) != required_obligations:
        raise RuleReplayError("spawn obligation shape mismatch")
    if not all(type(value) is bool for value in obligations.values()):
        raise RuleReplayError("spawn obligation value mismatch")

    supplied = profile["collection_sha256"]
    if not _is_digest(supplied):
        raise RuleReplayError("collection digest missing")
    unsigned = dict(profile)
    unsigned.pop("collection_sha256")
    if canonical_digest(unsigned) != supplied:
        raise RuleReplayError("collection digest mismatch")
    return profile


@dataclass(frozen=True)
class PatchEvidence:
    owner_id: str
    source_sha256: str
    rule: str


def plan_strong_replay(
    profile: object,
    patch: PatchEvidence,
    selected_targets: Sequence[str],
    packed_saving: float,
    projected_cpu: float,
    *,
    enabled: bool | None = None,
) -> dict[str, Any] | None:
    """Return a strong-tier plan only when every state obligation is closed."""

    if enabled is None:
        enabled = os.environ.get(ENABLE_ENV) == "1"
    if not enabled:
        return None
    try:
        checked = validate_profile(profile)
    except (RuleReplayError, KeyError, TypeError):
        return None
    targets = tuple(sorted(set(selected_targets)))
    if not targets or not set(targets) <= set(TARGET_COUNTS):
        return None
    if (
        not _is_digest(patch.owner_id)
        or not _is_digest(patch.source_sha256)
        or patch.rule not in RULES
        or type(packed_saving) not in (int, float)
        or type(projected_cpu) not in (int, float)
        or projected_cpu < 0
        or packed_saving <= projected_cpu
    ):
        return None
    owner = checked["owners"].get(patch.owner_id)
    if (
        not owner
        or owner["source_sha256"] != patch.source_sha256
        or owner["rule"] != patch.rule
        or owner["barriers"]
        or owner["state_independent"] is not True
        or not all(checked["spawn_obligations"].values())
    ):
        return None
    return {
        "tier": "strong",
        "owner_id": patch.owner_id,
        "rule": patch.rule,
        "targets": targets,
        "projected_net": packed_saving - projected_cpu,
        "profile": checked["collection_sha256"],
    }

