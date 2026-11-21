"""Shared source inventory for per-test guard observations.

The inventory is intentionally independent of prospective patches.  Every
supported guard in the pinned production tree receives a stable source label;
the runtime gate later decides whether a particular edit is exactly one of the
supported form changes.
"""

from __future__ import annotations

import ast
import subprocess
import types
from pathlib import Path


GUARD_NODES = (ast.If, ast.While, ast.IfExp)
OPERANDS = (ast.Name, ast.Attribute, ast.Call, ast.Subscript)
TRUTH_FORMS = {
    "truth": (False, True, False, False, True),
    "not": (True, False, True, True, False),
    "is_none": (False, False, True, False, False),
    "not_none": (True, True, False, True, True),
    "is_false": (False, False, False, True, False),
    "not_false": (True, True, True, False, True),
    "is_true": (False, False, False, False, True),
    "not_true": (True, True, True, True, False),
}
STATE_NAMES = ("false-nonbool", "true-nonbool", "none", "false", "true")

# Runtime classification deliberately recognizes exact built-in types only.
# Subclasses and arbitrary user objects may execute custom ``__bool__``,
# ``__len__``, ``__eq__`` or ``__ne__`` methods and therefore remain unknown.
_TYPE = type
_BOOL = bool

# Only immutable exact builtins are classified for truth.  The hook runs
# immediately before Python evaluates the real condition, so classifying a
# mutable container would create a second, potentially stale length
# observation if another thread mutates it between the two operations.  Exact
# float/complex truth can also touch native floating-point status for signaling
# NaNs.  Keeping those values unknown costs exemptions but avoids inventing an
# observation the original identity guards did not perform.
TRUTH_VALUE_TYPES = (
    type(None),
    bool,
    int,
    str,
    bytes,
    tuple,
    frozenset,
    range,
)
ALWAYS_TRUE_TYPES = (
    object,
    type,
    types.FunctionType,
    types.BuiltinFunctionType,
    types.MethodType,
    types.ModuleType,
)
NONE_COMPARISON_TYPES = TRUTH_VALUE_TYPES + (
    float,
    complex,
    bytearray,
    list,
    dict,
    set,
) + ALWAYS_TRUE_TYPES


def truth_state(value: object) -> str | None:
    """Classify truth without invoking an unknown user protocol."""

    if value is None:
        return "none"
    if value is False:
        return "false"
    if value is True:
        return "true"
    value_type = _TYPE(value)
    if value_type in TRUTH_VALUE_TYPES:
        return "true-nonbool" if _BOOL(value) else "false-nonbool"
    if value_type in ALWAYS_TRUE_TYPES:
        return "true-nonbool"
    return None


def none_comparison_safe(value: object) -> bool:
    """Whether exact-type equality with ``None`` cannot run user code."""

    return _TYPE(value) in NONE_COMPARISON_TYPES


def truth_form(node: ast.AST) -> tuple[str, ast.expr] | None:
    """Return a supported condition form and its already-evaluated operand."""

    if isinstance(node, OPERANDS):
        return "truth", node
    if (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, ast.Not)
        and isinstance(node.operand, OPERANDS)
    ):
        return "not", node.operand
    if (
        not isinstance(node, ast.Compare)
        or len(node.ops) != 1
        or len(node.comparators) != 1
        or not isinstance(node.ops[0], (ast.Is, ast.IsNot))
    ):
        return None
    operand, constant = node.left, node.comparators[0]
    if not isinstance(operand, OPERANDS) or not isinstance(constant, ast.Constant):
        return None
    if constant.value is None:
        suffix = "none"
    elif type(constant.value) is bool:
        suffix = "true" if constant.value else "false"
    else:
        return None
    prefix = "is_" if isinstance(node.ops[0], ast.Is) else "not_"
    return prefix + suffix, operand


def none_comparison(node: ast.AST) -> tuple[str, ast.expr, str] | None:
    """Return operator, non-None operand and its side for a simple comparison."""

    if (
        not isinstance(node, ast.Compare)
        or len(node.ops) != 1
        or len(node.comparators) != 1
        or not isinstance(node.ops[0], (ast.Is, ast.IsNot, ast.Eq, ast.NotEq))
    ):
        return None
    left, right = node.left, node.comparators[0]
    if isinstance(right, ast.Constant) and right.value is None:
        return type(node.ops[0]).__name__, left, "left"
    if isinstance(left, ast.Constant) and left.value is None:
        return type(node.ops[0]).__name__, right, "right"
    return None


def coordinates(node: ast.AST) -> tuple[int, int, int, int]:
    return node.lineno, node.col_offset, node.end_lineno, node.end_col_offset


def label(path: str, kind: str, node: ast.AST) -> str:
    return f"{kind}:{path}:{':'.join(map(str, coordinates(node)))}"


def source_sites(source: Path) -> dict[str, dict]:
    """Return the complete supported site inventory under ``source/sqlglot``."""

    sites: dict[str, dict] = {}

    try:
        tracked = subprocess.check_output(
            ["git", "-C", str(source), "ls-files", "-z", "--", "sqlglot"],
        ).split(b"\0")
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError("guard inventory requires a Git-tracked source tree") from error
    paths = []
    for raw in tracked:
        if not raw:
            continue
        try:
            relative = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("non-UTF-8 path in guard source inventory") from error
        candidate = Path(relative)
        if (
            candidate.is_absolute()
            or ".." in candidate.parts
            or not relative.startswith("sqlglot/")
            or candidate.suffix != ".py"
        ):
            continue
        path = source / candidate
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"invalid tracked Python source: {relative}")
        paths.append(path)

    def add(site_label: str, site: dict) -> None:
        if site_label in sites:
            raise ValueError(f"duplicate guard-site label: {site_label}")
        sites[site_label] = site

    for path in sorted(paths):
        relative = path.relative_to(source).as_posix()
        tree = ast.parse(path.read_text(), filename=relative, type_comments=True)
        for node in ast.walk(tree):
            if isinstance(node, GUARD_NODES):
                form = truth_form(node.test)
                if form is not None:
                    name, operand = form
                    site_label = label(relative, "truth", node.test)
                    add(site_label, {
                        "coordinates": list(coordinates(node.test)),
                        "form": name,
                        "kind": "truth",
                        "operand": ast.dump(operand, include_attributes=False),
                        "path": relative,
                    })
            comparison = none_comparison(node)
            if comparison is not None:
                operator, operand, side = comparison
                site_label = label(relative, "none", node)
                add(site_label, {
                    "coordinates": list(coordinates(node)),
                    "form": operator,
                    "kind": "none",
                    "operand": ast.dump(operand, include_attributes=False),
                    "path": relative,
                    "side": side,
                })
    return sites
