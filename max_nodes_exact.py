"""Exact, fail-closed certificate for ``TestParser.test_max_nodes``.

The certificate accepts only edits confined to the first statement of
``Parser.validate_expression`` and only a tiny monotone counter language.  It
symbolically evaluates every assertion in the pinned test from exact Python
3.13 event counts.  Any source, artifact, manifest, or shape uncertainty keeps
the real test selected.
"""

from __future__ import annotations

import ast
import copy
import gzip
import hashlib
import io
import inspect
import json
import re
import tokenize
from dataclasses import dataclass
from pathlib import Path
from typing import Any


FORMAT_VERSION = 1
IMPLEMENTATION_VERSION = "max-nodes-exact-v1"
PINNED_SOURCE_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"
PARSER_PATH = "sqlglot/parser.py"
TEST_PATH = "tests/test_parser.py"
TARGET_TEST = "tests/test_parser.py::TestParser::test_max_nodes"
ARTIFACT_CANONICAL_SHA256 = "02c5986ca0ef43f366785b26e9f1433068c8f68a5d53b2b5a32dd8e7e8807223"
COLLECTOR_SHA256 = "ef93abb9eca9ccb545991638a8458e4a1beba37db0627790edd3c61504efeb62"
PROFILE_DIGEST_NAME = b"ARTIFACT_CANONICAL_SHA256"
PROFILE_DIGEST_PATTERN = re.compile(PROFILE_DIGEST_NAME + rb' = "[^"]+"')
PROFILE_PATH = Path(__file__).with_name("max_nodes_exact_profile.json.gz")
PINNED_TREE = Path("/opt/sqlglot")
MAX_PROFILE_GZIP_BYTES = 64_000
MAX_PROFILE_JSON_BYTES = 256_000
MAX_SOURCE_BYTES = 2_000_000
MAX_LITERAL_MAGNITUDE = 1_000_000_000
MAX_MESSAGE_LENGTH = 1_024


class Unsupported(ValueError):
    """The prospective source is outside the exact proof language."""


def _json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def implementation_digest() -> str:
    source = inspect.getsource(inspect.getmodule(implementation_digest)).encode()
    normalized, count = PROFILE_DIGEST_PATTERN.subn(
        PROFILE_DIGEST_NAME + b' = "' + b"__MAX_NODES_PROFILE_SHA256__" + b'"',
        source,
    )
    if count != 1:
        raise Unsupported("profile digest sentinel is not unique")
    return _sha_bytes(normalized)


@dataclass(frozen=True)
class Contract:
    guard_operator: str
    guard_limit: int
    increment: int
    limit_operator: str
    limit_offset: int
    message_parts: tuple[str | None, ...]

    def guard(self, max_nodes: int) -> bool:
        return (
            max_nodes > self.guard_limit
            if self.guard_operator == ">"
            else max_nodes >= self.guard_limit
        )

    def first_raise(self, max_nodes: int) -> int | None:
        if not self.guard(max_nodes):
            return None
        boundary = max_nodes + self.limit_offset
        if self.limit_operator == ">":
            return boundary // self.increment + 1 if boundary >= 0 else 1
        if boundary <= 0:
            return 1
        return (boundary + self.increment - 1) // self.increment

    def message(self, max_nodes: int) -> str:
        return "".join(
            str(max_nodes) if part is None else part for part in self.message_parts
        )


def _dump(node: ast.AST) -> str:
    return ast.dump(node, include_attributes=False)


def _sha_ast(node: ast.AST) -> str:
    return _sha_bytes(_dump(node).encode())


def _state_accesses(tree: ast.Module) -> list[list[Any]]:
    """Inventory every Parser counter/limit attribute read or write."""
    parents = {
        child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)
    }
    result = []
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Attribute)
            and node.attr in {"max_nodes", "_node_count"}
            and isinstance(node.value, ast.Name)
            and node.value.id == "self"
        ):
            continue
        parent = parents.get(node)
        role = (
            "augassign"
            if isinstance(parent, ast.AugAssign) and parent.target is node
            else type(node.ctx).__name__.lower()
        )
        result.append([node.attr, node.lineno, node.end_lineno or node.lineno, role])
    return sorted(result)


def _class_method(tree: ast.Module, class_name: str, method_name: str) -> ast.FunctionDef:
    matches = [
        statement
        for statement in tree.body
        if isinstance(statement, ast.ClassDef) and statement.name == class_name
        for statement in statement.body
        if isinstance(statement, ast.FunctionDef) and statement.name == method_name
    ]
    if len(matches) != 1:
        raise Unsupported(f"{class_name}.{method_name} is not unique")
    return matches[0]


def _self_attribute(node: ast.AST, name: str) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == name
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
        and isinstance(node.ctx, ast.Load)
    )


def _integer(node: ast.AST) -> int:
    try:
        value = ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError) as exc:
        raise Unsupported("expected an integer literal") from exc
    if type(value) is not int or abs(value) > MAX_LITERAL_MAGNITUDE:
        raise Unsupported("integer literal is not within the proof bound")
    return value


def _comparison(node: ast.AST, left_attribute: str) -> tuple[str, ast.AST]:
    if (
        not isinstance(node, ast.Compare)
        or len(node.ops) != 1
        or len(node.comparators) != 1
        or not _self_attribute(node.left, left_attribute)
    ):
        raise Unsupported("comparison shape is not certified")
    if isinstance(node.ops[0], ast.Gt):
        return ">", node.comparators[0]
    if isinstance(node.ops[0], ast.GtE):
        return ">=", node.comparators[0]
    raise Unsupported("comparison is not monotone")


def _limit_offset(node: ast.AST) -> int:
    if _self_attribute(node, "max_nodes"):
        return 0
    if not isinstance(node, ast.BinOp) or not _self_attribute(node.left, "max_nodes"):
        raise Unsupported("limit must be max_nodes plus/minus an integer")
    value = _integer(node.right)
    if isinstance(node.op, ast.Add):
        return value
    if isinstance(node.op, ast.Sub):
        return -value
    raise Unsupported("limit arithmetic is not certified")


def _message_parts(node: ast.AST) -> tuple[str | None, ...]:
    if isinstance(node, ast.Constant) and type(node.value) is str:
        parts: list[str | None] = [node.value]
    elif isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant) and type(value.value) is str:
                parts.append(value.value)
            elif (
                isinstance(value, ast.FormattedValue)
                and value.conversion == -1
                and value.format_spec is None
                and _self_attribute(value.value, "max_nodes")
            ):
                parts.append(None)
            else:
                raise Unsupported("f-string observes an uncertified value")
    else:
        raise Unsupported("error message is not certified")
    if sum(len(part) for part in parts if part is not None) > MAX_MESSAGE_LENGTH:
        raise Unsupported("error message exceeds the proof bound")
    return tuple(parts)


def _contract(method: ast.FunctionDef) -> Contract:
    outer = method.body[0] if method.body else None
    if not isinstance(outer, ast.If) or outer.orelse or len(outer.body) != 2:
        raise Unsupported("outer block shape is not certified")
    guard_operator, guard_rhs = _comparison(outer.test, "max_nodes")
    guard_limit = _integer(guard_rhs)

    update, inner = outer.body
    if (
        not isinstance(update, ast.AugAssign)
        or not isinstance(update.op, ast.Add)
        or not isinstance(update.target, ast.Attribute)
        or update.target.attr != "_node_count"
        or not isinstance(update.target.value, ast.Name)
        or update.target.value.id != "self"
        or not isinstance(update.target.ctx, ast.Store)
    ):
        raise Unsupported("node counter update is not certified")
    increment = _integer(update.value)
    if increment <= 0:
        raise Unsupported("node counter increment must be positive")

    if not isinstance(inner, ast.If) or inner.orelse or len(inner.body) != 1:
        raise Unsupported("inner block shape is not certified")
    limit_operator, limit_rhs = _comparison(inner.test, "_node_count")
    limit_offset = _limit_offset(limit_rhs)
    effect = inner.body[0]
    if (
        not isinstance(effect, ast.Expr)
        or not isinstance(effect.value, ast.Call)
        or effect.value.keywords
        or len(effect.value.args) != 1
        or not isinstance(effect.value.func, ast.Attribute)
        or effect.value.func.attr != "raise_error"
        or not isinstance(effect.value.func.value, ast.Name)
        or effect.value.func.value.id != "self"
    ):
        raise Unsupported("the only certified effect is self.raise_error(message)")
    return Contract(
        guard_operator,
        guard_limit,
        increment,
        limit_operator,
        limit_offset,
        _message_parts(effect.value.args[0]),
    )


def _profile(path: Path = PROFILE_PATH) -> tuple[dict[str, Any], bytes] | None:
    try:
        if not path.is_file() or path.stat().st_size > MAX_PROFILE_GZIP_BYTES:
            return None
        with gzip.open(path, "rb") as stream:
            raw = stream.read(MAX_PROFILE_JSON_BYTES + 1)
        if len(raw) > MAX_PROFILE_JSON_BYTES:
            return None
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (OSError, EOFError, UnicodeError, ValueError, TypeError, MemoryError):
        return None
    return (value, raw) if isinstance(value, dict) else None


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _manifest_digest(tests: list[dict]) -> str:
    return _sha_bytes(_json_bytes(tests))


def _profile_valid(
    profile: dict[str, Any],
    raw: bytes,
    original_source: str,
    tests: list[dict],
    tree: Path,
) -> bool:
    try:
        original_tree = ast.parse(original_source, filename=PARSER_PATH, type_comments=True)
        method = _class_method(original_tree, "Parser", "validate_expression")
        raise_method = _class_method(original_tree, "Parser", "raise_error")
        test_raw = (tree / TEST_PATH).read_bytes()
        test_tree = ast.parse(test_raw, filename=TEST_PATH, type_comments=True)
        test_method = _class_method(test_tree, "TestParser", "test_max_nodes")
        target = [test for test in tests if test.get("id") == TARGET_TEST]
        scenarios = profile["scenarios"]
        return (
            _json_bytes(profile) == raw
            and _sha_bytes(raw) == ARTIFACT_CANONICAL_SHA256
            and profile["format"] == FORMAT_VERSION
            and profile["implementation_version"] == IMPLEMENTATION_VERSION
            and profile["source_revision"] == PINNED_SOURCE_SHA
            and profile["python"] == "CPython 3.13.18"
            and profile["implementation_sha256"] == implementation_digest()
            and profile["collector_sha256"] == COLLECTOR_SHA256
            and profile["parser_sha256"] == _sha_bytes(original_source.encode())
            and profile["test_sha256"] == _sha_bytes(test_raw)
            and profile["test_manifest_sha256"] == _manifest_digest(tests)
            and profile["validate_expression_sha256"] == _sha_ast(method)
            and profile["raise_error_sha256"] == _sha_ast(raise_method)
            and profile["test_method_sha256"] == _sha_ast(test_method)
            and profile["state_accesses"] == _state_accesses(original_tree)
            and profile["evidence_sha256"] == _sha_bytes(_json_bytes(profile["evidence"]))
            and target == [profile["target_test"]]
            and isinstance(scenarios, list)
            and len(scenarios) == 6
            and [scenario.get("name") for scenario in scenarios]
            == [
                "small-select",
                "five-hundred-columns",
                "million-node-limit",
                "fifty-thousand-limit",
                "reset-setup-limit",
                "reset-followup",
            ]
            and all(
                set(scenario)
                == {
                    "name",
                    "max_nodes",
                    "validation_calls",
                    "should_raise",
                    "required_substring",
                }
                and type(scenario["max_nodes"]) is int
                and type(scenario["validation_calls"]) is int
                and 0 < scenario["validation_calls"] <= 2_000_000
                and type(scenario["should_raise"]) is bool
                and (
                    scenario["required_substring"] is None
                    or type(scenario["required_substring"]) is str
                )
                for scenario in scenarios
            )
            and profile["immediate_raise_verified"] is True
        )
    except (
        KeyError,
        OSError,
        SyntaxError,
        ValueError,
        TypeError,
        MemoryError,
        RecursionError,
        Unsupported,
    ):
        return False


def _only_prefix_changed(
    original_tree: ast.Module,
    prospective_tree: ast.Module,
    original_source: str,
    prospective_source: str,
) -> tuple[ast.FunctionDef, ast.FunctionDef] | None:
    original_method = _class_method(original_tree, "Parser", "validate_expression")
    prospective_method = _class_method(prospective_tree, "Parser", "validate_expression")
    if not original_method.body or not prospective_method.body:
        return None
    original_block = original_method.body[0]
    prospective_block = prospective_method.body[0]
    if (
        prospective_block.end_lineno - prospective_block.lineno > 16
        or len(ast.get_source_segment(prospective_source, prospective_block).encode()) > 4_096
    ):
        return None
    block_source = ast.get_source_segment(prospective_source, prospective_block)
    try:
        if any(
            token.type == tokenize.COMMENT
            for token in tokenize.generate_tokens(io.StringIO(block_source).readline)
        ):
            return None
    except (tokenize.TokenError, IndentationError):
        return None

    # Exact bytes outside the certified statement must remain identical.  This
    # is stricter than AST equality and closes comments/directives/source reads.
    original_lines = original_source.splitlines(keepends=True)
    prospective_lines = prospective_source.splitlines(keepends=True)
    if (
        original_lines[: original_block.lineno - 1]
        != prospective_lines[: prospective_block.lineno - 1]
        or original_lines[original_block.end_lineno :]
        != prospective_lines[prospective_block.end_lineno :]
    ):
        return None

    # Independently compare the complete AST after replacing only that block.
    original_copy = copy.deepcopy(original_tree)
    prospective_copy = copy.deepcopy(prospective_tree)
    _class_method(original_copy, "Parser", "validate_expression").body[0] = ast.Pass()
    _class_method(prospective_copy, "Parser", "validate_expression").body[0] = ast.Pass()
    if _dump(original_copy) != _dump(prospective_copy):
        return None
    return original_method, prospective_method


def can_skip(
    original_source: str,
    prospective_source: str,
    tests: list[dict],
    *,
    tree: Path | None = None,
    profile_path: Path = PROFILE_PATH,
) -> bool:
    """Return true only when the pinned expensive test is exactly proved passing."""
    try:
        tree = PINNED_TREE if tree is None else tree
        if (
            type(original_source) is not str
            or type(prospective_source) is not str
            or len(original_source.encode()) > MAX_SOURCE_BYTES
            or len(prospective_source.encode()) > MAX_SOURCE_BYTES
            or original_source == prospective_source
        ):
            return False
        loaded = _profile(profile_path)
        if loaded is None or not _profile_valid(
            loaded[0], loaded[1], original_source, tests, tree
        ):
            return False
        original_tree = ast.parse(original_source, filename=PARSER_PATH, type_comments=True)
        prospective_tree = ast.parse(
            prospective_source, filename=PARSER_PATH, type_comments=True
        )
        compile(prospective_source, PARSER_PATH, "exec", dont_inherit=True)
        methods = _only_prefix_changed(
            original_tree, prospective_tree, original_source, prospective_source
        )
        if methods is None:
            return False
        original_method, prospective_method = methods
        if _sha_ast(original_method) != loaded[0]["validate_expression_sha256"]:
            return False
        proof = _contract(prospective_method)
        for scenario in loaded[0]["scenarios"]:
            first_raise = proof.first_raise(scenario["max_nodes"])
            raised = first_raise is not None and first_raise <= scenario["validation_calls"]
            if raised != scenario["should_raise"]:
                return False
            required = scenario["required_substring"]
            if raised and required is not None and required not in proof.message(
                scenario["max_nodes"]
            ):
                return False
        return True
    except (
        OSError,
        SyntaxError,
        ValueError,
        TypeError,
        MemoryError,
        RecursionError,
        Unsupported,
    ):
        return False
