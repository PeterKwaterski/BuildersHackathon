"""Select tests from answer-independent coverage, fixture, and symbol maps."""

import ast
import gzip
import hashlib
import io
import json
import base64
import keyword
import os
import re
import sys
import tokenize
import types
from collections import deque
from pathlib import Path

from binary_copy_patch import FEATURE_ENABLED as BINARY_FIXTURE_ENABLED
from binary_copy_patch import binary_patch_readers, load_preimages
from semantic import SemanticProof
from none_static_runtime import load_profile as load_none_static_profile
from none_static_runtime import match as match_none_static
from tpc_entry_key_access import FEATURE_ENABLED as TPC_ENTRY_ENABLED
from tpc_entry_key_access import PATH as TPC_ENTRY_PATH
from tpc_entry_key_access import load_provenance as load_tpc_entry_provenance
from tpc_entry_key_access import readers as tpc_entry_readers
from shared_arg_write_runtime import (
    fresh_receiver_candidate,
    load_model as load_shared_arg_model,
)
from tpc_plan_runtime import verify_patch as verify_tpc_plan_patch
from tpc_fixture_verify import FIXTURE as TPCDS_FIXTURE_PATH
from tpc_fixture_verify import verify as verify_tpcds_fixture

DATA = Path("/data")
MODEL = Path(__file__).with_name("selector_model.json.gz")
SEMANTIC_SOURCES = Path(__file__).with_name("semantic_sources.json.gz")
ZERO_READER_MODEL = Path(__file__).with_name("zero_reader_model.json.gz")
PREDICATE_PROFILE = Path(__file__).with_name("predicate_profile.json.gz")
ARG_TYPE_DERIVATION_MODEL = Path(__file__).with_name(
    "arg_type_derivation_model.json.gz"
)
CLASS_ATTRIBUTE_MODEL = Path(__file__).with_name("class_attribute_model.json.gz")
FRESH_ALIAS_PROFILE = Path(__file__).with_name("fresh_alias_profile.json.gz")
SHARED_ARG_WRITE_MODEL = Path(__file__).with_name("shared_arg_write_model.json.gz")
BINARY_FIXTURE_PREIMAGES = Path(__file__).with_name("fixture_binary_preimages.json.gz")
TPC_ENTRY_PROVENANCE = Path(__file__).with_name("tpc_entry_reader_provenance.json.gz")
# The artifact admits only calls whose exact-formal identity and non-escape
# fixed point proves that mutations stay within a fresh owned object graph.
SHARED_ARG_WRITE_ENABLED = True
_SHARED_ARG_WRITE_MODEL = None
NEW_MODULE_MODEL = Path(__file__).with_name("new_module_model.json.gz")
NEW_MODULE_PROFILE_SHA256 = "1b24ab53483bb1932d8139b80fa17e797a1974ee3078157a110c0f25b28f4e10"
NEW_MODULE_SOURCE_SHA256 = "b7f798c9e8015db63d6e160ab73f59828e445cef8739cfb383aba44d5de5f5f0"
NEW_MODULE_INVENTORY_SHA256 = "b30749cd488217746916b61c0eb138d46ab9f3543b32e0dbbd4688c0ac9ee12b"
MAX_WORKERS = 8
WORKER_COST_MS = 2_000
HUNK = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
COMMENT_DIRECTIVE = re.compile(r"(?i)(coding\s*[:=]|type:|noqa|pragma|fmt:|pyright|mypy)")
NEW_MODULE_PATH = re.compile(
    r"sqlglot(?:/[A-Za-z_][A-Za-z0-9_]*)*/[A-Za-z_][A-Za-z0-9_]*\.py\Z"
)
PROCESS_SERIALIZATION_FILES = {"sqlglot/serde.py"}
_PINNED_SOURCES = None
_SOURCE_TREES = {}
_SOURCE_INDEXES = {}
_IMPORT_DEFINITION_RANGES = {}
_SOURCE_CODE = {}
_INIT_SUBCLASS_ATTRIBUTES = None

# Independent review found no opaque package-discovery path reachable from the
# pinned test manifest and locked pure-Python runtime. Every source-visible
# discovery site retains its complete reader set; malformed evidence fails shut.
NEW_MODULE_PROOF_ENABLED = True

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


def best_cost_ms(tests: list[dict]) -> int:
    if not tests:
        return 0
    return min(split(tests, count)[1] for count in range(1, MAX_WORKERS + 1))


TPC_PLAN_TESTS = {
    "tpcds_executor": {"tests/test_executor.py::TestExecutor::test_execute_tpcds"},
    "tpcds_optimizer": {"tests/test_optimizer.py::TestOptimizer::test_tpcds"},
    "tpch_executor": {"tests/test_executor.py::TestExecutor::test_execute_tpch"},
    "tpch_optimizer": {
        "tests/test_optimizer.py::TestOptimizer::test_tpch",
        "tests/test_executor.py::TestExecutor::test_optimized_tpch",
    },
}
TPCDS_EXECUTOR_ID = "tests/test_executor.py::TestExecutor::test_execute_tpcds"


def tpc_plan_patch_eligible(patch: Path, changes: list[dict] | None = None) -> bool:
    """Admit one ordinary optimizer function-body edit to prospective replay."""
    try:
        changes = patch_changes(patch) if changes is None else changes
    except (OSError, UnicodeError, ValueError, TypeError):
        return False
    if len(changes) != 1:
        return False
    change = changes[0]
    path = change.get("old")
    if (
        type(path) is not str
        or change.get("new") != path
        or change.get("diff_old") != path
        or change.get("diff_new") != path
        or not path.startswith("sqlglot/optimizer/")
        or not path.endswith(".py")
        or change.get("new_file_mode_count")
        or not change.get("lines")
        or invalid_python_patch(change, path)
    ):
        return False
    tree = source_tree(path)
    old_source = pinned_sources().get(path)
    new_source = patched_source(change, path)
    if tree is None or old_source is None or new_source is None:
        return False
    try:
        old_tokens = [
            token
            for token in tokenize.generate_tokens(io.StringIO(old_source).readline)
            if token.type not in {tokenize.ENCODING, tokenize.ENDMARKER}
        ]
        new_tokens = [
            token
            for token in tokenize.generate_tokens(io.StringIO(new_source).readline)
            if token.type not in {tokenize.ENCODING, tokenize.ENDMARKER}
        ]
    except (tokenize.TokenError, IndentationError):
        return False
    differences = [
        (left, right)
        for left, right in zip(old_tokens, new_tokens)
        if (left.type, left.string) != (right.type, right.string)
    ]
    if len(old_tokens) != len(new_tokens) or len(differences) != 1:
        return False
    left, right = differences[0]
    allowed_names = {"is", "not", "in", "True", "False", "None"}
    if left.type == tokenize.NAME or right.type == tokenize.NAME:
        if left.string not in allowed_names or right.string not in allowed_names:
            return False
    elif left.type not in {tokenize.OP, tokenize.NUMBER, tokenize.STRING} or right.type not in {
        tokenize.OP,
        tokenize.NUMBER,
        tokenize.STRING,
    }:
        return False
    functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and all(
            node.lineno < line <= (node.end_lineno or node.lineno)
            for line in change["lines"]
        )
    ]
    if not functions:
        return False
    owner = min(
        functions,
        key=lambda node: ((node.end_lineno or node.lineno) - node.lineno, node.col_offset),
    )
    if owner.decorator_list or isinstance(owner, ast.AsyncFunctionDef):
        return False
    return all(
        preserves_function_bindings(change, path, line) for line in change["lines"]
    )


def tpc_function_docstring_only(patch: Path) -> bool:
    """Prove a patch changes only ordinary function docstring contents."""
    try:
        if patch.stat().st_size > 65_536:
            return False
        changes = patch_changes(patch)
    except (OSError, UnicodeError, ValueError, TypeError):
        return False
    if len(changes) != 1:
        return False
    change = changes[0]
    path = change.get("old")
    if (
        type(path) is not str
        or change.get("new") != path
        or change.get("diff_old") != path
        or change.get("diff_new") != path
        or not path.startswith("sqlglot/optimizer/")
        or not path.endswith(".py")
        or change.get("new_file_mode_count")
        or change.get("structural_invalid")
        or change.get("non_lf")
        or any(COMMENT_DIRECTIVE.search(line) for line in change.get("payload", ()))
    ):
        return False
    original = pinned_sources().get(path)
    prospective = patched_source(change, path)
    if original is None or prospective is None:
        return False
    try:
        old_tree = ast.parse(original, filename=path, type_comments=True)
        new_tree = ast.parse(prospective, filename=path, type_comments=True)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return False

    def docstrings(tree: ast.Module) -> list[tuple[str, str, bool]]:
        result = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                value = ast.get_docstring(node, clean=False)
                if value is not None:
                    result.append((node.name, value, bool(node.decorator_list)))
        return result

    old_docs = docstrings(old_tree)
    new_docs = docstrings(new_tree)

    def compile_internable(value: str) -> bool:
        return bool(value) and (
            value.isidentifier()
            or (
                value.isascii()
                and all(character.isalnum() or character == "_" for character in value)
            )
        )

    if (
        [(name, decorated) for name, _value, decorated in old_docs]
        != [(name, decorated) for name, _value, decorated in new_docs]
        or old_docs == new_docs
        or any(
            old_decorated
            for (_old_name, old_value, old_decorated),
            (_new_name, new_value, _new_decorated) in zip(old_docs, new_docs)
            if old_value != new_value
        )
        or any(
            compile_internable(old_value) or compile_internable(new_value)
            for (_old_name, old_value, _old_decorated),
            (_new_name, new_value, _new_decorated) in zip(old_docs, new_docs)
            if old_value != new_value
        )
    ):
        return False

    class Normalize(ast.NodeTransformer):
        def visit_Module(self, node):
            for child in node.body:
                if (
                    isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and child.body
                    and isinstance(child.body[0], ast.Expr)
                    and isinstance(child.body[0].value, ast.Constant)
                    and isinstance(child.body[0].value.value, str)
                ):
                    child.body[0].value.value = "__KASHIMO_DOCSTRING__"
            return node

    Normalize().visit(old_tree)
    Normalize().visit(new_tree)
    return ast.dump(old_tree, include_attributes=False) == ast.dump(
        new_tree, include_attributes=False
    )


def patch_changes(patch: Path) -> list[dict]:
    """Return each changed path and its affected line anchors in the base tree."""
    changes: list[dict] = []
    change = None
    hunk = None
    old_line = 0
    new_line = 0
    addition_anchor = None
    in_hunk = False
    non_lf = b"\r" in patch.read_bytes()
    for line in patch.read_text().splitlines():
        if line.startswith("diff --git "):
            header = line.split(" ")
            change = {
                "old": None,
                "new": None,
                "lines": set(),
                "payload": [],
                "removed": [],
                "added": [],
                "added_at": [],
                "added_new_at": [],
                "hunks": [],
                "diff_old": header[2][2:] if len(header) == 4 and header[2].startswith("a/") else None,
                "diff_new": header[3][2:] if len(header) == 4 and header[3].startswith("b/") else None,
                "new_file_mode": None,
                "new_file_mode_count": 0,
                "old_marker_count": 0,
                "new_marker_count": 0,
                "index_count": 0,
                "new_file_index": False,
                "structural_invalid": False,
                "binary": False,
                "non_lf": non_lf,
                "no_newline_marker": False,
            }
            changes.append(change)
            hunk = None
            in_hunk = False
        elif change is None:
            continue
        elif line.startswith("GIT binary patch") or line.startswith("Binary files "):
            change["binary"] = True
        elif line.startswith("\\ No newline at end of file"):
            change["no_newline_marker"] = True
        elif not in_hunk and line.startswith("new file mode "):
            change["new_file_mode"] = line.removeprefix("new file mode ")
            change["new_file_mode_count"] += 1
        elif not in_hunk and line.startswith("index "):
            change["index_count"] += 1
            change["new_file_index"] = bool(
                re.fullmatch(r"index 0{7,64}\.\.[0-9a-f]{7,64}", line)
            )
        elif not in_hunk and line.startswith("rename from "):
            change["old"] = line.removeprefix("rename from ")
            change["structural_invalid"] = True
        elif not in_hunk and line.startswith("rename to "):
            change["new"] = line.removeprefix("rename to ")
            change["structural_invalid"] = True
        elif not in_hunk and line.startswith(
            (
                "old mode ",
                "new mode ",
                "deleted file mode ",
                "similarity index ",
                "dissimilarity index ",
                "copy from ",
                "copy to ",
            )
        ):
            change["structural_invalid"] = True
        elif match := HUNK.match(line):
            old_start = int(match.group(1))
            old_count = int(match.group(2) or 1)
            old_line = old_start + (old_count == 0)
            new_start = int(match.group(3))
            new_count = int(match.group(4) or 1)
            new_line = new_start
            addition_anchor = None
            hunk = {
                "old_start": old_start,
                "old_count": old_count,
                "new_start": new_start,
                "new_count": new_count,
                "lines": [],
            }
            change["hunks"].append(hunk)
            in_hunk = True
        elif not in_hunk and line.startswith("--- "):
            change["old_marker_count"] += 1
            name = line[4:].split("\t", 1)[0]
            change["old"] = name[2:] if name.startswith("a/") else name
        elif not in_hunk and line.startswith("+++ "):
            change["new_marker_count"] += 1
            name = line[4:].split("\t", 1)[0]
            change["new"] = name[2:] if name.startswith("b/") else name
        elif line.startswith(("-", "+", " ")) and hunk is None:
            # A rejected binary or malformed structural body can contain
            # payload-looking lines without a unified text hunk. Never index a
            # missing hunk; mark the section unknown so ordinary selection
            # retains the complete test inventory.
            change["structural_invalid"] = True
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
            change["added_new_at"].append((new_line, line[1:]))
            new_line += 1
        elif line.startswith(" "):
            hunk["lines"].append((" ", line[1:]))
            old_line += 1
            new_line += 1
            addition_anchor = None
        elif in_hunk:
            change["structural_invalid"] = True
    return changes


def pinned_sources() -> dict[str, str]:
    global _PINNED_SOURCES
    if _PINNED_SOURCES is None:
        with gzip.open(SEMANTIC_SOURCES, "rt", encoding="utf-8") as source_file:
            _PINNED_SOURCES = json.load(source_file)
    return _PINNED_SOURCES


def source_tree(path: str) -> ast.Module | None:
    if path not in _SOURCE_TREES:
        source = pinned_sources().get(path)
        if source is None:
            return None
        try:
            _SOURCE_TREES[path] = ast.parse(source, filename=path, type_comments=True)
        except (SyntaxError, ValueError):
            _SOURCE_TREES[path] = None
    return _SOURCE_TREES[path]


class _AstIndex:
    """One breadth-first AST pass with the same node order as ``ast.walk``."""

    __slots__ = ("nodes", "parents", "statements", "definitions", "functions")

    def __init__(self, tree: ast.AST):
        nodes = []
        parents = {}
        pending = deque([tree])
        while pending:
            node = pending.popleft()
            nodes.append(node)
            children = []
            for _field, value in ast.iter_fields(node):
                if isinstance(value, ast.AST):
                    children.append(value)
                elif isinstance(value, list):
                    children.extend(item for item in value if isinstance(item, ast.AST))
            for child in children:
                parents[child] = node
                pending.append(child)
        self.nodes = tuple(nodes)
        self.parents = parents
        self.statements = tuple(node for node in nodes if isinstance(node, ast.stmt))
        self.definitions = tuple(
            node
            for node in nodes
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        )
        self.functions = tuple(
            node for node in nodes if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        )

    def path(self, node: ast.AST) -> tuple[tuple[str, int | None], ...] | None:
        components = []
        root = self.nodes[0]
        while node is not root:
            parent = self.parents.get(node)
            if parent is None:
                return None
            component = None
            for field, value in ast.iter_fields(parent):
                if value is node:
                    component = (field, None)
                    break
                if isinstance(value, list):
                    for index, item in enumerate(value):
                        if item is node:
                            component = (field, index)
                            break
                    if component is not None:
                        break
            if component is None:
                return None
            components.append(component)
            node = parent
        return tuple(reversed(components))


def _source_index(path: str) -> _AstIndex | None:
    tree = source_tree(path)
    cached = _SOURCE_INDEXES.get(path)
    if cached is None or cached[0] is not tree:
        cached = (tree, _AstIndex(tree) if tree is not None else None)
        _SOURCE_INDEXES[path] = cached
    return cached[1]


def precise_coverage_line(path: str, line: int) -> bool:
    """Whether executing a line necessarily reaches the changed expression."""
    tree = source_tree(path)
    index = _source_index(path)
    if tree is None or index is None:
        return False
    statements = [
        node
        for node in index.statements
        if node.lineno <= line <= (node.end_lineno or node.lineno)
    ]
    if not statements:
        return False
    statement = min(
        statements,
        key=lambda node: ((node.end_lineno or node.lineno) - node.lineno, node.col_offset),
    )
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return False
    definitions = [
        node
        for node in index.definitions
        if node is not statement
        and node.lineno <= statement.lineno
        and (node.end_lineno or node.lineno) >= (statement.end_lineno or statement.lineno)
    ]
    if not definitions:
        return False
    definition = min(
        definitions,
        key=lambda node: ((node.end_lineno or node.lineno) - node.lineno, node.col_offset),
    )
    if not isinstance(definition, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    if (
        definition.body
        and definition.body[0] is statement
        and isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    ):
        # A function docstring is observable through ``__doc__`` even though
        # executing the function never produces a coverage event for it.
        return False
    if path not in _SOURCE_CODE:
        try:
            _SOURCE_CODE[path] = compile(
                pinned_sources()[path], path, "exec", dont_inherit=True
            )
        except (SyntaxError, ValueError, OverflowError):
            return False
    first_line = min(
        [definition.lineno, *(decorator.lineno for decorator in definition.decorator_list)]
    )
    matches = []
    pending = [_SOURCE_CODE[path]]
    while pending:
        code = pending.pop()
        if code.co_name == definition.name and code.co_firstlineno == first_line:
            matches.append(code)
        pending.extend(
            constant for constant in code.co_consts if isinstance(constant, types.CodeType)
        )
    if len(matches) != 1 or not any(
        code_line == line for _, _, code_line in matches[0].co_lines()
    ):
        # Constant-folded statements and other non-emitting source lines can
        # be semantically observable after a patch despite having no coverage.
        return False
    if statement.lineno == (statement.end_lineno or statement.lineno) == line:
        return True
    header_expressions = []
    if isinstance(statement, (ast.If, ast.While, ast.Assert)):
        header_expressions.append(statement.test)
    elif isinstance(statement, (ast.For, ast.AsyncFor)):
        header_expressions.extend((statement.target, statement.iter))
    elif isinstance(statement, (ast.With, ast.AsyncWith)):
        header_expressions.extend(item.context_expr for item in statement.items)
    return any(
        expression.lineno == (expression.end_lineno or expression.lineno) == line
        for expression in header_expressions
    )


def import_definition_line(path: str, line: int) -> bool:
    """Whether a definition fragment executes while its module is imported."""
    if path not in _IMPORT_DEFINITION_RANGES:
        tree = source_tree(path)
        index = _source_index(path)
        if tree is None or index is None:
            _IMPORT_DEFINITION_RANGES[path] = []
        else:
            parents = index.parents
            ranges = []
            for node in index.definitions:
                ancestor = parents.get(node)
                nested_in_function = False
                while ancestor is not None:
                    if isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                        nested_in_function = True
                        break
                    ancestor = parents.get(ancestor)
                if nested_in_function:
                    continue
                body_start = min(
                    (statement.lineno for statement in node.body),
                    default=node.lineno,
                )
                ranges.append((node.lineno, max(node.lineno, body_start - 1)))
                ranges.extend(
                    (decorator.lineno, decorator.end_lineno or decorator.lineno)
                    for decorator in node.decorator_list
                )
            _IMPORT_DEFINITION_RANGES[path] = ranges
    return any(
        start <= line <= end for start, end in _IMPORT_DEFINITION_RANGES[path]
    )


def init_subclass_attributes() -> set[str]:
    """Class attributes read directly by pinned ``__init_subclass__`` hooks."""
    global _INIT_SUBCLASS_ATTRIBUTES
    if _INIT_SUBCLASS_ATTRIBUTES is None:
        attributes = set()
        for path, source in pinned_sources().items():
            if "def __init_subclass__" not in source:
                continue
            tree = source_tree(path)
            if tree is None:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if node.name != "__init_subclass__" or not node.args.args:
                    continue
                receiver = node.args.args[0].arg
                attributes.update(
                    child.attr
                    for child in ast.walk(node)
                    if isinstance(child, ast.Attribute)
                    and isinstance(child.value, ast.Name)
                    and child.value.id == receiver
                    and isinstance(child.ctx, ast.Load)
                )
        _INIT_SUBCLASS_ATTRIBUTES = attributes
    return _INIT_SUBCLASS_ATTRIBUTES


def import_expression_hazard(
    change: dict, path: str, hook_attributes: set[str] | None = None
) -> bool:
    """Detect changed class/module expressions that can now fail during import."""
    source = pinned_sources().get(path)
    changed = patched_source(change, path)
    if source is None or changed is None:
        return False
    original_tree = source_tree(path)
    original_index = _source_index(path)
    if original_tree is None or original_index is None:
        return True

    def annotations_deferred(tree: ast.Module) -> bool:
        return any(
            isinstance(statement, ast.ImportFrom)
            and statement.module == "__future__"
            and any(alias.name == "annotations" for alias in statement.names)
            for statement in tree.body
        )

    def context(
        tree: ast.Module, index: _AstIndex, line: int
    ) -> tuple[ast.stmt | None, bool]:
        parents = index.parents
        candidates = []
        for parent in index.nodes:
            start = getattr(parent, "lineno", None)
            end = getattr(parent, "end_lineno", start)
            if start is not None and start <= line <= (end or start):
                candidates.append(parent)
        if not candidates:
            return None, False
        node = min(
            candidates,
            key=lambda item: (
                (getattr(item, "end_lineno", line) or line)
                - getattr(item, "lineno", line),
                (getattr(item, "end_col_offset", 0) or 0)
                - getattr(item, "col_offset", 0),
            ),
        )
        nested_runtime = False
        statement = None
        while node is not None:
            if isinstance(node, ast.Lambda):
                nested_runtime = True
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                body_start = min(
                    (item.lineno for item in node.body),
                    default=node.end_lineno or node.lineno,
                )
                if line > node.lineno and line >= body_start:
                    nested_runtime = True
            if statement is None and isinstance(node, ast.stmt):
                statement = node
            node = parents.get(node)
        return statement, nested_runtime

    def assignment_used_later(
        tree: ast.Module, index: _AstIndex, statement: ast.stmt
    ) -> bool:
        """Whether an assigned name is loaded later during the same import."""
        if isinstance(statement, ast.Assign):
            targets = statement.targets
        elif isinstance(statement, ast.AnnAssign):
            targets = [statement.target]
        else:
            return False
        names = {target.id for target in targets if isinstance(target, ast.Name)}
        if len(names) != len(targets):
            return True

        parents = index.parents
        container = parents.get(statement)
        if not isinstance(container, (ast.Module, ast.ClassDef)):
            return False
        try:
            following = container.body[container.body.index(statement) + 1 :]
        except ValueError:
            return True

        class ImportLoads(ast.NodeVisitor):
            found = False

            def visit_Name(self, node: ast.Name) -> None:
                if isinstance(node.ctx, ast.Load) and node.id in names:
                    self.found = True

            def _definition_header(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
                for decorator in node.decorator_list:
                    self.visit(decorator)
                for default in (*node.args.defaults, *node.args.kw_defaults):
                    if default is not None:
                        self.visit(default)
                for argument in (
                    *node.args.posonlyargs,
                    *node.args.args,
                    *node.args.kwonlyargs,
                ):
                    if argument.annotation is not None:
                        self.visit(argument.annotation)
                if node.args.vararg and node.args.vararg.annotation is not None:
                    self.visit(node.args.vararg.annotation)
                if node.args.kwarg and node.args.kwarg.annotation is not None:
                    self.visit(node.args.kwarg.annotation)
                if node.returns is not None:
                    self.visit(node.returns)

            visit_FunctionDef = _definition_header
            visit_AsyncFunctionDef = _definition_header

            def visit_Lambda(self, node: ast.Lambda) -> None:
                for default in (*node.args.defaults, *node.args.kw_defaults):
                    if default is not None:
                        self.visit(default)

        visitor = ImportLoads()
        for later in following:
            visitor.visit(later)
            if visitor.found:
                return True
        return False

    original_lines = change["lines"] if change["removed"] else set()
    try:
        changed_tree = ast.parse(changed, filename=path, type_comments=True)
    except (SyntaxError, ValueError):
        return True
    changed_index = _AstIndex(changed_tree)

    lines = {line for line, _ in change["added_new_at"]}
    if (
        original_lines
        and all(context(original_tree, original_index, line)[1] for line in original_lines)
        and (
            not lines
            or all(context(changed_tree, changed_index, line)[1] for line in lines)
        )
    ):
        return False
    original_statements = {
        statement
        for line in original_lines
        for statement, nested_runtime in [context(original_tree, original_index, line)]
        if statement is not None and not nested_runtime
    }
    patched_statements = {
        statement
        for line in lines
        for statement, nested_runtime in [context(changed_tree, changed_index, line)]
        if statement is not None and not nested_runtime
    }

    def class_assignment_key(
        tree: ast.Module, statement: ast.stmt
    ) -> tuple[tuple[str, ...], str] | None:
        if isinstance(statement, ast.Assign):
            if len(statement.targets) != 1 or not isinstance(statement.targets[0], ast.Name):
                return None
            target = statement.targets[0].id
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
            target = statement.target.id
        else:
            return None
        parents = (
            original_index.parents if tree is original_tree else changed_index.parents
        )
        owner = parents.get(statement)
        if not isinstance(owner, ast.ClassDef):
            return None
        names = []
        while isinstance(owner, ast.ClassDef):
            names.append(owner.name)
            owner = parents.get(owner)
        if not isinstance(owner, ast.Module):
            return None
        return tuple(reversed(names)), target

    def literal_shape(value: ast.AST | None):
        if value is None:
            return ("none",)
        try:
            literal = ast.literal_eval(value)
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            return None

        def shape(item):
            if isinstance(item, dict):
                return (
                    "dict",
                    tuple(
                        ((type(key).__qualname__, repr(key)), shape(child))
                        for key, child in item.items()
                    ),
                )
            if isinstance(item, list):
                return ("list", tuple(shape(child) for child in item))
            if isinstance(item, tuple):
                return ("tuple", tuple(shape(child) for child in item))
            if isinstance(item, set):
                return (
                    "set",
                    tuple(sorted((shape(child) for child in item), key=repr)),
                )
            return ("scalar", type(item).__qualname__)

        return shape(literal)

    original_class_assignments = {
        key: statement
        for statement in original_statements
        for key in [class_assignment_key(original_tree, statement)]
        if key is not None
    }
    patched_class_assignments = {
        key: statement
        for statement in patched_statements
        for key in [class_assignment_key(changed_tree, statement)]
        if key is not None
    }
    for key in original_class_assignments.keys() | patched_class_assignments.keys():
        original_statement = original_class_assignments.get(key)
        patched_statement = patched_class_assignments.get(key)
        if original_statement is None or patched_statement is None:
            return True
        original_value = original_statement.value
        patched_value = patched_statement.value
        original_shape = literal_shape(original_value)
        patched_shape = literal_shape(patched_value)
        if original_shape != patched_shape:
            return True
        if (
            key[1] in (hook_attributes or init_subclass_attributes())
            and original_shape is not None
            and original_shape[0] != "dict"
            and ast.dump(original_value, include_attributes=False)
            != ast.dump(patched_value, include_attributes=False)
        ):
            return True

    for statement in original_statements:
        if isinstance(statement, ast.Assign):
            if not all(isinstance(target, ast.Name) for target in statement.targets):
                return True
            value = statement.value
        elif isinstance(statement, ast.AnnAssign):
            if not isinstance(statement.target, ast.Name):
                return True
            if not annotations_deferred(original_tree):
                return True
            value = statement.value
        else:
            # Removing or replacing an import-time mutation/definition can
            # alter every importer even when old coordinates vanish from the
            # patched tree.
            return True
        if assignment_used_later(original_tree, original_index, statement):
            return True
        if value is not None:
            try:
                ast.literal_eval(value)
            except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                return True

    for line in lines:
        statement, nested_runtime = context(changed_tree, changed_index, line)
        if nested_runtime:
            continue
        if statement is None:
            old_statement, old_nested_runtime = context(
                original_tree, original_index, line
            )
            if old_statement is not None and not old_nested_runtime:
                return True
            continue
        if isinstance(statement, ast.Assign):
            if not all(isinstance(target, ast.Name) for target in statement.targets):
                return True
            value = statement.value
        elif isinstance(statement, ast.AnnAssign):
            if not isinstance(statement.target, ast.Name):
                return True
            if not annotations_deferred(changed_tree):
                return True
            value = statement.value
        elif isinstance(statement, ast.Expr):
            value = statement.value
        else:
            # Definition headers have a separate import-time gate. Other class
            # and module statements can execute arbitrary code.
            if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                return True
            if change["added"]:
                return True
            continue
        if value is None:
            continue
        if assignment_used_later(changed_tree, changed_index, statement):
            return True
        try:
            ast.literal_eval(value)
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            return True
    return False


def comment_only_addition(change: dict) -> bool:
    return (
        bool(change["added"])
        and not change["removed"]
        and all(line.strip().startswith("#") for line in change["added"] if line.strip())
    )


def patched_source(change: dict, path: str) -> str | None:
    """Apply one file's unified hunks to its pinned source."""
    if "_patched_source" in change:
        return change["_patched_source"]
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
            change["_patched_source"] = None
            return None
        result.extend(original[cursor:start])
        cursor = start
        for marker, text in hunk["lines"]:
            if marker == "+":
                result.append(text)
                continue
            if cursor >= len(original) or original[cursor] != text:
                change["_patched_source"] = None
                return None
            if marker == " ":
                result.append(original[cursor])
            cursor += 1
    result.extend(original[cursor:])
    ending = "\n" if source.endswith("\n") else ""
    change["_patched_source"] = "\n".join(result) + ending
    return change["_patched_source"]


def contained_fresh_receiver_edit(change: dict, path: str) -> bool:
    """Apply the source-derived fresh-object ownership admission gate."""
    global _SHARED_ARG_WRITE_MODEL
    if not SHARED_ARG_WRITE_ENABLED:
        return False
    if _SHARED_ARG_WRITE_MODEL is None:
        _SHARED_ARG_WRITE_MODEL = load_shared_arg_model(SHARED_ARG_WRITE_MODEL)
    source = pinned_sources().get(path)
    changed = patched_source(change, path)
    return bool(
        _SHARED_ARG_WRITE_MODEL is not None
        and source is not None
        and changed is not None
        and fresh_receiver_candidate(
            change, path, source, changed, _SHARED_ARG_WRITE_MODEL
        )
    )


def invalid_python_patch(change: dict, path: str) -> bool:
    if not path.endswith(".py") or path not in pinned_sources():
        return False
    changed = patched_source(change, path)
    if changed is None:
        return True
    try:
        change["_patched_code"] = compile(changed, path, "exec", dont_inherit=True)
    except (SyntaxError, ValueError, OverflowError):
        return True
    return False


def preserves_function_bindings(change: dict, path: str, line: int) -> bool:
    """Prove an edit cannot change name binding or generator semantics elsewhere."""
    tree = source_tree(path)
    index = _source_index(path)
    if tree is None or index is None:
        return False
    functions = [
        node
        for node in index.functions
        if node.lineno <= line <= (node.end_lineno or node.lineno)
    ]
    if not functions:
        return False
    function = min(
        functions,
        key=lambda node: ((node.end_lineno or node.lineno) - node.lineno, node.col_offset),
    )
    first_line = min(
        [function.lineno, *(decorator.lineno for decorator in function.decorator_list)]
    )
    if path not in _SOURCE_CODE:
        try:
            _SOURCE_CODE[path] = compile(
                pinned_sources()[path], path, "exec", dont_inherit=True
            )
        except (SyntaxError, ValueError, OverflowError):
            return False
    patched_code = change.get("_patched_code")
    if patched_code is None:
        changed = patched_source(change, path)
        if changed is None:
            return False
        try:
            patched_code = compile(changed, path, "exec", dont_inherit=True)
        except (SyntaxError, ValueError, OverflowError):
            return False

    def matching_codes(root: types.CodeType) -> list[types.CodeType]:
        matches = []
        stack = [root]
        while stack:
            code = stack.pop()
            if code.co_name == function.name and code.co_firstlineno == first_line:
                matches.append(code)
            stack.extend(
                constant for constant in code.co_consts if isinstance(constant, types.CodeType)
            )
        return matches

    original_matches = matching_codes(_SOURCE_CODE[path])
    patched_matches = matching_codes(patched_code)
    if len(original_matches) != 1 or len(patched_matches) != 1:
        return False

    def binding_fingerprint(code: types.CodeType) -> tuple:
        return (
            code.co_argcount,
            code.co_posonlyargcount,
            code.co_kwonlyargcount,
            code.co_nlocals,
            code.co_varnames,
            code.co_cellvars,
            code.co_freevars,
            code.co_flags,
        )

    return binding_fingerprint(original_matches[0]) == binding_fingerprint(
        patched_matches[0]
    )


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




def fresh_table_alias_copy_edit(
    change: dict,
    path: str,
    fresh_alias_model: dict,
    hook_attributes: set[str] | None = None,
) -> bool:
    """Prove ``copy=`` is irrelevant for a profiled fresh inline table."""
    # Avoid parsing or walking sources for unrelated changes. The AST check
    # below remains authoritative; this gate only recognizes one boolean copy
    # keyword token changing on an otherwise text-identical removed/added line.
    if len(change["removed"]) != 1 or len(change["added"]) != 1:
        return False
    old_line, new_line = change["removed"][0], change["added"][0]
    copy_token = re.compile(r"\bcopy\s*=\s*(True|False)\b")
    old_matches = list(copy_token.finditer(old_line))
    new_matches = list(copy_token.finditer(new_line))
    if (
        len(old_matches) != 1
        or len(new_matches) != 1
        or old_matches[0].group(1) == new_matches[0].group(1)
        or copy_token.sub("copy=<bool>", old_line)
        != copy_token.sub("copy=<bool>", new_line)
    ):
        return False

    entries = fresh_alias_model.get("d", {}).get(path)
    source = pinned_sources().get(path)
    changed = patched_source(change, path)
    if (
        not entries
        or source is None
        or changed is None
        or path in PROCESS_SERIALIZATION_FILES
        or any(COMMENT_DIRECTIVE.search(line) for line in change["payload"])
    ):
        return False
    try:
        original_tree = ast.parse(source, filename=path, type_comments=True)
        changed_tree = ast.parse(changed, filename=path, type_comments=True)
    except (SyntaxError, ValueError):
        return False

    candidates = []
    for start, end, call_dump, state, readers in entries:
        if state != "safe" or not any(start <= line <= end for line in change["lines"]):
            continue
        if not isinstance(readers, list) or any(
            type(index) is not int
            or index < 0
            or index >= fresh_alias_model.get("n", 0)
            for index in readers
        ):
            return False
        matches = [
            node
            for node in ast.walk(original_tree)
            if isinstance(node, ast.Call)
            and node.lineno == start
            and (node.end_lineno or node.lineno) == end
            and ast.dump(node, include_attributes=False) == call_dump
        ]
        if len(matches) != 1:
            return False
        candidates.append(matches[0])
    if len(candidates) != 1:
        return False
    original_call = candidates[0]

    def changed_candidate(tree: ast.Module) -> tuple[ast.Call, ast.keyword] | None:
        matches = []
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and node.lineno == original_call.lineno
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "exp"
                and node.func.attr == "alias_"
                and node.args
                and isinstance(node.args[0], ast.Call)
                and isinstance(node.args[0].func, ast.Attribute)
                and isinstance(node.args[0].func.value, ast.Name)
                and node.args[0].func.value.id == "exp"
                and node.args[0].func.attr == "table_"
            ):
                continue
            keywords = [keyword for keyword in node.keywords if keyword.arg == "copy"]
            if (
                len(keywords) == 1
                and isinstance(keywords[0].value, ast.Constant)
                and type(keywords[0].value.value) is bool
            ):
                matches.append((node, keywords[0]))
        return matches[0] if len(matches) == 1 else None

    original = changed_candidate(original_tree)
    patched = changed_candidate(changed_tree)
    if original is None or patched is None:
        return False
    original_call, original_copy = original
    _, patched_copy = patched
    if original_copy.value.value == patched_copy.value.value:
        return False
    original_copy.value = ast.Constant(value=False)
    patched_copy.value = ast.Constant(value=False)
    if ast.dump(original_tree, include_attributes=False) != ast.dump(
        changed_tree, include_attributes=False
    ):
        return False
    return preserves_function_bindings(
        change, path, original_call.lineno
    ) and not import_expression_hazard(change, path, hook_attributes)


def mapped_set(model: dict, set_id: int) -> set[int]:
    return set(model["z"][set_id])


def deferred_factory_shape(value: ast.AST, tree: ast.Module, path: str) -> tuple | None:
    """Recognize a call that only allocates and returns a closure.

    Literal arguments are evaluated before the call, while the factory itself
    may only define one undecorated, default-free nested function and return it.
    With deferred annotations this executes no user expression and has no
    observable effect unless the resulting dictionary value is read.
    """
    if not (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and not any(isinstance(argument, ast.Starred) for argument in value.args)
        and all(keyword.arg is not None for keyword in value.keywords)
    ):
        return None
    for argument in [*value.args, *(keyword.value for keyword in value.keywords)]:
        try:
            ast.literal_eval(argument)
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            return None

    def effective_bindings(module: ast.Module, name: str) -> tuple[list[ast.AST], bool]:
        """Inventory every possible binding of a factory name conservatively."""
        bindings: list[ast.AST] = []
        dynamic = False
        for node in ast.walk(module):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.name == name:
                    bindings.append(node)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    if alias.name == "*":
                        dynamic = True
                    bound = alias.asname or (
                        alias.name.split(".", 1)[0]
                        if isinstance(node, ast.Import)
                        else alias.name
                    )
                    if bound == name:
                        bindings.append(alias)
            elif isinstance(node, ast.Name) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                if node.id == name:
                    bindings.append(node)
            elif isinstance(node, ast.Attribute) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                if node.attr == name:
                    bindings.append(node)
            elif isinstance(node, ast.ExceptHandler) and node.name == name:
                bindings.append(node)
            elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name == name:
                bindings.append(node)
            elif isinstance(node, ast.MatchMapping) and node.rest == name:
                bindings.append(node)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in {"exec", "globals", "locals"}:
                    dynamic = True
                elif (
                    node.func.id == "setattr"
                    and len(node.args) >= 2
                    and isinstance(node.args[1], ast.Constant)
                    and node.args[1].value == name
                ):
                    dynamic = True
        return bindings, dynamic

    definition_tree = tree
    definition_name = value.func.id
    definitions = [
        statement
        for statement in definition_tree.body
        if isinstance(statement, ast.FunctionDef)
        and statement.name == definition_name
    ]
    selected_binding: ast.AST | None = definitions[0] if len(definitions) == 1 else None
    selected_binding_line = (
        selected_binding.lineno if isinstance(selected_binding, ast.FunctionDef) else None
    )
    if not definitions:
        imports = [
            (statement, alias)
            for statement in tree.body
            if isinstance(statement, ast.ImportFrom)
            and statement.level == 0
            and statement.module
            for alias in statement.names
            if (alias.asname or alias.name) == value.func.id
        ]
        if len(imports) != 1:
            return None
        statement, alias = imports[0]
        selected_binding = alias
        selected_binding_line = statement.lineno
        imported_path = f"{statement.module.replace('.', '/')}.py"
        imported_source = pinned_sources().get(imported_path)
        if imported_source is None:
            return None
        try:
            definition_tree = ast.parse(
                imported_source, filename=imported_path, type_comments=True
            )
        except (SyntaxError, ValueError):
            return None
        definition_name = alias.name
        definitions = [
            item
            for item in definition_tree.body
            if isinstance(item, ast.FunctionDef)
            and item.name == definition_name
        ]
    if len(definitions) != 1:
        return None
    factory = definitions[0]
    call_bindings, call_dynamic = effective_bindings(tree, value.func.id)
    definition_bindings, definition_dynamic = effective_bindings(
        definition_tree, definition_name
    )
    if (
        call_dynamic
        or definition_dynamic
        or selected_binding is None
        or selected_binding_line is None
        or selected_binding_line >= value.lineno
        or len(call_bindings) != 1
        or call_bindings[0] is not selected_binding
        or len(definition_bindings) != 1
        or definition_bindings[0] is not factory
    ):
        return None
    if factory.decorator_list or len(factory.body) != 2:
        return None
    nested, returned = factory.body
    if not (
        isinstance(nested, (ast.FunctionDef, ast.AsyncFunctionDef))
        and not nested.decorator_list
        and not getattr(nested, "type_params", ())
        and not nested.args.defaults
        and not any(default is not None for default in nested.args.kw_defaults)
        and isinstance(returned, ast.Return)
        and isinstance(returned.value, ast.Name)
        and returned.value.id == nested.name
    ):
        return None
    deferred_annotations = any(
        isinstance(statement, ast.ImportFrom)
        and statement.module == "__future__"
        and any(alias.name == "annotations" for alias in statement.names)
        for statement in definition_tree.body
    )
    if not deferred_annotations:
        annotations = [
            nested.returns,
            *(argument.annotation for argument in nested.args.posonlyargs),
            *(argument.annotation for argument in nested.args.args),
            *(argument.annotation for argument in nested.args.kwonlyargs),
            nested.args.vararg.annotation if nested.args.vararg else None,
            nested.args.kwarg.annotation if nested.args.kwarg else None,
        ]
        if any(annotation is not None for annotation in annotations):
            return None
    return (
        definition_name,
        len(value.args),
        tuple(keyword.arg for keyword in value.keywords),
    )


def zero_reader_dict_edit(
    change: dict,
    path: str,
    zero_model: dict,
    hook_attributes: set[str] | None = None,
) -> set[int] | None:
    """Narrow dictionary value edits to their exact certified key readers."""
    entries = zero_model.get("d", {}).get(path)
    source = pinned_sources().get(path)
    changed = patched_source(change, path)
    if not entries or source is None or changed is None:
        return None
    try:
        original_tree = ast.parse(source, filename=path, type_comments=True)
        changed_tree = ast.parse(changed, filename=path, type_comments=True)
    except (SyntaxError, ValueError):
        return None

    def assignments(tree: ast.Module):
        result = {}

        def visit_body(body: list[ast.stmt], owner: tuple[str, ...]) -> None:
            for statement in body:
                if isinstance(statement, ast.Assign):
                    targets = statement.targets
                elif isinstance(statement, ast.AnnAssign):
                    targets = [statement.target]
                else:
                    targets = []
                if (
                    len(targets) == 1
                    and isinstance(targets[0], ast.Name)
                    and isinstance(getattr(statement, "value", None), ast.Dict)
                ):
                    key = owner, targets[0].id
                    if key in result:
                        result[key] = None
                    else:
                        result[key] = statement
                if isinstance(statement, ast.ClassDef):
                    visit_body(statement.body, (*owner, statement.name))

        visit_body(tree.body, ())
        return result

    original_assignments = assignments(original_tree)
    changed_assignments = assignments(changed_tree)
    candidates = []
    changed_lines = change["lines"]
    for start, end, target, key_readers in entries:
        if not any(start <= line <= end for line in changed_lines):
            continue
        matches = [
            (key, statement)
            for key, statement in original_assignments.items()
            if key[1] == target
            and statement is not None
            and statement.lineno == start
            and (statement.end_lineno or statement.lineno) == end
        ]
        if len(matches) != 1:
            return None
        candidates.append((*matches[0], key_readers))
    if len(candidates) != 1:
        return None

    key, original_statement, key_readers = candidates[0]
    if not isinstance(key_readers, dict):
        return None
    changed_statement = changed_assignments.get(key)
    if changed_statement is None:
        return None
    original_dict = original_statement.value
    changed_dict = changed_statement.value
    if len(original_dict.keys) != len(changed_dict.keys):
        return None
    original_key_dumps = [
        ast.dump(item, include_attributes=False) if item is not None else None
        for item in original_dict.keys
    ]
    changed_key_dumps = [
        ast.dump(item, include_attributes=False) if item is not None else None
        for item in changed_dict.keys
    ]
    if original_key_dumps != changed_key_dumps:
        return None

    runtime_keys = []
    for key_node in original_dict.keys:
        if key_node is None:
            continue
        try:
            runtime_key = ast.literal_eval(key_node)
            hash(runtime_key)
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            return None
        if runtime_key in runtime_keys:
            return None
        runtime_keys.append(runtime_key)

    changed_values = [
        index
        for index, (old, new) in enumerate(
            zip(original_dict.values, changed_dict.values)
        )
        if ast.dump(old, include_attributes=False)
        != ast.dump(new, include_attributes=False)
    ]
    if not changed_values:
        return None
    all_changed_values_are_deferred_factories = True
    selected_readers: set[int] = set()

    def deferred_lambda_shape(value: ast.AST):
        if not isinstance(value, ast.Lambda):
            return None
        arguments = value.args
        if (
            arguments.defaults
            or any(default is not None for default in arguments.kw_defaults)
            or any(
                argument.annotation is not None
                for argument in [
                    *arguments.posonlyargs,
                    *arguments.args,
                    *arguments.kwonlyargs,
                    *([arguments.vararg] if arguments.vararg else []),
                    *([arguments.kwarg] if arguments.kwarg else []),
                ]
            )
        ):
            return None
        return ast.dump(arguments, include_attributes=False)

    for index in changed_values:
        key_dump = original_key_dumps[index]
        readers = key_readers.get(key_dump) if key_dump is not None else None
        if (
            not isinstance(readers, list)
            or any(
                type(reader) is not int
                or reader < 0
                or reader >= zero_model.get("n", 0)
                for reader in readers
            )
        ):
            return None
        selected_readers.update(readers)
        try:
            ast.literal_eval(original_dict.values[index])
            ast.literal_eval(changed_dict.values[index])
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            original_shape = deferred_factory_shape(
                original_dict.values[index], original_tree, path
            )
            changed_shape = deferred_factory_shape(
                changed_dict.values[index], changed_tree, path
            )
            if original_shape is None or original_shape != changed_shape:
                original_shape = deferred_lambda_shape(original_dict.values[index])
                changed_shape = deferred_lambda_shape(changed_dict.values[index])
                if original_shape is None or original_shape != changed_shape:
                    return None
        else:
            all_changed_values_are_deferred_factories = False
        original_dict.values[index] = ast.Constant(value=None)
        changed_dict.values[index] = ast.Constant(value=None)

    if ast.dump(original_tree, include_attributes=False) != ast.dump(
        changed_tree, include_attributes=False
    ):
        return None
    if not all_changed_values_are_deferred_factories and import_expression_hazard(
        change, path, hook_attributes
    ):
        return None
    return selected_readers


def profile_equivalent_predicate_edit(
    change: dict,
    path: str,
    predicate_model: dict,
    hook_attributes: set[str] | None = None,
) -> bool:
    """Prove the changed ordering operator is equivalent on the raw profile."""
    entries = predicate_model.get("d", {}).get(path)
    source = pinned_sources().get(path)
    changed = patched_source(change, path)
    if (
        not entries
        or source is None
        or changed is None
        or path in PROCESS_SERIALIZATION_FILES
        or any(COMMENT_DIRECTIVE.search(line) for line in change["payload"])
    ):
        return False
    try:
        original_tree = ast.parse(source, filename=path, type_comments=True)
        changed_tree = ast.parse(changed, filename=path, type_comments=True)
    except (SyntaxError, ValueError):
        return False

    def node_paths(tree: ast.AST):
        pending = [(tree, ())]
        while pending:
            node, path_parts = pending.pop()
            yield node, path_parts
            children = []
            for field, value in ast.iter_fields(node):
                if isinstance(value, ast.AST):
                    children.append((value, (*path_parts, (field, None))))
                elif isinstance(value, list):
                    children.extend(
                        (item, (*path_parts, (field, index)))
                        for index, item in enumerate(value)
                        if isinstance(item, ast.AST)
                    )
            pending.extend(reversed(children))

    def follow(tree: ast.AST, path_parts):
        node = tree
        for field, index in path_parts:
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

    positions = {
        (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset): (
            node,
            node_path,
        )
        for node, node_path in node_paths(original_tree)
        if isinstance(node, ast.Compare)
    }
    candidates = []
    for entry in entries:
        if len(entry) != 7:
            continue
        start, column, end, end_column, source_operator, state, observations = entry
        if not any(start <= line <= end for line in change["lines"]):
            continue
        found = positions.get((start, column, end, end_column))
        if found is None:
            continue
        original_compare, compare_path = found
        changed_compare = follow(changed_tree, compare_path)
        if (
            isinstance(changed_compare, ast.Compare)
            and len(original_compare.ops) == 1
            and len(changed_compare.ops) == 1
            and type(original_compare.ops[0]).__name__ == source_operator
        ):
            candidates.append(
                (
                    original_compare,
                    changed_compare,
                    compare_path,
                    source_operator,
                    state,
                    observations,
                )
            )
    if len(candidates) != 1:
        return False

    original_compare, changed_compare, _, old_operator, state, observations = candidates[0]
    new_operator = type(changed_compare.ops[0]).__name__
    if len(original_compare.ops) != 1 or len(changed_compare.ops) != 1:
        return False
    if len(original_compare.comparators) != 1 or len(changed_compare.comparators) != 1:
        return False
    if type(original_compare.ops[0]).__name__ != old_operator:
        return False
    if type(changed_compare.ops[0]).__name__ != new_operator:
        return False
    adjacent = {
        ("Lt", "LtE"),
        ("LtE", "Lt"),
        ("Gt", "GtE"),
        ("GtE", "Gt"),
    }
    if (old_operator, new_operator) not in adjacent:
        return False
    outcome_index = {"Lt": 0, "LtE": 1, "Gt": 2, "GtE": 3, "Eq": 4, "NotEq": 5}
    if (
        state != "safe"
        or not isinstance(observations, list)
        or not observations
        or any(
            not isinstance(outcome, list)
            or len(outcome) != len(outcome_index)
            or any(type(value) is not bool for value in outcome)
            or outcome[outcome_index[old_operator]]
            != outcome[outcome_index[new_operator]]
            for outcome in observations
        )
    ):
        return False

    def literal(node: ast.AST) -> bool:
        try:
            ast.literal_eval(node)
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            return False
        return True

    if not (
        literal(original_compare.left)
        or literal(original_compare.comparators[0])
    ):
        return False

    # The certificate is usable only when normalizing the one approved
    # operator makes the complete executable trees identical.  Operands,
    # evaluation order, surrounding expressions, bindings and type comments
    # therefore cannot change under this shortcut.
    original_compare.ops[0] = ast.Eq()
    changed_compare.ops[0] = ast.Eq()
    if ast.dump(original_tree, include_attributes=False) != ast.dump(
        changed_tree, include_attributes=False
    ):
        return False
    return preserves_function_bindings(
        change, path, original_compare.lineno
    ) and not import_expression_hazard(change, path, hook_attributes)


def class_attribute_edit(
    change: dict,
    path: str,
    attribute_model: dict,
    hook_attributes: set[str] | None = None,
) -> set[int] | None:
    """Narrow a literal class-attribute edit to exact owner-aware readers."""
    entries = attribute_model.get("d", {}).get(path)
    source = pinned_sources().get(path)
    changed = patched_source(change, path)
    if (
        not entries
        or source is None
        or changed is None
        or path in PROCESS_SERIALIZATION_FILES
        or any(COMMENT_DIRECTIVE.search(line) for line in change["payload"])
    ):
        return None
    try:
        original_tree = ast.parse(source, filename=path, type_comments=True)
        changed_tree = ast.parse(changed, filename=path, type_comments=True)
    except (SyntaxError, ValueError):
        return None

    def assignments(tree: ast.Module):
        result = {}

        def visit(body: list[ast.stmt], owners: tuple[str, ...]) -> None:
            for statement in body:
                if not isinstance(statement, ast.ClassDef):
                    continue
                owner = (*owners, statement.name)
                for item in statement.body:
                    if isinstance(item, ast.Assign):
                        targets = item.targets
                    elif isinstance(item, ast.AnnAssign):
                        targets = [item.target]
                    else:
                        continue
                    if len(targets) == 1 and isinstance(targets[0], ast.Name):
                        key = (owner, targets[0].id)
                        result[key] = item if key not in result else None
                visit(statement.body, owner)

        visit(tree.body, ())
        return result

    original_assignments = assignments(original_tree)
    changed_assignments = assignments(changed_tree)
    candidates = []
    for start, end, qualname, name, value_dump, state, readers in entries:
        if state != "safe" or not any(start <= line <= end for line in change["lines"]):
            continue
        key = (tuple(qualname.split(".")), name)
        statement = original_assignments.get(key)
        if (
            statement is None
            or statement.lineno != start
            or (statement.end_lineno or statement.lineno) != end
            or ast.dump(statement.value, include_attributes=False) != value_dump
        ):
            continue
        candidates.append((key, statement, readers))
    if len(candidates) != 1:
        return None
    key, original_statement, readers = candidates[0]
    changed_statement = changed_assignments.get(key)
    if changed_statement is None:
        return None
    old_value = original_statement.value
    new_value = changed_statement.value
    try:
        old_literal = ast.literal_eval(old_value)
        new_literal = ast.literal_eval(new_value)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return None

    def safe_literal(value) -> bool:
        return type(value) in (type(None), bool, int, float, complex, str, bytes) or (
            type(value) is tuple and all(safe_literal(item) for item in value)
        )

    if (
        not safe_literal(old_literal)
        or not safe_literal(new_literal)
        or type(old_literal) is not type(new_literal)
        or old_literal == new_literal
        or not isinstance(readers, list)
        or any(
            type(index) is not int
            or index < 0
            or index >= attribute_model.get("n", 0)
            for index in readers
        )
    ):
        return None
    original_statement.value = ast.Constant(value=None)
    changed_statement.value = ast.Constant(value=None)
    if ast.dump(original_tree, include_attributes=False) != ast.dump(
        changed_tree, include_attributes=False
    ):
        return None
    if import_expression_hazard(change, path, hook_attributes):
        return None
    return set(readers)


def derived_arg_types_edit(
    change: dict,
    path: str,
    derivation_model: dict,
    hook_attributes: set[str] | None = None,
) -> set[int] | None:
    """Narrow a boolean arg_types edit to its direct and derived consumers."""
    entries = derivation_model.get("d", {}).get(path)
    source = pinned_sources().get(path)
    changed = patched_source(change, path)
    if (
        not entries
        or source is None
        or changed is None
        or path in PROCESS_SERIALIZATION_FILES
        or any(COMMENT_DIRECTIVE.search(line) for line in change["payload"])
    ):
        return None
    try:
        original_tree = ast.parse(source, filename=path, type_comments=True)
        changed_tree = ast.parse(changed, filename=path, type_comments=True)
    except (SyntaxError, ValueError):
        return None

    def assignments(tree: ast.Module):
        result = {}

        def visit_body(body: list[ast.stmt], owner: tuple[str, ...]) -> None:
            for statement in body:
                if isinstance(statement, ast.Assign):
                    targets = statement.targets
                elif isinstance(statement, ast.AnnAssign):
                    targets = [statement.target]
                else:
                    targets = []
                if (
                    len(targets) == 1
                    and isinstance(targets[0], ast.Name)
                    and isinstance(getattr(statement, "value", None), ast.Dict)
                ):
                    key = owner, targets[0].id
                    result[key] = statement if key not in result else None
                if isinstance(statement, ast.ClassDef):
                    visit_body(statement.body, (*owner, statement.name))

        visit_body(tree.body, ())
        return result

    original_assignments = assignments(original_tree)
    changed_assignments = assignments(changed_tree)
    candidates = []
    for start, end, target, key_entries in entries:
        if not any(start <= line <= end for line in change["lines"]):
            continue
        matches = [
            (key, statement)
            for key, statement in original_assignments.items()
            if key[1] == target
            and statement is not None
            and statement.lineno == start
            and (statement.end_lineno or statement.lineno) == end
        ]
        if len(matches) != 1:
            return None
        candidates.append((*matches[0], dict(key_entries)))
    if len(candidates) != 1:
        return None

    key, original_statement, readers = candidates[0]
    changed_statement = changed_assignments.get(key)
    if changed_statement is None:
        return None
    original_dict = original_statement.value
    changed_dict = changed_statement.value
    if any(item is None for item in (*original_dict.keys, *changed_dict.keys)):
        return None
    if len(original_dict.keys) != len(changed_dict.keys):
        return None
    original_key_dumps = [
        ast.dump(item, include_attributes=False) for item in original_dict.keys
    ]
    if original_key_dumps != [
        ast.dump(item, include_attributes=False) for item in changed_dict.keys
    ]:
        return None

    runtime_keys = []
    for key_node in original_dict.keys:
        try:
            runtime_key = ast.literal_eval(key_node)
            hash(runtime_key)
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            return None
        if runtime_key in runtime_keys:
            return None
        runtime_keys.append(runtime_key)

    changed_values = [
        index
        for index, (old, new) in enumerate(zip(original_dict.values, changed_dict.values))
        if ast.dump(old, include_attributes=False)
        != ast.dump(new, include_attributes=False)
    ]
    if not changed_values:
        return None
    selected = set()
    for index in changed_values:
        old_value = original_dict.values[index]
        new_value = changed_dict.values[index]
        if not (
            isinstance(old_value, ast.Constant)
            and type(old_value.value) is bool
            and isinstance(new_value, ast.Constant)
            and type(new_value.value) is bool
            and original_key_dumps[index] in readers
        ):
            return None
        key_readers = readers[original_key_dumps[index]]
        if not isinstance(key_readers, list) or any(
            type(reader) is not int
            or reader < 0
            or reader >= derivation_model.get("n", 0)
            for reader in key_readers
        ):
            return None
        selected.update(key_readers)
        original_dict.values[index] = ast.Constant(value=None)
        changed_dict.values[index] = ast.Constant(value=None)

    if ast.dump(original_tree, include_attributes=False) != ast.dump(
        changed_tree, include_attributes=False
    ):
        return None
    if import_expression_hazard(change, path, hook_attributes):
        return None
    return selected


def path_dependency_cone(
    paths: tuple[str | None, ...],
    model: dict,
    test_file_indices: dict[str, set[int]] | None,
) -> tuple[set[int], bool]:
    selected: set[int] = set()
    known = False
    for path in paths:
        if path in (None, "/dev/null"):
            continue
        if test_file_indices and path in test_file_indices:
            selected.update(test_file_indices[path])
            known = True
        for mapping in (model.get("x", {}), model.get("r", {})):
            set_id = mapping.get(path)
            if set_id is not None:
                selected.update(mapped_set(model, set_id))
                known = True
        entry = model.get("f", {}).get(path)
        if entry is not None:
            selected.update(mapped_set(model, entry["f"]))
            known = True
        parts = Path(path).parts
        if (
            len(parts) >= 3
            and parts[0] == "sqlglot"
            and parts[1] in {"dialects", "parsers", "generators", "typing"}
        ):
            set_id = model.get("q", {}).get(Path(path).stem.lower())
            if set_id is not None:
                selected.update(mapped_set(model, set_id))
                known = True
    return selected, known


def _stable_json_digest(value: object) -> str | None:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":")
        ).encode()
    except (TypeError, ValueError, OverflowError, RecursionError, MemoryError):
        return None
    return hashlib.sha256(encoded).hexdigest()


def valid_new_module_model(
    profile: object, pinned_sha: object, test_digest: str, n: int
) -> bool:
    """Validate the complete source/discovery certificate or fail closed."""
    if not isinstance(profile, dict) or set(profile) != {
        "a", "b", "d", "f", "i", "k", "m", "n", "p", "r", "sha", "t", "v", "w"
    }:
        return False
    if (
        profile.get("v") != 1
        or profile.get("sha") != pinned_sha
        or profile.get("t") != test_digest
        or profile.get("n") != n
        or profile.get("d") != NEW_MODULE_SOURCE_SHA256
        or profile.get("f") != 363
        or profile.get("w") != 192226
        or profile.get("k") != 5
        or profile.get("m") != 1 << 21
        or profile.get("a")
        != [
            "sqlglot",
            "sqlglot/dialects",
            "sqlglot/executor",
            "sqlglot/expressions",
            "sqlglot/generators",
            "sqlglot/optimizer",
            "sqlglot/parsers",
            "sqlglot/typing",
        ]
    ):
        return False
    inventory = profile.get("i")
    readers = profile.get("r")
    if (
        not isinstance(inventory, list)
        or len(inventory) != 42
        or not isinstance(readers, list)
        or readers != sorted(set(readers))
        or any(type(reader) is not int or reader < 0 or reader >= n for reader in readers)
    ):
        return False
    for entry in inventory:
        if (
            not isinstance(entry, list)
            or len(entry) != 5
            or type(entry[0]) is not str
            or type(entry[1]) is not int
            or type(entry[2]) is not int
            or entry[1] <= 0
            or entry[2] < entry[1]
            or entry[3]
            not in {
                "dynamic-code",
                "dynamic-import",
                "directory-listing",
                "package-reflection",
                "package-data",
                "path-probe",
                "source-reader",
                "subprocess",
            }
            or type(entry[4]) is not str
        ):
            return False
    if _stable_json_digest(inventory) != NEW_MODULE_INVENTORY_SHA256:
        return False
    try:
        bloom = base64.b64decode(profile.get("b", ""), validate=True)
    except (ValueError, TypeError):
        return False
    if len(bloom) != (1 << 21) // 8:
        return False
    body = {key: profile[key] for key in ("a", "b", "d", "f", "i", "k", "m", "r", "w")}
    return (
        _stable_json_digest(body) == NEW_MODULE_PROFILE_SHA256
        and profile.get("p") == NEW_MODULE_PROFILE_SHA256
    )


def _new_module_word_present(word: str, profile: dict) -> bool:
    try:
        bits = base64.b64decode(profile["b"], validate=True)
    except (KeyError, ValueError, TypeError):
        return True
    digest = hashlib.sha256(word.encode("ascii")).digest()
    for index in range(profile["k"]):
        start = index * 4
        position = int.from_bytes(digest[start : start + 4], "big") & (profile["m"] - 1)
        if not bits[position >> 3] & (1 << (position & 7)):
            return False
    return True


def isolated_new_module_indices(
    changes: list[dict], profile: dict | None
) -> set[int] | None:
    """Return conservative discovery readers for one provably isolated module."""
    if profile is None or len(changes) != 1:
        return None
    change = changes[0]
    path = change.get("new")
    if (
        change.get("old") != "/dev/null"
        or type(path) is not str
        or not NEW_MODULE_PATH.fullmatch(path)
        or change.get("diff_old") != path
        or change.get("diff_new") != path
        or change.get("new_file_mode") != "100644"
        or change.get("new_file_mode_count") != 1
        or change.get("old_marker_count") != 1
        or change.get("new_marker_count") != 1
        or change.get("index_count") != 1
        or not change.get("new_file_index")
        or change.get("structural_invalid")
        or change.get("binary")
        or change.get("non_lf")
        or change.get("no_newline_marker")
        or path in pinned_sources()
    ):
        return None
    parent = Path(path).parent.as_posix()
    stem = Path(path).stem
    lowered = stem.lower()
    if (
        parent not in profile["a"]
        or not stem.isascii()
        or not stem.isidentifier()
        or keyword.iskeyword(stem)
        or stem.startswith("__")
        or stem.endswith("__")
        or lowered == "conftest"
        or lowered.startswith("test")
        or lowered.endswith("test")
        or _new_module_word_present(stem, profile)
    ):
        return None
    hunks = change.get("hunks")
    added = change.get("added")
    if (
        not isinstance(hunks, list)
        or len(hunks) != 1
        or hunks[0].get("old_start") != 0
        or hunks[0].get("old_count") != 0
        or hunks[0].get("new_start") != 1
        or not isinstance(added, list)
        or not added
        or hunks[0].get("new_count") != len(added)
        or change.get("removed")
        or change.get("payload") != added
        or any(marker != "+" for marker, _text in hunks[0].get("lines", ()))
        or change.get("added_new_at")
        != list(zip(range(1, len(added) + 1), added))
    ):
        return None
    source = "\n".join(added) + "\n"
    try:
        compile(source, path, "exec", dont_inherit=True)
    except (SyntaxError, ValueError, OverflowError, MemoryError):
        return None
    return set(profile["r"])


def selected_indices(
    patch: Path,
    model: dict,
    all_indices: set[int],
    test_file_indices: dict[str, set[int]] | None = None,
    zero_model: dict | None = None,
    predicate_model: dict | None = None,
    derivation_model: dict | None = None,
    attribute_model: dict | None = None,
    fresh_alias_model: dict | None = None,
    none_static_profile: dict | None = None,
    binary_preimages: dict | None = None,
    tpc_entry_provenance: dict | None = None,
    new_module_model: dict | None = None,
    parsed_changes: list[dict] | None = None,
) -> set[int]:
    if BINARY_FIXTURE_ENABLED and binary_preimages is not None:
        try:
            binary_indices = binary_patch_readers(
                patch.read_text(encoding="utf-8"), model, model.get("t"), binary_preimages
            )
        except (OSError, UnicodeError):
            binary_indices = None
        if binary_indices is not None:
            return binary_indices

    selected: set[int] = set()
    changes = patch_changes(patch) if parsed_changes is None else parsed_changes
    if not changes:
        return set(all_indices)
    new_module_readers = (
        isolated_new_module_indices(changes, new_module_model)
        if NEW_MODULE_PROOF_ENABLED
        else None
    )
    if new_module_readers is not None:
        return new_module_readers & all_indices
    helper_changes = [
        change for change in changes
        if TPC_ENTRY_PATH in (change.get("old"), change.get("new"))
    ]
    if helper_changes:
        if (
            TPC_ENTRY_ENABLED
            and tpc_entry_provenance is not None
            and len(changes) == len(helper_changes) == 1
            and helper_changes[0].get("old") == helper_changes[0].get("new") == TPC_ENTRY_PATH
        ):
            original = pinned_sources().get(TPC_ENTRY_PATH)
            changed = patched_source(helper_changes[0], TPC_ENTRY_PATH)
            if original is not None and changed is not None:
                entry_indices = tpc_entry_readers(
                    TPC_ENTRY_PATH, original, changed, model.get("t"), tpc_entry_provenance
                )
                if entry_indices is not None:
                    return entry_indices & all_indices
        return set(all_indices)
    if len(changes) == 1:
        only = changes[0]
        only_path = only.get("old")
        original = pinned_sources().get(only_path) if isinstance(only_path, str) else None
        prospective = patched_source(only, only_path) if isinstance(only_path, str) else None
        retained = match_none_static(changes, none_static_profile, original, prospective)
        if retained is not None:
            return retained & all_indices
    for change in changes:
        old_path = change["old"]
        new_path = change["new"]
        path = old_path if old_path not in (None, "/dev/null") else new_path
        if path in (None, "/dev/null"):
            selected.update(all_indices)
            continue
        if old_path != new_path:
            # Renames and deletions invalidate their known consumers even when
            # no executable line changed. Unknown additions remain global.
            if any(
                candidate not in (None, "/dev/null")
                and candidate.startswith("tests/")
                and candidate.endswith(".py")
                for candidate in (old_path, new_path)
            ):
                selected.update(all_indices)
                continue
            cone, known = path_dependency_cone(
                (old_path, new_path), model, test_file_indices
            )
            selected.update(cone)
            if not known:
                selected.update(all_indices)
                continue
        if invalid_python_patch(change, path):
            # Python parses the whole module before any test can import it.
            selected.update(all_indices)
            continue
        fresh_receiver_contained = contained_fresh_receiver_edit(change, path)
        if comment_only_addition(change) and any(
            COMMENT_DIRECTIVE.search(line) for line in change["added"]
        ):
            selected.update(all_indices)
            continue
        if inert_comment_addition(change, path):
            continue
        if fresh_alias_model is not None and len(changes) == 1 and fresh_table_alias_copy_edit(
            change, path, fresh_alias_model, model.get("h")
        ):
            continue
        if test_file_indices and path in test_file_indices:
            # A syntax or import error fails every collected test in the file,
            # even when only one test function covered the changed line.
            selected.update(test_file_indices[path])

        fixture_set = model["x"].get(path)
        if fixture_set is not None:
            selected.update(mapped_set(model, fixture_set))
            continue
        if path.startswith("tests/fixtures/"):
            # An unseen fixture can be shared or loaded during class setup.
            selected.update(all_indices)
            continue

        if zero_model is not None:
            dictionary_indices = zero_reader_dict_edit(
                change, path, zero_model, model.get("h")
            )
            if dictionary_indices is not None:
                selected.update(dictionary_indices)
                continue

        if predicate_model is not None and profile_equivalent_predicate_edit(
            change, path, predicate_model, model.get("h")
        ):
            continue

        if derivation_model is not None:
            derived_indices = derived_arg_types_edit(
                change, path, derivation_model, model.get("h")
            )
            if derived_indices is not None:
                selected.update(derived_indices)
                continue

        if attribute_model is not None:
            attribute_indices = class_attribute_edit(
                change, path, attribute_model, model.get("h")
            )
            if attribute_indices is not None:
                selected.update(attribute_indices)
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
            if (
                change["removed"]
                and precise_coverage_line(path, line)
                and preserves_function_bindings(change, path, line)
            ):
                set_id = line_sets.get(line)
                if set_id is not None:
                    selected.update(mapped_set(model, set_id))
                continue
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

        expression_hazard = import_expression_hazard(change, path, model.get("h"))
        if (
            not fresh_receiver_contained
            and any(
                start <= line <= end
                for start, end in entry.get("i", ())
                for line in changed_lines
            )
        ) or any(
            import_definition_line(path, line) for line in changed_lines
        ) or expression_hazard:
            importer_set = model.get("r", {}).get(path)
            if importer_set is not None:
                selected.update(mapped_set(model, importer_set))
            if expression_hazard:
                parts = Path(path).parts
                if path.startswith("tests/"):
                    selected.update(all_indices)
                elif (
                    len(parts) >= 3
                    and parts[0] == "sqlglot"
                    and parts[1] in {"dialects", "parsers", "generators", "typing"}
                ):
                    dialect_set = model.get("q", {}).get(Path(path).stem.lower())
                    if dialect_set is not None:
                        selected.update(mapped_set(model, dialect_set))

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
    model["h"] = set(model.get("h", ()))
    with gzip.open(ZERO_READER_MODEL, "rt", encoding="utf-8") as zero_model_file:
        zero_model = json.load(zero_model_file)
    with gzip.open(PREDICATE_PROFILE, "rt", encoding="utf-8") as predicate_model_file:
        predicate_model = json.load(predicate_model_file)
    with gzip.open(ARG_TYPE_DERIVATION_MODEL, "rt", encoding="utf-8") as derivation_model_file:
        derivation_model = json.load(derivation_model_file)
    with gzip.open(CLASS_ATTRIBUTE_MODEL, "rt", encoding="utf-8") as attribute_model_file:
        attribute_model = json.load(attribute_model_file)
    with gzip.open(FRESH_ALIAS_PROFILE, "rt", encoding="utf-8") as fresh_alias_file:
        fresh_alias_model = json.load(fresh_alias_file)
    binary_preimages = load_preimages(
        BINARY_FIXTURE_PREIMAGES, MODEL, model, model.get("t")
    )
    tpc_entry_provenance = load_tpc_entry_provenance(
        TPC_ENTRY_PROVENANCE, MODEL, model, model.get("t")
    )
    try:
        with gzip.open(NEW_MODULE_MODEL, "rt", encoding="utf-8") as new_module_file:
            new_module_model = json.load(new_module_file)
    except (
        OSError,
        EOFError,
        UnicodeError,
        json.JSONDecodeError,
        ValueError,
        TypeError,
        RecursionError,
        MemoryError,
    ):
        new_module_model = None
    test_digest = hashlib.sha256(
        "\0".join(test["id"] for test in tests).encode("utf-8")
    ).hexdigest()
    none_static_profile = (
        load_none_static_profile(test_digest, len(tests))
        if model.get("t") == [test["id"] for test in tests]
        else None
    )
    if (
        zero_model.get("v") != 2
        or zero_model.get("sha") != model.get("sha")
        or zero_model.get("n") != len(tests)
        or zero_model.get("t")
        != test_digest
    ):
        zero_model = {"d": {}}
    if (
        predicate_model.get("v") != 2
        or predicate_model.get("sha") != model.get("sha")
        or predicate_model.get("n") != len(tests)
        or predicate_model.get("t") != test_digest
    ):
        predicate_model = {"d": {}}
    if (
        derivation_model.get("v") != 2
        or derivation_model.get("sha") != model.get("sha")
        or derivation_model.get("n") != len(tests)
        or derivation_model.get("t") != test_digest
    ):
        derivation_model = {"d": {}}
    if (
        attribute_model.get("v") != 1
        or attribute_model.get("sha") != model.get("sha")
        or attribute_model.get("n") != len(tests)
        or attribute_model.get("t") != test_digest
    ):
        attribute_model = {"d": {}}
    if (
        fresh_alias_model.get("v") != 1
        or fresh_alias_model.get("sha") != model.get("sha")
        or fresh_alias_model.get("n") != len(tests)
        or fresh_alias_model.get("t") != test_digest
    ):
        fresh_alias_model = {"d": {}}
    if not valid_new_module_model(
        new_module_model, model.get("sha"), test_digest, len(tests)
    ):
        new_module_model = None
    mapped_tests = [tests_by_id.get(test_id) for test_id in model["t"]]
    all_indices = {index for index, test in enumerate(mapped_tests) if test is not None}
    test_file_indices: dict[str, set[int]] = {}
    for index, test in enumerate(mapped_tests):
        if test is not None:
            test_file_indices.setdefault(test["file"], set()).add(index)
    modeled_ids = set(model["t"])
    unmapped_tests = [test for test in tests if test["id"] not in modeled_ids]

    jobs = []
    tpc_ids = set().union(*TPC_PLAN_TESTS.values())
    for patch in sorted((DATA / "commits").glob("*.patch")):
        changes = patch_changes(patch)
        indices = selected_indices(
            patch,
            model,
            all_indices,
            test_file_indices,
            zero_model,
            predicate_model,
            derivation_model,
            attribute_model,
            fresh_alias_model,
            none_static_profile,
            binary_preimages,
            tpc_entry_provenance,
            new_module_model,
            changes,
        )
        selected = [mapped_tests[index] for index in indices if mapped_tests[index] is not None]
        selected.extend(unmapped_tests)
        without_all_tpc = [test for test in selected if test["id"] not in tpc_ids]
        prospective_saving = best_cost_ms(selected) - best_cost_ms(without_all_tpc)
        fixture_change = (
            changes[0]
            if len(changes) == 1
            and changes[0].get("old")
            == changes[0].get("new")
            == TPCDS_FIXTURE_PATH
            else None
        )
        without_tpcds_executor = [
            test for test in selected if test["id"] != TPCDS_EXECUTOR_ID
        ]
        jobs.append(
            {
                "patch": patch,
                "selected": selected,
                "prospective_saving": prospective_saving,
                "docstring_only": tpc_function_docstring_only(patch),
                "eligible": prospective_saving > 16_000
                and tpc_plan_patch_eligible(patch, changes),
                "fixture_change": fixture_change,
                "fixture_saving": best_cost_ms(selected)
                - best_cost_ms(without_tpcds_executor),
            }
        )

    execution_order = sorted(
        range(len(jobs)),
        key=lambda index: jobs[index]["prospective_saving"],
        reverse=True,
    )
    for index in execution_order:
        job = jobs[index]
        if job["docstring_only"]:
            # The pinned numbered roster contains no doctest/docstring reader.
            # A whole-module census also finds no optimizer function __doc__ or
            # code-constant observer, so the executable outcome is unchanged.
            job["selected"] = list(unmapped_tests)
        elif job["eligible"]:
            selected = job["selected"]
            patch = job["patch"]
            verdicts, verifier_cpu = verify_tpc_plan_patch(patch)
            if verdicts is not None:
                removable = set().union(
                    *(
                        TPC_PLAN_TESTS[name]
                        for name, equal in verdicts.items()
                        if equal
                    )
                )
                narrowed = [test for test in selected if test["id"] not in removable]
                realized = best_cost_ms(selected) - best_cost_ms(narrowed)
                if realized > round(verifier_cpu * 1_200):
                    job["selected"] = narrowed

    # Fixture-only edits cannot enter the optimizer-plan lane above. Keep this
    # independently budgeted pass after plan scheduling so it cannot reorder or
    # consume the plan verifier's opportunities.
    fixture_order = sorted(
        range(len(jobs)),
        key=lambda index: jobs[index]["fixture_saving"],
        reverse=True,
    )
    for index in fixture_order:
        job = jobs[index]
        change = job["fixture_change"]
        if change is None or job["fixture_saving"] <= 0:
            continue
        passed, verifier_cpu, _reason = verify_tpcds_fixture(change)
        accepted = False
        realized = 0
        if passed:
            selected = job["selected"]
            narrowed = [
                test for test in selected if test["id"] != TPCDS_EXECUTOR_ID
            ]
            realized = best_cost_ms(selected) - best_cost_ms(narrowed)
            if realized > round(verifier_cpu * 1_200):
                job["selected"] = narrowed
                accepted = True
        if os.environ.get("BR_TPC_FIXTURE_TRACE") == "1":
            print(
                "tpc_fixture_verify="
                + json.dumps(
                    {
                        "accepted": accepted,
                        "commit": job["patch"].stem,
                        "cpu": round(verifier_cpu, 6),
                        "passed": passed,
                        "realized": round(realized / 1_000, 6),
                        "reason": _reason,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                file=sys.stderr,
            )

    selection_count = 0
    for job in jobs:
        selected = job["selected"]
        selection_count += len(selected)
        workers = best_split(selected)
        print(
            json.dumps(
                {"commit": job["patch"].stem, "workers": workers},
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
