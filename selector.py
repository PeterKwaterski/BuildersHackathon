"""Select tests from answer-independent coverage, fixture, and symbol maps."""

import ast
import gzip
import hashlib
import io
import json
import base64
import keyword
import re
import sys
import tokenize
import types
from collections import Counter, deque
from pathlib import Path

from semantic import SemanticProof
from semantic_noops import (
    external_import_reorder,
    local_binding_rename,
    plain_definition_reorder,
)
from runtime_verify import verify_candidates
from tokenizer_keyword_runtime import (
    TokenizerKeywordContext,
    load_context as load_tokenizer_keyword_context,
    tokenizer_keyword_patch,
)

DATA = Path("/data")
MODEL = Path(__file__).with_name("selector_model.json.gz")
SEMANTIC_SOURCES = Path(__file__).with_name("semantic_sources.json.gz")
SEMANTIC_SOURCES_SHA256 = "f453c6266c20edcc9ba7127ebedde0bdf45d44633279352c2daafe1fa123da5f"
ZERO_READER_MODEL = Path(__file__).with_name("zero_reader_model.json.gz")
PREDICATE_PROFILE = Path(__file__).with_name("predicate_profile.json.gz")
GUARD_PROFILE = Path(__file__).with_name("guard_profile.json.gz")
# Deterministic artifact from independently admitted normal and synchronous
# Python 3.13 traces at the pinned source revision.
GUARD_PROFILE_SHA256 = "31bc8832c304e14e0c75173d61379f8570975a0e93620e883f5a78d87463aecb"
ARG_TYPE_DERIVATION_MODEL = Path(__file__).with_name(
    "arg_type_derivation_model.json.gz"
)
CLASS_ATTRIBUTE_MODEL = Path(__file__).with_name("class_attribute_model.json.gz")
TOKENIZER_SETTING_FLOW_MODEL = Path(__file__).with_name(
    "tokenizer_setting_flow_model.json.gz"
)
TOKENIZER_KEYWORD_MODEL = Path(__file__).with_name(
    "tokenizer_keyword_model.json.gz"
)
MODULE_CONSTANT_MODEL = Path(__file__).with_name("module_constant_model.json.gz")
CODE_REFLECTION_MODEL = Path(__file__).with_name("code_reflection_model.json.gz")
CODE_REFLECTION_RANGES_SHA256 = "c84e754efedb3fbaa3323a6ceb381e180c46dd385f295a5b2b44e22ec7401338"
CODE_REFLECTION_PROFILE_SHA256 = "f62a0b161fa6d372766d8e290ee6450b368c4deee9bfcfd306f5aa184392298c"
FRESH_ALIAS_PROFILE = Path(__file__).with_name("fresh_alias_profile.json.gz")
GENERATOR_DISPATCH_MODEL = Path(__file__).with_name("generator_dispatch_model.json.gz")
NEW_MODULE_MODEL = Path(__file__).with_name("new_module_model.json.gz")
FUNCTION_DEFAULT_MODEL = Path(__file__).with_name("function_default_model.json.gz")
MAX_NODES_TEST_ID = "tests/test_parser.py::TestParser::test_max_nodes"
# Filled only after all exact Python 3.13 traces build the final artifact.
# An empty pin intentionally disables the profile.
FUNCTION_DEFAULT_PROFILE_SHA256 = "f729c7f9c1eb6a30646b513006ad6829b159ca118e42714e07082bda966d2968"
TOKENIZER_SETTING_FLOW_PROFILE_SHA256 = "1ef2cde294620c5767403894a6684900c88442ba30227da7b026349c1e56a056"
TOKENIZER_SETTING_SELECTOR_MODEL_SHA256 = "d61c504e9a4a1006217e6702e1c6f05c04846b3dd5a09ec5572523fd8b2cb382"
TOKENIZER_SETTING_CLASS_MODEL_SHA256 = "55eb6911b5d72408c7cd947adc08b07e6b41542a8da1ee86d908f74a1b0b6fd4"
TOKENIZER_SETTING_BUILDER_SHA256 = "cd45fe8eace881ac34ade5b5ceb26b2fd5a684c10d330d3ed438e2cdd3517e7a"
TOKENIZER_KEYWORD_MODEL_SHA256 = "28a5241f3d8006f075f283ac8e59f46793be482457bece67de97a4ecdd3db230"
TOKENIZER_SETTING_TRACE_SHA256 = {
    "normal": "4afe4afc075b26f4e947de92cfb5a9598ab1bea22c30f137d76ada1cc7c35ecf",
    "synchronous-worker": "709a17acaf46f8516553f94577dac156e04f17ad0a5e7f88ab7bffa77f749868",
}
TOKENIZER_SETTING_MANIFEST_SHA256 = {
    "normal": "ac04ff11895a8eaa24979d5bcddd83845c0aff961beff50b31548b72bb70f9ca",
    "synchronous-worker": "63107844c3db71a3befb864fa2f34fbeff918604a835042fa31e7cea9eceef31",
}
GENERATOR_DISPATCH_INVENTORY_SHA256 = "3e3cb5a12da0fb01cd68f9b2fc789bc8d020523e015fea7016e04679c34d1dca"
GENERATOR_DISPATCH_PROFILE_SHA256 = "8829e844dbd6870f2bca81cc7fb4f89f16ccdef7ecbba278748cdd850aeb1bfd"
NEW_MODULE_PROFILE_SHA256 = "1b24ab53483bb1932d8139b80fa17e797a1974ee3078157a110c0f25b28f4e10"
NEW_MODULE_SOURCE_SHA256 = "b7f798c9e8015db63d6e160ab73f59828e445cef8739cfb383aba44d5de5f5f0"
NEW_MODULE_INVENTORY_SHA256 = "b30749cd488217746916b61c0eb138d46ab9f3543b32e0dbbd4688c0ac9ee12b"
MAX_WORKERS = 8
WORKER_COST_MS = 2_000
HUNK = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
COMPARISON_OPERATOR = re.compile(r"\bis\s+not\b|\bis\b|==|!=")
COMMENT_DIRECTIVE = re.compile(r"(?i)(coding\s*[:=]|type:|noqa|pragma|fmt:|pyright|mypy)")
RUNTIME_COMMENT_DIRECTIVE = re.compile(
    r"(?i)(?:type\s*:\s*ignore\b|noqa\b|pragma\b|fmt\s*:|pyright\b|mypy\b)"
)
ASCII_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
NEW_MODULE_PATH = re.compile(
    r"sqlglot(?:/[A-Za-z_][A-Za-z0-9_]*)*/[A-Za-z_][A-Za-z0-9_]*\.py\Z"
)
PROCESS_SERIALIZATION_FILES = {"sqlglot/serde.py"}
_SEMANTIC_PROOF = None
_PINNED_SOURCES = None
_SOURCE_TREES = {}
_SOURCE_INDEXES = {}
_IMPORT_DEFINITION_RANGES = {}
_SOURCE_CODE = {}
_INIT_SUBCLASS_ATTRIBUTES = None
_TYPING_CODE_FINGERPRINTS = None

# Proof families are independent kill switches.  Import and definition order
# remain quarantined until their missing construction/namespace certificates
# exist; see tools/SEMANTIC_NOOP_PROOFS.md.
SEMANTIC_NOOP_LOCAL_RENAME = True
SEMANTIC_NOOP_IMPORT_REORDER = False
SEMANTIC_NOOP_DEFINITION_REORDER = False
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
            name = line[4:].split("\t", 1)[0]
            change["old"] = name[2:] if name.startswith("a/") else name
        elif not in_hunk and line.startswith("+++ "):
            name = line[4:].split("\t", 1)[0]
            change["new"] = name[2:] if name.startswith("b/") else name
        elif not in_hunk and line.startswith("rename from "):
            change["old"] = line.removeprefix("rename from ")
        elif not in_hunk and line.startswith("rename to "):
            change["new"] = line.removeprefix("rename to ")
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
    return changes


def pinned_sources() -> dict[str, str]:
    global _PINNED_SOURCES
    if _PINNED_SOURCES is None:
        try:
            raw = SEMANTIC_SOURCES.read_bytes()
            if hashlib.sha256(raw).hexdigest() != SEMANTIC_SOURCES_SHA256:
                _PINNED_SOURCES = {}
            else:
                document = json.loads(gzip.decompress(raw).decode("utf-8"))
                _PINNED_SOURCES = (
                    document
                    if isinstance(document, dict)
                    and all(
                        type(path) is str and type(source) is str
                        for path, source in document.items()
                    )
                    else {}
                )
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
            _PINNED_SOURCES = {}
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


def valid_function_default_model(model: object) -> bool:
    """Validate the exact offline-proved default payload by its canonical pin."""
    if (
        not isinstance(model, dict)
        or set(model) != {"d", "n", "p", "sha", "t", "v"}
        or not isinstance(model.get("d"), dict)
        or type(model.get("n")) is not int
        or model["n"] < 0
        or type(model.get("p")) is not str
        or len(model["p"]) != 64
        or type(model.get("sha")) is not str
        or type(model.get("t")) is not str
        or model.get("v") != 1
    ):
        return False
    try:
        profile_digest = hashlib.sha256(
            json.dumps(
                model["d"], sort_keys=True, separators=(",", ":")
            ).encode()
        ).hexdigest()
    except (TypeError, ValueError, OverflowError, MemoryError, RecursionError):
        return False
    return (
        bool(FUNCTION_DEFAULT_PROFILE_SHA256)
        and model["p"] == FUNCTION_DEFAULT_PROFILE_SHA256
        and profile_digest == FUNCTION_DEFAULT_PROFILE_SHA256
    )


def valid_tokenizer_setting_flow_model(
    model: object, pinned_sha: str, test_digest: str, n: int
) -> bool:
    """Validate the complete narrow Tokenizer-to-core field certificate."""
    if (
        not isinstance(model, dict)
        or set(model) != {"b", "c", "d", "m", "n", "p", "r", "s", "sha", "t", "v"}
        or model.get("v") != 1
        or model.get("sha") != pinned_sha
        or model.get("t") != test_digest
        or model.get("n") != n
        or model.get("s") != TOKENIZER_SETTING_SELECTOR_MODEL_SHA256
        or model.get("c") != TOKENIZER_SETTING_CLASS_MODEL_SHA256
        or model.get("b") != TOKENIZER_SETTING_BUILDER_SHA256
        or model.get("r") != TOKENIZER_SETTING_TRACE_SHA256
        or model.get("m") != TOKENIZER_SETTING_MANIFEST_SHA256
        or not isinstance(model.get("d"), dict)
    ):
        return False
    try:
        profile_digest = hashlib.sha256(
            json.dumps(model["d"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    except (TypeError, ValueError, OverflowError, MemoryError, RecursionError):
        return False
    if (
        profile_digest != TOKENIZER_SETTING_FLOW_PROFILE_SHA256
        or model.get("p") != TOKENIZER_SETTING_FLOW_PROFILE_SHA256
    ):
        return False
    for path, entries in model["d"].items():
        if type(path) is not str or not isinstance(entries, list):
            return False
        for entry in entries:
            if not isinstance(entry, list) or len(entry) != 7:
                return False
            start, end, qualname, name, value_dump, field, readers = entry
            if (
                type(start) is not int
                or type(end) is not int
                or start <= 0
                or end < start
                or any(type(value) is not str for value in (qualname, name, value_dump, field))
                or not isinstance(readers, list)
                or readers != sorted(set(readers))
                or any(type(index) is not int or index < 0 or index >= n for index in readers)
            ):
                return False
    return True


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
                    children.extend(
                        item for item in value if isinstance(item, ast.AST)
                    )
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
        """Reconstruct a structural path only for the rare node that needs it."""
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


def semantic_code_fingerprint(code: types.CodeType) -> tuple:
    """Return recursively complete executable and source-position code state."""

    def constant(value):
        if isinstance(value, types.CodeType):
            return ("code", semantic_code_fingerprint(value))
        if isinstance(value, tuple):
            return ("tuple", tuple(constant(item) for item in value))
        if isinstance(value, frozenset):
            return ("frozenset", tuple(sorted((constant(item) for item in value), key=repr)))
        return (type(value).__qualname__, repr(value))

    return (
        code.co_name,
        code.co_qualname,
        code.co_firstlineno,
        code.co_argcount,
        code.co_posonlyargcount,
        code.co_kwonlyargcount,
        code.co_nlocals,
        code.co_stacksize,
        code.co_flags,
        code.co_code,
        tuple(constant(item) for item in code.co_consts),
        code.co_names,
        code.co_varnames,
        code.co_freevars,
        code.co_cellvars,
        code.co_exceptiontable,
        code.co_linetable,
        tuple(code.co_positions()),
    )


def positionless_code_fingerprint(code: types.CodeType) -> tuple:
    """Return every executable CodeType field except source coordinates.

    A comment-only insertion can shift line tables without changing Python
    execution.  Those positions remain observable to tests which enter the
    containing function (and are therefore retained by ordinary scope
    coverage) or explicitly read its code object (retained by the independent
    reflection profile).  This fingerprint proves the directive changed no
    opcode, constant, binding, exception edge, closure, or nested code object.
    """

    def constant(value):
        if isinstance(value, types.CodeType):
            return ("code", positionless_code_fingerprint(value))
        if isinstance(value, tuple):
            return ("tuple", tuple(constant(item) for item in value))
        if isinstance(value, frozenset):
            return ("frozenset", tuple(sorted((constant(item) for item in value), key=repr)))
        return (type(value).__qualname__, repr(value))

    return (
        code.co_name,
        code.co_qualname,
        code.co_argcount,
        code.co_posonlyargcount,
        code.co_kwonlyargcount,
        code.co_nlocals,
        code.co_stacksize,
        code.co_flags,
        code.co_code,
        tuple(constant(item) for item in code.co_consts),
        code.co_names,
        code.co_varnames,
        code.co_freevars,
        code.co_cellvars,
        code.co_exceptiontable,
    )


def semantic_noop_edit(change: dict, path: str) -> str | None:
    """Return the independently enabled semantic no-op proof family."""

    original = pinned_sources().get(path)
    if original is None or not path.endswith(".py"):
        return None
    changed = None
    if SEMANTIC_NOOP_LOCAL_RENAME and len(change["removed"]) == len(change["added"]):
        possible = False
        for old_line, new_line in zip(change["removed"], change["added"]):
            old_names = [(match.span(), match.group()) for match in ASCII_IDENTIFIER.finditer(old_line)]
            new_names = [(match.span(), match.group()) for match in ASCII_IDENTIFIER.finditer(new_line)]
            if [span for span, _name in old_names] != [span for span, _name in new_names]:
                break
            old_masked = ASCII_IDENTIFIER.sub("", old_line)
            new_masked = ASCII_IDENTIFIER.sub("", new_line)
            if old_masked != new_masked:
                break
            possible |= old_names != new_names
        else:
            if possible:
                changed = patched_source(change, path)
                if changed is not None and local_binding_rename(original, changed, path):
                    return "local-binding-rename"
    if not (SEMANTIC_NOOP_IMPORT_REORDER or SEMANTIC_NOOP_DEFINITION_REORDER):
        return None
    if changed is None:
        changed = patched_source(change, path)
    if changed is None:
        return None
    if SEMANTIC_NOOP_IMPORT_REORDER and external_import_reorder(original, changed, path):
        return "external-import-reorder"
    if SEMANTIC_NOOP_DEFINITION_REORDER and plain_definition_reorder(
        original, changed, path
    ):
        return "plain-definition-reorder"
    return None


def local_annotation_only_edit(change: dict, path: str) -> bool:
    """Prove an edit changes only one ignored local-variable annotation.

    Python does not evaluate or retain annotations on assignments inside a
    function.  Full-tree normalization proves the patch changes no target,
    value, binding, or neighboring syntax; compiled fingerprints independently
    prove that executable code, constants, and traceback positions are identical.
    """
    source = pinned_sources().get(path)
    if (
        source is None
        or not change["removed"]
        or len(change["hunks"]) != 1
        or any(COMMENT_DIRECTIVE.search(line) for line in change["payload"])
    ):
        return False

    # Most patches do not touch an annotation.  Use the cached pinned tree to
    # reject them before reparsing either complete source document.
    candidate_tree = source_tree(path)
    candidate_index = _source_index(path)
    if candidate_tree is None or candidate_index is None:
        return False

    candidate_parents = candidate_index.parents

    def is_local_assignment(node: ast.AnnAssign, parents: dict) -> bool:
        parent = parents.get(node)
        while parent is not None and not isinstance(
            parent, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            parent = parents.get(parent)
        return isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef))

    if not any(
        isinstance(node, ast.AnnAssign)
        and is_local_assignment(node, candidate_parents)
        and any(
            node.annotation.lineno
            <= line
            <= (node.annotation.end_lineno or node.annotation.lineno)
            for line in change["lines"]
        )
        for node in candidate_index.nodes
    ):
        return False

    changed = patched_source(change, path)
    if changed is None:
        return False
    try:
        changed_tree = ast.parse(changed, filename=path, type_comments=True)
    except (SyntaxError, ValueError):
        return False
    original_tree = candidate_tree

    def follow(tree: ast.AST, node_path):
        node = tree
        for field, index in node_path:
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

    parents = candidate_index.parents

    sentinel = ast.Name(id="__blast_radius_local_annotation__", ctx=ast.Load())
    for node in candidate_index.nodes:
        if (
            not isinstance(node, ast.AnnAssign)
            or not is_local_assignment(node, parents)
            or not any(
                node.annotation.lineno
                <= line
                <= (node.annotation.end_lineno or node.annotation.lineno)
                for line in change["lines"]
            )
        ):
            continue
        node_path = candidate_index.path(node)
        if node_path is None:
            continue
        changed_node = follow(changed_tree, node_path)
        if not isinstance(changed_node, ast.AnnAssign):
            continue
        original_annotation = node.annotation
        changed_annotation = changed_node.annotation
        try:
            node.annotation = sentinel
            changed_node.annotation = sentinel
            try:
                equivalent = ast.dump(
                    original_tree, include_attributes=False
                ) == ast.dump(changed_tree, include_attributes=False)
            except (MemoryError, RecursionError):
                equivalent = False
        finally:
            node.annotation = original_annotation
            changed_node.annotation = changed_annotation
        if equivalent:
            if path not in _SOURCE_CODE:
                try:
                    _SOURCE_CODE[path] = compile(
                        source, path, "exec", dont_inherit=True
                    )
                except (SyntaxError, ValueError, TypeError, OverflowError):
                    return False
            changed_code = change.get("_patched_code")
            if changed_code is None:
                try:
                    changed_code = compile(
                        changed, path, "exec", dont_inherit=True
                    )
                except (SyntaxError, ValueError, TypeError, OverflowError):
                    return False
            return semantic_code_fingerprint(
                _SOURCE_CODE[path]
            ) == semantic_code_fingerprint(changed_code)
    return False


def runtime_body_patch_source(change: dict, path: str) -> str | None:
    """Return patched source only for a binding-stable function-body edit.

    The warm verifier intentionally preloads a common test substrate.  Limiting
    it to an unloaded module's function body ensures that importing the patched
    module has the same construction side effects as the pinned module; only
    calls or reflection performed by the exact candidate test can distinguish
    the new code.
    """
    source = pinned_sources().get(path)
    changed = patched_source(change, path)
    changed_lines = change["lines"]
    if (
        source is None
        or changed is None
        or len(change["removed"]) != 1
        or len(change["added"]) != 1
        or not changed_lines
        or any(COMMENT_DIRECTIVE.search(line) for line in change["payload"])
        or any(import_definition_line(path, line) for line in changed_lines)
        or not all(
            precise_coverage_line(path, line, change)
            and preserves_function_bindings(change, path, line)
            for line in changed_lines
        )
    ):
        return None
    original_tree = source_tree(path)
    original_index = _source_index(path)
    if original_tree is None or original_index is None:
        return None
    try:
        changed_tree = ast.parse(changed, filename=path, type_comments=True)
    except (SyntaxError, ValueError):
        return None

    candidates = [
        node
        for node in original_index.functions
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and all(
            node.lineno <= line <= (node.end_lineno or node.lineno)
            for line in changed_lines
        )
    ]
    if not candidates:
        return None
    target = min(
        candidates,
        key=lambda node: ((node.end_lineno or node.lineno) - node.lineno, node.col_offset),
    )
    body_start = min((statement.lineno for statement in target.body), default=target.end_lineno)
    if target.decorator_list or any(line < body_start for line in changed_lines):
        return None

    def follow(root: ast.AST, node_path):
        node = root
        for field, index in node_path:
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

    target_path = original_index.path(target)
    changed_target = follow(changed_tree, target_path) if target_path is not None else None
    if not isinstance(changed_target, type(target)) or changed_target.name != target.name:
        return None
    original_body = target.body
    changed_body = changed_target.body
    try:
        target.body = [ast.Pass()]
        changed_target.body = [ast.Pass()]
        try:
            equivalent = ast.dump(
                original_tree, include_attributes=False
            ) == ast.dump(changed_tree, include_attributes=False)
        except (MemoryError, RecursionError):
            equivalent = False
    finally:
        target.body = original_body
        changed_target.body = changed_body
    if not equivalent:
        return None
    return changed


def patch_local_expression_line(change: dict, path: str, line: int) -> bool:
    """Prove a patch is wholly contained by one expression on ``line``.

    Replacing the containing expression in both complete module trees must
    make them identical. This rejects edits to multiline boolean connectors
    and other changes that can make an uncovered continuation line reachable.
    """
    changed = patched_source(change, path)
    original = pinned_sources().get(path)
    if changed is None or original is None:
        return False
    try:
        original_tree = ast.parse(original, filename=path, type_comments=True)
        changed_tree = ast.parse(changed, filename=path, type_comments=True)
    except (SyntaxError, ValueError):
        return False

    def node_paths(tree: ast.AST):
        pending = [(tree, ())]
        while pending:
            node, node_path = pending.pop()
            yield node, node_path
            children = []
            for field, value in ast.iter_fields(node):
                if isinstance(value, ast.AST):
                    children.append((value, (*node_path, (field, None))))
                elif isinstance(value, list):
                    children.extend(
                        (item, (*node_path, (field, index)))
                        for index, item in enumerate(value)
                        if isinstance(item, ast.AST)
                    )
            pending.extend(reversed(children))

    def follow(tree: ast.AST, node_path):
        node = tree
        for field, index in node_path:
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

    def replace(tree: ast.AST, node_path, replacement: ast.expr):
        if not node_path:
            return None
        parent = follow(tree, node_path[:-1])
        if parent is None:
            return None
        field, index = node_path[-1]
        value = getattr(parent, field, None)
        if index is None and isinstance(value, ast.AST):
            setattr(parent, field, replacement)
            return parent, field, None, value
        if isinstance(value, list) and index is not None and index < len(value):
            previous = value[index]
            value[index] = replacement
            return parent, field, index, previous
        return None

    def restore(state):
        parent, field, index, previous = state
        if index is None:
            setattr(parent, field, previous)
        else:
            getattr(parent, field)[index] = previous

    candidates = [
        (node, node_path)
        for node, node_path in node_paths(original_tree)
        if isinstance(node, ast.expr)
        and node.lineno == (node.end_lineno or node.lineno) == line
    ]
    for _, node_path in candidates:
        changed_expression = follow(changed_tree, node_path)
        if (
            not isinstance(changed_expression, ast.expr)
            or changed_expression.lineno
            != (changed_expression.end_lineno or changed_expression.lineno)
        ):
            continue
        original_state = replace(
            original_tree, node_path, ast.Constant(value="__blast_radius_expression__")
        )
        changed_state = replace(
            changed_tree, node_path, ast.Constant(value="__blast_radius_expression__")
        )
        if original_state is None or changed_state is None:
            if original_state is not None:
                restore(original_state)
            if changed_state is not None:
                restore(changed_state)
            continue
        equivalent = ast.dump(original_tree, include_attributes=False) == ast.dump(
            changed_tree, include_attributes=False
        )
        restore(original_state)
        restore(changed_state)
        if equivalent:
            return True
    return False


def precise_coverage_line(path: str, line: int, change: dict | None = None) -> bool:
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
    if any(
        expression.lineno == (expression.end_lineno or expression.lineno) == line
        for expression in header_expressions
    ):
        return True
    return change is not None and patch_local_expression_line(change, path, line)


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


def runtime_inert_directive_comment(change: dict, path: str) -> bool:
    """Admit only comment directives with bytecode-identical execution.

    Encoding declarations remain global because they can change how Python
    decodes the complete file.  The supported lint/type/format directives are
    runtime comments; a default AST comparison and a recursively complete
    position-free code comparison independently require that to be true for
    this exact patch.  Ordinary scope and reflection ownership still run after
    this gate, retaining every test that can observe shifted source positions.
    """

    # The pinned typing regression reads every ``sqlglot/typing`` source file
    # directly before parsing it.  That source-observer family is intentionally
    # outside the code-reflection artifact, so keep those paths broad.
    if (
        not comment_only_addition(change)
        or not path.endswith(".py")
        or path == "sqlglot/typing/__init__.py"
        or path.startswith("sqlglot/typing/")
    ):
        return False
    comments = [line.strip() for line in change["added"] if line.strip()]
    if (
        not comments
        or any(not line.startswith("#") for line in comments)
        or any(re.search(r"(?i)coding\s*[:=]", line) for line in comments)
        or any(RUNTIME_COMMENT_DIRECTIVE.search(line) is None for line in comments)
    ):
        return False
    original = pinned_sources().get(path)
    prospective = patched_source(change, path)
    if original is None or prospective is None:
        return False
    try:
        original_tree = ast.parse(original, filename=path, type_comments=False)
        prospective_tree = ast.parse(prospective, filename=path, type_comments=False)
        original_code = compile(original, path, "exec", dont_inherit=True)
        prospective_code = compile(prospective, path, "exec", dont_inherit=True)
        return (
            ast.dump(original_tree, include_attributes=False)
            == ast.dump(prospective_tree, include_attributes=False)
            and positionless_code_fingerprint(original_code)
            == positionless_code_fingerprint(prospective_code)
        )
    except (SyntaxError, ValueError, TypeError, OverflowError, MemoryError, RecursionError):
        return False


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


def exact_max_nodes_passes(changes: list[dict], tests: list[dict]) -> bool:
    """Prove the pinned expensive parser limit test passes without running it."""
    if len(changes) != 1:
        return False
    change = changes[0]
    if (
        change.get("old") != "sqlglot/parser.py"
        or change.get("new") != "sqlglot/parser.py"
    ):
        return False
    original = pinned_sources().get("sqlglot/parser.py")
    prospective = patched_source(change, "sqlglot/parser.py")
    if original is None or prospective is None:
        return False
    try:
        from max_nodes_exact import can_skip

        return can_skip(original, prospective, tests)
    except (ImportError, OSError, ValueError, TypeError, MemoryError, RecursionError):
        return False


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


def position_preserving_formatting_edit(change: dict, path: str) -> bool:
    """Prove a replacement changes only lexically invisible formatting.

    Unlike the broader comment-insertion proof, this rule requires the complete
    recursive code fingerprint, including every line table and instruction
    position, to remain identical.  Token text (including comments) must also
    be unchanged.  This leaves only whitespace which neither tokenization nor
    any executable/source position can distinguish.

    The pinned typing tests read production source bytes directly, so that
    package remains outside this proof even when compilation is identical.
    """

    if (
        not path.startswith("sqlglot/")
        or not path.endswith(".py")
        or path == "sqlglot/typing/__init__.py"
        or path.startswith("sqlglot/typing/")
        or path in PROCESS_SERIALIZATION_FILES
        or not change.get("removed")
        or len(change["removed"]) != len(change.get("added", ()))
        or change.get("non_lf")
        or change.get("no_newline_marker")
        or any(COMMENT_DIRECTIVE.search(line) for line in change.get("payload", ()))
    ):
        return False
    original = pinned_sources().get(path)
    prospective = patched_source(change, path)
    if (
        original is None
        or prospective is None
        or original.count("\n") != prospective.count("\n")
    ):
        return False

    def tokens(source: str) -> tuple[tuple[int, str], ...]:
        return tuple(
            (token.type, token.string)
            for token in tokenize.generate_tokens(io.StringIO(source).readline)
            if token.type != tokenize.ENDMARKER
        )

    try:
        if tokens(original) != tokens(prospective):
            return False
        original_tree = ast.parse(original, filename=path, type_comments=True)
        prospective_tree = ast.parse(prospective, filename=path, type_comments=True)
        if ast.dump(original_tree, include_attributes=False) != ast.dump(
            prospective_tree, include_attributes=False
        ):
            return False
        original_code = compile(original, path, "exec", dont_inherit=True)
        prospective_code = compile(prospective, path, "exec", dont_inherit=True)
        return semantic_code_fingerprint(original_code) == semantic_code_fingerprint(
            prospective_code
        )
    except (
        SyntaxError,
        tokenize.TokenError,
        ValueError,
        TypeError,
        OverflowError,
        MemoryError,
        RecursionError,
    ):
        return False


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
        _SEMANTIC_PROOF = SemanticProof(
            {
                source_path: source
                for source_path, source in pinned_sources().items()
                if source_path.startswith("sqlglot/")
            }
        )
    return _SEMANTIC_PROOF.covers(path, change["lines"])


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


def generator_transform_edit(
    change: dict,
    path: str,
    dispatch_model: dict,
) -> set[int] | None:
    """Narrow a deferred Generator.TRANSFORMS lambda to exact dispatch readers."""
    entries = dispatch_model.get("d", {}).get(path)
    source = pinned_sources().get(path)
    changed = patched_source(change, path)
    if (
        not entries
        or source is None
        or changed is None
        or len(change.get("hunks", ())) != 1
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

        def visit(body: list[ast.stmt], owner: tuple[str, ...]) -> None:
            for statement in body:
                if isinstance(statement, ast.ClassDef):
                    visit(statement.body, (*owner, statement.name))
                    continue
                targets = statement.targets if isinstance(statement, ast.Assign) else (
                    [statement.target] if isinstance(statement, ast.AnnAssign) else []
                )
                if (
                    len(targets) == 1
                    and isinstance(targets[0], ast.Name)
                    and targets[0].id == "TRANSFORMS"
                    and isinstance(getattr(statement, "value", None), ast.Dict)
                ):
                    key = (".".join(owner), statement.lineno, statement.end_lineno or statement.lineno)
                    result[key] = statement if key not in result else None

        visit(tree.body, ())
        return result

    original_assignments = assignments(original_tree)
    changed_assignments = assignments(changed_tree)
    by_assignment = {}
    for entry in entries:
        if not isinstance(entry, list) or len(entry) != 8:
            return None
        start, end, owner, index, key_dump, value_dump, state, readers = entry
        by_assignment.setdefault((owner, start, end), {})[index] = (
            key_dump, value_dump, state, readers
        )

    candidates = []
    for assignment_key, indexed_entries in by_assignment.items():
        original_statement = original_assignments.get(assignment_key)
        changed_statement = changed_assignments.get(assignment_key)
        if original_statement is None or changed_statement is None:
            continue
        original_dict = original_statement.value
        changed_dict = changed_statement.value
        if len(original_dict.keys) != len(changed_dict.keys):
            continue
        old_keys = [
            ast.dump(key, include_attributes=False) if key is not None else None
            for key in original_dict.keys
        ]
        new_keys = [
            ast.dump(key, include_attributes=False) if key is not None else None
            for key in changed_dict.keys
        ]
        if old_keys != new_keys:
            continue
        changed_indices = [
            index
            for index, (old, new) in enumerate(zip(original_dict.values, changed_dict.values))
            if ast.dump(old, include_attributes=False) != ast.dump(new, include_attributes=False)
        ]
        if len(changed_indices) != 1:
            continue
        index = changed_indices[0]
        record = indexed_entries.get(index)
        if record is None:
            continue
        key_dump, value_dump, state, readers = record
        if (
            state != "safe"
            or old_keys[index] != key_dump
            or ast.dump(original_dict.values[index], include_attributes=False) != value_dump
            or not isinstance(readers, list)
            or any(
                type(reader) is not int
                or reader < 0
                or reader >= dispatch_model.get("n", 0)
                for reader in readers
            )
        ):
            continue
        candidates.append((original_dict.values[index], changed_dict.values[index], readers))
    if len(candidates) != 1:
        return None
    original_value, changed_value, readers = candidates[0]

    def lambda_shape(value: ast.AST):
        if not isinstance(value, ast.Lambda):
            return None
        arguments = value.args
        if arguments.defaults or any(default is not None for default in arguments.kw_defaults):
            return None
        return ast.dump(arguments, include_attributes=False)

    if lambda_shape(original_value) is None or lambda_shape(original_value) != lambda_shape(changed_value):
        return None

    class Replace(ast.NodeTransformer):
        def __init__(self, target: ast.AST):
            self.target = target

        def generic_visit(self, node):
            if node is self.target:
                return ast.Constant(value="__blast_radius_generator_transform__")
            return super().generic_visit(node)

    Replace(original_value).visit(original_tree)
    Replace(changed_value).visit(changed_tree)
    if ast.dump(original_tree, include_attributes=False) != ast.dump(
        changed_tree, include_attributes=False
    ):
        return None
    return set(readers)


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
    outcome_index = {"Lt": 0, "LtE": 1, "Gt": 2, "GtE": 3, "Eq": 4, "NotEq": 5}
    # The artifact stores the result of every profiled operator on the exact
    # same immutable operands.  The proof therefore does not depend on the
    # replacement being the adjacent inclusive/exclusive ordering operator:
    # any distinct recorded pair is equivalent when its booleans agree for
    # every observation.  Identity operators remain excluded because their
    # outcomes are not present in this artifact and source instrumentation can
    # perturb constant interning.
    if (
        old_operator == new_operator
        or old_operator not in outcome_index
        or new_operator not in outcome_index
    ):
        return False
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

    # Quiet-NaN ordering can raise FE_INVALID even when equality returns the
    # same boolean. Native floating-point status is not part of a Python bool,
    # so reject the one recorded outcome vector that can hide this difference.
    # This also conservatively covers recursively safe tuples containing a
    # distinct NaN. Same-class ordering replacements retain the same FP
    # comparison class, while NotEq cannot equal an ordering result on this
    # vector in the first place.
    unordered_nan = [False, False, False, False, False, True]
    ordering_operators = {"Lt", "LtE", "Gt", "GtE"}
    if (
        (old_operator in ordering_operators) != (new_operator in ordering_operators)
        and any(outcome == unordered_nan for outcome in observations)
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


GUARD_RESULTS = {
    "truth": (False, True, False, False, True),
    "not": (True, False, True, True, False),
    "is_none": (False, False, True, False, False),
    "not_none": (True, True, False, True, True),
    "is_false": (False, False, False, True, False),
    "not_false": (True, True, True, False, True),
    "is_true": (False, False, False, False, True),
    "not_true": (True, True, True, True, False),
}
GUARD_OPERANDS = (ast.Name, ast.Attribute, ast.Call, ast.Subscript)


def _truth_guard_form(node: ast.AST) -> tuple[str, ast.expr] | None:
    if isinstance(node, GUARD_OPERANDS):
        return "truth", node
    if (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, ast.Not)
        and isinstance(node.operand, GUARD_OPERANDS)
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
    if not isinstance(operand, GUARD_OPERANDS) or not isinstance(constant, ast.Constant):
        return None
    if constant.value is None:
        suffix = "none"
    elif type(constant.value) is bool:
        suffix = "true" if constant.value else "false"
    else:
        return None
    return ("is_" if isinstance(node.ops[0], ast.Is) else "not_") + suffix, operand


def _none_guard_form(node: ast.AST) -> tuple[str, ast.expr, str] | None:
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


def valid_guard_profile(profile: dict | None, revision: str, digest: str, count: int) -> bool:
    if (
        not isinstance(profile, dict)
        or profile.get("v") != 1
        or profile.get("sha") != revision
        or profile.get("t") != digest
        or profile.get("n") != count
        or not isinstance(profile.get("tree"), str)
        or not isinstance(profile.get("d"), dict)
        or not isinstance(profile.get("provenance"), dict)
    ):
        return False
    return all(
        isinstance(path, str)
        and isinstance(entries, list)
        and all(isinstance(entry, list) for entry in entries)
        for path, entries in profile["d"].items()
    )


def guard_profile_exemptions(
    change: dict,
    path: str,
    profile: dict,
    hook_attributes: set[str] | None = None,
) -> set[int] | None:
    """Return tests proven insensitive to one exact guard-form change."""

    entries = profile.get("d", {}).get(path)
    source = pinned_sources().get(path)
    changed = patched_source(change, path)
    count = profile.get("n")
    if (
        not entries
        or source is None
        or changed is None
        or type(count) is not int
        or count <= 0
        or path in PROCESS_SERIALIZATION_FILES
        or any(COMMENT_DIRECTIVE.search(line) for line in change["payload"])
    ):
        return None
    try:
        original_tree = ast.parse(source, filename=path, type_comments=True)
        changed_tree = ast.parse(changed, filename=path, type_comments=True)
    except (SyntaxError, ValueError):
        return None

    def walk_paths(root: ast.AST):
        pending = [(root, ())]
        while pending:
            node, node_path = pending.pop()
            yield node, node_path
            children = []
            for field, value in ast.iter_fields(node):
                if isinstance(value, ast.AST):
                    children.append((value, (*node_path, (field, None))))
                elif isinstance(value, list):
                    children.extend(
                        (item, (*node_path, (field, index)))
                        for index, item in enumerate(value)
                        if isinstance(item, ast.AST)
                    )
            pending.extend(reversed(children))

    def follow(root: ast.AST, node_path):
        node = root
        for field, index in node_path:
            value = getattr(node, field, None)
            if index is None:
                node = value
            elif isinstance(value, list) and 0 <= index < len(value):
                node = value[index]
            else:
                return None
            if not isinstance(node, ast.AST):
                return None
        return node

    truth_nodes = {
        (node.test.lineno, node.test.col_offset, node.test.end_lineno, node.test.end_col_offset):
        (node, node_path)
        for node, node_path in walk_paths(original_tree)
        if isinstance(node, (ast.If, ast.While, ast.IfExp))
    }
    none_nodes = {
        (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset):
        (node, node_path)
        for node, node_path in walk_paths(original_tree)
        if isinstance(node, ast.Compare)
    }

    def masks(values, expected):
        if len(values) != expected or any(type(value) is not str for value in values):
            return None
        try:
            parsed = [int(value, 16) for value in values]
        except ValueError:
            return None
        limit = 1 << count
        return parsed if all(0 <= value < limit for value in parsed) else None

    candidates = []
    for entry in entries:
        if len(entry) < 12:
            continue
        start, column, end, end_column, kind, source_form, operand_dump, side, state = entry[:9]
        if (
            any(type(value) is not int for value in (start, column, end, end_column))
            or not any(start <= line <= end for line in change["lines"])
            or state != "safe"
            or type(source_form) is not str
            or type(operand_dump) is not str
        ):
            continue
        position = (start, column, end, end_column)
        if kind == "truth":
            found = truth_nodes.get(position)
            parsed_masks = masks(entry[9:], 7)
        elif kind == "none":
            found = none_nodes.get(position)
            parsed_masks = masks(entry[9:], 3)
        else:
            continue
        if found is not None and parsed_masks is not None:
            candidates.append((kind, source_form, operand_dump, side, found, parsed_masks))
    accepted = []
    for kind, source_form, operand_dump, side, (original_node, node_path), parsed in candidates:
        changed_node = follow(changed_tree, node_path)
        if kind == "truth":
            if not isinstance(changed_node, type(original_node)):
                continue
            before = _truth_guard_form(original_node.test)
            after = _truth_guard_form(changed_node.test)
            if (
                before is None
                or after is None
                or before[0] != source_form
                or before[0] == after[0]
                or ast.dump(before[1], include_attributes=False) != operand_dump
                or ast.dump(before[1], include_attributes=False)
                != ast.dump(after[1], include_attributes=False)
                or ast.get_source_segment(source, before[1]) is None
                or ast.get_source_segment(source, before[1])
                != ast.get_source_segment(changed, after[1])
            ):
                continue
            original_test, changed_test = original_node.test, changed_node.test
            original_node.test = ast.Constant("__blast_radius_guard__")
            changed_node.test = ast.Constant("__blast_radius_guard__")
            equivalent = ast.dump(original_tree, include_attributes=False) == ast.dump(
                changed_tree, include_attributes=False
            )
            original_node.test, changed_node.test = original_test, changed_test
            if not equivalent:
                continue
            seen, unknown, *states = parsed
            if (
                unknown & ~seen
                or any(state_mask & ~seen for state_mask in states)
                or seen != unknown | states[0] | states[1] | states[2] | states[3] | states[4]
            ):
                continue
            safe = seen & ~unknown
            for old_result, new_result, state_mask in zip(
                GUARD_RESULTS[before[0]], GUARD_RESULTS[after[0]], states
            ):
                if old_result != new_result:
                    safe &= ~state_mask
        else:
            if not isinstance(changed_node, ast.Compare):
                continue
            before = _none_guard_form(original_node)
            after = _none_guard_form(changed_node)
            if (
                before is None
                or after is None
                or before[0] != source_form
                or before[2] != side
                or before[2] != after[2]
                or ast.dump(before[1], include_attributes=False) != operand_dump
                or ast.dump(before[1], include_attributes=False)
                != ast.dump(after[1], include_attributes=False)
                or ast.get_source_segment(source, before[1]) is None
                or ast.get_source_segment(source, before[1])
                != ast.get_source_segment(changed, after[1])
            ):
                continue
            operators = {before[0], after[0]}
            if operators == {"Is", "Eq"}:
                unsafe_index = 1
                replacement = ast.Is()
            elif operators == {"IsNot", "NotEq"}:
                unsafe_index = 2
                replacement = ast.IsNot()
            else:
                continue
            original_operator, changed_operator = original_node.ops[0], changed_node.ops[0]
            original_node.ops[0] = replacement
            changed_node.ops[0] = type(replacement)()
            equivalent = ast.dump(original_tree, include_attributes=False) == ast.dump(
                changed_tree, include_attributes=False
            )
            original_node.ops[0], changed_node.ops[0] = original_operator, changed_operator
            if not equivalent:
                continue
            seen, unsafe_eq, unsafe_ne = parsed
            if unsafe_eq & ~seen or unsafe_ne & ~seen:
                continue
            safe = seen & ~parsed[unsafe_index]
        accepted.append({index for index in range(count) if safe & (1 << index)})
    if len(accepted) != 1:
        return None
    first_line = min(change["lines"], default=0)
    if not preserves_function_bindings(change, path, first_line) or import_expression_hazard(
        change, path, hook_attributes
    ):
        return None
    return accepted[0]


def guard_profile_indices(
    change: dict,
    path: str,
    profile: dict,
    model: dict,
    hook_attributes: set[str] | None = None,
) -> set[int] | None:
    """Apply per-test exemptions to the ordinary exact-line dependency set."""

    exemptions = guard_profile_exemptions(change, path, profile, hook_attributes)
    if not exemptions:
        return None
    entry = model.get("f", {}).get(path)
    if entry is None:
        return None
    line_sets = {line: set_id for line, set_id in entry.get("l", ())}
    candidates = set()
    for line in change["lines"]:
        if (
            not precise_coverage_line(path, line, change)
            or not preserves_function_bindings(change, path, line)
            or line not in line_sets
        ):
            return None
        candidates.update(mapped_set(model, line_sets[line]))
    return candidates - exemptions


def tokenizer_setting_flow_edit(
    change: dict,
    path: str,
    flow_model: dict,
) -> set[int] | None:
    """Narrow one certified Tokenizer setting to its core-field readers."""
    entries = flow_model.get("d", {}).get(path)
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
    for start, end, qualname, name, value_dump, _field, readers in entries:
        if not any(start <= line <= end for line in change["lines"]):
            continue
        key = (tuple(qualname.split(".")), name)
        statement = original_assignments.get(key)
        if (
            statement is not None
            and statement.lineno == start
            and (statement.end_lineno or statement.lineno) == end
            and ast.dump(statement.value, include_attributes=False) == value_dump
        ):
            candidates.append((key, statement, readers))
    if len(candidates) != 1:
        return None
    key, original_statement, readers = candidates[0]
    changed_statement = changed_assignments.get(key)
    if changed_statement is None:
        return None
    try:
        old_literal = ast.literal_eval(original_statement.value)
        new_literal = ast.literal_eval(changed_statement.value)
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
            or index >= flow_model.get("n", 0)
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
    return set(readers)


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


def function_default_edit(
    change: dict,
    path: str,
    default_model: dict,
    hook_attributes: set[str] | None = None,
) -> set[int] | None:
    """Narrow a literal function-default edit to calls omitting that default."""
    entries = default_model.get("d", {}).get(path)
    changed_lines = change.get("lines", ())
    if not entries or not any(
        isinstance(entry, list)
        and len(entry) == 8
        and type(entry[0]) is int
        and type(entry[1]) is int
        and entry[6] == "safe"
        and any(entry[0] <= line <= entry[1] for line in changed_lines)
        for entry in entries
    ):
        return None
    source = pinned_sources().get(path)
    changed = patched_source(change, path)
    if (
        source is None
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

    def defaults(tree: ast.Module):
        result = {}

        def visit(body: list[ast.stmt], prefix: tuple[str, ...]) -> None:
            for statement in body:
                if isinstance(statement, ast.ClassDef):
                    visit(statement.body, (*prefix, statement.name))
                    continue
                if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                qualname = ".".join((*prefix, statement.name))
                positional = [*statement.args.posonlyargs, *statement.args.args]
                aligned = [None] * (
                    len(positional) - len(statement.args.defaults)
                ) + list(statement.args.defaults)
                values = [
                    (argument.arg, default)
                    for argument, default in zip(positional, aligned)
                    if default is not None
                ]
                values.extend(
                    (argument.arg, default)
                    for argument, default in zip(
                        statement.args.kwonlyargs, statement.args.kw_defaults
                    )
                    if default is not None
                )
                for name, default in values:
                    key = (qualname, name)
                    result[key] = (
                        (statement, default) if key not in result else None
                    )
                visit(statement.body, (*prefix, statement.name, "<locals>"))

        visit(tree.body, ())
        return result

    original_defaults = defaults(original_tree)
    changed_defaults = defaults(changed_tree)
    candidates = []
    for start, end, function_line, qualname, name, value_dump, state, readers in entries:
        if state != "safe" or not any(start <= line <= end for line in changed_lines):
            continue
        found = original_defaults.get((qualname, name))
        changed_found = changed_defaults.get((qualname, name))
        if (
            found is None
            or changed_found is None
            or found[0].lineno != function_line
            or found[1].lineno != start
            or (found[1].end_lineno or found[1].lineno) != end
            or ast.dump(found[1], include_attributes=False) != value_dump
            or ast.dump(found[1], include_attributes=False)
            == ast.dump(changed_found[1], include_attributes=False)
        ):
            continue
        candidates.append(((qualname, name), found, readers))
    if len(candidates) != 1:
        return None
    key, (_, original_default), readers = candidates[0]
    changed_found = changed_defaults.get(key)
    if changed_found is None:
        return None
    changed_default = changed_found[1]
    try:
        old_literal = ast.literal_eval(original_default)
        new_literal = ast.literal_eval(changed_default)
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
            or index >= default_model.get("n", 0)
            for index in readers
        )
    ):
        return None

    class Replace(ast.NodeTransformer):
        def __init__(self, target: ast.expr):
            self.target = target

        def generic_visit(self, node):
            if node is self.target:
                return ast.Constant(value="__blast_radius_default__")
            return super().generic_visit(node)

    Replace(original_default).visit(original_tree)
    Replace(changed_default).visit(changed_tree)
    if ast.dump(original_tree, include_attributes=False) != ast.dump(
        changed_tree, include_attributes=False
    ) or ast.dump(original_tree, include_attributes=True) != ast.dump(
        changed_tree, include_attributes=True
    ):
        return None
    return set(readers)


def module_constant_edit(
    change: dict,
    path: str,
    constant_model: dict,
) -> set[int] | None:
    """Narrow one immutable module-literal edit to its traced readers."""
    data = constant_model.get("d", {})
    entries = data.get(path) if isinstance(data, dict) else None
    source = pinned_sources().get(path)
    changed = patched_source(change, path)
    if (
        not entries
        or source is None
        or changed is None
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
        for statement in tree.body:
            if isinstance(statement, ast.Assign):
                targets = statement.targets
            elif isinstance(statement, ast.AnnAssign):
                targets = [statement.target]
            else:
                continue
            if len(targets) == 1 and isinstance(targets[0], ast.Name):
                name = targets[0].id
                result[name] = statement if name not in result else None
        return result

    original_assignments = assignments(original_tree)
    changed_assignments = assignments(changed_tree)
    candidates = []
    for entry in entries:
        if not isinstance(entry, list) or len(entry) != 6:
            continue
        start, end, name, value_dump, state, readers = entry
        if (
            type(start) is not int
            or type(end) is not int
            or type(name) is not str
            or type(value_dump) is not str
        ):
            continue
        if state != "safe" or not any(start <= line <= end for line in change["lines"]):
            continue
        statement = original_assignments.get(name)
        if (
            statement is None
            or statement.lineno != start
            or (statement.end_lineno or statement.lineno) != end
            or ast.dump(statement.value, include_attributes=False) != value_dump
        ):
            continue
        candidates.append((name, statement, readers))
    if len(candidates) != 1:
        return None
    name, original_statement, readers = candidates[0]
    changed_statement = changed_assignments.get(name)
    if changed_statement is None:
        return None
    try:
        old_literal = ast.literal_eval(original_statement.value)
        new_literal = ast.literal_eval(changed_statement.value)
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
        or not readers
        or any(
            type(index) is not int
            or index < 0
            or index >= constant_model.get("n", 0)
            for index in readers
        )
    ):
        return None

    # Erasing exactly the approved values must make the complete executable
    # trees identical. This excludes target, annotation, type-comment,
    # neighboring statement, and all other simultaneous changes.
    original_statement.value = ast.Constant(value=None)
    changed_statement.value = ast.Constant(value=None)
    if ast.dump(original_tree, include_attributes=False) != ast.dump(
        changed_tree, include_attributes=False
    ):
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


def line_in_function(path: str, line: int) -> bool:
    """Whether a source line is contained by any Python function code object."""
    tree = source_tree(path)
    index = _source_index(path)
    return bool(
        tree
        and index
        and any(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
            and min(
                [
                    node.lineno,
                    *(decorator.lineno for decorator in node.decorator_list),
                ]
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                else [node.lineno]
            )
            <= line
            <= (node.end_lineno or node.lineno)
            for node in index.nodes
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
        )
    )


def code_reflection_indices(
    path: str,
    lines: set[int],
    reflection_model: dict | None,
    all_indices: set[int],
) -> set[int]:
    """Return readers which observe containing function code without calling it."""
    if reflection_model is None:
        return set(all_indices) if any(line_in_function(path, line) for line in lines) else set()
    selected = set()
    for start, end, _name, state, readers in reflection_model["d"].get(path, ()):
        if state != "unobserved" and any(start <= line <= end for line in lines):
            selected.update(readers)
    return selected


def file_code_reflection_indices(
    path: str,
    reflection_model: dict | None,
    all_indices: set[int],
) -> set[int]:
    """Retain every reader of code objects whose positions can shift.

    Inserting a source line can change position metadata for functions after
    the insertion even when no executable field changes.  The ordinary range
    lookup covers the containing function only, so directive-comment proofs
    conservatively retain every observed code-object reader in the file.
    Missing evidence fails closed for the complete candidate set.
    """

    if reflection_model is None:
        return set(all_indices)
    selected = set()
    for _start, _end, _name, state, readers in reflection_model["d"].get(path, ()):
        if state != "unobserved":
            selected.update(readers)
    return selected


def _nested_code_objects(root: types.CodeType) -> list[types.CodeType]:
    result = []
    pending = [root]
    while pending:
        code = pending.pop()
        children = [
            value for value in code.co_consts if isinstance(value, types.CodeType)
        ]
        result.extend(children)
        pending.extend(children)
    return result


def _typing_test_code_fingerprint(code: types.CodeType) -> tuple:
    """Exactly mirror tests/test_typing.py::_same_code."""
    return (code.co_code, code.co_names, code.co_varnames, code.co_consts)


def typing_reflection_outcome_equivalent(
    change: dict,
    path: str,
    reflection_model: dict | None,
    proof_family: str | None,
    local_annotation: bool,
) -> bool:
    """Prove a semantic no-op cannot create redundant typing metadata.

    The only pinned code-reflection reader compares annotator code by four
    exact CodeType fields. Local annotations preserve the complete compiled
    fingerprint. A same-width local rename may change ``co_varnames``; it is
    safe only when every changed prospective fingerprint remains unique across
    the complete pinned typing package, so it cannot newly equal a parent
    annotator. This uses a superset of the functions the test can inspect.
    """
    if (
        reflection_model is None
        or not (
            path == "sqlglot/typing/__init__.py"
            or path.startswith("sqlglot/typing/")
        )
        or not path.endswith(".py")
        or (proof_family != "local-binding-rename" and not local_annotation)
        or code_reflection_indices(path, change["lines"], reflection_model, set())
        != {1619}
    ):
        return False

    original = pinned_sources().get(path)
    prospective = patched_source(change, path)
    if original is None or prospective is None:
        return False
    try:
        original_root = compile(original, path, "exec", dont_inherit=True)
        prospective_root = compile(prospective, path, "exec", dont_inherit=True)
    except (SyntaxError, ValueError, TypeError, OverflowError, MemoryError):
        return False

    def keyed(root: types.CodeType) -> dict[tuple, types.CodeType] | None:
        result = {}
        for code in _nested_code_objects(root):
            key = (code.co_qualname, code.co_name, code.co_firstlineno)
            if key in result:
                return None
            result[key] = code
        return result

    original_codes = keyed(original_root)
    prospective_codes = keyed(prospective_root)
    if (
        original_codes is None
        or prospective_codes is None
        or original_codes.keys() != prospective_codes.keys()
    ):
        return False
    changed_keys = [
        key
        for key in original_codes
        if _typing_test_code_fingerprint(original_codes[key])
        != _typing_test_code_fingerprint(prospective_codes[key])
    ]
    if not changed_keys:
        return True

    observed = reflection_model["d"].get(path, ())
    for key in changed_keys:
        _qualname, name, first_line = key
        if not any(
            entry_name == name
            and start == first_line
            and state == "observed"
            and readers == [1619]
            and any(start <= line <= end for line in change["lines"])
            for start, end, entry_name, state, readers in observed
        ):
            return False

    global _TYPING_CODE_FINGERPRINTS
    if _TYPING_CODE_FINGERPRINTS is None:
        fingerprints = Counter()
        for source_path, source in pinned_sources().items():
            if not (
                source_path == "sqlglot/typing/__init__.py"
                or source_path.startswith("sqlglot/typing/")
            ) or not source_path.endswith(".py"):
                continue
            try:
                root = compile(source, source_path, "exec", dont_inherit=True)
            except (SyntaxError, ValueError, TypeError, OverflowError, MemoryError):
                return False
            fingerprints.update(
                _typing_test_code_fingerprint(code)
                for code in _nested_code_objects(root)
            )
        _TYPING_CODE_FINGERPRINTS = fingerprints

    prospective_fingerprints = _TYPING_CODE_FINGERPRINTS.copy()
    for key in changed_keys:
        prospective_fingerprints[
            _typing_test_code_fingerprint(original_codes[key])
        ] -= 1
    for key in changed_keys:
        prospective_fingerprints[
            _typing_test_code_fingerprint(prospective_codes[key])
        ] += 1
    for key in changed_keys:
        new = _typing_test_code_fingerprint(prospective_codes[key])
        if prospective_fingerprints[new] != 1:
            return False
    return True


def valid_code_reflection_model(model: object, pinned_sha: str, test_digest: str, n: int) -> bool:
    """Validate the complete bundled reflection profile before trusting any range."""
    if (
        not isinstance(model, dict)
        or model.get("v") != 1
        or model.get("sha") != pinned_sha
        or model.get("t") != test_digest
        or model.get("n") != n
        or not isinstance(model.get("d"), dict)
    ):
        return False
    ranges = []
    for path in sorted(model["d"]):
        entries = model["d"][path]
        if type(path) is not str or not isinstance(entries, list):
            return False
        for entry in entries:
            if not isinstance(entry, list) or len(entry) != 5:
                return False
            start, end, name, state, readers = entry
            if (
                type(start) is not int
                or type(end) is not int
                or start <= 0
                or end < start
                or type(name) is not str
                or state not in {"observed", "unobserved", "import-read"}
                or not isinstance(readers, list)
                or any(type(index) is not int or index < 0 or index >= n for index in readers)
                or readers != sorted(set(readers))
                or (state == "unobserved" and readers)
                or (state == "observed" and not readers)
                or (state == "import-read" and readers != list(range(n)))
            ):
                return False
            ranges.append([path, start, end, name])
    ranges_digest = hashlib.sha256(
        json.dumps(ranges, separators=(",", ":")).encode()
    ).hexdigest()
    try:
        profile_digest = hashlib.sha256(
            json.dumps(model["d"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    except (TypeError, ValueError, OverflowError, RecursionError, MemoryError):
        return False
    return (
        model.get("p") == CODE_REFLECTION_RANGES_SHA256
        and ranges_digest == CODE_REFLECTION_RANGES_SHA256
        and profile_digest == CODE_REFLECTION_PROFILE_SHA256
    )


def valid_generator_dispatch_model(
    model: object, pinned_sha: str, test_digest: str, n: int
) -> bool:
    """Validate every generator entry before any precise dispatch decision."""
    if (
        not isinstance(model, dict)
        or set(model) != {"d", "n", "p", "sha", "t", "v"}
        or model.get("v") != 1
        or model.get("sha") != pinned_sha
        or model.get("t") != test_digest
        or model.get("n") != n
        or not isinstance(model.get("d"), dict)
    ):
        return False
    try:
        profile_digest = hashlib.sha256(
            json.dumps(model["d"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    except (TypeError, ValueError, OverflowError, RecursionError, MemoryError):
        return False
    if model.get("p") != profile_digest:
        return False
    states = {
        "safe",
        "unsupported-value",
        "ineffective",
        "json-path-order",
        "unsafe-observation",
    }
    actual_inventory = []
    for path, entries in model["d"].items():
        if type(path) is not str or not isinstance(entries, list):
            return False
        for entry in entries:
            if not isinstance(entry, list) or len(entry) != 8:
                return False
            start, end, owner, index, key_dump, value_dump, state, readers = entry
            if (
                type(start) is not int
                or type(end) is not int
                or start <= 0
                or end < start
                or type(owner) is not str
                or type(index) is not int
                or index < 0
                or type(key_dump) is not str
                or type(value_dump) is not str
                or state not in states
                or not isinstance(readers, list)
                or readers != sorted(set(readers))
                or any(
                    type(reader) is not int or reader < 0 or reader >= n
                    for reader in readers
                )
            ):
                return False
            actual_inventory.append([path, start, end, owner, index, key_dump, value_dump])

    try:
        inventory_digest = hashlib.sha256(
            json.dumps(sorted(actual_inventory), separators=(",", ":")).encode()
        ).hexdigest()
    except (TypeError, ValueError, OverflowError, MemoryError, RecursionError):
        return False
    return (
        len(actual_inventory) == 1350
        and inventory_digest == GENERATOR_DISPATCH_INVENTORY_SHA256
        and profile_digest == GENERATOR_DISPATCH_PROFILE_SHA256
    )


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
    constant_model: dict | None = None,
    reflection_model: dict | None = None,
    fresh_alias_model: dict | None = None,
    generator_dispatch_model: dict | None = None,
    new_module_model: dict | None = None,
    default_model: dict | None = None,
    tokenizer_setting_flow_model: dict | None = None,
    tokenizer_keyword_context: TokenizerKeywordContext | None = None,
    guard_model: dict | None = None,
) -> set[int]:
    selected: set[int] = set()
    changes = patch_changes(patch)
    if not changes:
        return set(all_indices)
    # Every narrow proof depends on the exact pinned source snapshot. If its
    # raw artifact fails validation, even syntax-check fallback is unavailable.
    if not pinned_sources():
        return set(all_indices)
    new_module_readers = (
        isolated_new_module_indices(changes, new_module_model)
        if NEW_MODULE_PROOF_ENABLED
        else None
    )
    if new_module_readers is not None:
        return new_module_readers
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
        directive_comment_proved = False
        if path.endswith(".py") and comment_only_addition(change) and any(
            COMMENT_DIRECTIVE.search(line) for line in change["added"]
        ):
            if reflection_model is None or not runtime_inert_directive_comment(change, path):
                selected.update(all_indices)
                continue
            directive_comment_proved = True
        reflection_indices = code_reflection_indices(
            path, change["lines"], reflection_model, all_indices
        )
        if reflection_model is not None and position_preserving_formatting_edit(
            change, path
        ):
            selected.update(reflection_indices)
            continue
        if directive_comment_proved:
            reflection_indices.update(
                file_code_reflection_indices(path, reflection_model, all_indices)
            )
        if inert_comment_addition(change, path):
            selected.update(reflection_indices)
            continue
        semantic_noop = semantic_noop_edit(change, path)
        local_annotation = local_annotation_only_edit(change, path)
        if not typing_reflection_outcome_equivalent(
            change,
            path,
            reflection_model,
            semantic_noop,
            local_annotation,
        ):
            selected.update(reflection_indices)
        if semantic_noop is not None:
            continue
        if local_annotation:
            continue
        if tokenizer_keyword_context is not None:
            tokenizer_keyword_indices = tokenizer_keyword_patch(
                changes, tokenizer_keyword_context
            )
            if tokenizer_keyword_indices is not None:
                selected.update(tokenizer_keyword_indices)
                continue
        if proven_identity_equality(change, path, model):
            continue
        if fresh_alias_model is not None and len(changes) == 1 and fresh_table_alias_copy_edit(
            change, path, fresh_alias_model, model.get("h")
        ):
            continue
        if test_file_indices and path in test_file_indices:
            # A syntax or import error fails every collected test in the file,
            # even when only one test function covered the changed line.
            selected.update(test_file_indices[path])

        if generator_dispatch_model is not None and len(changes) == 1:
            generator_indices = generator_transform_edit(
                change, path, generator_dispatch_model
            )
            if generator_indices is not None:
                selected.update(generator_indices)
                continue

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

        if guard_model is not None and len(changes) == 1:
            guard_indices = guard_profile_indices(
                change, path, guard_model, model, model.get("h")
            )
            if guard_indices is not None:
                selected.update(guard_indices)
                continue

        if derivation_model is not None:
            derived_indices = derived_arg_types_edit(
                change, path, derivation_model, model.get("h")
            )
            if derived_indices is not None:
                selected.update(derived_indices)
                continue

        if tokenizer_setting_flow_model is not None and len(changes) == 1:
            tokenizer_indices = tokenizer_setting_flow_edit(
                change, path, tokenizer_setting_flow_model
            )
            if tokenizer_indices is not None:
                selected.update(tokenizer_indices)
                continue

        if attribute_model is not None:
            attribute_indices = class_attribute_edit(
                change, path, attribute_model, model.get("h")
            )
            if attribute_indices is not None:
                selected.update(attribute_indices)
                continue

        if constant_model is not None:
            constant_indices = module_constant_edit(change, path, constant_model)
            if constant_indices is not None:
                selected.update(constant_indices)
                continue

        if default_model is not None and len(changes) == 1:
            default_indices = function_default_edit(
                change, path, default_model, model.get("h")
            )
            if default_indices is not None:
                selected.update(default_indices)
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
                and precise_coverage_line(path, line, change)
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
        if any(
            start <= line <= end
            for start, end in entry.get("i", ())
            for line in changed_lines
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
    try:
        guard_raw = GUARD_PROFILE.read_bytes()
        if not GUARD_PROFILE_SHA256 or hashlib.sha256(guard_raw).hexdigest() != GUARD_PROFILE_SHA256:
            raise ValueError("guard profile is not pinned")
        guard_model = json.loads(gzip.decompress(guard_raw))
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
        guard_model = None
    with gzip.open(ARG_TYPE_DERIVATION_MODEL, "rt", encoding="utf-8") as derivation_model_file:
        derivation_model = json.load(derivation_model_file)
    with gzip.open(CLASS_ATTRIBUTE_MODEL, "rt", encoding="utf-8") as attribute_model_file:
        attribute_model = json.load(attribute_model_file)
    try:
        tokenizer_raw = TOKENIZER_SETTING_FLOW_MODEL.read_bytes()
        tokenizer_setting_flow_model = json.loads(gzip.decompress(tokenizer_raw))
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
        tokenizer_setting_flow_model = None
    try:
        tokenizer_keyword_raw = TOKENIZER_KEYWORD_MODEL.read_bytes()
        tokenizer_keyword_sources_raw = SEMANTIC_SOURCES.read_bytes()
        tokenizer_keyword_context = load_tokenizer_keyword_context(
            tokenizer_keyword_raw,
            TOKENIZER_KEYWORD_MODEL_SHA256,
            tokenizer_keyword_sources_raw,
            SEMANTIC_SOURCES_SHA256,
        )
    except (OSError, MemoryError):
        tokenizer_keyword_context = None
    with gzip.open(MODULE_CONSTANT_MODEL, "rt", encoding="utf-8") as constant_model_file:
        constant_model = json.load(constant_model_file)
    with gzip.open(CODE_REFLECTION_MODEL, "rt", encoding="utf-8") as reflection_model_file:
        reflection_model = json.load(reflection_model_file)
    with gzip.open(FRESH_ALIAS_PROFILE, "rt", encoding="utf-8") as fresh_alias_file:
        fresh_alias_model = json.load(fresh_alias_file)
    try:
        with gzip.open(GENERATOR_DISPATCH_MODEL, "rt", encoding="utf-8") as dispatch_file:
            generator_dispatch_model = json.load(dispatch_file)
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
        generator_dispatch_model = {"d": {}}
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
    try:
        with gzip.open(FUNCTION_DEFAULT_MODEL, "rt", encoding="utf-8") as default_file:
            default_model = json.load(default_file)
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
        default_model = {"d": {}}
    test_digest = hashlib.sha256(
        "\0".join(test["id"] for test in tests).encode("utf-8")
    ).hexdigest()
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
    if not valid_guard_profile(guard_model, model.get("sha"), test_digest, len(tests)):
        guard_model = None
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
        hashlib.sha256(MODEL.read_bytes()).hexdigest()
        != TOKENIZER_SETTING_SELECTOR_MODEL_SHA256
        or hashlib.sha256(CLASS_ATTRIBUTE_MODEL.read_bytes()).hexdigest()
        != TOKENIZER_SETTING_CLASS_MODEL_SHA256
        or not valid_tokenizer_setting_flow_model(
            tokenizer_setting_flow_model, model.get("sha"), test_digest, len(tests)
        )
    ):
        tokenizer_setting_flow_model = None
    if not valid_code_reflection_model(
        reflection_model, model.get("sha"), test_digest, len(tests)
    ):
        reflection_model = None
    if (
        not isinstance(constant_model, dict)
        or constant_model.get("v") != 1
        or constant_model.get("sha") != model.get("sha")
        or constant_model.get("n") != len(tests)
        or constant_model.get("t") != test_digest
        or not isinstance(constant_model.get("d"), dict)
    ):
        constant_model = {"d": {}}
    if (
        fresh_alias_model.get("v") != 1
        or fresh_alias_model.get("sha") != model.get("sha")
        or fresh_alias_model.get("n") != len(tests)
        or fresh_alias_model.get("t") != test_digest
    ):
        fresh_alias_model = {"d": {}}
    if not valid_generator_dispatch_model(
        generator_dispatch_model, model.get("sha"), test_digest, len(tests)
    ):
        generator_dispatch_model = {"d": {}}
    if not valid_new_module_model(
        new_module_model, model.get("sha"), test_digest, len(tests)
    ):
        new_module_model = None
    if (
        not isinstance(default_model, dict)
        or default_model.get("v") != 1
        or default_model.get("sha") != model.get("sha")
        or default_model.get("n") != len(tests)
        or default_model.get("t") != test_digest
        or not valid_function_default_model(default_model)
    ):
        default_model = {"d": {}}
    mapped_tests = [tests_by_id.get(test_id) for test_id in model["t"]]
    all_indices = {index for index, test in enumerate(mapped_tests) if test is not None}
    test_file_indices: dict[str, set[int]] = {}
    for index, test in enumerate(mapped_tests):
        if test is not None:
            test_file_indices.setdefault(test["file"], set()).add(index)
    modeled_ids = set(model["t"])
    unmapped_tests = [test for test in tests if test["id"] not in modeled_ids]

    selection_count = 0
    for patch in sorted((DATA / "commits").glob("*.patch")):
        indices = selected_indices(
            patch,
            model,
            all_indices,
            test_file_indices,
            zero_model,
            predicate_model,
            derivation_model,
            attribute_model,
            constant_model,
            reflection_model,
            fresh_alias_model,
            generator_dispatch_model,
            new_module_model,
            default_model,
            tokenizer_setting_flow_model,
            tokenizer_keyword_context,
            guard_model,
        )
        selected = [
            mapped_tests[index]
            for index in sorted(indices)
            if mapped_tests[index] is not None
        ]
        changes = patch_changes(patch)
        if any(test["id"] == MAX_NODES_TEST_ID for test in selected) and exact_max_nodes_passes(
            changes, tests
        ):
            selected = [test for test in selected if test["id"] != MAX_NODES_TEST_ID]
        verification_sources = []
        if changes and all(
            change["old"] == change["new"]
            and isinstance(change["old"], str)
            and change["old"].startswith("sqlglot/")
            and change["old"].endswith(".py")
            for change in changes
        ):
            for change in changes:
                changed_source = runtime_body_patch_source(change, change["old"])
                if changed_source is None:
                    verification_sources = []
                    break
                verification_sources.append((change["old"], changed_source))
        if verification_sources:
            selected = verify_candidates(verification_sources, selected)
        selected.extend(unmapped_tests)
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
