"""Conservative semantic no-op recognizers.

These predicates are intentionally independent of coverage.  A successful proof
means that the executable/source-position state described by the predicate is
unchanged, not merely that the changed line happened to be uncovered once.
"""

from __future__ import annotations

import ast
import io
import token
import tokenize
import types
from dataclasses import dataclass


_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
_DYNAMIC_NAMES = {
    "Bytecode",
    "FrameSummary",
    "StackSummary",
    "TracebackException",
    "__builtins__",
    "__file__",
    "__getattribute__",
    "_current_exceptions",
    "_current_frames",
    "breakpoint",
    "compile",
    "delattr",
    "dis",
    "dir",
    "eval",
    "exec",
    "findsource",
    "extract_stack",
    "extract_tb",
    "format_exc",
    "format_exception",
    "format_list",
    "format_tb",
    "get_data",
    "get_source",
    "getline",
    "getlines",
    "get_instructions",
    "get_referents",
    "get_referrers",
    "getattr",
    "getattr_static",
    "globals",
    "hasattr",
    "help",
    "locals",
    "open",
    "register_callback",
    "read_bytes",
    "read_text",
    "setattr",
    "show_code",
    "print_exc",
    "print_exception",
    "vars",
    "traceback",
    "currentframe",
    "getclosurevars",
    "getframeinfo",
    "getsource",
    "getsourcelines",
    "stack",
    "setprofile",
    "settrace",
}
_DYNAMIC_ATTRIBUTES = {
    "Bytecode",
    "FrameSummary",
    "StackSummary",
    "TracebackException",
    "__code__",
    "__dict__",
    "__file__",
    "__getattribute__",
    "_current_exceptions",
    "_current_frames",
    "_getframe",
    "ag_frame",
    "attrgetter",
    "code_info",
    "co_cellvars",
    "co_freevars",
    "co_varnames",
    "cr_frame",
    "currentframe",
    "dis",
    "exception",
    "f_back",
    "f_code",
    "f_globals",
    "f_locals",
    "findsource",
    "extract_stack",
    "extract_tb",
    "format_exc",
    "format_exception",
    "format_list",
    "format_tb",
    "get_data",
    "get_source",
    "getline",
    "getlines",
    "get_instructions",
    "get_referents",
    "get_referrers",
    "getclosurevars",
    "getframeinfo",
    "getattr",
    "getattr_static",
    "getmembers",
    "getmembers_static",
    "getargvalues",
    "getasyncgenlocals",
    "getcoroutinelocals",
    "getgeneratorlocals",
    "getinnerframes",
    "getouterframes",
    "getsource",
    "getsourcelines",
    "gi_frame",
    "monitoring",
    "methodcaller",
    "open",
    "register_callback",
    "read_bytes",
    "read_text",
    "setattr",
    "setprofile",
    "settrace",
    "show_code",
    "print_exc",
    "print_exception",
    "stack",
    "tb_frame",
    "tb_lasti",
    "tb_lineno",
    "tb_next",
    "walk_stack",
    "walk_tb",
    "trace",
}

# Import aliases retain the original API name only on ``ast.alias``.  Checking
# these names closes ``from builtins import getattr as g`` and corresponding
# aliases of inspect/dis/operator/frame APIs before the alias is ever called.
_DYNAMIC_IMPORTS = _DYNAMIC_NAMES | _DYNAMIC_ATTRIBUTES | {
    "attrgetter",
    "code_info",
    "getmembers",
    "getmembers_static",
    "methodcaller",
    "trace",
    "walk_stack",
    "walk_tb",
}


@dataclass(frozen=True)
class RenameProof:
    """Evidence emitted by :func:`local_binding_rename`."""

    pairs: tuple[tuple[str, str], ...]
    occurrences: int


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }


def _token_pairs(original: str, changed: str) -> list[tuple[str, str]] | None:
    """Return the NAME substitutions when every other concrete token is fixed."""

    def tokens(source: str):
        return [
            item
            for item in tokenize.generate_tokens(io.StringIO(source).readline)
            if item.type not in {tokenize.ENCODING}
        ]

    try:
        left = tokens(original)
        right = tokens(changed)
    except (IndentationError, SyntaxError, tokenize.TokenError):
        return None
    if len(left) != len(right):
        return None
    pairs = []
    for old, new in zip(left, right):
        if (
            old.type == new.type
            and old.string == new.string
            and old.start == new.start
            and old.end == new.end
        ):
            continue
        if (
            old.type != token.NAME
            or new.type != token.NAME
            or old.start != new.start
            or old.end != new.end
            or len(old.string) != len(new.string)
            or old.string == new.string
        ):
            return None
        pairs.append((old.string, new.string))
    return pairs or None


def _ast_rename_pairs(
    old: ast.AST, new: ast.AST
) -> tuple[list[tuple[ast.AST, ast.AST, str, str]], dict[ast.AST, ast.AST]] | None:
    """Compare complete ASTs, permitting only Name and except-as identifiers."""

    changes: list[tuple[ast.AST, ast.AST, str, str]] = []
    correspondence: dict[ast.AST, ast.AST] = {}

    def compare(left, right, field: str | None = None) -> bool:
        if isinstance(left, ast.AST) or isinstance(right, ast.AST):
            if type(left) is not type(right):
                return False
            correspondence[left] = right
            for attribute in getattr(left, "_attributes", ()):  # positions are observable
                if getattr(left, attribute, None) != getattr(right, attribute, None):
                    return False
            for name in left._fields:
                lvalue = getattr(left, name)
                rvalue = getattr(right, name)
                if isinstance(left, ast.Name) and name == "id" and lvalue != rvalue:
                    changes.append((left, right, lvalue, rvalue))
                    continue
                if (
                    isinstance(left, ast.ExceptHandler)
                    and name == "name"
                    and lvalue != rvalue
                    and isinstance(lvalue, str)
                    and isinstance(rvalue, str)
                ):
                    changes.append((left, right, lvalue, rvalue))
                    continue
                if not compare(lvalue, rvalue, name):
                    return False
            return True
        if isinstance(left, list) or isinstance(right, list):
            return (
                isinstance(left, list)
                and isinstance(right, list)
                and len(left) == len(right)
                and all(compare(a, b, field) for a, b in zip(left, right))
            )
        return type(left) is type(right) and left == right

    return (changes, correspondence) if compare(old, new) and changes else None


def _nearest_scope(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> ast.AST | None:
    """Return the lexical executable scope for an identifier node.

    The first iterable of a comprehension is evaluated by the containing scope;
    all targets, filters, subsequent iterables and the result use the implicit
    comprehension scope.
    """

    child = node
    parent = parents.get(child)
    while parent is not None:
        if isinstance(parent, _COMPREHENSIONS):
            first_iter = parent.generators[0].iter
            cursor = child
            inside_first_iter = cursor is first_iter
            while not inside_first_iter and cursor is not parent:
                cursor = parents.get(cursor)
                inside_first_iter = cursor is first_iter
                if cursor is None:
                    break
            if not inside_first_iter:
                return parent
        if isinstance(parent, _FUNCTIONS):
            return parent
        if isinstance(parent, (ast.Module, ast.ClassDef)):
            return parent
        child, parent = parent, parents.get(parent)
    return None


def _scope_nodes(scope: ast.AST, parents: dict[ast.AST, ast.AST]):
    """Yield nodes evaluated in ``scope`` (nested code bodies excluded)."""

    for node in ast.walk(scope):
        if node is scope:
            yield node
            continue
        nearest = _nearest_scope(node, parents)
        if nearest is scope:
            yield node


def _has_dynamic_observation(scope: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    # Nested code can inspect an active parent's frame, so scan the complete
    # subtree rather than only nodes executed directly in this code object.
    for node in ast.walk(scope):
        if isinstance(node, ast.Import) and any(
            alias.name.split(".", 1)[0] in {"_testcapi", "cffi", "ctypes"}
            for alias in node.names
        ):
            return True
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".", 1)[0] in {
            "_testcapi",
            "cffi",
            "ctypes",
        }:
            return True
        if isinstance(node, ast.Name) and node.id in _DYNAMIC_NAMES:
            return True
        if isinstance(node, ast.Attribute) and node.attr in _DYNAMIC_ATTRIBUTES:
            return True
        if isinstance(node, ast.alias) and (
            node.name.rsplit(".", 1)[-1] in _DYNAMIC_IMPORTS
            or (node.asname is not None and node.asname in _DYNAMIC_IMPORTS)
        ):
            return True
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and any(
            marker in node.value
            for marker in ("f_locals", "co_varnames", "__code__", "getsource")
        ):
            return True
    return False


def _parameter_names(scope: ast.AST) -> set[str]:
    if not isinstance(scope, _FUNCTIONS):
        return set()
    arguments = scope.args
    result = {
        argument.arg
        for argument in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs)
    }
    if arguments.vararg:
        result.add(arguments.vararg.arg)
    if arguments.kwarg:
        result.add(arguments.kwarg.arg)
    return result


def _binding_kind(
    scope: ast.AST, name: str, parents: dict[ast.AST, ast.AST]
) -> str | None:
    """Classify a binding without treating a free/global load as local."""

    if name in _parameter_names(scope):
        return "parameter"
    if isinstance(scope, _COMPREHENSIONS):
        for generator in scope.generators:
            if any(
                isinstance(node, ast.Name)
                and isinstance(node.ctx, ast.Store)
                and node.id == name
                for node in ast.walk(generator.target)
            ):
                return "comprehension"
        return "free"
    if not isinstance(scope, _FUNCTIONS):
        return None
    global_names = {
        item
        for node in _scope_nodes(scope, parents)
        if isinstance(node, ast.Global)
        for item in node.names
    }
    nonlocal_names = {
        item
        for node in _scope_nodes(scope, parents)
        if isinstance(node, ast.Nonlocal)
        for item in node.names
    }
    if name in global_names:
        return "global"
    if name in nonlocal_names:
        return "nonlocal"
    for node in _scope_nodes(scope, parents):
        if isinstance(node, ast.Name) and node.id == name and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            return "local"
        if isinstance(node, ast.ExceptHandler) and node.name == name:
            return "except"
    return "free"


def _safe_definite_binding(
    scope: ast.AST,
    name: str,
    kind: str,
    parents: dict[ast.AST, ast.AST],
) -> bool:
    """Exclude renames that can alter an UnboundLocalError/NameError message."""

    if kind == "comprehension":
        # Generator-expression frames are externally exposed as ``gi_frame``.
        return not isinstance(scope, ast.GeneratorExp)
    if kind == "except":
        handlers = [
            node
            for node in _scope_nodes(scope, parents)
            if isinstance(node, ast.ExceptHandler) and node.name == name
        ]
        if len(handlers) != 1:
            return False
        handler = handlers[0]
        body_nodes = {descendant for statement in handler.body for descendant in ast.walk(statement)}
        return all(
            not isinstance(node, ast.Name)
            or node.id != name
            or (
                node in body_nodes
                and _nearest_scope(node, parents) is scope
            )
            for node in ast.walk(scope)
        )
    if kind != "local" or not isinstance(scope, _FUNCTIONS) or isinstance(scope, ast.Lambda):
        return False
    if isinstance(scope, ast.AsyncFunctionDef) or any(
        isinstance(node, (ast.Yield, ast.YieldFrom, ast.Await))
        for node in ast.walk(scope)
    ):
        # Suspended generator/coroutine frames have public frame accessors.
        return False
    if any(
        isinstance(node, ast.Name)
        and node.id == name
        and isinstance(node.ctx, ast.Del)
        for node in _scope_nodes(scope, parents)
    ):
        return False
    # Only an unconditional assignment in the initial straight-line prefix is
    # accepted.  It dominates every later use, including closure creation/calls.
    body = scope.body
    if not isinstance(body, list):
        return False
    for statement in body:
        if (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        ):
            continue
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            return False
        if isinstance(statement, ast.AnnAssign) and statement.value is None:
            return False
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        bound = any(
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Store)
            and node.id == name
            for target in targets
            for node in ast.walk(target)
        )
        if bound:
            value = statement.value
            return not any(
                isinstance(node, ast.Name) and node.id == name for node in ast.walk(value)
            )
    return False


def _code_equivalent(
    old: types.CodeType, new: types.CodeType, pairs: set[tuple[str, str]]
) -> bool:
    """Recursively compare executable and source-position state.

    Local/free/cell name tuple entries may differ only by a proven AST binding
    pair.  Global and attribute names (``co_names``) are never canonicalized.
    """

    raw = (
        "co_name",
        "co_qualname",
        "co_firstlineno",
        "co_argcount",
        "co_posonlyargcount",
        "co_kwonlyargcount",
        "co_nlocals",
        "co_stacksize",
        "co_flags",
        "co_code",
        "co_names",
        "co_exceptiontable",
        "co_linetable",
    )
    if any(getattr(old, item) != getattr(new, item) for item in raw):
        return False
    if tuple(old.co_positions()) != tuple(new.co_positions()):
        return False
    parameter_count = (
        old.co_argcount
        + old.co_kwonlyargcount
        + bool(old.co_flags & 0x04)
        + bool(old.co_flags & 0x08)
    )
    if old.co_varnames[:parameter_count] != new.co_varnames[:parameter_count]:
        return False

    def names(left: tuple[str, ...], right: tuple[str, ...], offset: int = 0) -> bool:
        return len(left) == len(right) and all(
            a == b or (a, b) in pairs
            for a, b in zip(left[offset:], right[offset:])
        )

    if not names(old.co_varnames, new.co_varnames, parameter_count):
        return False
    if not names(old.co_freevars, new.co_freevars):
        return False
    if not names(old.co_cellvars, new.co_cellvars):
        return False
    if len(old.co_consts) != len(new.co_consts):
        return False
    for left, right in zip(old.co_consts, new.co_consts):
        if isinstance(left, types.CodeType) or isinstance(right, types.CodeType):
            if not (
                isinstance(left, types.CodeType)
                and isinstance(right, types.CodeType)
                and _code_equivalent(left, right, pairs)
            ):
                return False
        elif type(left) is not type(right) or left != right:
            return False
    return True


def local_binding_rename(original: str, changed: str, filename: str) -> RenameProof | None:
    """Prove a consistent one-to-one rename of non-parameter local bindings."""

    # Pytest assertion rewriting and collection inspect test functions outside
    # the sqlglot source/reflection certificate.  Test-module edits therefore
    # stay on the selector's ordinary whole-file safety path.
    if filename.startswith("tests/"):
        return None
    concrete = _token_pairs(original, changed)
    if concrete is None:
        return None
    try:
        old_tree = ast.parse(original, filename=filename, type_comments=True)
        new_tree = ast.parse(changed, filename=filename, type_comments=True)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return None
    compared = _ast_rename_pairs(old_tree, new_tree)
    if compared is None:
        return None
    changes, _correspondence = compared
    ast_pairs = [(old, new) for _left, _right, old, new in changes]
    if concrete != ast_pairs:
        return None
    forward: dict[str, str] = {}
    reverse: dict[str, str] = {}
    for old, new in ast_pairs:
        if (
            old in forward and forward[old] != new
            or new in reverse and reverse[new] != old
        ):
            return None
        forward[old] = new
        reverse[new] = old
    if len(forward) != len(reverse):
        return None

    old_parents = _parents(old_tree)
    new_parents = _parents(new_tree)
    # Import-time tracing/profiling can observe subsequently-created frames even
    # when the renamed function does not invoke the observer itself.
    if _has_dynamic_observation(old_tree, old_parents):
        return None
    defining: set[tuple[ast.AST, str, str]] = set()
    impacted_scopes: set[ast.AST] = set()
    for old_node, new_node, old_name, new_name in changes:
        old_scope = _nearest_scope(old_node, old_parents)
        new_scope = _nearest_scope(new_node, new_parents)
        if old_scope is None or new_scope is None or type(old_scope) is not type(new_scope):
            return None
        old_kind = _binding_kind(old_scope, old_name, old_parents)
        new_kind = _binding_kind(new_scope, new_name, new_parents)
        if old_kind != new_kind or old_kind in {None, "parameter", "global", "nonlocal"}:
            return None
        impacted_scopes.add(old_scope)
        if old_kind in {"local", "except", "comprehension"}:
            defining.add((old_scope, old_name, old_kind))
        elif old_kind == "free":
            # A free reference is admitted only if its binding is independently
            # present among the renamed local definitions in an enclosing scope.
            cursor = old_parents.get(old_scope)
            resolved = False
            while cursor is not None:
                if isinstance(cursor, (_FUNCTIONS, _COMPREHENSIONS)):
                    kind = _binding_kind(cursor, old_name, old_parents)
                    if kind in {"local", "except", "comprehension"}:
                        defining.add((cursor, old_name, kind))
                        impacted_scopes.add(cursor)
                        resolved = True
                        break
                if isinstance(cursor, ast.Module):
                    break
                cursor = old_parents.get(cursor)
            if not resolved:
                return None
    if not defining:
        return None
    for scope in impacted_scopes:
        if _has_dynamic_observation(scope, old_parents):
            return None
    for scope, name, kind in defining:
        if not _safe_definite_binding(scope, name, kind, old_parents):
            return None

    try:
        old_code = compile(original, filename, "exec", dont_inherit=True)
        new_code = compile(changed, filename, "exec", dont_inherit=True)
    except (SyntaxError, ValueError, TypeError, OverflowError, MemoryError, RecursionError):
        return None
    pair_set = set(forward.items())
    if not _code_equivalent(old_code, new_code, pair_set):
        return None
    return RenameProof(tuple(sorted(pair_set)), len(ast_pairs))


def _bound_import_names(statement: ast.stmt) -> tuple[str, ...] | None:
    if isinstance(statement, ast.Import):
        return tuple(alias.asname or alias.name.split(".", 1)[0] for alias in statement.names)
    if isinstance(statement, ast.ImportFrom):
        if statement.level or statement.module in {None, "__future__"}:
            return None
        if any(alias.name == "*" for alias in statement.names):
            return None
        return tuple(alias.asname or alias.name for alias in statement.names)
    return None


def external_import_reorder(original: str, changed: str, filename: str) -> bool:
    """Recognize a structurally isolated external-import permutation.

    This closes syntax/binding/reflection channels but cannot by itself prove
    third-party module initialization commutes.  The selector therefore keeps
    this family disabled pending an import-state certificate.
    """

    if filename.startswith("tests/"):
        return False
    try:
        old = ast.parse(original, filename=filename, type_comments=True)
        new = ast.parse(changed, filename=filename, type_comments=True)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return False
    if len(old.body) != len(new.body):
        return False
    differing = [
        index
        for index, (left, right) in enumerate(zip(old.body, new.body))
        if ast.dump(left, include_attributes=False) != ast.dump(right, include_attributes=False)
    ]
    if len(differing) < 2 or differing != list(range(min(differing), max(differing) + 1)):
        return False
    left_run = old.body[differing[0] : differing[-1] + 1]
    right_run = new.body[differing[0] : differing[-1] + 1]
    left_dump = [ast.dump(node, include_attributes=False) for node in left_run]
    right_dump = [ast.dump(node, include_attributes=False) for node in right_run]
    if sorted(left_dump) != sorted(right_dump) or left_dump == right_dump:
        return False
    bindings = []
    for statement in left_run:
        names = _bound_import_names(statement)
        if names is None:
            return False
        modules = [alias.name for alias in statement.names] if isinstance(statement, ast.Import) else [statement.module]
        if any(module.split(".", 1)[0] in {"sqlglot", "tests"} for module in modules):
            return False
        bindings.extend(names)
    if len(bindings) != len(set(bindings)):
        return False
    observation_names = {"__import__", "import_module", "invalidate_caches", "reload"}
    observation_attrs = {"meta_path", "modules", "path_hooks", "path_importer_cache"}
    return not any(
        isinstance(node, ast.Name) and node.id in observation_names
        or isinstance(node, ast.Attribute) and node.attr in observation_attrs
        for node in ast.walk(old)
    )


def _constant_default(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) or (
        isinstance(node, (ast.Tuple, ast.List, ast.Set))
        and all(_constant_default(item) for item in node.elts)
    ) or (
        isinstance(node, ast.Dict)
        and all(key is not None and _constant_default(key) for key in node.keys)
        and all(_constant_default(value) for value in node.values)
    )


def _plain_definition(node: ast.stmt) -> bool:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return False
    if node.decorator_list or getattr(node, "type_params", ()):
        return False
    if isinstance(node, ast.ClassDef):
        return not node.bases and not node.keywords and all(
            isinstance(item, (ast.Pass, ast.FunctionDef, ast.AsyncFunctionDef))
            and (not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) or _plain_definition(item))
            for item in node.body
        )
    arguments = node.args
    annotations = [
        argument.annotation
        for argument in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs)
    ] + [arguments.vararg.annotation if arguments.vararg else None, arguments.kwarg.annotation if arguments.kwarg else None, node.returns]
    return not any(annotation is not None for annotation in annotations) and all(
        _constant_default(default)
        for default in (*arguments.defaults, *(item for item in arguments.kw_defaults if item is not None))
    )


def plain_definition_reorder(original: str, changed: str, filename: str) -> bool:
    """Recognize an isolated permutation of plain definitions in one body.

    Namespace insertion order and external source/code reflection remain
    observable even for this narrow form, so the selector keeps it disabled
    pending a complete namespace-order reader certificate.
    """

    if filename.startswith("tests/"):
        return False
    try:
        old = ast.parse(original, filename=filename, type_comments=True)
        new = ast.parse(changed, filename=filename, type_comments=True)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return False

    candidates = []

    def compare(left: ast.AST, right: ast.AST) -> bool:
        if type(left) is not type(right):
            return False
        for field in left._fields:
            lvalue, rvalue = getattr(left, field), getattr(right, field)
            if field == "body" and isinstance(lvalue, list) and isinstance(rvalue, list):
                if len(lvalue) != len(rvalue):
                    return False
                differing = [
                    i
                    for i, (a, b) in enumerate(zip(lvalue, rvalue))
                    if ast.dump(a, include_attributes=False) != ast.dump(b, include_attributes=False)
                ]
                if differing:
                    start, end = min(differing), max(differing) + 1
                    old_run, new_run = lvalue[start:end], rvalue[start:end]
                    old_dump = [ast.dump(item, include_attributes=False) for item in old_run]
                    new_dump = [ast.dump(item, include_attributes=False) for item in new_run]
                    is_permutation = (
                        differing == list(range(start, end))
                        and len(old_run) >= 2
                        and all(_plain_definition(item) for item in old_run)
                        and len({item.name for item in old_run}) == len(old_run)
                        and sorted(old_dump) == sorted(new_dump)
                    )
                    if is_permutation:
                        candidates.append((left, start, end))
                        if not all(
                            compare(a, b)
                            for a, b in zip(lvalue[:start], rvalue[:start])
                        ) or not all(
                            compare(a, b)
                            for a, b in zip(lvalue[end:], rvalue[end:])
                        ):
                            return False
                        continue
                if not all(compare(a, b) for a, b in zip(lvalue, rvalue)):
                    return False
            elif isinstance(lvalue, ast.AST):
                if not compare(lvalue, rvalue):
                    return False
            elif isinstance(lvalue, list):
                if len(lvalue) != len(rvalue) or any(
                    isinstance(a, ast.AST) and not compare(a, b) or not isinstance(a, ast.AST) and a != b
                    for a, b in zip(lvalue, rvalue)
                ):
                    return False
            elif lvalue != rvalue:
                return False
        return True

    if not compare(old, new) or len(candidates) != 1:
        return False
    hazards = {"vars", "dir", "getmembers", "getsource", "getsourcelines"}
    attrs = {"__dict__", "__definition_order__", "co_firstlineno"}
    return not any(
        isinstance(node, ast.Name) and node.id in hazards
        or isinstance(node, ast.Attribute) and node.attr in attrs
        for node in ast.walk(old)
    )
