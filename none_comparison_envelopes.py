"""Pinned source-flow certificates for exact None-comparison operand domains.

These are deliberately narrow and trace-free.  Only the sites below have a
complete pinned-tree constructor/caller closure proving an exact builtin
operand under every history of the fixed test suite.
"""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path


FILES = {
    "sqlglot/optimizer/simplify.py": "0b480e0094cde22b1b001a5aa52a2630617140d797d2fb3a32c76eaa3bb83893",
    "sqlglot/optimizer/eliminate_joins.py": "36e68a9151b2f7487351dc424aaa96589b8ff37890127963f3088858921ddd92",
    "sqlglot/optimizer/pushdown_projections.py": "f2a5e8599e7eb3a7026148dd57acb3fb5cf4311b3768f07831bcf7c740ead4a9",
    "sqlglot/optimizer/journal.py": "93dcc3aa14fba92023f3b9fc44caab09bded50c9ef54a7b9d95281b6ab5afc25",
    "sqlglot/optimizer/optimizer.py": "5dcaa086355bc0fd73c3ea1504bd596b48edba1dc2d757a148dcad11547cec02",
    "sqlglot/executor/table.py": "07751cc81cf60a44c571c0a5ac8194690a6805211eaab10236590849b7c3b90f",
    "sqlglot/executor/python.py": "14c0be0a65ff87803a56e1ec031308cdd99a96f6c2732fdf28055fab5fa0a4cc",
    "sqlglot/expressions/core.py": "9dd10dc5c3015536c94fb99634cd412a66c103273cdd31bbc1a2482ccbf83604",
    "sqlglot/expressions/query.py": "df6bda48f09bf59c10167eb024a7d454d6a2b4d38b464da76d49c21ff296db1b",
    "tests/test_optimizer.py": "35c02d71cacfa5d8e24319ef245963da3c1151b891281bac1864a00fa183cbf7",
    "tests/test_executor.py": "270a844a7b0b84045efde017135e6208ca07d7d93eba395be17c20c6e918923d",
}

# The rejected simplify and eliminate-joins sites are intentionally absent:
# their public APIs admit arbitrary hostile operands.  The remaining sites are
# admitted only after ``verify_closed_tree_domains`` proves the complete fixed
# source/test caller and write inventory below.
SITES = {
    ("sqlglot/optimizer/pushdown_projections.py", 496): "exact-list-or-none",
    ("sqlglot/executor/table.py", 109): "exact-tuple-or-none",
}

DANGEROUS_EXPRESSION_HOOKS = {
    "__eq__",
    "__ne__",
    "__getattr__",
    "__getattribute__",
}
# Filled from the complete pinned ``sqlglot/**/*.py`` + ``tests/**/*.py``
# inventory.  This binds the negative subclass/dynamic-assignment proof below,
# not merely the four files that contain admitted sites.
OVERRIDE_INVENTORY_SHA256 = "0b4dfddb1f1518a0e03d062a08a2c0c98f9845cdf981abd06357a3faaf8276ad"

# Filled only after the complete sqlglot/**/*.py + tests/**/*.py symbol census
# below is independently reproduced.  It includes definitions, imports,
# aliases, calls, keywords, stores and every dynamic/reflection primitive.
CLOSED_TREE_SYMBOL_INVENTORY_SHA256 = "c46f9e4591697b5cfa0ee646022c2e6523c4a7c8dbfce87adb71c8ebeeec9a64"

DOMAIN_FUNCTIONS = {
    ("sqlglot/executor/table.py", "Table.__init__"),
    ("sqlglot/executor/table.py", "Table.add_columns"),
    ("sqlglot/executor/table.py", "RowReader.__init__"),
    ("sqlglot/executor/python.py", "PythonExecutor.static"),
    ("sqlglot/optimizer/pushdown_projections.py", "pushdown_projections"),
    ("sqlglot/optimizer/pushdown_projections.py", "prune_projections"),
    ("sqlglot/optimizer/optimizer.py", "optimize"),
    ("tests/test_optimizer.py", "pushdown_projections"),
}

REFLECTION_CALLS = {
    "eval", "exec", "getattr", "globals", "hasattr", "import_module",
    "locals", "setattr", "vars", "__import__",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _node_at(tree: ast.AST, line: int) -> ast.Compare | None:
    matches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Compare)
        and node.lineno == line
        and len(node.ops) == 1
        and len(node.comparators) == 1
    ]
    return matches[0] if len(matches) == 1 else None


def _base_names(node: ast.AST) -> set[str]:
    """Return a conservative set of source names used by a class base."""

    result = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            result.add(child.id)
        elif isinstance(child, ast.Attribute):
            result.add(child.attr)
    return result


def _qualname_inventory(tree: ast.Module) -> dict[str, ast.AST]:
    """Return top-level/class functions with stable source qualnames."""

    result: dict[str, ast.AST] = {}

    def visit(body: list[ast.stmt], prefix: tuple[str, ...]) -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                result[".".join((*prefix, node.name))] = node
            elif isinstance(node, ast.ClassDef):
                visit(node.body, (*prefix, node.name))

    visit(tree.body, ())
    return result


def _call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _closed_tree_rows(root: Path) -> tuple[list[list[object]], dict[str, ast.Module]]:
    """Census every construct able to affect the two admitted domains.

    This intentionally records more than direct calls.  Any new alias,
    import, string/reflection primitive, attribute write, subclass, keyword or
    symbol use changes the authenticated digest and fails the build.
    """

    symbols = {
        "RowReader", "Table", "columns", "journal",
        "prune_projections", "pushdown_projections",
    }
    paths = sorted(
        path
        for directory in (root / "sqlglot", root / "tests")
        for path in directory.rglob("*.py")
        if path.is_file()
    )
    rows: list[list[object]] = []
    trees: dict[str, ast.Module] = {}
    for path in paths:
        relative = path.relative_to(root).as_posix()
        raw = path.read_bytes()
        rows.append([relative, 0, "file", hashlib.sha256(raw).hexdigest(), None])
        tree = ast.parse(raw, filename=relative, type_comments=True)
        trees[relative] = tree
        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        for node in ast.walk(tree):
            row: list[object] | None = None
            if isinstance(node, ast.Name) and node.id in symbols:
                row = ["name", node.id, type(node.ctx).__name__]
            elif isinstance(node, ast.Attribute) and node.attr in symbols:
                row = ["attribute", node.attr, type(node.ctx).__name__]
            elif isinstance(node, ast.alias) and (
                node.name in symbols or node.asname in symbols
            ):
                row = ["alias", node.name, node.asname]
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name in symbols:
                row = [type(node).__name__, node.name]
            elif isinstance(node, ast.keyword) and node.arg in symbols:
                row = ["keyword", node.arg, ast.dump(node.value, include_attributes=False)]
            elif isinstance(node, ast.Constant) and isinstance(node.value, str) and (
                node.value in symbols
                or any(symbol in node.value for symbol in ("RowReader", "prune_projections"))
            ):
                row = ["string", node.value]
            elif isinstance(node, ast.Call) and _call_name(node) in REFLECTION_CALLS:
                row = ["reflection", _call_name(node), ast.dump(node, include_attributes=False)]
            if row is not None:
                parent = parents.get(node)
                rows.append([
                    relative,
                    getattr(node, "lineno", 0),
                    *row,
                    type(parent).__name__ if parent is not None else None,
                ])
    return sorted(rows, key=lambda row: json.dumps(row, sort_keys=True)), trees


def _calls(tree: ast.AST, name: str) -> list[ast.Call]:
    return [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _call_name(node) == name
    ]


def _attribute_stores(trees: dict[str, ast.Module], name: str) -> list[tuple[str, int, str]]:
    rows = []
    for path, tree in trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == name and isinstance(node.ctx, (ast.Store, ast.Del)):
                parent = next(
                    (
                        candidate for candidate in ast.walk(tree)
                        if node in tuple(ast.iter_child_nodes(candidate))
                    ),
                    None,
                )
                rows.append((path, node.lineno, type(parent).__name__ if parent else ""))
    return sorted(rows)


def _attribute_tail(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _literal_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _literal_string(node.left)
        right = _literal_string(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _target_names(node: ast.AST) -> set[str]:
    return {
        child.id
        for child in ast.walk(node)
        if isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Store, ast.Del))
    }


def _namespace_capability(node: ast.AST, aliases: set[str]) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Attribute) and child.attr == "__dict__":
            return True
        if isinstance(child, ast.Name) and child.id in aliases:
            return True
        if isinstance(child, ast.Call):
            name = _attribute_tail(child.func)
            if name in {"globals", "locals", "vars"}:
                return True
            if (
                name == "getattr"
                and len(child.args) >= 2
                and _literal_string(child.args[1]) == "__dict__"
            ):
                return True
    return False


def verify_rowreader_dynamic_closure(trees: dict[str, ast.Module]) -> str:
    """Exclude every Python-level way the fixed tree can replace the domain.

    Direct writes, rebinding, subclassing, ``setattr``/mock mutation and
    module-dictionary mutation are checked structurally rather than merely
    hidden behind the complete-tree digest.  Reflection that only reads an
    unrelated object cannot change ``Table.columns`` or ``RowReader``.
    """

    rowreader_uses = []
    imports = []
    relevant_name_stores = []
    relevant_bases = []
    mutation_rows = []
    indirect_class_aliases = []
    namespace_subscript_stores = []
    executor_scopes = {"sqlglot/executor/table.py"}
    for path, tree in trees.items():
        if any(
            isinstance(node, ast.ImportFrom)
            and node.module in {"sqlglot.executor", "sqlglot.executor.table"}
            and any(alias.name in {"RowReader", "Table"} for alias in node.names)
            for node in ast.walk(tree)
        ):
            executor_scopes.add(path)
    namespace_aliases: dict[str, set[str]] = {}
    for path in executor_scopes:
        tree = trees[path]
        aliases: set[str] = set()
        while True:
            before = len(aliases)
            for node in ast.walk(tree):
                if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) or node.value is None:
                    continue
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if not _namespace_capability(node.value, aliases):
                    continue
                for target in targets:
                    aliases.update(_target_names(target))
            if len(aliases) == before:
                break
        namespace_aliases[path] = aliases
    for path, tree in trees.items():
        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id == "RowReader":
                rowreader_uses.append(
                    (path, node.lineno, type(node.ctx).__name__, type(parents.get(node)).__name__)
                )
            if isinstance(node, ast.ImportFrom) and node.module == "sqlglot.executor.table":
                imports.append(
                    (path, node.lineno, tuple((alias.name, alias.asname) for alias in node.names))
                )
            if (
                isinstance(node, ast.Name)
                and node.id in {"RowReader", "Table"}
                and isinstance(node.ctx, (ast.Store, ast.Del))
            ):
                relevant_name_stores.append((path, node.lineno, node.id))
            if isinstance(node, ast.ClassDef) and any(
                isinstance(child, ast.Name) and child.id in {"RowReader", "Table"}
                for base in node.bases for child in ast.walk(base)
            ):
                relevant_bases.append((path, node.lineno, node.name))
            if isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)):
                mapping = ast.dump(node.value, include_attributes=False)
                if _namespace_capability(node.value, namespace_aliases.get(path, set())):
                    namespace_subscript_stores.append((path, node.lineno, mapping))
            if (
                path in executor_scopes
                and isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
            ):
                value = node.value
                if value is None:
                    continue
                value_parents = {
                    child: parent
                    for parent in ast.walk(value)
                    for child in ast.iter_child_nodes(parent)
                }
                for child in ast.walk(value):
                    if not isinstance(child, ast.Name) or child.id not in {"RowReader", "Table"}:
                        continue
                    parent = value_parents.get(child)
                    # Constructed instances are values, not aliases of the
                    # constructor.  Any bare class value in an assignment or
                    # container creates an indirect construction capability.
                    if isinstance(parent, ast.Call) and parent.func is child:
                        continue
                    indirect_class_aliases.append((path, node.lineno, child.id))
            if not isinstance(node, ast.Call):
                continue
            name = _attribute_tail(node.func)
            if name in {"setattr", "__setattr__", "delattr", "__delattr__"}:
                if (
                    name == "setattr"
                    and path == "sqlglot/expressions/core.py"
                    and node.lineno == 112
                    and len(node.args) >= 2
                    and isinstance(node.args[1], ast.Constant)
                    and node.args[1].value == "__doc__"
                ):
                    mutation_rows.append((path, node.lineno, "safe-class-doc"))
                else:
                    raise ValueError("unclosed dynamic attribute mutation")
            if name in {"patch", "object", "dict"}:
                rendered = ast.dump(node, include_attributes=False)
                # mock.patch, patch.object and patch.dict may mutate only their
                # exact literal targets.  A computed target is rejected.
                if name == "patch":
                    if not node.args or not isinstance(node.args[0], ast.Constant):
                        raise ValueError("unclosed dynamic mock target")
                    targets = [node.args[0].value]
                elif name == "object" and isinstance(node.func, ast.Attribute) and node.func.attr == "object":
                    if len(node.args) < 2 or not isinstance(node.args[1], ast.Constant):
                        raise ValueError("unclosed dynamic mock attribute")
                    targets = [node.args[1].value]
                elif name == "dict" and isinstance(node.func, ast.Attribute) and node.func.attr == "dict":
                    targets = [
                        child.value for child in ast.walk(node)
                        if isinstance(child, ast.Constant) and isinstance(child.value, str)
                    ]
                else:
                    continue
                if any(
                    isinstance(target, str)
                    and (
                        any(word in target for word in ("RowReader", "executor.table", "__dict__"))
                        or target == "columns"
                        or target.endswith(".columns")
                    )
                    for target in targets
                ):
                    raise ValueError("RowReader domain mock mutation")
                mutation_rows.append((path, node.lineno, hashlib.sha256(rendered.encode()).hexdigest()))
            if name in {"update", "setitem", "__setitem__"}:
                target = node.func.value if isinstance(node.func, ast.Attribute) else None
                if name == "setitem" and node.args:
                    target = node.args[0]
                if target is not None and _namespace_capability(
                    target, namespace_aliases.get(path, set())
                ):
                    raise ValueError("RowReader namespace mutation")

    if sorted(rowreader_uses) != [
        ("sqlglot/executor/python.py", 268, "Load", "Call"),
        ("sqlglot/executor/table.py", 19, "Load", "Call"),
        ("sqlglot/executor/table.py", 31, "Load", "Call"),
        ("sqlglot/executor/table.py", 53, "Load", "FunctionDef"),
        ("sqlglot/executor/table.py", 86, "Load", "FunctionDef"),
    ]:
        raise ValueError("RowReader use/alias inventory mismatch")
    if sorted(imports) != [
        ("sqlglot/executor/__init__.py", 16, (("Table", None), ("ensure_tables", None))),
        ("sqlglot/executor/context.py", 8, (("Table", None), ("TableIter", None))),
        ("sqlglot/executor/python.py", 10, (("RowReader", None), ("Table", None))),
        ("tests/test_executor.py", 19, (("Table", None), ("ensure_tables", None))),
    ]:
        raise ValueError("executor Table/RowReader import inventory mismatch")
    if relevant_name_stores or relevant_bases or indirect_class_aliases:
        raise ValueError("RowReader/Table rebinding or subclass path")
    if [(path, line) for path, line, _mapping in namespace_subscript_stores] != [
        ("sqlglot/dialects/__init__.py", 126),
        ("sqlglot/optimizer/__init__.py", 64),
    ]:
        raise ValueError("RowReader namespace subscript mutation")
    payload = {
        "imports": imports,
        "mutations": sorted(mutation_rows),
        "namespace_subscript_stores": namespace_subscript_stores,
        "uses": rowreader_uses,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def verify_pushdown_entry_closure(trees: dict[str, ast.Module]) -> str:
    """Close direct, RULES, wrapper and ``**kwargs`` journal entry paths."""

    direct_pushdown = []
    direct_optimize = []
    journal_args = []
    journal_constants = []
    forwarding = []
    optimize_references = []
    generic_optimizer_calls = []
    check_file_calls = []
    partial_optimize_calls = []
    rules_mutations = []
    computed_journal_keys = []
    for path, tree in trees.items():
        string_aliases: dict[str, set[str]] = {}
        namespace_names: set[str] = set()
        while True:
            before = (
                tuple(sorted((name, tuple(sorted(values))) for name, values in string_aliases.items())),
                tuple(sorted(namespace_names)),
            )
            for candidate in ast.walk(tree):
                if not isinstance(candidate, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) or candidate.value is None:
                    continue
                targets = candidate.targets if isinstance(candidate, ast.Assign) else [candidate.target]
                names = set().union(*(_target_names(target) for target in targets))
                labels: set[str] = set()
                for child in ast.walk(candidate.value):
                    literal = _literal_string(child)
                    if literal in {"journal", "RULES"}:
                        labels.add(literal)
                    if isinstance(child, ast.Name):
                        labels.update(string_aliases.get(child.id, set()))
                for name in names:
                    string_aliases.setdefault(name, set()).update(labels)
                if _namespace_capability(candidate.value, namespace_names):
                    namespace_names.update(names)
            after = (
                tuple(sorted((name, tuple(sorted(values))) for name, values in string_aliases.items())),
                tuple(sorted(namespace_names)),
            )
            if after == before:
                break

        def string_labels(node: ast.AST) -> set[str]:
            labels: set[str] = set()
            literal = _literal_string(node)
            if literal in {"journal", "RULES"}:
                labels.add(literal)
            for child in ast.walk(node):
                if isinstance(child, ast.Name):
                    labels.update(string_aliases.get(child.id, set()))
            return labels

        rules_aliases: set[str] = set()
        for candidate in ast.walk(tree):
            if not isinstance(candidate, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) or candidate.value is None:
                continue
            if any(
                (isinstance(child, ast.Name) and child.id == "RULES")
                or (isinstance(child, ast.Attribute) and child.attr == "RULES")
                for child in ast.walk(candidate.value)
            ):
                targets = candidate.targets if isinstance(candidate, ast.Assign) else [candidate.target]
                rules_aliases.update(target.id for target in targets if isinstance(target, ast.Name))
        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.arg) and node.arg == "journal":
                journal_args.append((path, node.lineno))
            if isinstance(node, ast.Constant) and node.value == "journal":
                journal_constants.append((path, node.lineno))
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) and node.value is not None:
                if _literal_string(node.value) == "journal":
                    computed_journal_keys.append((path, node.lineno, ast.dump(node.value, include_attributes=False)))
            if isinstance(node, ast.Dict):
                for key in node.keys:
                    if key is None:
                        continue
                    labels = string_labels(key)
                    if "journal" in labels:
                        computed_journal_keys.append((path, node.lineno, ast.dump(key, include_attributes=False)))
            if isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)):
                labels = string_labels(node.slice)
                if "journal" in labels:
                    raise ValueError("computed journal mapping mutation")
                if "RULES" in labels and _namespace_capability(node.value, namespace_names):
                    raise ValueError("optimizer RULES namespace mutation")
            if isinstance(node, ast.Name) and node.id == "RULES" and isinstance(node.ctx, (ast.Store, ast.Del)):
                if path == "sqlglot/optimizer/optimizer.py":
                    rules_mutations.append((path, node.lineno, type(parents.get(node)).__name__))
                else:
                    raise ValueError("external optimizer RULES rebinding")
            if (
                isinstance(node, (ast.Attribute, ast.Subscript))
                and isinstance(node.ctx, (ast.Store, ast.Del))
                and any(
                    (isinstance(child, ast.Name) and (child.id == "RULES" or child.id in rules_aliases))
                    or (isinstance(child, ast.Attribute) and child.attr == "RULES")
                    for child in ast.walk(node)
                )
            ):
                raise ValueError("optimizer RULES container mutation")
            if (
                (isinstance(node, ast.Name) and node.id == "optimize")
                or (isinstance(node, ast.Attribute) and node.attr == "optimize")
            ):
                parent = parents.get(node)
                optimize_references.append(
                    (path, node.lineno, type(node).__name__, type(node.ctx).__name__, type(parent).__name__)
                )
            if isinstance(node, ast.alias) and node.name == "optimize":
                optimize_references.append(
                    (path, getattr(node, "lineno", 0), "alias", node.asname, type(parents.get(node)).__name__)
                )
            if isinstance(node, ast.Constant) and node.value == "optimize":
                optimize_references.append(
                    (path, node.lineno, "string", "optimize", type(parents.get(node)).__name__)
                )
            if not isinstance(node, ast.Call):
                continue
            name = _attribute_tail(node.func)
            unpacked = [keyword for keyword in node.keywords if keyword.arg is None]
            if name in {"append", "extend", "insert", "pop", "remove", "clear", "update", "__setitem__"}:
                target = node.func.value if isinstance(node.func, ast.Attribute) else None
                if target is not None and any(
                    (isinstance(child, ast.Name) and (child.id == "RULES" or child.id in rules_aliases))
                    or (isinstance(child, ast.Attribute) and child.attr == "RULES")
                    for child in ast.walk(target)
                ):
                    raise ValueError("optimizer RULES alias mutation")
            if name in {"update", "setitem", "__setitem__"}:
                target = node.func.value if isinstance(node.func, ast.Attribute) else None
                key_nodes: list[ast.AST] = list(node.args)
                if name == "setitem" and node.args:
                    target = node.args[0]
                    key_nodes = list(node.args[1:2])
                labels = set().union(*(string_labels(key) for key in key_nodes)) if key_nodes else set()
                if target is not None and _namespace_capability(target, namespace_names) and "RULES" in labels:
                    raise ValueError("optimizer RULES namespace mutation")
                if "journal" in labels:
                    raise ValueError("computed journal update")
            if name in {"patch", "object"}:
                rendered = ast.dump(node, include_attributes=False)
                if "RULES" in rendered:
                    raise ValueError("optimizer RULES mock mutation")
            if name == "check_file" and path == "tests/test_optimizer.py":
                if unpacked or any(keyword.arg == "journal" for keyword in node.keywords):
                    raise ValueError("check_file may inject journal")
                check_file_calls.append(
                    (node.lineno, tuple(keyword.arg for keyword in node.keywords))
                )
            if name == "partial" and any(
                (isinstance(child, ast.Name) and child.id == "optimize")
                or (isinstance(child, ast.Attribute) and child.attr == "optimize")
                for child in ast.walk(node)
            ):
                if unpacked or any(keyword.arg == "journal" for keyword in node.keywords):
                    raise ValueError("partial optimizer may inject journal")
                partial_optimize_calls.append(
                    (path, node.lineno, ast.dump(node, include_attributes=False))
                )
            if name == "pushdown_projections":
                if unpacked:
                    raise ValueError("unclosed pushdown **kwargs call")
                journal = [keyword for keyword in node.keywords if keyword.arg == "journal"]
                if journal and (
                    len(journal) != 1
                    or not isinstance(journal[0].value, ast.Name)
                    or journal[0].value.id != "journal"
                    or path != "tests/test_optimizer.py"
                ):
                    raise ValueError("non-exact direct journal operand")
                direct_pushdown.append((path, node.lineno, bool(journal)))
            if name == "optimize":
                if unpacked or any(keyword.arg == "journal" for keyword in node.keywords):
                    raise ValueError("optimizer may forward arbitrary journal")
                direct_optimize.append((path, node.lineno))
            if (
                path == "tests/test_optimizer.py"
                and isinstance(node.func, ast.Name)
                and node.func.id in {"func", "transform"}
            ):
                if unpacked and node.lineno != 38:
                    raise ValueError("unclosed optimizer callable-container forwarding")
                if any(keyword.arg == "journal" for keyword in node.keywords):
                    raise ValueError("generic optimizer call receives journal")
                generic_optimizer_calls.append(
                    (node.lineno, node.func.id, tuple(keyword.arg for keyword in node.keywords))
                )
            if unpacked and path in {
                "sqlglot/optimizer/optimizer.py", "tests/test_optimizer.py"
            }:
                forwarding.append(
                    (path, node.lineno, name, tuple(ast.dump(keyword.value, include_attributes=False) for keyword in unpacked))
                )

    if sorted(direct_pushdown) != [
        ("tests/test_optimizer.py", 70, False),
        ("tests/test_optimizer.py", 2886, True),
        ("tests/test_optimizer.py", 2911, True),
        ("tests/test_optimizer.py", 4980, False),
    ]:
        raise ValueError("pushdown direct-call inventory mismatch")
    if sorted(journal_args) != [
        ("sqlglot/optimizer/eliminate_ctes.py", 13),
        ("sqlglot/optimizer/journal.py", 12),
        ("sqlglot/optimizer/journal.py", 22),
        ("sqlglot/optimizer/pushdown_projections.py", 17),
        ("sqlglot/optimizer/pushdown_projections.py", 419),
    ] or journal_constants or computed_journal_keys:
        raise ValueError("journal construction inventory mismatch")
    if rules_mutations != [("sqlglot/optimizer/optimizer.py", 40, "AnnAssign")]:
        raise ValueError("optimizer RULES rebinding/mutation inventory mismatch")
    if sorted(forwarding) != [
        ("sqlglot/optimizer/optimizer.py", 115, "rule", ("Name(id='rule_kwargs', ctx=Load())",)),
        ("tests/test_optimizer.py", 38, "func", ("Name(id='kwargs', ctx=Load())",)),
        ("tests/test_optimizer.py", 51, "qualify", ("Name(id='qualify_kwargs', ctx=Load())",)),
        ("tests/test_optimizer.py", 55, "qualify", ("Name(id='kwargs', ctx=Load())",)),
        ("tests/test_optimizer.py", 69, "qualify_columns", ("Name(id='kwargs', ctx=Load())",)),
        ("tests/test_optimizer.py", 259, "submit", ("Name(id='func_kwargs', ctx=Load())",)),
    ]:
        raise ValueError("optimizer wrapper forwarding inventory mismatch")
    if sorted(generic_optimizer_calls) != [
        (38, "func", (None,)),
        (552, "transform", ("schema", "dialect")),
        (587, "transform", ("schema", "dialect")),
        (2062, "transform", ("dialect",)),
        (5088, "func", ("dialect", "schema")),
        (5116, "func", ()),
    ]:
        raise ValueError("generic optimizer call inventory mismatch")
    if [line for line, _keywords in sorted(check_file_calls)] != [
        300, 338, 408, 454, 998, 1004, 2069, 2072, 2143, 2151, 2157,
        2160, 2342, 2585, 2732, 2806, 2830, 2929, 3053, 3062, 3338,
        3361, 3364,
    ]:
        raise ValueError("check_file origin inventory mismatch")
    if sorted((path, line) for path, line, _dump in partial_optimize_calls) != [
        ("tests/test_optimizer.py", 2920),
        ("tests/test_optimizer.py", 3329),
    ]:
        raise ValueError("partial optimizer origin inventory mismatch")

    # All direct optimize calls have explicit keywords.  Remaining references
    # are exact fixed aliases passed to check_file/loops/partial; none of those
    # call sites has a journal keyword or an unbounded mapping.  Bind that
    # complete reference classification so a new alias fails the theorem.
    reference_digest = hashlib.sha256(
        json.dumps(sorted(optimize_references), separators=(",", ":")).encode()
    ).hexdigest()
    if reference_digest != "c44a292becaf4188869888d77e795f32eb3689e71a9c64a35a649029aff39e23":
        raise ValueError("optimizer alias/re-export inventory mismatch")
    payload = {
        "direct_optimize": sorted(direct_optimize),
        "direct_pushdown": sorted(direct_pushdown),
        "forwarding": sorted(forwarding),
        "generic_optimizer_calls": sorted(generic_optimizer_calls),
        "partial_optimize_calls": partial_optimize_calls,
        "references": reference_digest,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def verify_closed_tree_domains(root: Path) -> str:
    """Mechanically close the two exact-builtin operand domains."""

    rows, trees = _closed_tree_rows(root)
    digest = hashlib.sha256(
        json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if (
        not CLOSED_TREE_SYMBOL_INVENTORY_SHA256
        or digest != CLOSED_TREE_SYMBOL_INVENTORY_SHA256
    ):
        raise ValueError("closed-tree symbol inventory mismatch")

    # Every RowReader construction in the complete tree is explicit and one of
    # these three calls.  The first two receive Table.columns; its complete
    # write inventory is the exact tuple canonicalization plus tuple += tuple.
    row_calls = []
    for path, tree in trees.items():
        for call in _calls(tree, "RowReader"):
            row_calls.append((path, call.lineno, ast.dump(call, include_attributes=False)))
    if [(path, line) for path, line, _dump in sorted(row_calls)] != [
        ("sqlglot/executor/python.py", 268),
        ("sqlglot/executor/table.py", 19),
        ("sqlglot/executor/table.py", 31),
    ]:
        raise ValueError("RowReader constructor inventory mismatch")
    expected_row_args = {
        ("sqlglot/executor/python.py", 268): "Tuple(ctx=Load())",
        ("sqlglot/executor/table.py", 19): "Attribute(value=Name(id='self', ctx=Load()), attr='columns', ctx=Load())",
        ("sqlglot/executor/table.py", 31): "Attribute(value=Name(id='self', ctx=Load()), attr='columns', ctx=Load())",
    }
    for path, line, _dump in row_calls:
        calls = [call for call in _calls(trees[path], "RowReader") if call.lineno == line]
        if len(calls) != 1 or not calls[0].args or ast.dump(calls[0].args[0], include_attributes=False) != expected_row_args[(path, line)]:
            raise ValueError("RowReader operand construction mismatch")
    if _attribute_stores(trees, "columns") != [
        ("sqlglot/executor/table.py", 17, "AnnAssign"),
        ("sqlglot/executor/table.py", 26, "AugAssign"),
        ("sqlglot/executor/table.py", 107, "Assign"),
    ]:
        raise ValueError("columns write inventory mismatch")

    rowreader_dynamic_sha256 = verify_rowreader_dynamic_closure(trees)
    pushdown_entry_sha256 = verify_pushdown_entry_closure(trees)

    table_functions = _qualname_inventory(trees["sqlglot/executor/table.py"])
    python_functions = _qualname_inventory(trees["sqlglot/executor/python.py"])
    if set(table_functions) & {"Table.__init__", "Table.add_columns", "RowReader.__init__"} != {
        "Table.__init__", "Table.add_columns", "RowReader.__init__"
    } or "PythonExecutor.static" not in python_functions:
        raise ValueError("RowReader owner inventory mismatch")
    init = table_functions["Table.__init__"]
    add = table_functions["Table.add_columns"]
    if not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "tuple"
        for node in ast.walk(init)
    ) or not any(
        isinstance(node, ast.AugAssign)
        and isinstance(node.target, ast.Attribute)
        and node.target.attr == "columns"
        and isinstance(node.op, ast.Add)
        and isinstance(node.value, ast.Name)
        and node.value.id == "columns"
        for node in ast.walk(add)
    ):
        raise ValueError("Table tuple canonicalization mismatch")

    # prune_projections has exactly one production caller, forwarding the
    # pushdown function's same journal parameter.  Every complete-tree keyword
    # caller supplies the single local test variable initialized by exact [].
    prune_calls = [
        (path, call) for path, tree in trees.items()
        for call in _calls(tree, "prune_projections")
    ]
    if [(path, call.lineno) for path, call in prune_calls] != [
        ("sqlglot/optimizer/pushdown_projections.py", 39)
    ]:
        raise ValueError("prune_projections caller inventory mismatch")
    prune_keywords = {keyword.arg: keyword.value for keyword in prune_calls[0][1].keywords}
    if (
        "journal" not in prune_keywords
        or not isinstance(prune_keywords["journal"], ast.Name)
        or prune_keywords["journal"].id != "journal"
    ):
        raise ValueError("journal forwarding mismatch")
    journal_keywords = []
    for path, tree in trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "journal":
                journal_keywords.append((path, node.lineno, ast.dump(node.value, include_attributes=False)))
    if journal_keywords != [
        ("sqlglot/optimizer/pushdown_projections.py", 39, "Name(id='journal', ctx=Load())"),
        ("tests/test_optimizer.py", 2856, "Name(id='journal', ctx=Load())"),
        ("tests/test_optimizer.py", 2865, "Name(id='journal', ctx=Load())"),
        ("tests/test_optimizer.py", 2874, "Name(id='journal', ctx=Load())"),
        ("tests/test_optimizer.py", 2886, "Name(id='journal', ctx=Load())"),
        ("tests/test_optimizer.py", 2911, "Name(id='journal', ctx=Load())"),
    ]:
        raise ValueError("journal keyword inventory mismatch")
    test_tree = trees["tests/test_optimizer.py"]
    journal_bindings = [
        node for node in ast.walk(test_tree)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "journal" for target in node.targets)
    ]
    if (
        len(journal_bindings) != 1
        or not isinstance(journal_bindings[0].value, ast.List)
        or journal_bindings[0].value.elts
    ):
        raise ValueError("journal exact-list binding mismatch")

    payload = {
        "inventory": digest,
        "journal_keywords": journal_keywords,
        "row_calls": sorted(row_calls),
        "rowreader_dynamic_sha256": rowreader_dynamic_sha256,
        "pushdown_entry_sha256": pushdown_entry_sha256,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def verify_expression_override_closure(root: Path) -> str:
    """Prove the pinned tree cannot manufacture a hostile Expr comparator.

    The proof deliberately over-approximates inheritance by unqualified class
    names.  Every class declared in ``sqlglot/expressions`` is a seed; aliases
    and subclasses elsewhere are propagated to a fixed point.  Any comparison
    or attribute-access override in that closure is rejected except for the
    two authenticated base ``Expression`` methods.  Literal or direct dynamic
    writes of those hooks are rejected across the complete library/test tree.
    """

    paths = sorted(
        path
        for directory in (root / "sqlglot", root / "tests")
        for path in directory.rglob("*.py")
        if path.is_file()
    )
    if not paths:
        raise ValueError("empty Expression override inventory")

    inventory = []
    classes = []
    aliases: dict[str, set[str]] = {}
    for path in paths:
        relative = path.relative_to(root).as_posix()
        raw = path.read_bytes()
        inventory.append((relative, hashlib.sha256(raw).hexdigest()))
        tree = ast.parse(raw, filename=relative, type_comments=True)
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                methods = {
                    child.name
                    for child in node.body
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                }
                classes.append(
                    (relative, node.name, set().union(*(_base_names(base) for base in node.bases)) if node.bases else set(), methods)
                )
            elif isinstance(node, ast.ImportFrom) and node.module and (
                node.module == "sqlglot"
                or node.module.startswith("sqlglot.expressions")
            ):
                for imported in node.names:
                    aliases.setdefault(imported.asname or imported.name, set()).add(
                        imported.name
                    )
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Attribute) and target.attr in (
                        DANGEROUS_EXPRESSION_HOOKS | {"__bases__"}
                    ):
                        raise ValueError("dynamic Expression hook assignment")
            elif isinstance(node, (ast.AugAssign, ast.Delete)):
                targets = [node.target] if isinstance(node, ast.AugAssign) else node.targets
                if any(
                    isinstance(target, ast.Attribute)
                    and target.attr in (DANGEROUS_EXPRESSION_HOOKS | {"__bases__"})
                    for target in targets
                ):
                    raise ValueError("dynamic Expression hook assignment")
            elif (
                isinstance(node, ast.Constant)
                and node.value in DANGEROUS_EXPRESSION_HOOKS
            ):
                # Catches setattr/delattr, class-dict mutation and dynamic type
                # construction.  Method declarations do not contain their
                # name as a Constant in the AST.
                raise ValueError("dynamic Expression hook name")

    derived_names = {
        name for relative, name, _bases, _methods in classes
        if relative.startswith("sqlglot/expressions/")
    }
    while True:
        before = len(derived_names)
        for alias, sources in aliases.items():
            if sources & derived_names:
                derived_names.add(alias)
        for _relative, name, bases, _methods in classes:
            if bases & derived_names:
                derived_names.add(name)
        if len(derived_names) == before:
            break

    allowed = {
        ("sqlglot/expressions/core.py", "Expression", "__eq__"),
        ("sqlglot/expressions/core.py", "Expression", "__ne__"),
    }
    observed = {
        (relative, name, method)
        for relative, name, _bases, methods in classes
        if name in derived_names
        for method in methods & DANGEROUS_EXPRESSION_HOOKS
    }
    if observed != allowed:
        raise ValueError("Expression subclass comparison/access override")

    digest = hashlib.sha256(
        json.dumps(inventory, separators=(",", ":")).encode()
    ).hexdigest()
    if OVERRIDE_INVENTORY_SHA256 and digest != OVERRIDE_INVENTORY_SHA256:
        raise ValueError("Expression override inventory mismatch")
    return digest


def validate(root: Path) -> str:
    root = root.resolve()
    if any(_sha256(root / path) != digest for path, digest in FILES.items()):
        raise ValueError("None operand-flow source mismatch")
    for (path, line), _domain in SITES.items():
        tree = ast.parse((root / path).read_text(), filename=path, type_comments=True)
        node = _node_at(tree, line)
        if node is None or not isinstance(node.ops[0], (ast.Is, ast.IsNot)):
            raise ValueError("None operand-flow site mismatch")
        values = (node.left, *node.comparators)
        if not any(isinstance(value, ast.Constant) and value.value is None for value in values):
            raise ValueError("None operand-flow constant mismatch")
    closed_tree_sha256 = verify_closed_tree_domains(root)
    payload = {
        "files": FILES,
        "closed_tree_sha256": closed_tree_sha256,
        "sites": [[path, line, SITES[(path, line)]] for path, line in sorted(SITES)],
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def domain(path: str, line: int) -> str | None:
    return SITES.get((path, line))
