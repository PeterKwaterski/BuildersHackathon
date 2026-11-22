"""Runtime semantic checks derived from pinned source, never sample answers."""

from __future__ import annotations

import ast
import re
from collections import defaultdict


CLASS_DEFINITION = re.compile(r"(?m)^[ \t]*class[ \t]+([A-Za-z_]\w*)\b")


def _name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


class SemanticProof:
    def __init__(self, sources: dict[str, str]) -> None:
        self.sources = sources
        self.trees = {}
        self.module_paths = {
            path.removesuffix(".py").replace("/", ".").removesuffix(".__init__"): path
            for path in sources
        }
        self.class_paths = defaultdict(set)
        for path, source in sources.items():
            for match in CLASS_DEFINITION.finditer(source):
                self.class_paths[match.group(1)].add(path)
        self.classes = defaultdict(list)
        self.qualified_classes = {}
        self.imports = defaultdict(dict)
        self.parents = {}
        self.class_assignments = defaultdict(list)
        self.self_assignments = defaultdict(list)
        self.loaded_class_names = set()
        self.safe_ranges = {}
        self.class_enum_attributes = {}

    def _tree(self, path: str) -> ast.Module | None:
        if path in self.trees:
            return self.trees[path]
        source = self.sources.get(path)
        if source is None:
            return None
        try:
            tree = ast.parse(source, filename=path)
        except (SyntaxError, ValueError):
            return None
        self.trees[path] = tree
        module = path.removesuffix(".py").replace("/", ".").removesuffix(".__init__")
        stack = [(tree, None, None)]
        while stack:
            node, parent, owner = stack.pop()
            if parent is not None:
                self.parents[(path, node)] = parent
            if isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    self.imports[path][alias.asname or alias.name] = (
                        f"{node.module}.{alias.name}"
                    )
            if isinstance(node, ast.ClassDef):
                self.classes[node.name].append((path, node))
                self.qualified_classes[f"{module}.{node.name}"] = (path, node)
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and owner is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name) and parent is owner:
                        self.class_assignments[(path, owner, target.id)].append(node.value)
                    if (
                        isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == "self"
                    ):
                        annotation = node.annotation if isinstance(node, ast.AnnAssign) else None
                        self.self_assignments[(path, owner, target.attr)].append(
                            (node.value, annotation)
                        )
            child_owner = node if isinstance(node, ast.ClassDef) else owner
            children = list(ast.iter_child_nodes(node))
            stack.extend((child, node, child_owner) for child in reversed(children))
        return tree

    def _class_entries(self, name: str) -> list[tuple[str, ast.ClassDef]]:
        if name not in self.loaded_class_names:
            for path in self.class_paths.get(name, ()):
                self._tree(path)
            self.loaded_class_names.add(name)
        return self.classes.get(name, [])

    def _qualified_class(self, name: str) -> tuple[str, ast.ClassDef] | None:
        entry = self.qualified_classes.get(name)
        if entry is not None:
            return entry
        module, separator, _ = name.rpartition(".")
        if not separator:
            return None
        path = self.module_paths.get(module)
        if path is not None:
            self._tree(path)
        return self.qualified_classes.get(name)

    def _is_enum(self, name: str | None, seen=frozenset()) -> bool:
        if name == "Enum":
            return True
        if not name or name in seen:
            return False
        entries = self._class_entries(name)
        if len(entries) != 1:
            return False
        _, cls = entries[0]
        return any(self._is_enum(_name(base), seen | {name}) for base in cls.bases)

    def _identity_equality(self, name: str, path: str) -> bool:
        self._tree(path)
        qualified = self.imports[path].get(name)
        qualified_entry = self._qualified_class(qualified) if qualified else None
        entries = [qualified_entry] if qualified_entry else self._class_entries(name)
        if len(entries) != 1:
            return False
        _, cls = entries[0]
        if cls.decorator_list or any(
            isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == "__eq__"
            for item in cls.body
        ):
            return False
        return not cls.bases or all(_name(base) == "object" for base in cls.bases)

    def _enclosing_class(self, path: str, node: ast.AST) -> ast.ClassDef | None:
        while (parent := self.parents.get((path, node))) is not None:
            if isinstance(parent, ast.ClassDef):
                return parent
            node = parent
        return None

    def _value_is_enum(
        self,
        path: str,
        value: ast.AST,
        enum_name: str,
        owner: ast.ClassDef,
    ) -> bool:
        if isinstance(value, ast.Call):
            return _name(value.func) == enum_name
        if isinstance(value, ast.Attribute):
            if _name(value.value) == enum_name:
                return True
            if isinstance(value.value, ast.Name) and value.value.id == "self":
                definitions = self.class_assignments.get((path, owner, value.attr), ())
                return bool(definitions) and all(
                    self._value_is_enum(path, item, enum_name, owner)
                    for item in definitions
                )
        return False

    def _enum_attribute(self, path: str, node: ast.AST, enum_name: str) -> bool:
        if not (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "self"
        ):
            return False
        cls = self._enclosing_class(path, node)
        assignments = self.self_assignments.get((path, cls, node.attr), ()) if cls else ()
        return bool(assignments) and all(
            self._value_is_enum(path, value, enum_name, cls) for value, _ in assignments
        )

    def _local_enum_alias(self, path: str, node: ast.AST, enum_name: str) -> bool:
        """Prove one top-level Enum-attribute store dominates this local use."""
        if not isinstance(node, ast.Name):
            return False
        comparison = self.parents.get((path, node))
        if not isinstance(comparison, ast.Compare):
            return False

        cursor = comparison
        function = None
        while (parent := self.parents.get((path, cursor))) is not None:
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                function = parent
                break
            if isinstance(
                parent,
                (
                    ast.ClassDef,
                    ast.Lambda,
                    ast.ListComp,
                    ast.SetComp,
                    ast.DictComp,
                    ast.GeneratorExp,
                ),
            ):
                return False
            cursor = parent
        if function is None:
            return False

        arguments = (
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        )
        if (
            any(argument.arg == node.id for argument in arguments)
            or function.args.vararg is not None
            and function.args.vararg.arg == node.id
            or function.args.kwarg is not None
            and function.args.kwarg.arg == node.id
            or any(
                isinstance(candidate, (ast.Global, ast.Nonlocal))
                and node.id in candidate.names
                for candidate in ast.walk(function)
            )
        ):
            return False

        stores = [
            candidate
            for candidate in ast.walk(function)
            if isinstance(candidate, ast.Name)
            and candidate.id == node.id
            and isinstance(candidate.ctx, (ast.Store, ast.Del))
        ]
        if len(stores) != 1:
            return False
        target = stores[0]
        assignment = self.parents.get((path, target))
        if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
            return False
        targets = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
        if (
            self.parents.get((path, assignment)) is not function
            or len(targets) != 1
            or targets[0] is not target
            or assignment.value is None
            or not self._enum_attribute(path, assignment.value, enum_name)
        ):
            return False

        top = comparison
        while self.parents.get((path, top)) is not function:
            parent = self.parents.get((path, top))
            if parent is None or isinstance(
                parent,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                    ast.ClassDef,
                    ast.Lambda,
                    ast.ListComp,
                    ast.SetComp,
                    ast.DictComp,
                    ast.GeneratorExp,
                ),
            ):
                return False
            top = parent
        try:
            return function.body.index(assignment) < function.body.index(top)
        except ValueError:
            return False

    def _closed_class_enum_attribute(
        self, path: str, node: ast.AST, enum_name: str
    ) -> bool:
        """Prove every fixed-tree write to ``self.<name>`` is an Enum member.

        The proof is deliberately whole-tree: all direct class-body definitions
        of the attribute must be members of the same Enum, and every instance,
        reflective, deletion, descriptor, or dynamic-class write rejects it.
        """
        if not (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "self"
        ):
            return False
        key = (node.attr, enum_name)
        if key in self.class_enum_attributes:
            return self.class_enum_attributes[key]

        definitions = []
        safe = True
        for source_path in self.sources:
            tree = self._tree(source_path)
            if tree is None:
                safe = False
                break
            for candidate in ast.walk(tree):
                if isinstance(candidate, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    targets = (
                        candidate.targets
                        if isinstance(candidate, ast.Assign)
                        else [candidate.target]
                    )
                    for target in targets:
                        if any(
                            isinstance(part, ast.Attribute) and part.attr == node.attr
                            for part in ast.walk(target)
                        ):
                            safe = False
                        elif isinstance(target, ast.Name) and target.id == node.attr:
                            parent = self.parents.get((source_path, candidate))
                            if not isinstance(parent, ast.ClassDef) or isinstance(
                                candidate, ast.AugAssign
                            ):
                                continue
                            value = candidate.value
                            if not (
                                isinstance(value, ast.Attribute)
                                and isinstance(value.value, ast.Name)
                                and value.value.id == enum_name
                            ):
                                safe = False
                            definitions.append((source_path, parent.name, value))
                elif isinstance(candidate, (ast.Delete, ast.NamedExpr)):
                    targets = (
                        candidate.targets
                        if isinstance(candidate, ast.Delete)
                        else [candidate.target]
                    )
                    if any(
                        any(
                            isinstance(part, ast.Attribute) and part.attr == node.attr
                            for part in ast.walk(target)
                        )
                        for target in targets
                    ):
                        safe = False
                elif isinstance(candidate, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    if (
                        candidate.name == node.attr
                        and isinstance(
                            self.parents.get((source_path, candidate)), ast.ClassDef
                        )
                    ):
                        safe = False
                elif (
                    isinstance(candidate, ast.Call)
                    and isinstance(candidate.func, ast.Name)
                    and candidate.func.id in {"setattr", "delattr"}
                ):
                    if len(candidate.args) < 2 or not (
                        isinstance(candidate.args[1], ast.Constant)
                        and isinstance(candidate.args[1].value, str)
                        and candidate.args[1].value != node.attr
                    ):
                        safe = False
                elif isinstance(candidate, ast.Constant) and candidate.value == node.attr:
                    # Attribute names used by ordinary syntax are AST strings,
                    # not Constant nodes.  A literal spelling can feed a
                    # namespace, ``vars`` or reflection write.
                    safe = False
                elif (
                    isinstance(candidate, ast.Call)
                    and isinstance(candidate.func, ast.Attribute)
                    and candidate.func.attr in {"__setattr__", "__delattr__"}
                ):
                    safe = False
                elif (
                    isinstance(candidate, ast.Call)
                    and isinstance(candidate.func, ast.Name)
                    and candidate.func.id == "type"
                    and len(candidate.args) >= 3
                ):
                    namespace = candidate.args[2]
                    if not (
                        isinstance(namespace, ast.Dict)
                        and all(
                            isinstance(item, ast.Constant)
                            and isinstance(item.value, str)
                            and item.value != node.attr
                            for item in namespace.keys
                            if item is not None
                        )
                    ):
                        safe = False
                if not safe:
                    break
            if not safe:
                break

        owner = self._enclosing_class(path, node)
        result = bool(
            safe
            and owner is not None
            and definitions
            and any(
                source_path == path and class_name == owner.name
                for source_path, class_name, _value in definitions
            )
        )
        self.class_enum_attributes[key] = result
        return result

    def _identity_or_none(self, path: str, node: ast.AST) -> bool:
        if not (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "self"
        ):
            return False
        cls = self._enclosing_class(path, node)
        assignments = self.self_assignments.get((path, cls, node.attr), ()) if cls else ()
        annotations = [annotation for _, annotation in assignments if annotation is not None]
        names = {
            child.id
            for annotation in annotations
            for child in ast.walk(annotation)
            if isinstance(child, ast.Name) and child.id != "None"
        }
        return bool(names) and all(self._identity_equality(name, path) for name in names)

    def _safe_ranges(self, path: str) -> list[tuple[int, int]]:
        safe = []
        tree = self._tree(path)
        if tree is None:
            return safe
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Compare)
                and len(node.ops) == 1
                and isinstance(node.ops[0], (ast.Is, ast.IsNot))
            ):
                continue
            left, right = node.left, node.comparators[0]
            if isinstance(right, ast.Constant) and right.value is None:
                proven = self._identity_or_none(path, left)
            elif isinstance(right, ast.Attribute) and isinstance(right.value, ast.Name):
                enum_name = right.value.id
                proven = self._is_enum(enum_name) and (
                    self._enum_attribute(path, left, enum_name)
                    or self._local_enum_alias(path, left, enum_name)
                    or self._closed_class_enum_attribute(path, left, enum_name)
                )
            else:
                proven = False
            if proven:
                safe.append((node.lineno, node.end_lineno or node.lineno))
        return safe

    def covers(self, path: str, lines: set[int]) -> bool:
        if path not in self.safe_ranges:
            self.safe_ranges[path] = self._safe_ranges(path)
        return any(
            all(start <= line <= end for line in lines)
            for start, end in self.safe_ranges.get(path, ())
        )
