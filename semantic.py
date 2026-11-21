"""Runtime semantic checks derived from pinned source, never sample answers."""

from __future__ import annotations

import ast
from collections import defaultdict


def _name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


class SemanticProof:
    def __init__(self, sources: dict[str, str]) -> None:
        self.trees = {path: ast.parse(source) for path, source in sources.items()}
        self.classes = defaultdict(list)
        self.qualified_classes = {}
        self.imports = defaultdict(dict)
        self.parents = {}
        self.class_assignments = defaultdict(list)
        self.self_assignments = defaultdict(list)
        for path, tree in self.trees.items():
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
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        if isinstance(target, ast.Name) and parent is owner and owner:
                            self.class_assignments[(owner.name, target.id)].append(node.value)
                        if (
                            isinstance(target, ast.Attribute)
                            and isinstance(target.value, ast.Name)
                            and target.value.id == "self"
                            and owner
                        ):
                            annotation = node.annotation if isinstance(node, ast.AnnAssign) else None
                            self.self_assignments[(owner.name, target.attr)].append(
                                (node.value, annotation)
                            )
                child_owner = node if isinstance(node, ast.ClassDef) else owner
                children = list(ast.iter_child_nodes(node))
                stack.extend(
                    (child, node, child_owner) for child in reversed(children)
                )
        self.safe_ranges = {}

    def _is_enum(self, name: str | None, seen=frozenset()) -> bool:
        if name == "Enum":
            return True
        if not name or name in seen or len(self.classes.get(name, ())) != 1:
            return False
        _, cls = self.classes[name][0]
        return any(self._is_enum(_name(base), seen | {name}) for base in cls.bases)

    def _identity_equality(self, name: str, path: str) -> bool:
        qualified = self.imports[path].get(name)
        entries = (
            [self.qualified_classes[qualified]]
            if qualified in self.qualified_classes
            else self.classes.get(name, ())
        )
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

    def _value_is_enum(self, value: ast.AST, enum_name: str, owner: str) -> bool:
        if isinstance(value, ast.Call):
            return _name(value.func) == enum_name
        if isinstance(value, ast.Attribute):
            if _name(value.value) == enum_name:
                return True
            if isinstance(value.value, ast.Name) and value.value.id == "self":
                definitions = self.class_assignments.get((owner, value.attr), ())
                return bool(definitions) and all(
                    self._value_is_enum(item, enum_name, owner) for item in definitions
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
        assignments = self.self_assignments.get((cls.name, node.attr), ()) if cls else ()
        return bool(assignments) and all(
            self._value_is_enum(value, enum_name, cls.name) for value, _ in assignments
        )

    def _identity_or_none(self, path: str, node: ast.AST) -> bool:
        if not (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "self"
        ):
            return False
        cls = self._enclosing_class(path, node)
        assignments = self.self_assignments.get((cls.name, node.attr), ()) if cls else ()
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
        tree = self.trees.get(path)
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
                proven = self._is_enum(enum_name) and self._enum_attribute(
                    path, left, enum_name
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
