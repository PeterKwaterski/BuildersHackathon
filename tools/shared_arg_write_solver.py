#!/usr/bin/env python3
"""Conservative source-only interprocedural argument write/escape summaries.

The solver intentionally knows nothing about validation patches or answers.  It
indexes the pinned Python sources, binds calls to exact source functions where
possible, and computes a monotone fixed point over actual-argument -> formal-
slot edges.  Any ambiguous Python behavior is represented as an unsafe summary
instead of being guessed away.
"""

from __future__ import annotations

import argparse
import ast
import builtins
from collections import Counter, defaultdict
from dataclasses import dataclass, field
import gzip
import hashlib
import json
from pathlib import Path
from typing import Iterable, Mapping


PINNED_SOURCE_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"
PINNED_SOURCES_SHA256 = "f453c6266c20edcc9ba7127ebedde0bdf45d44633279352c2daafe1fa123da5f"

WRITE = 1
ESCAPE = 2
UNKNOWN = 4

MUTATING_METHODS = frozenset(
    {
        "add", "append", "clear", "difference_update", "discard", "extend",
        "insert", "intersection_update", "pop", "popitem", "remove",
        "reverse", "setdefault", "sort", "symmetric_difference_update",
        "update",
    }
)
REFLECTION_NAMES = frozenset(
    {
        "breakpoint", "compile", "delattr", "dir", "eval", "exec", "getattr",
        "globals", "hasattr", "help", "locals", "setattr", "vars",
    }
)
TRANSPARENT_DECORATORS = frozenset({"classmethod", "property", "staticmethod"})


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def module_name(path: str) -> str:
    return path.removesuffix(".py").replace("/", ".").removesuffix(".__init__")


def dotted(node: ast.AST) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def decorator_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        node = node.func
    value = dotted(node)
    return value.rsplit(".", 1)[-1] if value else None


def immediate_nodes(root: ast.AST) -> Iterable[ast.AST]:
    """Walk one function body without interpreting nested executable scopes."""
    pending = list(reversed(list(ast.iter_child_nodes(root))))
    while pending:
        node = pending.pop()
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        pending.extend(reversed(list(ast.iter_child_nodes(node))))


@dataclass(frozen=True, slots=True)
class Parameter:
    name: str
    kind: str
    default: bool


@dataclass(slots=True)
class FunctionInfo:
    key: str
    path: str
    module: str
    qualname: str
    parent_qualname: str | None
    class_qualname: str | None
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda
    parameters: tuple[Parameter, ...]
    decorators: frozenset[str]
    aliases: dict[str, set[int]] = field(default_factory=dict)
    fresh_names: set[str] = field(default_factory=set)
    fresh_classes: dict[str, tuple[str, str]] = field(default_factory=dict)
    ambiguous_fresh_classes: set[str] = field(default_factory=set)
    fresh_calls: set[tuple[int, int, str, str]] = field(default_factory=set)
    contained_fresh_calls: set[tuple[int, int, str, str]] = field(default_factory=set)
    direct: list[int] = field(default_factory=list)
    summary: list[int] = field(default_factory=list)
    return_alias: set[int] = field(default_factory=set)
    parameter_classes: dict[int, tuple[str, str]] = field(default_factory=dict)
    capture_from: dict[int, tuple[str, int]] = field(default_factory=dict)
    reasons: dict[int, set[str]] = field(default_factory=lambda: defaultdict(set))


@dataclass(frozen=True, slots=True)
class CallTarget:
    key: str
    receiver: ast.AST | None
    receiver_to_slot: bool
    skip_first: bool
    fresh_result: bool = False


@dataclass(frozen=True, slots=True)
class Edge:
    caller: str
    caller_slot: int
    callee: str
    callee_slot: int
    line: int
    column: int


def parameters(
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
) -> tuple[Parameter, ...]:
    result: list[Parameter] = []
    positional = [*node.args.posonlyargs, *node.args.args]
    first_default = len(positional) - len(node.args.defaults)
    for index, argument in enumerate(node.args.posonlyargs):
        result.append(Parameter(argument.arg, "positional-only", index >= first_default))
    offset = len(node.args.posonlyargs)
    for index, argument in enumerate(node.args.args, offset):
        result.append(Parameter(argument.arg, "positional-or-keyword", index >= first_default))
    if node.args.vararg is not None:
        result.append(Parameter(node.args.vararg.arg, "var-positional", False))
    for argument, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
        result.append(Parameter(argument.arg, "keyword-only", default is not None))
    if node.args.kwarg is not None:
        result.append(Parameter(node.args.kwarg.arg, "var-keyword", False))
    return tuple(result)


class SourceIndex:
    def __init__(self, sources: Mapping[str, str]) -> None:
        self.sources = sources
        self.trees: dict[str, ast.Module] = {}
        self.functions: dict[str, FunctionInfo] = {}
        self.function_by_qualname: dict[tuple[str, str], str] = {}
        self.module_functions: dict[tuple[str, str], list[str]] = defaultdict(list)
        self.child_functions: dict[tuple[str, str], list[str]] = defaultdict(list)
        self.class_methods: dict[tuple[str, str, str], list[str]] = defaultdict(list)
        self.classes: dict[tuple[str, str], ast.ClassDef] = {}
        self.classes_by_name: dict[tuple[str, str], list[str]] = defaultdict(list)
        self.global_classes_by_name: dict[str, list[tuple[str, str]]] = defaultdict(list)
        self.class_bases: dict[tuple[str, str], tuple[str, ...]] = {}
        self.direct_imports: dict[str, dict[str, str]] = defaultdict(dict)
        self.module_imports: dict[str, dict[str, str]] = defaultdict(dict)
        self.module_paths = {module_name(path): path for path in sources}
        self.returned_callables: dict[str, list[str]] = defaultdict(list)
        self._build()

    def _build(self) -> None:
        for path, source in sorted(self.sources.items()):
            if not path.startswith(("sqlglot/", "tests/")) or not path.endswith(".py"):
                continue
            tree = ast.parse(source, filename=path, type_comments=True)
            self.trees[path] = tree
            for statement in tree.body:
                if isinstance(statement, ast.ImportFrom) and statement.module:
                    for alias in statement.names:
                        if alias.name != "*":
                            self.direct_imports[path][alias.asname or alias.name] = (
                                f"{statement.module}.{alias.name}"
                            )
                elif isinstance(statement, ast.Import):
                    for alias in statement.names:
                        self.module_imports[path][alias.asname or alias.name.split(".", 1)[0]] = alias.name
            self._visit_body(path, tree.body, (), None, None)
        self._link_returned_callables()

    def _visit_body(
        self,
        path: str,
        body: list[ast.stmt],
        owners: tuple[str, ...],
        parent_function: str | None,
        class_qualname: str | None,
    ) -> None:
        for statement in body:
            if isinstance(statement, ast.ClassDef):
                qualname = ".".join((*owners, statement.name))
                self.classes[(path, qualname)] = statement
                self.classes_by_name[(path, statement.name)].append(qualname)
                self.global_classes_by_name[statement.name].append((path, qualname))
                self.class_bases[(path, qualname)] = tuple(
                    name for base in statement.bases if (name := dotted(base)) is not None
                )
                self._visit_body(path, statement.body, (*owners, statement.name), parent_function, qualname)
            elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualname = ".".join((*owners, statement.name))
                key = f"{path}:{qualname}:{statement.lineno}"
                info = FunctionInfo(
                    key=key,
                    path=path,
                    module=module_name(path),
                    qualname=qualname,
                    parent_qualname=".".join(owners) or None,
                    class_qualname=class_qualname,
                    node=statement,
                    parameters=parameters(statement),
                    decorators=frozenset(
                        name for item in statement.decorator_list if (name := decorator_name(item))
                    ),
                )
                info.aliases = {
                    parameter.name: {index} for index, parameter in enumerate(info.parameters)
                }
                info.direct = [0] * len(info.parameters)
                info.summary = [0] * len(info.parameters)
                self.functions[key] = info
                self.function_by_qualname[(path, qualname)] = key
                if parent_function is not None:
                    self.child_functions[(parent_function, statement.name)].append(key)
                elif class_qualname is not None:
                    self.class_methods[(path, class_qualname, statement.name)].append(key)
                else:
                    self.module_functions[(path, statement.name)].append(key)
                for child in immediate_nodes(statement):
                    if not isinstance(child, ast.Return) or not isinstance(child.value, ast.Lambda):
                        continue
                    lambda_node = child.value
                    lambda_qualname = f"{qualname}.<lambda>@{lambda_node.lineno}"
                    lambda_key = f"{path}:{lambda_qualname}:{lambda_node.lineno}"
                    lambda_info = FunctionInfo(
                        key=lambda_key,
                        path=path,
                        module=module_name(path),
                        qualname=lambda_qualname,
                        parent_qualname=qualname,
                        class_qualname=None,
                        node=lambda_node,
                        parameters=parameters(lambda_node),
                        decorators=frozenset(),
                    )
                    lambda_info.aliases = {
                        parameter.name: {index}
                        for index, parameter in enumerate(lambda_info.parameters)
                    }
                    lambda_info.direct = [0] * len(lambda_info.parameters)
                    lambda_info.summary = [0] * len(lambda_info.parameters)
                    self.functions[lambda_key] = lambda_info
                    self.function_by_qualname[(path, lambda_qualname)] = lambda_key
                    self.returned_callables[key].append(lambda_key)
                self._visit_body(
                    path,
                    statement.body,
                    (*owners, statement.name),
                    key,
                    class_qualname,
                )

    def _annotation_class(
        self, path: str, annotation: ast.AST
    ) -> tuple[str, str] | None:
        if isinstance(annotation, ast.Name):
            local = self.classes_by_name.get((path, annotation.id), ())
            if len(local) == 1:
                return path, local[0]
            qualified = self.direct_imports[path].get(annotation.id)
            if not qualified:
                return None
            target_module, _, target_name = qualified.rpartition(".")
            target_path = self.module_paths.get(target_module)
            candidates = self.classes_by_name.get((target_path, target_name), ())
            return (target_path, candidates[0]) if target_path and len(candidates) == 1 else None
        if isinstance(annotation, ast.Attribute) and isinstance(annotation.value, ast.Name):
            namespace = self.imported_module(path, annotation.value.id)
            candidates = self.global_classes_by_name.get(annotation.attr, ())
            matches = [
                candidate
                for candidate in candidates
                if namespace is not None
                and (
                    module_name(candidate[0]) == namespace
                    or module_name(candidate[0]).startswith(namespace + ".")
                )
            ]
            return matches[0] if len(matches) == 1 else None
        return None

    @staticmethod
    def _callable_arguments(annotation: ast.AST | None) -> list[ast.AST]:
        if not isinstance(annotation, ast.Subscript):
            return []
        name = dotted(annotation.value)
        if not name or name.rsplit(".", 1)[-1] != "Callable":
            return []
        value = annotation.slice
        if not isinstance(value, ast.Tuple) or not value.elts:
            return []
        arguments = value.elts[0]
        return list(arguments.elts) if isinstance(arguments, (ast.List, ast.Tuple)) else []

    def _link_returned_callables(self) -> None:
        """Model ordinary lambda arguments separately from captured cells."""
        for factory_key, lambda_keys in self.returned_callables.items():
            factory = self.functions[factory_key]
            annotations = self._callable_arguments(
                factory.node.returns
                if isinstance(factory.node, (ast.FunctionDef, ast.AsyncFunctionDef))
                else None
            )
            factory_slots = {
                parameter.name: index for index, parameter in enumerate(factory.parameters)
            }
            for lambda_key in lambda_keys:
                returned = self.functions[lambda_key]
                for slot, annotation in enumerate(annotations[: len(returned.parameters)]):
                    candidate = self._annotation_class(returned.path, annotation)
                    if candidate is not None:
                        returned.parameter_classes[slot] = candidate
                bound_names = {parameter.name for parameter in returned.parameters}
                free_names = {
                    node.id
                    for node in ast.walk(returned.node.body)
                    if isinstance(node, ast.Name)
                    and isinstance(node.ctx, ast.Load)
                    and node.id not in bound_names
                }
                for name in sorted(free_names & factory_slots.keys()):
                    capture_slot = len(returned.parameters)
                    returned.parameters = (*returned.parameters, Parameter(name, "capture", False))
                    returned.aliases[name] = {capture_slot}
                    returned.direct.append(0)
                    returned.summary.append(0)
                    returned.capture_from[capture_slot] = (factory_key, factory_slots[name])

    def method(self, path: str, class_qualname: str, name: str) -> list[str]:
        """Resolve an exact method through an unambiguous same-source MRO."""
        found = self.class_methods.get((path, class_qualname, name), ())
        if found:
            return list(found)
        results: list[str] = []
        for base in self.class_bases.get((path, class_qualname), ()):
            base_name = base.rsplit(".", 1)[-1]
            candidates = [
                qualname for qualname in self.classes_by_name.get((path, base_name), ())
            ]
            if len(candidates) != 1:
                return []
            results.extend(self.method(path, candidates[0], name))
        return sorted(set(results))

    def imported_function(self, path: str, name: str) -> list[str]:
        qualified = self.direct_imports[path].get(name)
        if not qualified:
            return []
        target_module, _, target_name = qualified.rpartition(".")
        target_path = self.module_paths.get(target_module)
        return list(self.module_functions.get((target_path, target_name), ())) if target_path else []

    def imported_module(self, path: str, name: str, seen=frozenset()) -> str | None:
        if (path, name) in seen:
            return None
        direct = self.module_imports[path].get(name)
        if direct in self.module_paths:
            return direct
        qualified = self.direct_imports[path].get(name)
        if not qualified:
            return None
        if qualified in self.module_paths:
            return qualified
        exporter, _, exported_name = qualified.rpartition(".")
        exporter_path = self.module_paths.get(exporter)
        if exporter_path is None:
            return None
        return self.imported_module(
            exporter_path, exported_name, seen | {(path, name)}
        )

    def constructor(self, path: str, node: ast.AST) -> tuple[str, str] | None:
        if isinstance(node, ast.Name):
            candidates = self.classes_by_name.get((path, node.id), ())
            return (path, candidates[0]) if len(candidates) == 1 else None
        if not isinstance(node, ast.Attribute) or not isinstance(node.value, ast.Name):
            return None
        namespace = self.imported_module(path, node.value.id)
        candidates = self.global_classes_by_name.get(node.attr, ())
        if namespace is None or len(candidates) != 1:
            return None
        candidate_path, qualname = candidates[0]
        candidate_module = module_name(candidate_path)
        if candidate_module != namespace and not candidate_module.startswith(namespace + "."):
            return None
        return candidate_path, qualname

    def fresh_constructor(self, path: str, node: ast.AST) -> tuple[str, str] | None:
        candidate = self.constructor(path, node)
        if candidate is None:
            return None
        pending = [candidate]
        seen = set()
        while pending:
            current = pending.pop()
            if current in seen:
                return None
            seen.add(current)
            class_path, qualname = current
            cls = self.classes[current]
            if cls.keywords or self.class_methods.get((class_path, qualname, "__new__")):
                return None
            for base in self.class_bases.get(current, ()):
                base_name = base.rsplit(".", 1)[-1]
                bases = self.global_classes_by_name.get(base_name, ())
                if len(bases) > 1:
                    return None
                if bases:
                    pending.append(bases[0])
        return candidate

    def module_attribute(self, path: str, root: str, name: str) -> list[str]:
        target_module = self.module_imports[path].get(root)
        target_path = self.module_paths.get(target_module) if target_module else None
        return list(self.module_functions.get((target_path, name), ())) if target_path else []


@dataclass(frozen=True, slots=True)
class OwnershipResult:
    safe: bool
    identity: bool = False
    written_fields: frozenset[str] = frozenset()


class OwnershipAnalyzer:
    """Context-sensitive non-escape proof for one exact fresh object graph."""

    UNKNOWN_VALUE = object()
    OWNED_VALUE = object()

    def __init__(self, solver: "SharedArgumentSolver") -> None:
        self.solver = solver
        self.index = solver.index
        self.memo: dict[tuple, OwnershipResult] = {}
        self.active: set[tuple] = set()
        self.failures: Counter = Counter()

    def _reject(self, reason: str) -> OwnershipResult:
        self.failures[reason] += 1
        return OwnershipResult(False)

    @staticmethod
    def _contains_alias(node: ast.AST | None, aliases: set[str]) -> bool:
        return bool(node) and any(
            isinstance(child, ast.Name)
            and isinstance(child.ctx, ast.Load)
            and child.id in aliases
            for child in ast.walk(node)
        )

    def _class_constant(
        self, domain: tuple[str, str], name: str, seen=frozenset()
    ) -> object:
        if domain in seen:
            return self.UNKNOWN_VALUE
        path, qualname = domain
        cls = self.index.classes.get(domain)
        if cls is None:
            return self.UNKNOWN_VALUE
        values = []
        for statement in cls.body:
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                if any(isinstance(target, ast.Name) and target.id == name for target in targets):
                    value = statement.value
                    if isinstance(value, ast.Constant):
                        values.append(value.value)
                    else:
                        return self.UNKNOWN_VALUE
        if values:
            return values[0] if all(value == values[0] for value in values) else self.UNKNOWN_VALUE
        inherited = []
        for base in self.index.class_bases.get(domain, ()):
            base_name = base.rsplit(".", 1)[-1]
            candidates = self.index.global_classes_by_name.get(base_name, ())
            if len(candidates) != 1:
                return self.UNKNOWN_VALUE
            value = self._class_constant(candidates[0], name, seen | {domain})
            if value is not self.UNKNOWN_VALUE:
                inherited.append(value)
        return (
            inherited[0]
            if inherited and all(value == inherited[0] for value in inherited)
            else self.UNKNOWN_VALUE
        )

    def _has_truth_protocol(self, domain: tuple[str, str]) -> bool:
        return bool(
            self.index.method(*domain, "__bool__")
            or self.index.method(*domain, "__len__")
        )

    def _known(
        self,
        node: ast.AST | None,
        aliases: set[str],
        values: Mapping[str, object],
        domain: tuple[str, str],
        fields: Mapping[str, object],
    ) -> object:
        if node is None:
            return None
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if node.id in aliases:
                return self.UNKNOWN_VALUE if self._has_truth_protocol(domain) else self.OWNED_VALUE
            return values.get(node.id, self.UNKNOWN_VALUE)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id in aliases:
                if node.attr in fields:
                    return fields[node.attr]
                return self._class_constant(domain, node.attr)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            value = self._known(node.operand, aliases, values, domain, fields)
            return self.UNKNOWN_VALUE if value is self.UNKNOWN_VALUE else not bool(value)
        if isinstance(node, ast.BoolOp):
            current: object = True if isinstance(node.op, ast.And) else False
            for value_node in node.values:
                current = self._known(value_node, aliases, values, domain, fields)
                if current is self.UNKNOWN_VALUE:
                    return current
                if isinstance(node.op, ast.And) and not bool(current):
                    return current
                if isinstance(node.op, ast.Or) and bool(current):
                    return current
            return current
        if isinstance(node, ast.Compare) and len(node.ops) == len(node.comparators) == 1:
            left = self._known(node.left, aliases, values, domain, fields)
            right = self._known(node.comparators[0], aliases, values, domain, fields)
            if left is self.UNKNOWN_VALUE or right is self.UNKNOWN_VALUE:
                return self.UNKNOWN_VALUE
            operation = node.ops[0]
            if isinstance(operation, ast.Is):
                return left is right
            if isinstance(operation, ast.IsNot):
                return left is not right
            if isinstance(operation, ast.Eq) and type(left) is type(right):
                return left == right
            if isinstance(operation, ast.NotEq) and type(left) is type(right):
                return left != right
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "isinstance"
            and len(node.args) == 2
        ):
            value = self._known(node.args[0], aliases, values, domain, fields)
            if value is not self.UNKNOWN_VALUE and value is not self.OWNED_VALUE:
                class_name = dotted(node.args[1])
                builtin = {
                    "bool": bool, "bytes": bytes, "dict": dict, "float": float,
                    "int": int, "list": list, "str": str, "tuple": tuple,
                }.get(class_name or "")
                if builtin is not None:
                    return isinstance(value, builtin)
                # A scalar cannot be an application source class.
                if type(value) in {bool, bytes, float, int, str, tuple, type(None)}:
                    return False
        return self.UNKNOWN_VALUE

    @staticmethod
    def _parameter_defaults(info: FunctionInfo) -> dict[int, object]:
        node = info.node
        if isinstance(node, ast.Lambda):
            arguments = node.args
        else:
            arguments = node.args
        positional = [*arguments.posonlyargs, *arguments.args]
        defaults = [None] * (len(positional) - len(arguments.defaults)) + list(arguments.defaults)
        result: dict[int, object] = {}
        for slot, default in enumerate(defaults):
            if isinstance(default, ast.Constant):
                result[slot] = default.value
        offset = len(positional) + (1 if arguments.vararg else 0)
        for index, default in enumerate(arguments.kw_defaults, offset):
            if isinstance(default, ast.Constant):
                result[index] = default.value
        return result

    def _call_target(
        self,
        info: FunctionInfo,
        call: ast.Call,
        aliases: set[str],
        domain: tuple[str, str],
    ) -> CallTarget | None:
        if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
            if call.func.value.id in aliases:
                candidates = self.index.method(*domain, call.func.attr)
                if len(candidates) != 1:
                    return None
                target = self.index.functions[candidates[0]]
                if target.decorators - TRANSPARENT_DECORATORS or "property" in target.decorators:
                    return None
                return CallTarget(target.key, call.func.value, True, True)
        return self.solver._resolve_call(info, call)

    def _call_effect(
        self,
        info: FunctionInfo,
        call: ast.Call,
        aliases: set[str],
        values: Mapping[str, object],
        domain: tuple[str, str],
        fields: Mapping[str, object],
    ) -> OwnershipResult:
        if not self._contains_alias(call, aliases):
            return OwnershipResult(True)
        direct_receiver = (
            isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id in aliases
        )
        direct_arguments = any(
            isinstance(argument, ast.Name) and argument.id in aliases
            for argument in call.args
        ) or any(
            isinstance(keyword.value, ast.Name) and keyword.value.id in aliases
            for keyword in call.keywords
        )
        nested_arguments = any(
            self._contains_alias(argument, aliases)
            and not (isinstance(argument, ast.Name) and argument.id in aliases)
            for argument in call.args
        ) or any(
            self._contains_alias(keyword.value, aliases)
            and not (isinstance(keyword.value, ast.Name) and keyword.value.id in aliases)
            for keyword in call.keywords
        )
        if nested_arguments:
            len_owned_field = (
                isinstance(call.func, ast.Name)
                and call.func.id == "len"
                and len(call.args) == 1
                and not call.keywords
                and isinstance(call.args[0], ast.Attribute)
                and isinstance(call.args[0].value, ast.Name)
                and call.args[0].value.id in aliases
                and self._owned_field_type(domain, call.args[0].attr) is not None
            )
            formatted_values = [
                argument
                for argument in call.args
                if self._contains_alias(argument, aliases)
            ]
            formatted_safe = bool(formatted_values) and all(
                isinstance(argument, ast.JoinedStr)
                and self._expression_safe(
                    info, argument, aliases, values, domain, fields
                ).safe
                for argument in formatted_values
            )
            if not len_owned_field and not formatted_safe:
                return self._reject("nested-alias-argument")
            return OwnershipResult(True)
        if not direct_receiver and not direct_arguments:
            if not self._owned_field_call(call, aliases, domain):
                return self._reject("unproved-owned-field-call")
            return OwnershipResult(True)
        if (
            isinstance(call.func, ast.Name)
            and call.func.id in {"isinstance", "type"}
            and call.args
            and isinstance(call.args[0], ast.Name)
            and call.args[0].id in aliases
        ):
            return OwnershipResult(True)
        target = self._call_target(info, call, aliases, domain)
        if target is None:
            return self._reject("unresolved-call")
        bound, error = self.solver._bind(call, target)
        if error is not None:
            return self._reject(f"binding:{error}")
        tracked_slots: set[int] = set()
        if (
            target.receiver_to_slot
            and isinstance(target.receiver, ast.Name)
            and target.receiver.id in aliases
        ):
            tracked_slots.add(0)
        known: dict[int, object] = {}
        for actual, slot in bound:
            if isinstance(actual, ast.Name) and actual.id in aliases:
                tracked_slots.add(slot)
            elif self._contains_alias(actual, aliases):
                return self._reject("nested-alias-argument")
            else:
                value = self._known(actual, aliases, values, domain, fields)
                if value is not self.UNKNOWN_VALUE:
                    known[slot] = value
        if len(tracked_slots) != 1:
            return self._reject("ambiguous-tracked-slots")
        tracked_slot = next(iter(tracked_slots))
        callee = self.index.functions[target.key]
        callee_domain = domain
        if tracked_slot != 0:
            callee_domain = domain
        result = self.prove(target.key, tracked_slot, callee_domain, known, fields)
        return result

    def _owned_field_call(
        self,
        call: ast.Call,
        aliases: set[str],
        domain: tuple[str, str],
    ) -> bool:
        """Prove a call is an exact builtin operation on an owned field."""
        if not (
            isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Attribute)
            and isinstance(call.func.value.value, ast.Name)
            and call.func.value.value.id in aliases
            and not call.func.attr.startswith("__")
        ):
            return False
        builtin_type = self._owned_field_type(domain, call.func.value.attr)
        if builtin_type is None:
            return False
        descriptor = vars(builtin_type).get(call.func.attr)
        return descriptor is not None and callable(descriptor)

    def _owned_field_type(
        self, domain: tuple[str, str], field_name: str
    ) -> type | None:
        annotations: set[str] = set()
        pending = [domain]
        seen = set()
        while pending:
            current = pending.pop()
            if current in seen:
                return False
            seen.add(current)
            cls = self.index.classes.get(current)
            if cls is None:
                return False
            for node in ast.walk(cls):
                if not isinstance(node, ast.AnnAssign):
                    continue
                target_matches = (
                    isinstance(node.target, ast.Attribute)
                    and isinstance(node.target.value, ast.Name)
                    and node.target.value.id == "self"
                    and node.target.attr == field_name
                ) or (isinstance(node.target, ast.Name) and node.target.id == field_name)
                if not target_matches:
                    continue
                builtin_annotations = {
                    child.id
                    for child in ast.walk(node.annotation)
                    if isinstance(child, ast.Name)
                    and child.id in {"dict", "list", "set", "tuple"}
                }
                annotations.update(builtin_annotations)
            for base in self.index.class_bases.get(current, ()):
                candidates = self.index.global_classes_by_name.get(base.rsplit(".", 1)[-1], ())
                if len(candidates) != 1:
                    return False
                pending.append(candidates[0])
        if len(annotations) != 1:
            return None
        builtin_name = next(iter(annotations)).rsplit(".", 1)[-1]
        return {"dict": dict, "list": list, "set": set, "tuple": tuple}.get(
            builtin_name
        )

    def _expression_safe(
        self,
        info: FunctionInfo,
        node: ast.AST | None,
        aliases: set[str],
        values: Mapping[str, object],
        domain: tuple[str, str],
        fields: Mapping[str, object],
    ) -> OwnershipResult:
        if node is None or not self._contains_alias(node, aliases):
            return OwnershipResult(True)
        if isinstance(node, ast.Call):
            return self._call_effect(info, node, aliases, values, domain, fields)
        if isinstance(node, ast.Name) and node.id in aliases:
            return OwnershipResult(True, identity=True)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in aliases:
            methods = self.index.method(*domain, node.attr)
            if methods:
                if len(methods) != 1:
                    return self._reject("ambiguous-descriptor")
                target = self.index.functions[methods[0]]
                if "property" not in target.decorators:
                    return self._reject("bound-method-escape")
                return self.prove(target.key, 0, domain, {}, fields)
            return OwnershipResult(True)
        if isinstance(node, (ast.BoolOp, ast.UnaryOp, ast.Compare)):
            known = self._known(node, aliases, values, domain, fields)
            return OwnershipResult(known is not self.UNKNOWN_VALUE)
        if isinstance(node, ast.IfExp):
            condition = self._known(node.test, aliases, values, domain, fields)
            if condition is self.UNKNOWN_VALUE:
                left = self._expression_safe(info, node.body, aliases, values, domain, fields)
                right = self._expression_safe(info, node.orelse, aliases, values, domain, fields)
                return OwnershipResult(
                    left.safe and right.safe,
                    left.identity and right.identity,
                    left.written_fields | right.written_fields,
                )
            return self._expression_safe(
                info,
                node.body if bool(condition) else node.orelse,
                aliases,
                values,
                domain,
                fields,
            )
        if isinstance(node, (ast.JoinedStr, ast.FormattedValue)):
            # Avoid mutating the pinned AST with parent pointers: explicitly
            # accept only occurrences used as ``owned.__class__``.
            for child in ast.walk(node):
                if isinstance(child, ast.Name) and child.id in aliases:
                    if not any(
                        isinstance(parent, ast.Attribute)
                        and parent.value is child
                        and parent.attr == "__class__"
                        for parent in ast.walk(node)
                    ):
                        return self._reject("dynamic-format-owned")
            return OwnershipResult(True)
        if isinstance(node, (ast.Tuple, ast.List, ast.Set, ast.Dict)):
            return self._reject("container-escape")
        return self._reject(f"unsupported-expression:{type(node).__name__}")

    def prove(
        self,
        function_key: str,
        tracked_slot: int,
        domain: tuple[str, str],
        known_slots: Mapping[int, object],
        initial_fields: Mapping[str, object],
    ) -> OwnershipResult:
        key = (
            function_key, tracked_slot, domain,
            tuple(sorted(known_slots.items())), tuple(sorted(initial_fields.items())),
        )
        if key in self.memo:
            return self.memo[key]
        if key in self.active:
            return self._reject("recursive-effect")
        self.active.add(key)
        info = self.index.functions[function_key]
        aliases = {info.parameters[tracked_slot].name}
        values = {
            info.parameters[slot].name: value
            for slot, value in self._parameter_defaults(info).items()
            if slot < len(info.parameters)
        }
        values.update(
            {
                info.parameters[slot].name: value
                for slot, value in known_slots.items()
                if slot < len(info.parameters)
            }
        )
        fields = dict(initial_fields)
        written: set[str] = set()
        returns: list[bool] = []
        external_names = {
            name
            for node in immediate_nodes(info.node)
            if isinstance(node, (ast.Global, ast.Nonlocal))
            for name in node.names
        }
        safe = True

        def visit_block(statements: list[ast.stmt]) -> bool:
            nonlocal aliases, values, fields, written
            def apply_effect(effect: OwnershipResult) -> None:
                written.update(effect.written_fields)
                for field_name in effect.written_fields:
                    fields.pop(field_name, None)

            def snapshot():
                return set(aliases), dict(values), dict(fields), set(written)

            def restore(state) -> None:
                nonlocal aliases, values, fields, written
                aliases, values, fields, written = (
                    set(state[0]), dict(state[1]), dict(state[2]), set(state[3])
                )

            def join(states) -> None:
                nonlocal aliases, values, fields, written
                aliases = set().union(*(state[0] for state in states))
                common_values = set.intersection(*(set(state[1]) for state in states))
                values = {
                    name: states[0][1][name]
                    for name in common_values
                    if all(
                        type(state[1][name]) is type(states[0][1][name])
                        and state[1][name] == states[0][1][name]
                        for state in states[1:]
                    )
                }
                common_fields = set.intersection(*(set(state[2]) for state in states))
                fields = {
                    name: states[0][2][name]
                    for name in common_fields
                    if all(
                        type(state[2][name]) is type(states[0][2][name])
                        and state[2][name] == states[0][2][name]
                        for state in states[1:]
                    )
                }
                written = set().union(*(state[3] for state in states))

            for statement in statements:
                if isinstance(statement, ast.If):
                    condition = self._known(statement.test, aliases, values, domain, fields)
                    branches = (
                        [statement.body] if condition is not self.UNKNOWN_VALUE and bool(condition)
                        else [statement.orelse] if condition is not self.UNKNOWN_VALUE
                        else [statement.body, statement.orelse]
                    )
                    base = snapshot()
                    exits = []
                    for branch in branches:
                        restore(base)
                        if not visit_block(branch):
                            self.failures["unsafe-branch"] += 1
                            return False
                        exits.append(snapshot())
                    join(exits)
                    continue
                if isinstance(statement, ast.While):
                    condition = self._known(statement.test, aliases, values, domain, fields)
                    if condition is not self.UNKNOWN_VALUE and not bool(condition):
                        continue
                    if self._contains_alias(statement.test, aliases):
                        self.failures["dynamic-owned-while"] += 1
                        return False
                    before = snapshot()
                    if not visit_block(statement.body):
                        self.failures["unsafe-while-body"] += 1
                        return False
                    after = snapshot()
                    join([before, after])
                    continue
                if isinstance(statement, (ast.For, ast.AsyncFor)):
                    owned_field_iteration = (
                        isinstance(statement.iter, ast.Attribute)
                        and isinstance(statement.iter.value, ast.Name)
                        and statement.iter.value.id in aliases
                    )
                    if self._contains_alias(statement.iter, aliases) and not owned_field_iteration:
                        effect = self._expression_safe(
                            info, statement.iter, aliases, values, domain, fields
                        )
                        if not effect.safe or effect.identity:
                            self.failures["iterate-owned"] += 1
                            return False
                        apply_effect(effect)
                    before = snapshot()
                    if not visit_block(statement.body):
                        self.failures["unsafe-loop-body"] += 1
                        return False
                    after = snapshot()
                    join([before, after])
                    continue
                if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                    value = statement.value
                    targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                    effect = self._expression_safe(info, value, aliases, values, domain, fields)
                    if not effect.safe:
                        self.failures["unsafe-assignment-value"] += 1
                        return False
                    apply_effect(effect)
                    known = self._known(value, aliases, values, domain, fields)
                    for target in targets:
                        if isinstance(target, ast.Name):
                            if target.id in external_names and self._contains_alias(value, aliases):
                                self.failures["global-nonlocal-store"] += 1
                                return False
                            if effect.identity:
                                aliases.add(target.id)
                            else:
                                aliases.discard(target.id)
                            if known is not self.UNKNOWN_VALUE:
                                values[target.id] = known
                            else:
                                values.pop(target.id, None)
                        elif isinstance(target, ast.Attribute):
                            if self._contains_alias(value, aliases) and not (
                                isinstance(target.value, ast.Name) and target.value.id in aliases
                            ):
                                self.failures["external-attribute-store"] += 1
                                return False
                            if isinstance(target.value, ast.Name) and target.value.id in aliases:
                                written.add(target.attr)
                                if known is not self.UNKNOWN_VALUE:
                                    fields[target.attr] = known
                                else:
                                    fields.pop(target.attr, None)
                        elif isinstance(target, ast.Subscript):
                            if self._contains_alias(value, aliases) and not self._contains_alias(
                                target.value, aliases
                            ):
                                self.failures["external-container-store"] += 1
                                return False
                    continue
                if isinstance(statement, ast.Expr):
                    effect = self._expression_safe(
                        info, statement.value, aliases, values, domain, fields
                    )
                    if not effect.safe:
                        self.failures["unsafe-expression"] += 1
                        return False
                    apply_effect(effect)
                    continue
                if isinstance(statement, ast.Return):
                    effect = self._expression_safe(
                        info, statement.value, aliases, values, domain, fields
                    )
                    if not effect.safe:
                        self.failures["unsafe-return"] += 1
                        return False
                    apply_effect(effect)
                    if self._contains_alias(statement.value, aliases) and not effect.identity:
                        self.failures["nonidentity-return"] += 1
                        return False
                    returns.append(effect.identity)
                    continue
                if isinstance(statement, (ast.Raise, ast.Yield, ast.YieldFrom)):
                    if self._contains_alias(statement, aliases):
                        if isinstance(statement, ast.Raise):
                            if (
                                isinstance(statement.exc, ast.Call)
                                and isinstance(statement.exc.func, ast.Name)
                                and not self.solver._resolve_name(info, statement.exc.func.id)
                                and isinstance(
                                    getattr(builtins, statement.exc.func.id, None),
                                    type,
                                )
                                and issubclass(
                                    getattr(builtins, statement.exc.func.id), BaseException
                                )
                                and all(
                                    (
                                        effect := self._expression_safe(
                                            info, argument, aliases, values, domain, fields
                                        )
                                    ).safe
                                    and not effect.identity
                                    for argument in statement.exc.args
                                )
                            ):
                                continue
                            effect = self._expression_safe(
                                info, statement.exc, aliases, values, domain, fields
                            )
                            if effect.safe and not effect.identity:
                                continue
                        self.failures["raise-yield-escape"] += 1
                        return False
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    if any(
                        isinstance(child, ast.Name)
                        and isinstance(child.ctx, ast.Load)
                        and child.id in aliases
                        for child in ast.walk(statement)
                    ):
                        self.failures["closure-escape"] += 1
                        return False
                if isinstance(statement, (ast.Global, ast.Nonlocal)) and aliases & set(statement.names):
                    self.failures["global-nonlocal"] += 1
                    return False
                if not isinstance(
                    statement,
                    (
                        ast.Pass, ast.Break, ast.Continue, ast.Global, ast.Nonlocal,
                        ast.Import, ast.ImportFrom,
                    ),
                ) and self._contains_alias(statement, aliases):
                    self.failures[f"unhandled-statement:{type(statement).__name__}"] += 1
                    return False
            return True

        body = info.node.body if not isinstance(info.node, ast.Lambda) else []
        safe = bool(body) and visit_block(body)

        def normal_fallthrough(statements: list[ast.stmt]) -> bool:
            falls = True
            for statement in statements:
                if not falls:
                    break
                if isinstance(statement, (ast.Return, ast.Raise)):
                    falls = False
                elif isinstance(statement, ast.If):
                    falls = normal_fallthrough(statement.body) or (
                        normal_fallthrough(statement.orelse) if statement.orelse else True
                    )
                elif isinstance(statement, ast.Match):
                    # Exhaustiveness is difficult to establish source-only.
                    falls = True
                elif isinstance(statement, (ast.Try, ast.TryStar, ast.With, ast.AsyncWith)):
                    falls = True
                else:
                    # Loops can execute zero times; all other handled
                    # statements continue normally.
                    falls = True
            return falls

        result = OwnershipResult(
            safe,
            safe and bool(returns) and all(returns) and not normal_fallthrough(body),
            frozenset(written),
        )
        self.active.remove(key)
        self.memo[key] = result
        return result


class SharedArgumentSolver:
    def __init__(self, sources: Mapping[str, str]) -> None:
        self.index = SourceIndex(sources)
        self.edges: set[Edge] = set()
        self.call_counts = Counter()
        self.fallbacks = Counter()
        self.shared_calls: dict[tuple[str, int], set[tuple[int, int]]] = defaultdict(set)
        self._fresh_class_cache: dict[tuple[str, int], tuple[str, str] | None] = {}

    @staticmethod
    def _taint(node: ast.AST | None, aliases: Mapping[str, set[int]]) -> set[int]:
        if node is None:
            return set()
        return {
            slot
            for child in ast.walk(node)
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load)
            for slot in aliases.get(child.id, ())
        }

    def _alias_roots(self, info: FunctionInfo, node: ast.AST | None) -> set[int]:
        """Return formal roots the expression result may itself alias.

        Reading an argument during a call is deliberately not enough.  Exact
        source callees contribute only their fixed-point return-alias slots;
        unresolved calls remain conservative and may return any input.
        """
        if node is None:
            return set()
        if isinstance(node, ast.Name):
            return set(info.aliases.get(node.id, ()))
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            return self._alias_roots(info, node.value)
        if isinstance(node, ast.NamedExpr):
            return self._alias_roots(info, node.value)
        if isinstance(node, ast.IfExp):
            return self._alias_roots(info, node.body) | self._alias_roots(info, node.orelse)
        if isinstance(node, ast.BoolOp):
            return set().union(*(self._alias_roots(info, value) for value in node.values))
        if isinstance(node, ast.Await):
            return self._alias_roots(info, node.value)
        if not isinstance(node, ast.Call):
            return set()
        target = self._resolve_call(info, node)
        if target is None:
            return self._taint(node, info.aliases)
        bound, error = self._bind(node, target)
        if error is not None:
            return self._taint(node, info.aliases)
        if target.fresh_result:
            return set()
        actuals: dict[int, set[int]] = defaultdict(set)
        if target.receiver_to_slot and target.receiver is not None:
            actuals[0].update(self._alias_roots(info, target.receiver))
        for actual, slot in bound:
            actuals[slot].update(self._alias_roots(info, actual))
        return set().union(
            *(actuals.get(slot, set()) for slot in self.index.functions[target.key].return_alias)
        )

    @staticmethod
    def _assign_alias(target: ast.AST, roots: set[int], aliases: dict[str, set[int]]) -> bool:
        changed = False
        if isinstance(target, ast.Name):
            before = len(aliases.setdefault(target.id, set()))
            aliases[target.id].update(roots)
            changed = len(aliases[target.id]) != before
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                changed |= SharedArgumentSolver._assign_alias(element, roots, aliases)
        return changed

    def _aliases(self, info: FunctionInfo) -> bool:
        initial = sum(len(roots) for roots in info.aliases.values())
        changed = True
        nodes = list(immediate_nodes(info.node))
        while changed:
            changed = False
            for node in nodes:
                if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                    value = node.value
                    roots = self._alias_roots(info, value)
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        changed |= self._assign_alias(target, roots, info.aliases)
                elif isinstance(node, (ast.For, ast.AsyncFor)):
                    changed |= self._assign_alias(
                        node.target, self._alias_roots(info, node.iter), info.aliases
                    )
                elif isinstance(node, ast.comprehension):
                    changed |= self._assign_alias(
                        node.target, self._alias_roots(info, node.iter), info.aliases
                    )
                elif isinstance(node, (ast.With, ast.AsyncWith)):
                    for item in node.items:
                        if item.optional_vars is not None:
                            changed |= self._assign_alias(
                                item.optional_vars,
                                self._alias_roots(info, item.context_expr),
                                info.aliases,
                            )
        return sum(len(roots) for roots in info.aliases.values()) != initial

    def _return_alias_fixed_point(self) -> int:
        rounds = 0
        changed = True
        while changed:
            changed = False
            rounds += 1
            for info in self.index.functions.values():
                changed |= self._aliases(info)
                returned = set().union(
                    *(self._alias_roots(info, value) for value in self._return_values(info))
                )
                before = len(info.return_alias)
                info.return_alias.update(returned)
                changed |= len(info.return_alias) != before
            if rounds > len(self.index.functions) + 1:
                raise RuntimeError("non-monotone return-alias fixed point")
        return rounds

    @staticmethod
    def _return_values(info: FunctionInfo) -> list[ast.AST]:
        if isinstance(info.node, ast.Lambda):
            return [info.node.body]
        return [
            node.value
            for node in immediate_nodes(info.node)
            if isinstance(node, ast.Return) and node.value is not None
        ]

    def _fresh_expression(self, info: FunctionInfo, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Name):
            return node.id in info.fresh_names
        if isinstance(node, ast.NamedExpr):
            return self._fresh_expression(info, node.value)
        if isinstance(node, ast.IfExp):
            return self._fresh_expression(info, node.body) and self._fresh_expression(
                info, node.orelse
            )
        if not isinstance(node, ast.Call):
            return False
        target = self._resolve_call(info, node)
        if target is None:
            return False
        if target.fresh_result:
            return True
        bound, error = self._bind(node, target)
        callee = self.index.functions[target.key]
        if error is not None or not callee.return_alias:
            return False
        return_nodes = (
            []
            if isinstance(callee.node, ast.Lambda)
            else [
                child
                for child in immediate_nodes(callee.node)
                if isinstance(child, ast.Return)
            ]
        )
        return_values = self._return_values(callee)
        if (
            (return_nodes and any(child.value is None for child in return_nodes))
            or not return_values
            or any(
            not self._alias_roots(callee, value)
            or not self._alias_roots(callee, value) <= callee.return_alias
            for value in return_values
            )
        ):
            return False
        actuals: dict[int, list[ast.AST]] = defaultdict(list)
        if target.receiver_to_slot and target.receiver is not None:
            actuals[0].append(target.receiver)
        for actual, slot in bound:
            actuals[slot].append(actual)
        return all(
            actuals.get(slot)
            and all(self._fresh_expression(info, actual) for actual in actuals[slot])
            for slot in callee.return_alias
        )

    def _fresh_class(
        self, info: FunctionInfo, node: ast.AST | None
    ) -> tuple[str, str] | None:
        if node is None:
            return None
        cache_key = (info.key, id(node))
        if cache_key in self._fresh_class_cache:
            return self._fresh_class_cache[cache_key]
        # A provisional miss also breaks recursive return-flow cycles.
        self._fresh_class_cache[cache_key] = None
        result = self._compute_fresh_class(info, node)
        self._fresh_class_cache[cache_key] = result
        return result

    def _compute_fresh_class(
        self, info: FunctionInfo, node: ast.AST
    ) -> tuple[str, str] | None:
        if isinstance(node, ast.Name):
            return info.fresh_classes.get(node.id)
        if isinstance(node, ast.NamedExpr):
            return self._fresh_class(info, node.value)
        if isinstance(node, ast.IfExp):
            left = self._fresh_class(info, node.body)
            right = self._fresh_class(info, node.orelse)
            return left if left is not None and left == right else None
        if not isinstance(node, ast.Call):
            return None
        constructor = self.index.fresh_constructor(info.path, node.func)
        if constructor is not None:
            return constructor
        target = self._resolve_call(info, node)
        if target is None:
            return None
        bound, error = self._bind(node, target)
        callee = self.index.functions[target.key]
        if error is not None or not callee.return_alias:
            return None
        actuals: dict[int, list[ast.AST]] = defaultdict(list)
        if target.receiver_to_slot and target.receiver is not None:
            actuals[0].append(target.receiver)
        for actual, slot in bound:
            actuals[slot].append(actual)
        classes = {
            candidate
            for slot in callee.return_alias
            for actual in actuals.get(slot, ())
            if (candidate := self._fresh_class(info, actual)) is not None
        }
        return next(iter(classes)) if len(classes) == 1 else None

    def _fresh_fixed_point(self) -> int:
        rounds = 0
        changed = True
        while changed:
            rounds += 1
            changed = False
            self._fresh_class_cache.clear()
            for info in self.index.functions.values():
                for node in immediate_nodes(info.node):
                    if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                        continue
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    if not self._fresh_expression(info, node.value):
                        continue
                    fresh_class = self._fresh_class(info, node.value)
                    for target in targets:
                        if isinstance(target, ast.Name) and target.id not in info.fresh_names:
                            info.fresh_names.add(target.id)
                            changed = True
                        if (
                            isinstance(target, ast.Name)
                            and fresh_class is not None
                            and target.id not in info.ambiguous_fresh_classes
                        ):
                            previous = info.fresh_classes.get(target.id)
                            if previous is None:
                                info.fresh_classes[target.id] = fresh_class
                                changed = True
                            elif previous != fresh_class:
                                del info.fresh_classes[target.id]
                                info.ambiguous_fresh_classes.add(target.id)
                                changed = True
            if rounds > len(self.index.functions) + 1:
                raise RuntimeError("non-monotone fresh-result fixed point")
        return rounds

    def _constructor_fields(self, domain: tuple[str, str]) -> dict[str, object]:
        methods = self.index.method(*domain, "__init__")
        if len(methods) != 1:
            return {}
        info = self.index.functions[methods[0]]
        if not info.parameters:
            return {}
        receiver = info.parameters[0].name
        fields: dict[str, object] = {}
        for node in immediate_nodes(info.node):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if not isinstance(node.value, ast.Constant):
                continue
            for target in targets:
                if (
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == receiver
                ):
                    fields[target.attr] = node.value.value
        return fields

    def _owned_expression(
        self,
        analyzer: OwnershipAnalyzer,
        info: FunctionInfo,
        node: ast.AST,
    ) -> tuple[tuple[str, str], dict[str, object]] | None:
        if isinstance(node, ast.Name) and node.id in info.fresh_classes:
            domain = info.fresh_classes[node.id]
            return domain, self._constructor_fields(domain)
        if not isinstance(node, ast.Call):
            return None
        constructor = self.index.fresh_constructor(info.path, node.func)
        if constructor is not None:
            return constructor, self._constructor_fields(constructor)
        target = self._resolve_call(info, node)
        if target is None:
            return None
        bound, error = self._bind(node, target)
        if error is not None:
            return None
        callee = self.index.functions[target.key]
        candidates = [
            (slot, self._owned_expression(analyzer, info, actual))
            for actual, slot in bound
            if slot in callee.return_alias
        ]
        candidates = [(slot, value) for slot, value in candidates if value is not None]
        if len(candidates) != 1:
            return None
        slot, (domain, fields) = candidates[0]
        known = {
            actual_slot: actual.value
            for actual, actual_slot in bound
            if isinstance(actual, ast.Constant)
        }
        result = analyzer.prove(target.key, slot, domain, known, fields)
        if not result.safe or not result.identity:
            return None
        for field_name in result.written_fields:
            fields.pop(field_name, None)
        return domain, fields

    def _prove_contained_fresh_calls(self) -> int:
        analyzer = OwnershipAnalyzer(self)
        admitted = 0
        for info in self.index.functions.values():
            if not info.fresh_calls:
                continue
            assignments: dict[str, ast.AST] = {}
            calls: dict[tuple[int, int], ast.Call] = {}
            for node in immediate_nodes(info.node):
                if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        if isinstance(target, ast.Name):
                            assignments[target.id] = node.value
                elif isinstance(node, ast.Call):
                    calls[(node.lineno, node.col_offset)] = node
            for line, column, receiver, target_key in sorted(info.fresh_calls):
                call = calls.get((line, column))
                value = assignments.get(receiver)
                if call is None or value is None:
                    continue
                owned = self._owned_expression(analyzer, info, value)
                if owned is None:
                    continue
                domain, fields = owned
                target = self._resolve_call(info, call)
                if target is None or target.key != target_key:
                    continue
                bound, error = self._bind(call, target)
                if error is not None:
                    continue
                known = {
                    slot: actual.value
                    for actual, slot in bound
                    if isinstance(actual, ast.Constant)
                }
                result = analyzer.prove(target.key, 0, domain, known, fields)
                if result.safe:
                    record = (line, column, receiver, target_key)
                    info.contained_fresh_calls.add(record)
                    admitted += 1
        return admitted

    def _unsafe(self, info: FunctionInfo, roots: Iterable[int], flags: int, reason: str) -> None:
        for slot in roots:
            info.direct[slot] |= flags
            info.reasons[slot].add(reason)

    def _resolve_name(self, info: FunctionInfo, name: str) -> list[str]:
        current: str | None = info.key
        while current is not None:
            nested = self.index.child_functions.get((current, name), ())
            if nested:
                return list(nested)
            parent_qualname = self.index.functions[current].parent_qualname
            current = (
                self.index.function_by_qualname.get((info.path, parent_qualname))
                if parent_qualname
                else None
            )
        local = self.index.module_functions.get((info.path, name), ())
        return list(local) if local else self.index.imported_function(info.path, name)

    def _resolve_call(self, info: FunctionInfo, call: ast.Call) -> CallTarget | None:
        candidates: list[str] = []
        receiver = None
        receiver_to_slot = False
        skip_first = False
        fresh_result = False
        if isinstance(call.func, ast.Call):
            factory = self._resolve_call(info, call.func)
            if factory is None:
                return None
            _factory_bound, factory_error = self._bind(call.func, factory)
            returned = self.index.returned_callables.get(factory.key, ())
            if factory_error is not None or len(returned) != 1:
                return None
            return CallTarget(returned[0], None, False, False, False)
        if isinstance(call.func, ast.Name):
            candidates = self._resolve_name(info, call.func.id)
            # Exact same-module constructor calls bind __init__ but do not
            # expose the freshly allocated receiver to a caller argument.
            constructor = self.index.fresh_constructor(info.path, call.func)
            if not candidates and constructor is not None:
                class_path, class_qualname = constructor
                candidates = self.index.method(class_path, class_qualname, "__init__")
                if candidates:
                    skip_first = True
                    fresh_result = True
        elif isinstance(call.func, ast.Attribute):
            attribute = call.func.attr
            if (
                isinstance(call.func.value, ast.Name)
                and (
                    call.func.value.id in info.aliases
                    or call.func.value.id in info.fresh_classes
                )
            ):
                if (
                    info.class_qualname is not None
                    and info.parameters
                    and call.func.value.id == info.parameters[0].name
                ):
                    candidates = self.index.method(info.path, info.class_qualname, attribute)
                    receiver = call.func.value
                    receiver_to_slot = True
                    skip_first = True
                if not candidates:
                    roots = info.aliases.get(call.func.value.id, set())
                    domains = {
                        info.parameter_classes[slot]
                        for slot in roots
                        if slot in info.parameter_classes
                    }
                    if len(roots) == 1 and len(domains) == 1:
                        class_path, class_qualname = next(iter(domains))
                        candidates = self.index.method(class_path, class_qualname, attribute)
                        if candidates:
                            receiver = call.func.value
                            receiver_to_slot = True
                            skip_first = True
                if not candidates and call.func.value.id in info.fresh_classes:
                    class_path, class_qualname = info.fresh_classes[call.func.value.id]
                    candidates = self.index.method(class_path, class_qualname, attribute)
                    if candidates:
                        receiver = call.func.value
                        receiver_to_slot = True
                        skip_first = True
            chain = dotted(call.func.value)
            if not candidates and chain:
                candidates = self.index.module_attribute(info.path, chain, attribute)
                class_names = self.index.classes_by_name.get((info.path, chain), ())
                if not candidates and len(class_names) == 1:
                    candidates = self.index.method(info.path, class_names[0], attribute)
                    if candidates:
                        target = self.index.functions[candidates[0]] if len(candidates) == 1 else None
                        if target and "staticmethod" in target.decorators:
                            skip_first = False
                        elif target and "classmethod" in target.decorators:
                            skip_first = True
                        else:
                            skip_first = False
            if not candidates:
                constructor = self.index.fresh_constructor(info.path, call.func)
                if constructor is not None:
                    class_path, class_qualname = constructor
                    candidates = self.index.method(class_path, class_qualname, "__init__")
                    if candidates:
                        skip_first = True
                        fresh_result = True
        if len(candidates) != 1:
            return None
        target = self.index.functions[candidates[0]]
        if target.decorators - TRANSPARENT_DECORATORS or "property" in target.decorators:
            return None
        if "staticmethod" in target.decorators:
            receiver = None
            receiver_to_slot = False
            skip_first = False
        elif "classmethod" in target.decorators:
            receiver = None
            receiver_to_slot = False
            skip_first = True
        return CallTarget(
            target.key, receiver, receiver_to_slot, skip_first, fresh_result
        )

    def _bind(
        self, call: ast.Call, target: CallTarget
    ) -> tuple[list[tuple[ast.AST, int]], str | None]:
        parameters_ = self.index.functions[target.key].parameters
        start = 1 if target.skip_first else 0
        positional_slots = [
            index
            for index, parameter in enumerate(parameters_)
            if index >= start and parameter.kind in {"positional-only", "positional-or-keyword"}
        ]
        vararg = next(
            (index for index, parameter in enumerate(parameters_) if parameter.kind == "var-positional"),
            None,
        )
        kwarg = next(
            (index for index, parameter in enumerate(parameters_) if parameter.kind == "var-keyword"),
            None,
        )
        by_name = {
            parameter.name: index
            for index, parameter in enumerate(parameters_)
            if index >= start and parameter.kind not in {"positional-only", "var-positional", "var-keyword"}
        }
        result: list[tuple[ast.AST, int]] = []
        assigned: set[int] = set()
        cursor = 0
        for argument in call.args:
            if isinstance(argument, ast.Starred):
                return [], "starred-positional"
            if cursor < len(positional_slots):
                slot = positional_slots[cursor]
                cursor += 1
            elif vararg is not None:
                slot = vararg
            else:
                return [], "too-many-positional"
            result.append((argument, slot)); assigned.add(slot)
        for keyword in call.keywords:
            if keyword.arg is None:
                return [], "starred-keyword"
            slot = by_name.get(keyword.arg, kwarg)
            if slot is None:
                return [], "unknown-keyword"
            if slot in assigned and slot != kwarg:
                return [], "duplicate-argument"
            result.append((keyword.value, slot)); assigned.add(slot)
        return result, None

    def _call(self, info: FunctionInfo, call: ast.Call) -> None:
        self.call_counts["total"] += 1
        roots = self._taint(call, info.aliases)
        target = self._resolve_call(info, call)
        if target is None:
            self.call_counts["unresolved"] += 1
            name = dotted(call.func) or type(call.func).__name__
            reason = "reflection-call" if name.rsplit(".", 1)[-1] in REFLECTION_NAMES else "unresolved-call"
            self.fallbacks[reason] += 1
            self._unsafe(info, roots, WRITE | ESCAPE | UNKNOWN, reason)
            return
        bound, error = self._bind(call, target)
        if error is not None:
            self.call_counts["binding-fallback"] += 1
            self.fallbacks[error] += 1
            self._unsafe(info, roots, WRITE | ESCAPE | UNKNOWN, error)
            return
        self.call_counts["resolved"] += 1
        if (
            isinstance(target.receiver, ast.Name)
            and target.receiver.id in info.fresh_classes
        ):
            info.fresh_calls.add(
                (call.lineno, call.col_offset, target.receiver.id, target.key)
            )
        if isinstance(call.func, ast.Call):
            self.call_counts["immediate-factory"] += 1
        if target.receiver_to_slot and target.receiver is not None:
            for caller_slot in self._alias_roots(info, target.receiver):
                self.edges.add(
                    Edge(info.key, caller_slot, target.key, 0, call.lineno, call.col_offset)
                )
                self.shared_calls[(info.key, caller_slot)].add((call.lineno, call.col_offset))
        for actual, callee_slot in bound:
            for caller_slot in self._alias_roots(info, actual):
                self.edges.add(
                    Edge(
                        info.key, caller_slot, target.key, callee_slot,
                        call.lineno, call.col_offset,
                    )
                )
                self.shared_calls[(info.key, caller_slot)].add((call.lineno, call.col_offset))

    def _direct(self, info: FunctionInfo) -> None:
        self._aliases(info)
        parents = {
            child: parent
            for parent in immediate_nodes(info.node)
            for child in ast.iter_child_nodes(parent)
        }
        globals_ = {
            name
            for node in immediate_nodes(info.node)
            if isinstance(node, (ast.Global, ast.Nonlocal))
            for name in node.names
        }
        for node in immediate_nodes(info.node):
            if isinstance(node, ast.Call):
                self._call(info, node)
            elif isinstance(node, (ast.Yield, ast.YieldFrom, ast.Raise)):
                value = node.exc if isinstance(node, ast.Raise) else node.value
                self._unsafe(
                    info, self._alias_roots(info, value), ESCAPE,
                    "yield-or-raise-escape",
                )
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                captured = self._taint(node, info.aliases)
                self._unsafe(info, captured, ESCAPE | UNKNOWN, "closure-or-class-capture")
            elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                value_roots = self._alias_roots(info, node.value)
                for target in targets:
                    if isinstance(target, ast.Name) and target.id in globals_:
                        self._unsafe(info, value_roots, ESCAPE, "global-or-nonlocal-store")
                    elif isinstance(target, (ast.Attribute, ast.Subscript)):
                        self._unsafe(info, value_roots, ESCAPE, "container-store")
                        self._unsafe(
                            info, self._alias_roots(info, target.value), WRITE,
                            "attribute-or-subscript-write",
                        )
            elif isinstance(node, ast.Delete):
                for target in node.targets:
                    if isinstance(target, (ast.Attribute, ast.Subscript)):
                        self._unsafe(
                            info, self._alias_roots(info, target.value), WRITE,
                            "attribute-or-subscript-delete",
                        )
            elif isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                self._unsafe(
                    info, self._alias_roots(info, node.value), WRITE,
                    "attribute-or-subscript-write",
                )
            elif isinstance(node, ast.AugAssign):
                self._unsafe(
                    info, self._alias_roots(info, node.target),
                    WRITE | UNKNOWN, "augmented-assignment",
                )
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                self._unsafe(
                    info, self._taint(node.iter, info.aliases),
                    WRITE | ESCAPE | UNKNOWN, "iteration-protocol",
                )
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    self._unsafe(
                        info, self._taint(item.context_expr, info.aliases),
                        WRITE | ESCAPE | UNKNOWN, "context-manager-protocol",
                    )
            elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
                parent = parents.get(node)
                if not (isinstance(parent, ast.Call) and parent.func is node):
                    self._unsafe(
                        info, self._taint(node.value, info.aliases),
                        WRITE | ESCAPE | UNKNOWN, "property-or-descriptor-read",
                    )
            elif isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
                self._unsafe(
                    info, self._taint(node.value, info.aliases),
                    WRITE | ESCAPE | UNKNOWN, "getitem-protocol",
                )
            elif isinstance(
                node,
                (ast.BinOp, ast.UnaryOp, ast.Compare, ast.BoolOp, ast.Await, ast.FormattedValue),
            ):
                # Identity comparisons are the only protocol-free comparisons.
                if isinstance(node, ast.Compare) and all(
                    isinstance(operation, (ast.Is, ast.IsNot)) for operation in node.ops
                ):
                    continue
                self._unsafe(
                    info, self._taint(node, info.aliases),
                    WRITE | ESCAPE | UNKNOWN, "dynamic-protocol",
                )

    def solve(self) -> dict[str, object]:
        alias_rounds = self._return_alias_fixed_point()
        fresh_rounds = self._fresh_fixed_point()
        for info in self.index.functions.values():
            self._direct(info)
            info.summary[:] = info.direct
        contained_fresh_calls = self._prove_contained_fresh_calls()
        changed = True
        rounds = 0
        ordered_edges = sorted(
            self.edges,
            key=lambda edge: (
                edge.caller, edge.caller_slot, edge.callee, edge.callee_slot,
                edge.line, edge.column,
            ),
        )
        while changed:
            changed = False
            rounds += 1
            for edge in ordered_edges:
                caller = self.index.functions[edge.caller]
                callee = self.index.functions[edge.callee]
                propagated = callee.summary[edge.callee_slot]
                value = caller.summary[edge.caller_slot] | propagated
                if value != caller.summary[edge.caller_slot]:
                    caller.summary[edge.caller_slot] = value
                    changed = True
            if rounds > len(self.index.functions) + 1:
                raise RuntimeError("non-monotone shared-argument fixed point")
        records = []
        summary_counts = Counter()
        for info in sorted(self.index.functions.values(), key=lambda item: item.key):
            slots = []
            for index, (parameter, flags) in enumerate(zip(info.parameters, info.summary)):
                summary_counts["slots"] += 1
                summary_counts["safe" if flags == 0 else "unsafe"] += 1
                if flags & WRITE:
                    summary_counts["write"] += 1
                if flags & ESCAPE:
                    summary_counts["escape"] += 1
                if flags & UNKNOWN:
                    summary_counts["unknown"] += 1
                slots.append(
                    [
                        parameter.name, parameter.kind, parameter.default, flags,
                        sorted(info.reasons.get(index, ())),
                    ]
                )
            records.append(
                [
                    info.key, info.path, info.qualname, info.node.lineno,
                    info.node.end_lineno or info.node.lineno, sorted(info.decorators), slots,
                    sorted(info.return_alias), sorted(info.fresh_names),
                    [[slot, *domain] for slot, domain in sorted(info.parameter_classes.items())],
                    [
                        [slot, factory, factory_slot]
                        for slot, (factory, factory_slot) in sorted(info.capture_from.items())
                    ],
                    [[name, *domain] for name, domain in sorted(info.fresh_classes.items())],
                    [list(call) for call in sorted(info.fresh_calls)],
                    [list(call) for call in sorted(info.contained_fresh_calls)],
                ]
            )
        shared = {
            key: sites for key, sites in self.shared_calls.items() if len(sites) >= 2
        }
        safe_shared = sum(
            self.index.functions[key[0]].summary[key[1]] == 0 for key in shared
        )
        return {
            "v": 2,
            "source_sha": PINNED_SOURCE_SHA,
            "source_sha256": PINNED_SOURCES_SHA256,
            "functions": records,
            "edges": [
                [edge.caller, edge.caller_slot, edge.callee, edge.callee_slot, edge.line, edge.column]
                for edge in ordered_edges
            ],
            "stats": {
                "functions": len(self.index.functions),
                "return_alias_rounds": alias_rounds,
                "return_alias_slots": sum(
                    len(info.return_alias) for info in self.index.functions.values()
                ),
                "fresh_result_rounds": fresh_rounds,
                "fresh_local_names": sum(
                    len(info.fresh_names) for info in self.index.functions.values()
                ),
                "fresh_local_classes": sum(
                    len(info.fresh_classes) for info in self.index.functions.values()
                ),
                "fresh_receiver_calls": sum(
                    len(info.fresh_calls) for info in self.index.functions.values()
                ),
                "contained_fresh_receiver_calls": contained_fresh_calls,
                "typed_formal_slots": sum(
                    len(info.parameter_classes) for info in self.index.functions.values()
                ),
                "captured_formal_slots": sum(
                    len(info.capture_from) for info in self.index.functions.values()
                ),
                "fixed_point_rounds": rounds,
                "summary": dict(sorted(summary_counts.items())),
                "calls": dict(sorted(self.call_counts.items())),
                "fallbacks": dict(sorted(self.fallbacks.items())),
                "edges": len(ordered_edges),
                "shared_formal_slots": len(shared),
                "safe_shared_formal_slots": safe_shared,
            },
        }


def load_sources(path: Path) -> dict[str, str]:
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PINNED_SOURCES_SHA256:
        raise SystemExit("wrong semantic source artifact")
    value = json.loads(gzip.decompress(raw))
    if not isinstance(value, dict) or any(
        type(key) is not str or type(source) is not str for key, source in value.items()
    ):
        raise SystemExit("malformed semantic source artifact")
    return value


def compact(document: dict[str, object]) -> bytes:
    return gzip.compress(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode(),
        compresslevel=9,
        mtime=0,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    document = SharedArgumentSolver(load_sources(args.sources)).solve()
    args.output.write_bytes(compact(document))
    print(json.dumps(document["stats"], sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
