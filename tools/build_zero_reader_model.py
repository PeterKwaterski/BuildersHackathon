#!/usr/bin/env python3
"""Build a conservative exact-reader dictionary-key certificate.

The input traces are answer-independent observations from the complete pinned
test suite.  A dictionary is admitted only when static taint proves its object
identity reaches keyed reads or key/shape-only operations and no value-wide or
opaque consumer. Each literal key records its complete set of owning tests,
including the empty set. The runtime selector still re-proves the patch shape.
"""

from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import json
import subprocess
from collections import defaultdict
from pathlib import Path


PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"
VALUE_WILDCARD = repr(("__BR_WILDCARD__", "values"))


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument(
        "--suite-nodeids",
        type=Path,
        required=True,
        help="nodeids captured by the successful unfiltered instrumented run",
    )
    parser.add_argument("--trace", type=Path, action="append", required=True)
    parser.add_argument("--child-trace", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def trace_files(paths: list[Path]) -> list[Path]:
    result = []
    for path in paths:
        if path.is_dir():
            result.extend(sorted(path.glob("*.json")))
        else:
            result.append(path)
    return result


def merge_traces(paths: list[Path]) -> dict[str, dict[str, set[str]]]:
    merged: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for path in paths:
        for label, events in json.loads(path.read_text()).items():
            for key, owners in events.items():
                merged[label][key].update(owners)
    return merged


def final_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def target_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def is_reference(node: ast.AST, names: set[str]) -> bool:
    return (
        isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Load)
        and node.id in names
    ) or (
        isinstance(node, ast.Attribute)
        and isinstance(node.ctx, ast.Load)
        and node.attr in names
    )


def callable_parameters(
    call: ast.Call, definitions: dict[str, list[ast.AST]]
) -> tuple[list[str], set[str]] | None:
    name = final_name(call.func)
    candidates = definitions.get(name or "", [])
    if len(candidates) != 1:
        return None
    definition = candidates[0]
    if isinstance(definition, ast.ClassDef):
        initializers = [
            item
            for item in definition.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            and item.name == "__init__"
        ]
        if len(initializers) != 1:
            return None
        function = initializers[0]
        positional = [*function.args.posonlyargs, *function.args.args][1:]
    elif isinstance(definition, (ast.FunctionDef, ast.AsyncFunctionDef)):
        function = definition
        positional = [*function.args.posonlyargs, *function.args.args]
    else:
        return None
    return [argument.arg for argument in positional], {
        argument.arg for argument in function.args.kwonlyargs
    }


def build_flow_model(
    modules: list[tuple[ast.Module, dict[ast.AST, ast.AST]]],
    definitions: dict[str, list[ast.AST]],
) -> tuple[dict[str, set[str]], set[str]]:
    """Index identity-preserving name flow and every unsafe value sink."""
    edges: dict[str, set[str]] = defaultdict(set)
    unsafe = set()
    keyed_methods = {"get", "__getitem__", "__contains__"}
    key_methods = {"keys"}
    for tree, parents in modules:
        def truth_only(node: ast.AST) -> bool:
            parent = parents.get(node)
            if isinstance(parent, (ast.If, ast.While)) and parent.test is node:
                return True
            if isinstance(parent, ast.IfExp) and parent.test is node:
                return True
            if isinstance(parent, ast.UnaryOp) and isinstance(parent.op, ast.Not):
                return truth_only(parent)
            if isinstance(parent, ast.BoolOp):
                return truth_only(parent)
            return (
                isinstance(parent, ast.Call)
                and isinstance(parent.func, ast.Name)
                and parent.func.id == "bool"
                and node in parent.args
            )

        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                name = node.id
            elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
                name = node.attr
            else:
                continue
            parent = parents.get(node)
            if isinstance(parent, (ast.Assign, ast.AnnAssign)) and parent.value is node:
                targets = parent.targets if isinstance(parent, ast.Assign) else [parent.target]
                target_names = [target_name(item) for item in targets]
                if any(target is None for target in target_names):
                    unsafe.add(name)
                else:
                    edges[name].update(target_names)
                continue
            if isinstance(parent, ast.Attribute) and parent.value is node:
                call = parents.get(parent)
                if (
                    parent.attr in keyed_methods | key_methods
                    and isinstance(call, ast.Call)
                    and call.func is parent
                ):
                    continue
                unsafe.add(name)
                continue
            if isinstance(parent, ast.Subscript) and parent.value is node:
                continue
            if isinstance(parent, ast.Compare):
                membership = any(
                    comparator is node and isinstance(operator, (ast.In, ast.NotIn))
                    for operator, comparator in zip(parent.ops, parent.comparators)
                )
                if membership:
                    continue
                unsafe.add(name)
                continue
            if isinstance(parent, ast.Call):
                if (
                    isinstance(parent.func, ast.Name)
                    and parent.func.id in {"bool", "len"}
                    and node in parent.args
                ):
                    continue
                parameters = callable_parameters(parent, definitions)
                if parameters is None:
                    unsafe.add(name)
                    continue
                positional, keyword_only = parameters
                if node in parent.args:
                    index = parent.args.index(node)
                    if index < len(positional):
                        edges[name].add(positional[index])
                        continue
                unsafe.add(name)
                continue
            if isinstance(parent, ast.keyword) and parent.value is node:
                call = parents.get(parent)
                if not isinstance(call, ast.Call):
                    unsafe.add(name)
                    continue
                parameters = callable_parameters(call, definitions)
                if parameters is None:
                    unsafe.add(name)
                    continue
                positional, keyword_only = parameters
                if parent.arg and parent.arg in set(positional) | keyword_only:
                    edges[name].add(parent.arg)
                    continue
                unsafe.add(name)
                continue
            if isinstance(parent, (ast.If, ast.While)) and parent.test is node:
                continue
            if isinstance(parent, ast.BoolOp):
                if truth_only(parent):
                    continue
                unsafe.add(name)
                continue
            if isinstance(parent, ast.IfExp) and parent.test is node:
                continue
            if isinstance(parent, ast.UnaryOp) and isinstance(parent.op, ast.Not):
                continue
            if isinstance(parent, (ast.For, ast.AsyncFor)) and parent.iter is node:
                continue
            if isinstance(parent, ast.comprehension) and parent.iter is node:
                continue
            unsafe.add(name)
    return edges, unsafe


def certified_target(seed: tuple, edges: dict[tuple, set[tuple]], unsafe: set[tuple]) -> bool:
    pending = [seed]
    reached = set()
    while pending:
        name = pending.pop()
        if name in reached:
            continue
        reached.add(name)
        if name in unsafe:
            return False
        pending.extend(edges.get(name, ()))
    return True


def build_scoped_flow_model(
    modules: list[tuple[str, ast.Module, dict[ast.AST, ast.AST]]],
) -> tuple[dict[tuple, set[tuple]], set[tuple], dict[tuple[str, int, str], tuple]]:
    """Build name flow without conflating unrelated modules, owners, or parameters.

    Attribute loads on ``self``/``cls`` conservatively reach every class
    binding with that attribute name.  Explicit ``ClassName.attribute`` loads
    resolve to that class when the class definition is unambiguous.
    """
    edges: dict[tuple, set[tuple]] = defaultdict(set)
    unsafe: set[tuple] = set()
    assignment_symbols: dict[tuple[str, int, str], tuple] = {}
    all_class_attributes: dict[str, set[tuple]] = defaultdict(set)
    dynamic_attributes: set[str] = set()
    named_class_attributes: dict[tuple[str, str], set[tuple]] = defaultdict(set)
    explicit_class_attributes: set[tuple[str, str]] = set()
    keyed_methods = {"get", "__getitem__", "__contains__"}
    key_methods = {"keys"}

    for relative, tree, parents in modules:
        containers = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)

        def owner(node: ast.AST) -> ast.AST:
            current = node
            while not isinstance(current, containers):
                current = parents[current]
            return current

        def container_id(node: ast.AST) -> tuple:
            if isinstance(node, ast.Module):
                return (relative, "module", 0)
            return (relative, type(node).__name__, node.lineno, node.name)

        bindings: dict[ast.AST, dict[str, tuple]] = defaultdict(dict)
        definitions: dict[tuple, ast.AST] = {}
        functions_by_name: dict[str, list[ast.AST]] = defaultdict(list)
        class_attributes: dict[str, set[tuple]] = defaultdict(set)

        def bind(scope: ast.AST, name: str) -> tuple:
            return bindings[scope].setdefault(name, (*container_id(scope), name))

        # Definitions are bindings in their enclosing scope. Parameters and
        # simple assignments are bindings in the scope that directly owns them.
        for node in ast.walk(tree):
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                parent_scope = owner(parents[node])
                symbol = bind(parent_scope, node.name)
                definitions[symbol] = node
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    functions_by_name[node.name].append(node)
                    arguments = [
                        *node.args.posonlyargs,
                        *node.args.args,
                        *node.args.kwonlyargs,
                    ]
                    if node.args.vararg:
                        arguments.append(node.args.vararg)
                    if node.args.kwarg:
                        arguments.append(node.args.kwarg)
                    for argument in arguments:
                        bind(node, argument.arg)
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                scope = owner(parents[node])
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        symbol = bind(scope, target.id)
                        if isinstance(scope, ast.ClassDef):
                            class_attributes[target.id].add(symbol)
                            all_class_attributes[target.id].add(symbol)
                            named_class_attributes[(scope.name, target.id)].add(symbol)
                        if isinstance(node.value, ast.Dict):
                            assignment_symbols[(relative, node.lineno, target.id)] = symbol

        def enclosing_scope(node: ast.AST) -> ast.AST:
            return owner(parents[node])

        def outer_scope(scope: ast.AST) -> ast.AST | None:
            if isinstance(scope, ast.Module):
                return None
            outer = owner(parents[scope])
            # A method does not lexically close over its class namespace.
            if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) and isinstance(
                outer, ast.ClassDef
            ):
                return owner(parents[outer])
            return outer

        def resolve_name(node: ast.Name) -> set[tuple]:
            scope = enclosing_scope(node)
            while scope is not None:
                symbol = bindings.get(scope, {}).get(node.id)
                if symbol is not None:
                    return {symbol}
                scope = outer_scope(scope)
            return {(relative, "unresolved", node.id)}

        def resolve_reference(node: ast.AST) -> set[tuple]:
            if isinstance(node, ast.Name):
                return resolve_name(node)
            if not isinstance(node, ast.Attribute):
                return set()
            if isinstance(node.value, ast.Name):
                if node.value.id in {"self", "cls"}:
                    dynamic_attributes.add(node.attr)
                    return {("dynamic_attribute", node.attr)}
                receiver = resolve_name(node.value)
                classes = [
                    definitions.get(symbol)
                    for symbol in receiver
                    if isinstance(definitions.get(symbol), ast.ClassDef)
                ]
                exact = {
                    bindings[class_node][node.attr]
                    for class_node in classes
                    if node.attr in bindings.get(class_node, {})
                }
                if exact:
                    return exact
                if node.value.id[:1].isupper():
                    key = (node.value.id, node.attr)
                    explicit_class_attributes.add(key)
                    return {("class_attribute", *key)}
            # Imported classes commonly have a module qualifier, for example
            # ``parser.Parser.FUNCTIONS``. The terminal class name still
            # identifies a unique pinned class, so keep its value-wide import
            # reads from poisoning every unrelated subclass dictionary.
            if (
                isinstance(node.value, ast.Attribute)
                and node.value.attr[:1].isupper()
            ):
                key = (node.value.attr, node.attr)
                explicit_class_attributes.add(key)
                return {("class_attribute", *key)}
            dynamic_attributes.add(node.attr)
            return {("dynamic_attribute", node.attr)}

        def target_symbols(node: ast.AST) -> set[tuple]:
            if isinstance(node, ast.Name):
                scope = enclosing_scope(node)
                return {bind(scope, node.id)}
            if isinstance(node, ast.Attribute):
                return resolve_reference(node)
            return set()

        def call_definitions(call: ast.Call) -> list[ast.AST]:
            if isinstance(call.func, ast.Name):
                return [
                    definitions[symbol]
                    for symbol in resolve_name(call.func)
                    if isinstance(
                        definitions.get(symbol), (ast.FunctionDef, ast.AsyncFunctionDef)
                    )
                ]
            if isinstance(call.func, ast.Attribute):
                return functions_by_name.get(call.func.attr, [])
            return []

        def parameter_for(
            call: ast.Call, definition: ast.AST, argument: ast.AST, keyword: str | None
        ) -> tuple | None:
            if not isinstance(definition, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return None
            positional = [*definition.args.posonlyargs, *definition.args.args]
            if isinstance(call.func, ast.Attribute) and positional and positional[0].arg in {
                "self",
                "cls",
            }:
                positional = positional[1:]
            if keyword is not None:
                names = {arg.arg: arg for arg in [*positional, *definition.args.kwonlyargs]}
                parameter = names.get(keyword)
            else:
                try:
                    parameter = positional[call.args.index(argument)]
                except (ValueError, IndexError):
                    parameter = None
            return bind(definition, parameter.arg) if parameter is not None else None

        def truth_only(node: ast.AST) -> bool:
            parent = parents.get(node)
            if isinstance(parent, (ast.If, ast.While)) and parent.test is node:
                return True
            if isinstance(parent, ast.IfExp) and parent.test is node:
                return True
            if isinstance(parent, ast.UnaryOp) and isinstance(parent.op, ast.Not):
                return truth_only(parent)
            if isinstance(parent, ast.BoolOp):
                return truth_only(parent)
            return (
                isinstance(parent, ast.Call)
                and isinstance(parent.func, ast.Name)
                and parent.func.id == "bool"
                and node in parent.args
            )

        for node in ast.walk(tree):
            if not (
                isinstance(node, (ast.Name, ast.Attribute))
                and isinstance(node.ctx, ast.Load)
            ):
                continue
            symbols = resolve_reference(node)
            if not symbols:
                continue
            parent = parents.get(node)
            if isinstance(parent, (ast.Assign, ast.AnnAssign)) and parent.value is node:
                targets = parent.targets if isinstance(parent, ast.Assign) else [parent.target]
                destinations = set().union(*(target_symbols(item) for item in targets))
                if not destinations:
                    unsafe.update(symbols)
                else:
                    for symbol in symbols:
                        edges[symbol].update(destinations)
                continue
            if isinstance(parent, ast.Attribute) and parent.value is node:
                call = parents.get(parent)
                if (
                    parent.attr in keyed_methods | key_methods
                    and isinstance(call, ast.Call)
                    and call.func is parent
                ):
                    continue
                unsafe.update(symbols)
                continue
            if isinstance(parent, ast.Subscript) and parent.value is node:
                continue
            if isinstance(parent, ast.Compare):
                membership = any(
                    comparator is node and isinstance(operator, (ast.In, ast.NotIn))
                    for operator, comparator in zip(parent.ops, parent.comparators)
                )
                if membership:
                    continue
                identity_none = all(
                    isinstance(operator, (ast.Is, ast.IsNot))
                    and (
                        isinstance(comparator, ast.Constant)
                        and comparator.value is None
                        or isinstance(parent.left, ast.Constant)
                        and parent.left.value is None
                    )
                    for operator, comparator in zip(parent.ops, parent.comparators)
                )
                if identity_none:
                    continue
                unsafe.update(symbols)
                continue
            call = parent if isinstance(parent, ast.Call) else None
            keyword = None
            if isinstance(parent, ast.keyword) and parent.value is node:
                call = parents.get(parent)
                keyword = parent.arg
            if isinstance(call, ast.Call):
                if (
                    isinstance(call.func, ast.Name)
                    and call.func.id in {"bool", "len"}
                    and node in call.args
                ):
                    continue
                candidates = call_definitions(call)
                destinations = {
                    parameter
                    for definition in candidates
                    for parameter in [parameter_for(call, definition, node, keyword)]
                    if parameter is not None
                }
                if not candidates or not destinations:
                    unsafe.update(symbols)
                else:
                    for symbol in symbols:
                        edges[symbol].update(destinations)
                continue
            if isinstance(parent, (ast.If, ast.While)) and parent.test is node:
                continue
            if isinstance(parent, ast.BoolOp):
                if truth_only(parent):
                    continue
                unsafe.update(symbols)
                continue
            if isinstance(parent, ast.IfExp) and parent.test is node:
                continue
            if isinstance(parent, ast.UnaryOp) and isinstance(parent.op, ast.Not):
                continue
            if isinstance(parent, (ast.For, ast.AsyncFor)) and parent.iter is node:
                continue
            if isinstance(parent, ast.comprehension) and parent.iter is node:
                continue
            unsafe.update(symbols)

        # Merge this module's scoped results into the global graph. Symbols
        # already carry their relative path, so unrelated owners stay distinct.
        # The dictionaries are shared across iterations by closure.
    for attribute in dynamic_attributes:
        dynamic = ("dynamic_attribute", attribute)
        for symbol in all_class_attributes.get(attribute, ()):
            edges[symbol].add(dynamic)
    for class_name, attribute in explicit_class_attributes:
        dynamic = ("class_attribute", class_name, attribute)
        for symbol in named_class_attributes.get((class_name, attribute), ()):
            edges[symbol].add(dynamic)
    return edges, unsafe, assignment_symbols


def main() -> None:
    args = arguments()
    source = args.source.resolve()
    revision = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    if revision != PINNED_SHA:
        raise SystemExit(f"source is {revision}, expected {PINNED_SHA}")

    test_ids = [
        test["id"] for test in json.loads(args.tests.read_text())["tests"]
    ]
    expected_tests = set(test_ids)
    completed_value = json.loads(args.suite_nodeids.read_text())
    if isinstance(completed_value, dict) and completed_value.get("exitstatus") != 0:
        raise SystemExit("instrumented suite manifest records a nonzero exit status")
    completed_tests = set(
        completed_value.get("tests", ())
        if isinstance(completed_value, dict)
        else completed_value
    )
    missing_tests = expected_tests - completed_tests
    if missing_tests:
        raise SystemExit(
            f"instrumented suite manifest is missing {len(missing_tests)} tests"
        )
    traces = merge_traces([*args.trace, *trace_files(args.child_trace)])
    unknown_owners = {
        owner
        for events in traces.values()
        for owners in events.values()
        for owner in owners
        if owner != "__NO_TEST__" and owner not in expected_tests
    }
    if unknown_owners:
        raise SystemExit(f"trace contains {len(unknown_owners)} unknown tests")

    modules = []
    scoped_modules = []
    definitions: dict[str, list[ast.AST]] = defaultdict(list)
    assignments = []
    for path in sorted((source / "sqlglot").rglob("*.py")):
        relative = path.relative_to(source).as_posix()
        tree = ast.parse(path.read_text(), filename=relative, type_comments=True)
        parents = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent
        modules.append((tree, parents))
        scoped_modules.append((relative, tree, parents))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                definitions[node.name].append(node)
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            if not isinstance(value, ast.Dict):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if len(targets) != 1 or not isinstance(targets[0], ast.Name):
                continue
            if not isinstance(parents.get(node), (ast.Module, ast.ClassDef)):
                continue
            target = targets[0].id
            label = f"{relative}:{node.lineno}:{node.end_lineno or node.lineno}:{target}"
            assignments.append((relative, node, target, label))

    legacy_edges, legacy_unsafe = build_flow_model(modules, definitions)
    flow_edges, unsafe_names, assignment_symbols = build_scoped_flow_model(scoped_modules)
    certificate_cache = {}
    legacy_certificate_cache = {}
    certified: dict[str, list[list[object]]] = defaultdict(list)
    for relative, node, target, label in assignments:
        events = traces.get(label)
        if not events or VALUE_WILDCARD in events:
            continue
        symbol = assignment_symbols.get((relative, node.lineno, target))
        if symbol is None:
            continue
        if symbol not in certificate_cache:
            certificate_cache[symbol] = certified_target(
                symbol, flow_edges, unsafe_names
            )
        if target not in legacy_certificate_cache:
            legacy_certificate_cache[target] = certified_target(
                target, legacy_edges, legacy_unsafe
            )
        scoped_certificate = certificate_cache[symbol]
        legacy_certificate = legacy_certificate_cache[target]
        if not (scoped_certificate or legacy_certificate):
            continue
        runtime_keys = []
        key_readers = {}
        valid = True
        for key in node.value.keys:
            # ``None`` is an unchanged ``**mapping`` entry. The wrapped final
            # dictionary still observes exact-key reads; only explicit literal
            # keys can be certified and changed at runtime.
            if key is None:
                continue
            try:
                runtime_key = ast.literal_eval(key)
                hash(runtime_key)
            except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                valid = False
                break
            if runtime_key in runtime_keys:
                valid = False
                break
            runtime_keys.append(runtime_key)
            owners = events.get(repr(runtime_key), ())
            if "__NO_TEST__" in owners:
                continue
            if not scoped_certificate and owners:
                # Preserve the already-audited legacy zero-reader proof, but
                # require the owner-aware scoped proof before narrowing a
                # nonzero reader set.
                continue
            key_readers[ast.dump(key, include_attributes=False)] = sorted(
                test_ids.index(owner) for owner in owners
            )
        if valid and key_readers:
            certified[relative].append(
                [node.lineno, node.end_lineno or node.lineno, target, key_readers]
            )

    output = {
        "v": 2,
        "sha": PINNED_SHA,
        "n": len(expected_tests),
        "t": hashlib.sha256("\0".join(test_ids).encode("utf-8")).hexdigest(),
        "d": {path: entries for path, entries in sorted(certified.items())},
    }
    payload = json.dumps(
        output, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    args.output.write_bytes(gzip.compress(payload, compresslevel=9, mtime=0))
    print(
        f"certified exact readers for {sum(len(entries) for entries in certified.values())} dictionaries "
        f"across {len(certified)} files"
    )


if __name__ == "__main__":
    main()
