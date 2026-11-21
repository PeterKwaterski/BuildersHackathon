#!/usr/bin/env python3
"""Trace owner-resolved reads of literal class attributes in the pinned suite."""

from __future__ import annotations

import argparse
import ast
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from collect_dict_access import synchronous_worker_tests, validate_source


SAFE = (type(None), bool, int, float, complex, str, bytes)


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--synchronous-workers", action="store_true")
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER)
    return parser.parse_args()


def safe_literal(value) -> bool:
    return type(value) in SAFE or (
        type(value) is tuple and all(safe_literal(item) for item in value)
    )


def source_labels(source: Path) -> dict[tuple[str, str, str], str]:
    labels: dict[tuple[str, str, str], str | None] = {}
    for path in sorted((source / "sqlglot").rglob("*.py")):
        relative = path.relative_to(source).as_posix()
        module = relative.removesuffix("/__init__.py").removesuffix(".py").replace("/", ".")
        tree = ast.parse(path.read_text(), filename=relative, type_comments=True)

        def visit(body: list[ast.stmt], owners: tuple[str, ...]) -> None:
            for statement in body:
                if isinstance(statement, ast.ClassDef):
                    qualname = ".".join((*owners, statement.name))
                    for item in statement.body:
                        if isinstance(item, ast.Assign):
                            targets = item.targets
                        elif isinstance(item, ast.AnnAssign):
                            targets = [item.target]
                        else:
                            continue
                        if len(targets) != 1 or not isinstance(targets[0], ast.Name):
                            continue
                        value_node = getattr(item, "value", None)
                        if value_node is None:
                            continue
                        try:
                            value = ast.literal_eval(value_node)
                        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                            continue
                        if not safe_literal(value):
                            continue
                        name = targets[0].id
                        label = (
                            f"{relative}:{item.lineno}:{item.end_lineno or item.lineno}:"
                            f"{qualname}:{name}"
                        )
                        key = (module, qualname, name)
                        labels[key] = label if key not in labels else None
                    visit(statement.body, (*owners, statement.name))

        visit(tree.body, ())
    return {key: label for key, label in labels.items() if label is not None}


TRACKER_TEMPLATE = r'''from __future__ import annotations

import atexit
import builtins
import inspect
import json
import os
from collections import defaultdict
from pathlib import Path

CURRENT_TEST = os.environ.get("BR_PARENT_TEST")
EVENTS = defaultdict(lambda: defaultdict(set))
LABELS = __LABELS__

def owner():
    return CURRENT_TEST or "__NO_TEST__"

def class_chain(value):
    if isinstance(value, type):
        seen = set()
        for base in (*value.__mro__, *type(value).__mro__):
            if base not in seen:
                seen.add(base)
                yield base
        return
    try:
        namespace = object.__getattribute__(value, "__dict__")
    except BaseException:
        namespace = None
    if isinstance(namespace, dict):
        yield None
    yield from type(value).__mro__

def label_for(value, name):
    for base in class_chain(value):
        if base is None:
            # An instance attribute shadows every class assignment.
            if name in object.__getattribute__(value, "__dict__"):
                return None
            continue
        try:
            namespace = type.__getattribute__(base, "__dict__")
        except BaseException:
            continue
        if name not in namespace:
            continue
        return LABELS.get((base.__module__, base.__qualname__, name))
    return None

def record(value, name, kind="read"):
    label = label_for(value, name)
    if label:
        EVENTS[label][kind].add(owner())

def record_all(value, kind="reflect"):
    for base in class_chain(value):
        if base is None:
            continue
        prefix = (base.__module__, base.__qualname__)
        for (module, qualname, name), label in LABELS.items():
            if (module, qualname) == prefix:
                EVENTS[label][kind].add(owner())

def class_attr(value, name):
    result = getattr(value, name)
    record(value, name)
    return result

def traced_getattr(value, name, *default):
    result = builtins.getattr(value, name, *default)
    if type(name) is str:
        record(value, name)
    else:
        record_all(value)
    return result

def traced_hasattr(value, name):
    # Literal class assignments are always present; a value-only change cannot
    # affect ``hasattr`` or ``dir``.
    return builtins.hasattr(value, name)

def traced_setattr(value, name, new_value):
    if type(name) is str:
        record(value, name, "mutation")
    else:
        record_all(value, "mutation")
    return builtins.setattr(value, name, new_value)

def traced_delattr(value, name):
    if type(name) is str:
        record(value, name, "mutation")
    else:
        record_all(value, "mutation")
    return builtins.delattr(value, name)

def traced_vars(value):
    result = builtins.vars(value)
    return TrackingNamespace(value, result) if isinstance(value, type) else result

def traced_dir(value):
    return builtins.dir(value)

class TrackingNamespace:
    def __init__(self, value, source):
        self._value = value
        self._source = source

    def __getitem__(self, key):
        record(self._value, key)
        return self._source[key]

    def get(self, key, default=None):
        record(self._value, key)
        return self._source.get(key, default)

    def __contains__(self, key):
        return key in self._source

    def __len__(self):
        return len(self._source)

    def __iter__(self):
        return iter(self._source)

    def __reversed__(self):
        return reversed(self._source)

    def keys(self):
        return self._source.keys()

    def items(self):
        record_all(self._value)
        return self._source.items()

    def values(self):
        record_all(self._value)
        return self._source.values()

    def copy(self):
        record_all(self._value)
        return self._source.copy()

    def __or__(self, other):
        record_all(self._value)
        return self._source | other

    def __ror__(self, other):
        record_all(self._value)
        return other | self._source

    def __repr__(self):
        record_all(self._value)
        return repr(self._source)

def traced_class_dict(value):
    result = getattr(value, "__dict__")
    return TrackingNamespace(value, result) if isinstance(value, type) else result

def traced_reflect_call(function, value, *args, **kwargs):
    result = function(value, *args, **kwargs)
    record_all(value)
    return result

def document():
    return {
        label: {kind: sorted(owners) for kind, owners in sorted(events.items())}
        for label, events in sorted(EVENTS.items())
    }

def write_child():
    directory = os.environ.get("CLASS_ATTR_CHILD_DIR")
    if not directory or not CURRENT_TEST:
        return
    path = Path(directory, f"{os.getpid()}.json")
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(document(), sort_keys=True, separators=(",", ":")))
    temporary.replace(path)

builtins._br_class_attr = class_attr
builtins._br_getattr = traced_getattr
builtins._br_hasattr = traced_hasattr
builtins._br_setattr = traced_setattr
builtins._br_delattr = traced_delattr
builtins._br_vars = traced_vars
builtins._br_dir = traced_dir
builtins._br_class_dict = traced_class_dict
builtins._br_reflect_call = traced_reflect_call
atexit.register(write_child)
'''


PLUGIN = r'''from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import _br_class_attribute

EXECUTED = set()

@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_protocol(item, nextitem):
    EXECUTED.add(item.nodeid)
    _br_class_attribute.CURRENT_TEST = item.nodeid
    os.environ["BR_PARENT_TEST"] = item.nodeid
    try:
        yield
    finally:
        _br_class_attribute.CURRENT_TEST = None
        os.environ.pop("BR_PARENT_TEST", None)

def pytest_sessionfinish(session, exitstatus):
    child_count = 0
    for path in sorted(Path(os.environ["CLASS_ATTR_CHILD_DIR"]).glob("*.json")):
        child_count += 1
        for label, events in json.loads(path.read_text()).items():
            for kind, owners in events.items():
                _br_class_attribute.EVENTS[label][kind].update(owners)
    Path(os.environ["CLASS_ATTR_TRACE"]).write_text(
        json.dumps(_br_class_attribute.document(), sort_keys=True, separators=(",", ":"))
    )
    Path(os.environ["CLASS_ATTR_MANIFEST"]).write_text(json.dumps({
        "child_logs": child_count,
        "exitstatus": exitstatus,
        "mode": os.environ["CLASS_ATTR_MODE"],
        "tests": sorted(EXECUTED),
    }, sort_keys=True, separators=(",", ":")))
'''


class Instrumenter(ast.NodeTransformer):
    def __init__(self, attribute_names: set[str]):
        self.attribute_names = attribute_names
        self.count = 0

    def visit_Attribute(self, node: ast.Attribute):
        node = self.generic_visit(node)
        if not isinstance(node.ctx, ast.Load):
            return node
        if node.attr == "__dict__":
            self.count += 1
            return ast.copy_location(
                ast.Call(ast.Name("_br_class_dict", ast.Load()), [node.value], []), node
            )
        if node.attr in self.attribute_names:
            self.count += 1
            return ast.copy_location(
                ast.Call(
                    ast.Name("_br_class_attr", ast.Load()),
                    [node.value, ast.Constant(node.attr)],
                    [],
                ),
                node,
            )
        return node

    def visit_Call(self, node: ast.Call):
        node = self.generic_visit(node)
        if isinstance(node.func, ast.Name):
            wrappers = {
                "getattr": "_br_getattr",
                "hasattr": "_br_hasattr",
                "setattr": "_br_setattr",
                "delattr": "_br_delattr",
                "vars": "_br_vars",
                "dir": "_br_dir",
            }
            wrapper = wrappers.get(node.func.id)
            if wrapper and node.args and not (
                node.func.id in {"vars", "dir"} and len(node.args) != 1
            ):
                self.count += 1
                node.func = ast.copy_location(ast.Name(wrapper, ast.Load()), node.func)
                return node
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"getmembers", "getmembers_static"}
            and node.args
        ):
            self.count += 1
            return ast.copy_location(
                ast.Call(
                    ast.Name("_br_reflect_call", ast.Load()),
                    [node.func, *node.args],
                    node.keywords,
                ),
                node,
            )
        return node


def instrument_tree(path: Path, attribute_names: set[str]) -> int:
    text = path.read_text()
    tree = ast.parse(text, filename=path.as_posix(), type_comments=True)
    instrumenter = Instrumenter(attribute_names)
    changed = instrumenter.visit(tree)
    if instrumenter.count:
        ast.fix_missing_locations(changed)
        path.write_text(ast.unparse(changed) + "\n")
    return instrumenter.count


def main() -> None:
    args = arguments()
    source = args.source.resolve()
    python = args.python.expanduser().absolute()
    output = args.output.resolve()
    manifest = args.manifest.resolve()
    validate_source(source)
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest.parent.mkdir(parents=True, exist_ok=True)
    labels = source_labels(source)
    names = {name for _, _, name in labels}

    with tempfile.TemporaryDirectory(prefix="blast-radius-class-attribute-") as temporary:
        temporary_path = Path(temporary)
        work = temporary_path / "sqlglot"
        support = temporary_path / "support"
        children = temporary_path / "children"
        shutil.copytree(source, work, ignore=shutil.ignore_patterns(
            ".git", ".pytest_cache", ".coverage*", "__pycache__", "*.pyc"
        ))
        support.mkdir()
        children.mkdir()
        tracker = TRACKER_TEMPLATE.replace("__LABELS__", repr(labels))
        (support / "_br_class_attribute.py").write_text(tracker)
        (support / "class_attribute_plugin.py").write_text(PLUGIN)
        (support / "sitecustomize.py").write_text("import _br_class_attribute\n")
        if args.synchronous_workers:
            synchronous_worker_tests(work)
        instrumented = 0
        for root_name in ("sqlglot", "tests"):
            for path in sorted((work / root_name).rglob("*.py")):
                instrumented += instrument_tree(path, names)
        environment = os.environ.copy()
        environment.update({
            "CLASS_ATTR_CHILD_DIR": str(children),
            "CLASS_ATTR_MANIFEST": str(manifest),
            "CLASS_ATTR_MODE": "synchronous-worker" if args.synchronous_workers else "normal",
            "CLASS_ATTR_TRACE": str(output),
            "PYTHONPATH": os.pathsep.join((str(support), str(work), environment.get("PYTHONPATH", ""))).rstrip(os.pathsep),
            "SKIP_INTEGRATION": "0",
        })
        command = [str(python), "-m", "pytest", "-q", "-p", "class_attribute_plugin"]
        command.extend(argument for argument in args.pytest_args if argument != "--")
        result = subprocess.run(command, cwd=work, env=environment, check=False)
        if result.returncode:
            raise SystemExit(f"pytest exited {result.returncode}; trace is not admissible")

    document = json.loads(manifest.read_text())
    expected = {test["id"] for test in json.loads(args.tests.read_text())["tests"]}
    missing = expected - set(document.get("tests", ()))
    if document.get("exitstatus") != 0 or missing:
        raise SystemExit(f"inadmissible suite manifest; {len(missing)} tests missing")
    print(
        f"wrote {output} from {len(labels)} class attributes, "
        f"{instrumented} read sites, and {len(document['tests'])} tests"
    )


if __name__ == "__main__":
    main()
