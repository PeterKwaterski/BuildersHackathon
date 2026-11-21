#!/usr/bin/env python3
"""Trace ``arg_types`` reads and identity-linked ``required_args`` consumers.

This is an answer-independent provenance collector.  It instruments a temporary
copy of the pinned sqlglot checkout, executes the complete suite, and records
pytest node IDs for dictionary operations and for reads of sets derived by the
validated ``Expr.__init_subclass__`` hook.
"""

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

from collect_dict_access import (
    absolute_offset,
    source_offsets,
    synchronous_worker_tests,
    validate_source,
)


TRACKER = r'''from __future__ import annotations

import atexit
import builtins
import json
import os
from collections import defaultdict
from pathlib import Path

CURRENT_TEST = os.environ.get("BR_PARENT_TEST")
DICT_EVENTS = defaultdict(lambda: defaultdict(set))
KEY_ONLY_EVENTS = defaultdict(lambda: defaultdict(set))
DERIVED_READS = defaultdict(set)
DERIVED_KEY_READS = defaultdict(lambda: defaultdict(set))
DERIVED_ORDER_READS = defaultdict(set)
DERIVATIONS = defaultdict(set)
UNMAPPED_READS = set()
CONFLICTS = set()
DERIVED = {}

def owner():
    return CURRENT_TEST or "__NO_TEST__"

def record(label, key):
    DICT_EVENTS[label][repr(key)].add(owner())

def record_key_only(label, key):
    KEY_ONLY_EVENTS[label][repr(key)].add(owner())

class TrackingDict(dict):
    def __init__(self, source, label):
        super().__init__(source)
        self._br_label = label

    def __getitem__(self, key):
        record(self._br_label, key)
        return super().__getitem__(key)

    def get(self, key, default=None):
        record(self._br_label, key)
        return super().get(key, default)

    def __contains__(self, key):
        record_key_only(self._br_label, key)
        return super().__contains__(key)

    def __len__(self):
        record(self._br_label, ("__BR_WILDCARD__", "shape"))
        return super().__len__()

    def __iter__(self):
        record(self._br_label, ("__BR_WILDCARD__", "keys"))
        return super().__iter__()

    def __reversed__(self):
        record(self._br_label, ("__BR_WILDCARD__", "keys"))
        return super().__reversed__()

    def keys(self):
        record(self._br_label, ("__BR_WILDCARD__", "keys"))
        return super().keys()

    def items(self):
        record(self._br_label, ("__BR_WILDCARD__", "values"))
        return super().items()

    def values(self):
        record(self._br_label, ("__BR_WILDCARD__", "values"))
        return super().values()

    def copy(self):
        record(self._br_label, ("__BR_WILDCARD__", "values"))
        return super().copy()

    def setdefault(self, key, default=None):
        record(self._br_label, key)
        return super().setdefault(key, default)

    def pop(self, key, *default):
        record(self._br_label, key)
        return super().pop(key, *default)

    def popitem(self):
        record(self._br_label, ("__BR_WILDCARD__", "values"))
        return super().popitem()

    def __setitem__(self, key, value):
        record(self._br_label, key)
        return super().__setitem__(key, value)

    def __delitem__(self, key):
        record(self._br_label, key)
        return super().__delitem__(key)

    def clear(self):
        record(self._br_label, ("__BR_WILDCARD__", "shape"))
        return super().clear()

    def update(self, *args, **kwargs):
        record(self._br_label, ("__BR_WILDCARD__", "values"))
        return super().update(*args, **kwargs)

    def __or__(self, other):
        record(self._br_label, ("__BR_WILDCARD__", "values"))
        return super().__or__(other)

    def __ror__(self, other):
        record(self._br_label, ("__BR_WILDCARD__", "values"))
        return super().__ror__(other)

    def __ior__(self, other):
        record(self._br_label, ("__BR_WILDCARD__", "values"))
        return super().__ior__(other)

    def __eq__(self, other):
        record(self._br_label, ("__BR_WILDCARD__", "values"))
        return super().__eq__(other)

    def __ne__(self, other):
        record(self._br_label, ("__BR_WILDCARD__", "values"))
        return super().__ne__(other)

    def __repr__(self):
        record(self._br_label, ("__BR_WILDCARD__", "values"))
        return super().__repr__()

    def __str__(self):
        record(self._br_label, ("__BR_WILDCARD__", "values"))
        return super().__str__()

    def __sizeof__(self):
        record(self._br_label, ("__BR_WILDCARD__", "shape"))
        return super().__sizeof__()

def trace_dict(label, source):
    return TrackingDict(source, label)

def derivation_items(source):
    # The builder validates the only injected call site as the exact
    # Expr.__init_subclass__ derivation.  Bypass TrackingDict.items here so
    # ordinary value-wide readers remain distinguishable in the trace.
    return dict.items(source)

def derive(source, result, attribute):
    label = getattr(source, "_br_label", None)
    if not isinstance(label, str):
        return result
    identity = id(result)
    prior = DERIVED.get(identity)
    if prior is not None and (
        prior[0] is not result
        or prior[1] != label
        or prior[2] != attribute
        or prior[3] is not source
    ):
        CONFLICTS.add(owner())
        return result
    DERIVED[identity] = (result, label, attribute, source)
    DERIVATIONS[label].add(owner())
    return result

def read_derived(result, attribute, values):
    mapping = DERIVED.get(id(result))
    if mapping is None or mapping[0] is not result or mapping[2] != attribute:
        UNMAPPED_READS.add(owner())
        return result
    label = mapping[1]
    DERIVED_READS[label].add(owner())
    # Record only keys whose requiredness can affect this invocation.  A
    # present nonempty value behaves identically whether the key is optional
    # or required; a missing/None/empty-list value can change the errors.
    source = mapping[3]
    missing_required = False
    for key in dict.keys(source):
        value = values.get(key)
        if value is None or (isinstance(value, list) and not value):
            DERIVED_KEY_READS[label][repr(key)].add(owner())
            if dict.__getitem__(source, key):
                missing_required = True
    # Adding/removing even a present key can change a set's iteration order.
    # If another currently required key is missing, conservatively retain the
    # owner for every candidate key because error ordering may be observable.
    if missing_required:
        DERIVED_ORDER_READS[label].add(owner())
    return result

def document():
    return {
        "conflicts": sorted(CONFLICTS),
        "derived": {label: sorted(owners) for label, owners in sorted(DERIVED_READS.items())},
        "derived_keys": {
            label: {key: sorted(owners) for key, owners in sorted(events.items())}
            for label, events in sorted(DERIVED_KEY_READS.items())
        },
        "derived_order": {
            label: sorted(owners) for label, owners in sorted(DERIVED_ORDER_READS.items())
        },
        "derivations": {label: sorted(owners) for label, owners in sorted(DERIVATIONS.items())},
        "dict": {
            label: {key: sorted(owners) for key, owners in sorted(events.items())}
            for label, events in sorted(DICT_EVENTS.items())
        },
        "keys": {
            label: {key: sorted(owners) for key, owners in sorted(events.items())}
            for label, events in sorted(KEY_ONLY_EVENTS.items())
        },
        "unmapped": sorted(UNMAPPED_READS),
    }

def write_child():
    directory = os.environ.get("ARG_DERIVATION_CHILD_DIR")
    if not directory or not CURRENT_TEST:
        return
    path = Path(directory, f"{os.getpid()}.json")
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(document(), sort_keys=True, separators=(",", ":")))
    temporary.replace(path)

builtins._br_trace_dict = trace_dict
builtins._br_derivation_items = derivation_items
builtins._br_derive = derive
builtins._br_read_derived = read_derived
atexit.register(write_child)
'''


PLUGIN = r'''from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import _br_arg_derivation

EXECUTED = set()

@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_protocol(item, nextitem):
    EXECUTED.add(item.nodeid)
    _br_arg_derivation.CURRENT_TEST = item.nodeid
    os.environ["BR_PARENT_TEST"] = item.nodeid
    try:
        yield
    finally:
        _br_arg_derivation.CURRENT_TEST = None
        os.environ.pop("BR_PARENT_TEST", None)

def merge(document):
    for label, events in document.get("dict", {}).items():
        for key, owners in events.items():
            _br_arg_derivation.DICT_EVENTS[label][key].update(owners)
    for label, events in document.get("keys", {}).items():
        for key, owners in events.items():
            _br_arg_derivation.KEY_ONLY_EVENTS[label][key].update(owners)
    for label, owners in document.get("derived", {}).items():
        _br_arg_derivation.DERIVED_READS[label].update(owners)
    for label, events in document.get("derived_keys", {}).items():
        for key, owners in events.items():
            _br_arg_derivation.DERIVED_KEY_READS[label][key].update(owners)
    for label, owners in document.get("derived_order", {}).items():
        _br_arg_derivation.DERIVED_ORDER_READS[label].update(owners)
    for label, owners in document.get("derivations", {}).items():
        _br_arg_derivation.DERIVATIONS[label].update(owners)
    _br_arg_derivation.UNMAPPED_READS.update(document.get("unmapped", ()))
    _br_arg_derivation.CONFLICTS.update(document.get("conflicts", ()))

def pytest_sessionfinish(session, exitstatus):
    child_count = 0
    for path in sorted(Path(os.environ["ARG_DERIVATION_CHILD_DIR"]).glob("*.json")):
        child_count += 1
        merge(json.loads(path.read_text()))
    Path(os.environ["ARG_DERIVATION_TRACE"]).write_text(
        json.dumps(_br_arg_derivation.document(), sort_keys=True, separators=(",", ":"))
    )
    Path(os.environ["ARG_DERIVATION_MANIFEST"]).write_text(json.dumps({
        "child_logs": child_count,
        "exitstatus": exitstatus,
        "mode": os.environ["ARG_DERIVATION_MODE"],
        "tests": sorted(EXECUTED),
    }, sort_keys=True, separators=(",", ":")))
'''


HOOK_OLD = "cls.required_args = {k for k, v in cls.arg_types.items() if v}"
HOOK_NEW = (
    'cls.required_args = _br_derive('
    'cls.arg_types, {k for k, v in _br_derivation_items(cls.arg_types) if v}, '
    '"required_args")'
)
READ_OLD = "for k in self.required_args:"
READ_NEW = 'for k in _br_read_derived(self.required_args, "required_args", self.args):'


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


def replace_once(path: Path, old: str, new: str) -> None:
    source = path.read_text()
    if source.count(old) != 1:
        raise SystemExit(f"expected one pinned marker in {path}: {old!r}")
    path.write_text(source.replace(old, new))


def instrument_dictionaries(source: Path) -> int:
    count = 0
    for path in sorted((source / "sqlglot").rglob("*.py")):
        text = path.read_text()
        tree = ast.parse(text, filename=path.as_posix(), type_comments=True)
        parents = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent
        lines, offsets = source_offsets(text)
        edits = []
        relative = path.relative_to(source).as_posix()
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)) or not isinstance(node.value, ast.Dict):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if len(targets) != 1 or not isinstance(targets[0], ast.Name):
                continue
            if not isinstance(parents.get(node), (ast.Module, ast.ClassDef)):
                continue
            label = f"{relative}:{node.lineno}:{node.end_lineno or node.lineno}:{targets[0].id}"
            start = absolute_offset(lines, offsets, node.value.lineno, node.value.col_offset)
            end = absolute_offset(lines, offsets, node.value.end_lineno, node.value.end_col_offset)
            edits.extend(((end, ")"), (start, f"_br_trace_dict({label!r}, ")))
            count += 1
        for position, replacement in sorted(edits, reverse=True):
            text = text[:position] + replacement + text[position:]
        if edits:
            path.write_text(text)
    return count


def main() -> None:
    args = arguments()
    source = args.source.resolve()
    python = args.python.expanduser().absolute()
    output = args.output.resolve()
    manifest = args.manifest.resolve()
    validate_source(source)
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="blast-radius-arg-derivation-") as temporary:
        temporary_path = Path(temporary)
        work = temporary_path / "sqlglot"
        support = temporary_path / "support"
        children = temporary_path / "children"
        shutil.copytree(source, work, ignore=shutil.ignore_patterns(
            ".git", ".pytest_cache", ".coverage*", "__pycache__", "*.pyc"
        ))
        support.mkdir()
        children.mkdir()
        (support / "_br_arg_derivation.py").write_text(TRACKER)
        (support / "arg_derivation_plugin.py").write_text(PLUGIN)
        (support / "sitecustomize.py").write_text("import _br_arg_derivation\n")

        core = work / "sqlglot/expressions/core.py"
        replace_once(core, HOOK_OLD, HOOK_NEW)
        replace_once(core, READ_OLD, READ_NEW)
        if args.synchronous_workers:
            synchronous_worker_tests(work)
        instrumented = instrument_dictionaries(work)

        environment = os.environ.copy()
        environment.update({
            "ARG_DERIVATION_CHILD_DIR": str(children),
            "ARG_DERIVATION_MANIFEST": str(manifest),
            "ARG_DERIVATION_MODE": "synchronous-worker" if args.synchronous_workers else "normal",
            "ARG_DERIVATION_TRACE": str(output),
            "PYTHONPATH": os.pathsep.join((str(support), str(work), environment.get("PYTHONPATH", ""))).rstrip(os.pathsep),
            "SKIP_INTEGRATION": "0",
        })
        command = [str(python), "-m", "pytest", "-q", "-p", "arg_derivation_plugin"]
        command.extend(arg for arg in args.pytest_args if arg != "--")
        result = subprocess.run(command, cwd=work, env=environment, check=False)
        if result.returncode:
            raise SystemExit(f"pytest exited {result.returncode}; trace is not admissible")

    manifest_doc = json.loads(manifest.read_text())
    expected = {test["id"] for test in json.loads(args.tests.read_text())["tests"]}
    missing = expected - set(manifest_doc.get("tests", ()))
    if manifest_doc.get("exitstatus") != 0 or missing:
        raise SystemExit(f"suite manifest is inadmissible; {len(missing)} runtime tests missing")
    print(
        f"wrote {output} from {instrumented} dictionaries, {manifest_doc['mode']} mode, "
        f"and {len(manifest_doc['tests'])} pytest nodes"
    )


if __name__ == "__main__":
    main()
