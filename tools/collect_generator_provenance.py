#!/usr/bin/env python3
"""Resolve source TRANSFORMS entries into effective generator dispatch tables."""

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

from collect_dict_access import validate_source
from collect_generator_dispatch import absolute_offset, source_offsets, transform_assignments


SUPPORT = r'''from __future__ import annotations
import builtins

class Origin:
    __slots__ = ("label", "value")
    def __init__(self, label, value):
        self.label = label
        self.value = value
    def __call__(self, *args, **kwargs):
        return self.value(*args, **kwargs)

def origin(label, value):
    return Origin(label, value)

builtins._br_generator_origin = origin
'''


DRIVER = r'''from __future__ import annotations
import importlib
import json
import pkgutil
import sys
from pathlib import Path
import sqlglot.dialects as dialects
import sqlglot.generators as generators
from sqlglot.generator import Generator
from sqlglot import expressions as exp
from _br_generator_origin import Origin

module_names = sorted(
    (module.name for module in pkgutil.iter_modules(generators.__path__, generators.__name__ + ".")),
    reverse=__REVERSE__,
)
for module_name in module_names:
    importlib.import_module(module_name)
dialect_names = sorted(dialects.__all__, reverse=__REVERSE__)
for name in dialect_names:
    getattr(dialects, name)

def subclasses(root):
    result, pending, seen = [], [root], set()
    while pending:
        cls = pending.pop()
        if cls in seen:
            continue
        seen.add(cls)
        result.append(cls)
        pending.extend(cls.__subclasses__())
    return result

classes = {}
opaque = []
origins = {}
json_path_keys = set()
for cls in sorted(subclasses(Generator), key=lambda value: (value.__module__, value.__qualname__)):
    class_name = f"{cls.__module__}.{cls.__qualname__}"
    entries = {}
    transforms = getattr(cls, "TRANSFORMS", None)
    if not isinstance(transforms, dict):
        opaque.append([class_name, "non-dict TRANSFORMS"])
        continue
    for key, value in transforms.items():
        key_name = f"{key.__module__}.{key.__qualname__}" if isinstance(key, type) else None
        if key_name is None:
            opaque.append([class_name, f"non-type key:{type(key).__module__}.{type(key).__qualname__}"])
            continue
        if issubclass(key, exp.JSONPathPart):
            json_path_keys.add(key_name)
        if isinstance(value, Origin):
            entries[key_name] = value.label
            origins.setdefault(value.label, set()).add(key_name)
    classes[class_name] = entries
Path(__OUTPUT__).write_text(json.dumps({
    "classes": classes,
    "opaque": opaque,
    "origins": {label: sorted(keys) for label, keys in sorted(origins.items())},
    "json_path_keys": sorted(json_path_keys),
    "import_mode": __IMPORT_MODE__,
    "dialects": dialect_names,
    "modules": module_names,
    "python": sys.version,
    "source_sha": __SOURCE_SHA__,
}, sort_keys=True, separators=(",", ":")))
'''


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reverse-imports", action="store_true")
    return parser.parse_args()


def instrument_values(source: Path) -> tuple[int, set[str]]:
    count = 0
    labels: set[str] = set()
    for path in sorted((source / "sqlglot").rglob("*.py")):
        text = path.read_text()
        tree = ast.parse(text, filename=path.as_posix(), type_comments=True)
        lines, offsets = source_offsets(text)
        edits: list[tuple[int, str]] = []
        relative = path.relative_to(source).as_posix()
        for statement, owner in transform_assignments(tree):
            for index, (key, value) in enumerate(zip(statement.value.keys, statement.value.values)):
                if key is None:
                    continue
                if not (
                    isinstance(key, ast.Attribute)
                    and isinstance(key.value, ast.Name)
                    and key.value.id == "exp"
                ):
                    raise SystemExit(f"unsupported TRANSFORMS key in {relative}:{key.lineno}")
                label = (
                    f"{relative}:{statement.lineno}:{statement.end_lineno or statement.lineno}:"
                    f"{'.'.join(owner)}:{index}:{key.attr}"
                )
                if label in labels:
                    raise SystemExit(f"duplicate source entry label {label}")
                labels.add(label)
                start = absolute_offset(lines, offsets, value.lineno, value.col_offset)
                end = absolute_offset(lines, offsets, value.end_lineno, value.end_col_offset)
                edits.extend(((end, ")"), (start, f"_br_generator_origin({label!r}, ")))
                count += 1
        for position, replacement in sorted(edits, reverse=True):
            text = text[:position] + replacement + text[position:]
        if edits:
            path.write_text(text)
    return count, labels


def main() -> None:
    args = arguments()
    source = args.source.resolve()
    python = args.python.expanduser().absolute()
    output = args.output.resolve()
    validate_source(source)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="blast-radius-generator-provenance-") as temporary:
        root = Path(temporary)
        work, support = root / "sqlglot", root / "support"
        shutil.copytree(source, work, ignore=shutil.ignore_patterns(
            ".git", ".pytest_cache", ".coverage*", "__pycache__", "*.pyc"
        ))
        support.mkdir()
        count, labels = instrument_values(work)
        (support / "_br_generator_origin.py").write_text(SUPPORT)
        (support / "sitecustomize.py").write_text("import _br_generator_origin\n")
        driver = (
            DRIVER.replace("__OUTPUT__", repr(str(output)))
            .replace("__SOURCE_SHA__", repr("eb11aec4be8cb2122afe713a4816662c3f0fb2fa"))
            .replace("__REVERSE__", repr(args.reverse_imports))
            .replace("__IMPORT_MODE__", repr("reverse" if args.reverse_imports else "forward"))
        )
        driver_path = root / "driver.py"
        driver_path.write_text(driver)
        environment = os.environ.copy()
        environment["PYTHONPATH"] = os.pathsep.join(
            (str(support), str(work), environment.get("PYTHONPATH", ""))
        ).rstrip(os.pathsep)
        subprocess.run([str(python), str(driver_path)], cwd=work, env=environment, check=True)
    document = json.loads(output.read_text())
    if not isinstance(document.get("python"), str) or not document["python"].startswith("3.13."):
        raise SystemExit(f"production provenance requires Python 3.13, got {document.get('python')!r}")
    effective = {
        label
        for entries in document.get("classes", {}).values()
        for label in entries.values()
    }
    unknown = effective - labels
    origin_map = document.get("origins", {})
    ambiguous = {label: keys for label, keys in origin_map.items() if len(keys) != 1}
    if unknown or ambiguous or count != 1350:
        raise SystemExit(f"provenance inventory mismatch: count={count}, unknown={len(unknown)}")
    document["inventory"] = sorted(labels)
    output.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")))
    print(
        f"wrote {output} with {count} entries, {len(effective)} effective origins, "
        f"and {len(document['classes'])} generator classes"
    )


if __name__ == "__main__":
    main()
