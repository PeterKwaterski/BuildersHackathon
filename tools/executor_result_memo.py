#!/usr/bin/env python3
"""Conservative, default-off memoization for pinned PythonExecutor results.

This module is research tooling.  It deliberately accepts a small value domain
and raises ``UnsupportedValue`` for everything else.  A miss or any validation
failure must be handled by normal uncached execution by the caller.
"""

from __future__ import annotations

import base64
import datetime as dt
import decimal
import gzip
import hashlib
import json
import os
import platform
import struct
import sys
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping


FORMAT = "sqlglot-python-executor-memo-v1"
TEST_ID = "tests/test_executor.py::TestExecutor::test_execute_tpcds"


class UnsupportedValue(ValueError):
    """The exact state is outside the deliberately closed encoding domain."""


class ExecutionCoverage:
    """Conservative per-query source coverage using called code-object spans."""

    def __init__(self, tree: Path) -> None:
        self.tree = tree.resolve()
        self._prefix = str(self.tree) + os.sep
        self.lines: dict[str, set[int]] = {}
        self._codes: set[Any] = set()
        self._previous = None

    def _profile(self, _frame: Any, event: str, arg: Any) -> None:
        if event != "call":
            return
        code = _frame.f_code
        if code in self._codes:
            return
        self._codes.add(code)
        filename = code.co_filename
        if not filename.startswith(self._prefix):
            return
        relative = filename[len(self._prefix) :].replace(os.sep, "/")
        if not relative.startswith("sqlglot/"):
            return
        lines = self.lines.setdefault(relative, set())
        if hasattr(code, "co_lines"):
            lines.update(line for _start, _end, line in code.co_lines() if line is not None)
        else:  # pragma: no cover - the pinned image is Python 3.13
            lines.add(code.co_firstlineno)

    def __enter__(self) -> "ExecutionCoverage":
        self._previous = sys.getprofile()
        sys.setprofile(self._profile)
        return self

    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        sys.setprofile(self._previous)

    def payload(self) -> dict[str, list[int]]:
        return {path: sorted(lines) for path, lines in sorted(self.lines.items())}


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _class_name(value: Any) -> str:
    cls = type(value)
    return f"{cls.__module__}.{cls.__qualname__}"


def _slots(cls: type) -> list[str]:
    result: list[str] = []
    for base in reversed(cls.__mro__):
        slots = base.__dict__.get("__slots__", ())
        if isinstance(slots, str):
            slots = (slots,)
        for slot in slots:
            if slot not in ("__dict__", "__weakref__") and slot not in result:
                result.append(slot)
    return result


class StructuralEncoder:
    """Encode supported Python object graphs with identity and order intact."""

    def __init__(self, *, omit_table_runtime: bool = False) -> None:
        self._seen: dict[int, int] = {}
        self._omit_table_runtime = omit_table_runtime

    def encode(self, value: Any) -> Any:
        if value is None:
            return ["none"]
        if type(value) is bool:
            return ["bool", value]
        if type(value) is int:
            return ["int", str(value)]
        if type(value) is float:
            return ["float64", struct.pack(">d", value).hex()]
        if type(value) is str:
            return ["str", value]
        if type(value) is bytes:
            return ["bytes", base64.b64encode(value).decode("ascii")]
        if isinstance(value, decimal.Decimal):
            return ["decimal", str(value), list(value.as_tuple())]
        if isinstance(value, dt.datetime):
            return ["datetime", value.isoformat(), value.fold]
        if isinstance(value, dt.date):
            return ["date", value.isoformat()]
        if isinstance(value, dt.time):
            return ["time", value.isoformat(), value.fold]
        if isinstance(value, Enum):
            return ["enum", _class_name(value), value.name, self.encode(value.value)]
        if isinstance(value, type):
            return ["type", f"{value.__module__}.{value.__qualname__}"]
        if isinstance(value, range):
            return ["range", value.start, value.stop, value.step]

        identity = id(value)
        if identity in self._seen:
            return ["ref", self._seen[identity]]
        reference = len(self._seen)
        self._seen[identity] = reference

        if type(value) is tuple:
            return ["tuple", reference, [self.encode(item) for item in value]]
        if type(value) is list:
            return ["list", reference, [self.encode(item) for item in value]]
        if type(value) is dict:
            return [
                "dict",
                reference,
                [[self.encode(key), self.encode(item)] for key, item in value.items()],
            ]

        cls_name = _class_name(value)
        if not cls_name.startswith("sqlglot."):
            raise UnsupportedValue(f"unsupported object {cls_name}")

        fields: list[list[Any]] = []
        names = _slots(type(value))
        if hasattr(value, "__dict__"):
            names.extend(name for name in vars(value) if name not in names)
        for name in names:
            if self._omit_table_runtime and cls_name == "sqlglot.executor.table.Table":
                if name in ("reader", "range_reader"):
                    continue
            if self._omit_table_runtime and cls_name == "sqlglot.executor.table.Tables":
                if name == "_supported_table_args":
                    continue
            if not hasattr(value, name):
                fields.append([name, ["absent"]])
                continue
            fields.append([name, self.encode(getattr(value, name))])
        return ["object", reference, cls_name, fields]


def structural_bytes(value: Any, *, omit_table_runtime: bool = False) -> bytes:
    return canonical_json(StructuralEncoder(omit_table_runtime=omit_table_runtime).encode(value))


def structural_digest(value: Any, *, omit_table_runtime: bool = False) -> str:
    return sha256_bytes(structural_bytes(value, omit_table_runtime=omit_table_runtime))


def source_manifest(tree: Path) -> list[list[str]]:
    """Bind every planner/executor-capable source and exact TPC-DS test input."""
    tree = tree.resolve()
    candidates: set[Path] = set((tree / "sqlglot").rglob("*.py"))
    candidates.update((tree / "tests" / "fixtures" / "optimizer" / "tpc-ds").rglob("*"))
    candidates.update((tree / name for name in ("tests/test_executor.py", "tests/helpers.py")))
    files = sorted(path for path in candidates if path.is_file())
    if not files:
        raise UnsupportedValue(f"no pinned sources found below {tree}")
    return [[path.relative_to(tree).as_posix(), sha256_bytes(path.read_bytes())] for path in files]


def runtime_identity() -> dict[str, Any]:
    seed = os.environ.get("PYTHONHASHSEED")
    if seed is None or not seed.isdecimal():
        raise UnsupportedValue("PYTHONHASHSEED must be an explicit non-negative integer")
    return {
        "implementation": sys.implementation.name,
        "cache_tag": sys.implementation.cache_tag,
        "version": list(sys.version_info[:5]),
        "executable_bits": struct.calcsize("P") * 8,
        "byteorder": sys.byteorder,
        "platform": platform.platform(),
        "python_hash_seed": seed,
    }


def build_provenance(tree: Path) -> dict[str, Any]:
    manifest = source_manifest(tree)
    return {
        "format": FORMAT,
        "test_id": TEST_ID,
        "runtime": runtime_identity(),
        "files": manifest,
        "files_sha256": sha256_bytes(canonical_json(manifest)),
    }


def build_cache_key(
    *,
    expression: Any,
    tables: Any,
    schema: Mapping[str, Any],
    provenance: Mapping[str, Any],
    query_identity: str,
    options: Mapping[str, Any],
) -> str:
    material = {
        "format": FORMAT,
        "query_identity": query_identity,
        "provenance": provenance,
        "expression": StructuralEncoder().encode(expression),
        "tables": StructuralEncoder().encode(tables),
        "schema": StructuralEncoder().encode(dict(schema)),
        "options": StructuralEncoder().encode(dict(options)),
    }
    return sha256_bytes(canonical_json(material))


def _pack_scalar(value: Any) -> Any:
    if value is None:
        return ["none"]
    if type(value) is bool:
        return ["bool", value]
    if type(value) is int:
        return ["int", str(value)]
    if type(value) is float:
        return ["float64", struct.pack(">d", value).hex()]
    if type(value) is str:
        return ["str", value]
    if type(value) is bytes:
        return ["bytes", base64.b64encode(value).decode("ascii")]
    if isinstance(value, decimal.Decimal):
        return ["decimal", str(value)]
    if isinstance(value, dt.datetime):
        return ["datetime", value.isoformat(), value.fold]
    if isinstance(value, dt.date):
        return ["date", value.isoformat()]
    if isinstance(value, dt.time):
        return ["time", value.isoformat(), value.fold]
    raise UnsupportedValue(f"unsupported cached scalar {_class_name(value)}")


def _unpack_scalar(value: Any) -> Any:
    tag = value[0]
    if tag == "none":
        return None
    if tag == "bool":
        return bool(value[1])
    if tag == "int":
        return int(value[1])
    if tag == "float64":
        return struct.unpack(">d", bytes.fromhex(value[1]))[0]
    if tag == "str":
        return value[1]
    if tag == "bytes":
        return base64.b64decode(value[1], validate=True)
    if tag == "decimal":
        return decimal.Decimal(value[1])
    if tag == "datetime":
        return dt.datetime.fromisoformat(value[1]).replace(fold=value[2])
    if tag == "date":
        return dt.date.fromisoformat(value[1])
    if tag == "time":
        return dt.time.fromisoformat(value[1]).replace(fold=value[2])
    raise UnsupportedValue(f"unsupported cached scalar tag {tag!r}")


def pack_table(table: Any) -> dict[str, Any]:
    return {
        "columns": [_pack_scalar(column) for column in table.columns],
        "rows": [[_pack_scalar(cell) for cell in row] for row in table.rows],
    }


def unpack_table(payload: Mapping[str, Any]) -> Any:
    from sqlglot.executor.table import Table

    columns = tuple(_unpack_scalar(value) for value in payload["columns"])
    rows = [tuple(_unpack_scalar(value) for value in row) for row in payload["rows"]]
    return Table(columns=columns, rows=rows)


def _leaf_tables(mapping: Mapping[str, Any], prefix: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], Any]]:
    for name, value in mapping.items():
        path = (*prefix, name)
        if _class_name(value) == "sqlglot.executor.table.Table":
            yield path, value
        elif type(value) is dict:
            yield from _leaf_tables(value, path)
        else:
            raise UnsupportedValue(f"unsupported Tables mapping leaf {_class_name(value)}")


def mutable_table_state(tables: Any) -> dict[str, Any]:
    state = []
    for path, table in _leaf_tables(tables.mapping):
        state.append(
            {
                "path": list(path),
                "reader_row": [_pack_scalar(value) for value in table.reader.row],
                "range": [
                    table.range_reader.range.start,
                    table.range_reader.range.stop,
                    table.range_reader.range.step,
                ],
            }
        )
    return {
        "supported_table_args": [_pack_scalar(value) for value in tables._supported_table_args],
        "tables": state,
    }


def apply_mutable_table_state(tables: Any, state: Mapping[str, Any]) -> None:
    actual = {path: table for path, table in _leaf_tables(tables.mapping)}
    expected_paths = {tuple(item["path"]) for item in state["tables"]}
    if expected_paths != set(actual):
        raise UnsupportedValue("cached table paths do not match")
    tables._supported_table_args = tuple(
        _unpack_scalar(value) for value in state["supported_table_args"]
    )
    for item in state["tables"]:
        table = actual[tuple(item["path"])]
        table.reader.row = tuple(_unpack_scalar(value) for value in item["reader_row"])
        table.range_reader.range = range(*item["range"])


def record_execution(
    executor: Any,
    plan: Any,
    tables: Any,
    *,
    coverage: ExecutionCoverage | None = None,
) -> tuple[dict[str, Any], Any]:
    immutable_before = structural_digest(tables, omit_table_runtime=True)
    if coverage is None:
        result = executor.execute(plan)
    else:
        with coverage:
            result = executor.execute(plan)
    immutable_after = structural_digest(tables, omit_table_runtime=True)
    if immutable_before != immutable_after:
        raise UnsupportedValue("execution mutated table rows/schema/identity")
    entry = {
        "immutable_tables_sha256": immutable_before,
        "post_table_state": mutable_table_state(tables),
        "result": pack_table(result),
    }
    entry["result_sha256"] = sha256_bytes(canonical_json(entry["result"]))
    return entry, result


def write_artifact(path: Path, payload: Mapping[str, Any]) -> tuple[str, str]:
    payload_bytes = canonical_json(payload)
    envelope = canonical_json(
        {"format": FORMAT, "payload_sha256": sha256_bytes(payload_bytes), "payload": payload}
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            compressed.write(envelope)
    return sha256_bytes(path.read_bytes()), sha256_bytes(payload_bytes)


def read_artifact(path: Path) -> dict[str, Any]:
    try:
        envelope = json.loads(gzip.decompress(path.read_bytes()))
        payload = envelope["payload"]
        if envelope["format"] != FORMAT:
            raise UnsupportedValue("artifact format mismatch")
        if envelope["payload_sha256"] != sha256_bytes(canonical_json(payload)):
            raise UnsupportedValue("artifact payload hash mismatch")
        return payload
    except UnsupportedValue:
        raise
    except Exception as error:
        raise UnsupportedValue(f"invalid artifact: {error}") from error


class MemoStore:
    """Validated memo lookup.  Disabled is the default and always misses."""

    def __init__(self, payload: Mapping[str, Any], *, enabled: bool = False) -> None:
        self.payload = payload
        self.enabled = enabled

    def lookup(self, *, key: str, tables: Any, provenance: Mapping[str, Any]) -> Any | None:
        if not self.enabled:
            return None
        if self.payload.get("format") != FORMAT:
            return None
        if self.payload.get("provenance") != provenance:
            return None
        entry = self.payload.get("entries", {}).get(key)
        if not entry:
            return None
        if structural_digest(tables, omit_table_runtime=True) != entry.get(
            "immutable_tables_sha256"
        ):
            return None
        original_state = mutable_table_state(tables)
        try:
            result_payload = entry["result"]
            if entry.get("result_sha256") != sha256_bytes(canonical_json(result_payload)):
                return None
            result = unpack_table(result_payload)
            apply_mutable_table_state(tables, entry["post_table_state"])
            return result
        except (KeyError, TypeError, ValueError, UnsupportedValue):
            try:
                apply_mutable_table_state(tables, original_state)
            except (KeyError, TypeError, ValueError, UnsupportedValue):
                pass
            return None
