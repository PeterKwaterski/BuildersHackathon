"""Canonical, identity-aware state for pinned SQLGlot expression graphs."""

from __future__ import annotations

import datetime as dt
import decimal
import enum
import hashlib
import json
from typing import Any


GRAPH_FORMAT = "kashimo-expression-graph-v2"


class UnsupportedGraph(ValueError):
    """The prospective graph is outside the deliberately closed domain."""


def _class_name(value: object) -> str:
    cls = type(value)
    return f"{cls.__module__}.{cls.__qualname__}"


class GraphEncoder:
    def __init__(self) -> None:
        self._indices: dict[int, int] = {}
        self._nodes: list[Any] = []
        self._expr_type: type | tuple[type, ...] | None = None

    def _is_expression(self, value: object) -> bool:
        if self._expr_type is None:
            from sqlglot import expressions as exp

            self._expr_type = exp.Expr
        return isinstance(value, self._expr_type)

    def _discover(self, value: object) -> None:
        if self._is_expression(value):
            identity = id(value)
            if identity in self._indices:
                return
            self._indices[identity] = len(self._nodes)
            self._nodes.append(value)
            args = value.args
            if type(args) is not dict:
                raise UnsupportedGraph("expression args are not an exact dict")
            for key, child in args.items():
                if type(key) is not str:
                    raise UnsupportedGraph("expression arg key is not a string")
                self._discover(child)
            self._discover(value._type)
            self._discover(value.comments)
            self._discover(value._meta)
            return
        if type(value) in {list, tuple}:
            for item in value:
                self._discover(item)
            return
        if type(value) is dict:
            for key, item in value.items():
                self._discover(key)
                self._discover(item)
            return
        if type(value) in {set, frozenset}:
            for item in value:
                self._discover(item)

    def _value(self, value: object) -> object:
        if self._is_expression(value):
            try:
                return ["ref", self._indices[id(value)]]
            except KeyError as error:
                raise UnsupportedGraph("undiscovered expression reference") from error
        if value is None:
            return ["none"]
        if type(value) is bool:
            return ["bool", value]
        if type(value) is int:
            return ["int", str(value)]
        if type(value) is float:
            return ["float", value.hex()]
        if type(value) is str:
            return ["str", value]
        if type(value) is bytes:
            return ["bytes", value.hex()]
        if type(value) is list:
            return ["list", [self._value(item) for item in value]]
        if type(value) is tuple:
            return ["tuple", [self._value(item) for item in value]]
        if type(value) is dict:
            return [
                "dict",
                [[self._value(key), self._value(item)] for key, item in value.items()],
            ]
        if type(value) in {set, frozenset}:
            rows = [self._value(item) for item in value]
            rows.sort(key=canonical_bytes)
            return ["frozenset" if type(value) is frozenset else "set", rows]
        if isinstance(value, decimal.Decimal):
            return ["decimal", str(value.as_tuple())]
        if isinstance(value, enum.Enum):
            return ["enum", _class_name(value), value.name, self._value(value.value)]
        if isinstance(value, dt.datetime):
            return ["datetime", value.isoformat(), value.fold]
        if isinstance(value, dt.date):
            return ["date", value.isoformat()]
        if isinstance(value, dt.time):
            return ["time", value.isoformat(), value.fold]
        if type(value) is range:
            return ["range", str(value.start), str(value.stop), str(value.step)]
        if isinstance(value, type):
            return ["type", f"{value.__module__}.{value.__qualname__}"]
        raise UnsupportedGraph(f"unsupported graph value: {_class_name(value)}")

    def _parent(self, node: object) -> object:
        parent = node.parent
        if parent is None:
            return ["none"]
        try:
            return ["ref", self._indices[id(parent)]]
        except KeyError as error:
            raise UnsupportedGraph("expression parent escapes the graph") from error

    def _validate_edges(self) -> None:
        for node in self._nodes:
            for key, value in node.args.items():
                if self._is_expression(value):
                    if (
                        value.parent is not node
                        or type(value.arg_key) is not str
                        or value.arg_key != key
                        or value.index is not None
                    ):
                        raise UnsupportedGraph("scalar child has inconsistent parent topology")
                elif type(value) is list:
                    for index, child in enumerate(value):
                        if self._is_expression(child) and (
                            child.parent is not node
                            or type(child.arg_key) is not str
                            or child.arg_key != key
                            or type(child.index) is not int
                            or child.index != index
                        ):
                            raise UnsupportedGraph("list child has inconsistent parent topology")
                        if not self._is_expression(child) and self._contains_expression(child):
                            raise UnsupportedGraph(
                                "expression is nested in an unsupported arg container"
                            )
                elif self._contains_expression(value):
                    raise UnsupportedGraph("expression is nested in an unsupported arg container")
            parent = node.parent
            if parent is None:
                if node.arg_key is not None or node.index is not None:
                    raise UnsupportedGraph("detached expression has child coordinates")
                continue
            if id(parent) not in self._indices:
                raise UnsupportedGraph("expression parent escapes the graph")
            key = node.arg_key
            if type(key) is not str or key not in parent.args:
                raise UnsupportedGraph("expression backlink has no parent argument")
            index = node.index
            if index is None:
                if parent.args[key] is not node:
                    raise UnsupportedGraph("scalar backlink does not identify the child")
            elif (
                type(index) is not int
                or type(parent.args[key]) is not list
                or not 0 <= index < len(parent.args[key])
                or parent.args[key][index] is not node
            ):
                raise UnsupportedGraph("list backlink does not identify the child")

    def _contains_expression(self, value: object) -> bool:
        if self._is_expression(value):
            return True
        if type(value) in {list, tuple, set, frozenset}:
            return any(self._contains_expression(item) for item in value)
        if type(value) is dict:
            return any(
                self._contains_expression(key) or self._contains_expression(item)
                for key, item in value.items()
            )
        return False

    def encode(self, root: object) -> list[object]:
        if not self._is_expression(root):
            raise UnsupportedGraph("root is not a SQLGlot expression")
        self._discover(root)
        self._validate_edges()
        rows = []
        for node in self._nodes:
            cached_hash = node._hash
            if cached_hash is not None and type(cached_hash) is not int:
                raise UnsupportedGraph("expression cached hash is not an exact integer")
            rows.append(
                [
                    _class_name(node),
                    [[key, self._value(value)] for key, value in node.args.items()],
                    self._parent(node),
                    self._value(node.arg_key),
                    self._value(node.index),
                    self._value(node.comments),
                    self._value(node._type),
                    self._value(node._meta),
                    self._value(cached_hash),
                ]
            )
        return [GRAPH_FORMAT, ["root", 0], rows]

    @staticmethod
    def _count(output: bytearray, value: int) -> None:
        if not 0 <= value < 2**64:
            raise UnsupportedGraph("graph collection is too large")
        output.extend(value.to_bytes(8, "big"))

    @classmethod
    def _blob(cls, output: bytearray, value: bytes) -> None:
        cls._count(output, len(value))
        output.extend(value)

    @classmethod
    def _text(cls, output: bytearray, value: str) -> None:
        cls._blob(output, value.encode("utf-8"))

    def _binary_value(self, output: bytearray, value: object) -> None:
        if self._is_expression(value):
            output.extend(b"X")
            try:
                self._count(output, self._indices[id(value)])
            except KeyError as error:
                raise UnsupportedGraph("undiscovered expression reference") from error
            return
        if value is None:
            output.extend(b"N")
            return
        if type(value) is bool:
            output.extend(b"B1" if value else b"B0")
            return
        if type(value) is int:
            output.extend(b"I")
            self._text(output, str(value))
            return
        if type(value) is float:
            output.extend(b"F")
            self._text(output, value.hex())
            return
        if type(value) is str:
            output.extend(b"S")
            self._text(output, value)
            return
        if type(value) is bytes:
            output.extend(b"Y")
            self._blob(output, value)
            return
        if type(value) in {list, tuple}:
            output.extend(b"L" if type(value) is list else b"T")
            self._count(output, len(value))
            for item in value:
                self._binary_value(output, item)
            return
        if type(value) is dict:
            output.extend(b"D")
            self._count(output, len(value))
            for key, item in value.items():
                self._binary_value(output, key)
                self._binary_value(output, item)
            return
        if type(value) in {set, frozenset}:
            output.extend(b"Q" if type(value) is frozenset else b"E")
            rows = []
            for item in value:
                row = bytearray()
                self._binary_value(row, item)
                rows.append(bytes(row))
            rows.sort()
            self._count(output, len(rows))
            for row in rows:
                self._blob(output, row)
            return
        if isinstance(value, decimal.Decimal):
            output.extend(b"C")
            self._text(output, str(value.as_tuple()))
            return
        if isinstance(value, enum.Enum):
            output.extend(b"M")
            self._text(output, _class_name(value))
            self._text(output, value.name)
            self._binary_value(output, value.value)
            return
        if isinstance(value, dt.datetime):
            output.extend(b"Z")
            self._text(output, value.isoformat())
            output.extend(bytes((value.fold,)))
            return
        if isinstance(value, dt.date):
            output.extend(b"A")
            self._text(output, value.isoformat())
            return
        if isinstance(value, dt.time):
            output.extend(b"O")
            self._text(output, value.isoformat())
            output.extend(bytes((value.fold,)))
            return
        if type(value) is range:
            output.extend(b"R")
            for item in (value.start, value.stop, value.step):
                self._text(output, str(item))
            return
        if isinstance(value, type):
            output.extend(b"K")
            self._text(output, f"{value.__module__}.{value.__qualname__}")
            return
        raise UnsupportedGraph(f"unsupported graph value: {_class_name(value)}")

    def canonical_bytes(self, root: object) -> bytes:
        """Return a closed, unambiguous binary encoding without dynamic equality."""
        if not self._is_expression(root):
            raise UnsupportedGraph("root is not a SQLGlot expression")
        self._discover(root)
        self._validate_edges()
        output = bytearray()
        output.extend(b"KASHIMO-EXPR-GRAPH\0\x02")
        self._count(output, len(self._nodes))
        for node in self._nodes:
            output.extend(b"V")
            self._text(output, _class_name(node))
            self._count(output, len(node.args))
            for key, value in node.args.items():
                self._text(output, key)
                self._binary_value(output, value)
            output.extend(b"P")
            self._binary_value(output, node.parent)
            output.extend(b"G")
            self._binary_value(output, node.arg_key)
            output.extend(b"J")
            self._binary_value(output, node.index)
            output.extend(b"C")
            self._binary_value(output, node.comments)
            output.extend(b"T")
            self._binary_value(output, node._type)
            output.extend(b"M")
            self._binary_value(output, node._meta)
            cached_hash = node._hash
            if cached_hash is not None and type(cached_hash) is not int:
                raise UnsupportedGraph("expression cached hash is not an exact integer")
            output.extend(b"H")
            self._binary_value(output, cached_hash)
        return bytes(output)


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=False,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def graph_digest(expression: object) -> str:
    return hashlib.sha256(GraphEncoder().canonical_bytes(expression)).hexdigest()
