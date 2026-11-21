#!/usr/bin/env python3
"""Disconnected v0 collector for exact Tokenizer KEYWORDS value lookups."""

from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

from collect_dict_access import (
    absolute_offset,
    source_offsets,
    synchronous_worker_tests,
    validate_source,
)
from build_tokenizer_setting_flow import closed_core_lifecycle


PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"
TESTS_SHA256 = "21257a93c58f4b0646c5122586d2141b4b340ad85b2f0bb251af3746de3f0dc2"
EXACT_TEST_COUNT = 1620
TRACKER_VERSION = 2
RESERVED = "_blast_radius_keyword_value_7c3a9e"
CORE_PATH = "sqlglot/tokenizer_core.py"
COLLECTOR_DOCKERFILE = "tools/tokenizer_keyword_collector.Dockerfile"
BASE_IMAGE = (
    "python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
REVIEWED_STATIC_SHA256 = "ecdd75f46a76164924b4168180ea352c6679ee8d88aebadfe397720aa063ff51"
REVIEWED_SOURCE_TREE_SHA256 = "d004c83c8491d811813c3852237b15eef6546331fecaa684f1cb35a3b14e3ab1"
REVIEWED_CORE_SHA256 = "142463b972f35299140172de19eb72bf0c32742867eb251e06c5592413f8083c"
REVIEWED_INVENTORY_SHA256 = "07d7909c5a70a3f07e316af0a552d50b515878a4f0aef8bb91219d2f2302b535"
REVIEWED_OPERATIONS_SHA256 = "9fc0f92f7726c53b37b4e7a77334a65e77af0502d53ee17989ebae349e2f4655"
REVIEW_PUBLIC_KEY_SHA256 = "f0f956bbebd967a450e025fb1c18a52562ac123554024770d84e28a2d125b4c4"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
TOKEN = re.compile(r"([1-9][0-9]*)-([1-9][0-9]*)\Z")
ENVIRONMENT_KEYS = {
    "implementation", "version", "executable", "prefix", "base_prefix",
    "distributions", "entry_points", "pytest_environment", "runtime_environment",
    "toolchain",
}
PYTEST_ENVIRONMENT_KEYS = {
    "PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTEST_DISABLE_PLUGIN_AUTOLOAD"
}
REVIEWED_PYTEST_PLUGINS = (
    "module:_pytest.assertion", "module:_pytest.cacheprovider",
    "module:_pytest.capture", "module:_pytest.debugging", "module:_pytest.doctest",
    "module:_pytest.faulthandler", "module:_pytest.fixtures", "module:_pytest.helpconfig",
    "module:_pytest.junitxml", "module:_pytest.legacypath", "module:_pytest.logging",
    "module:_pytest.main", "module:_pytest.mark", "module:_pytest.monkeypatch",
    "module:_pytest.pastebin", "module:_pytest.python", "module:_pytest.recwarn",
    "module:_pytest.reports", "module:_pytest.runner", "module:_pytest.setuponly",
    "module:_pytest.setupplan", "module:_pytest.skipping", "module:_pytest.stepwise",
    "module:_pytest.subtests", "module:_pytest.terminal", "module:_pytest.threadexception",
    "module:_pytest.tmpdir", "module:_pytest.unittest", "module:_pytest.unraisableexception",
    "module:_pytest.warnings", "module:tokenizer_keyword_plugin",
    "type:_pytest.cacheprovider.LFPlugin", "type:_pytest.cacheprovider.NFPlugin",
    "type:_pytest.capture.CaptureManager", "type:_pytest.config.Config",
    "type:_pytest.config.PytestPluginManager", "type:_pytest.fixtures.FixtureManager",
    "type:_pytest.legacypath.LegacyTmpdirPlugin", "type:_pytest.logging.LoggingPlugin",
    "type:_pytest.main.Session", "type:_pytest.terminal.TerminalReporter",
)
INVOCATION_ENVIRONMENT = {
    "PATH": "/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/tmp",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TZ": "UTC",
    "PYTHONHASHSEED": "0",
    "PYTHONSAFEPATH": "1",
    "PYTHONPATH": "/work/tools",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
}


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument(
        "--image-id",
        required=True,
        help="exact sha256:<64 hex> ID of the already-built collection image",
    )
    parser.add_argument("--synchronous-workers", action="store_true")
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER)
    return parser.parse_args()


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def file_set_digest(root: Path, paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths):
        relative = path.relative_to(root).as_posix().encode()
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def tree_digest(root: Path) -> str:
    return json_digest(filesystem_manifest(root))


def json_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def validate_reviewed_source(source: Path) -> None:
    """Call the shared validator without mutating global git configuration."""
    names = ("GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0")
    previous = {name: os.environ.get(name) for name in names}
    os.environ.update(
        {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "safe.directory",
            "GIT_CONFIG_VALUE_0": str(source),
        }
    )
    try:
        validate_source(source)
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    status = subprocess.check_output(
        [
            "git", "-c", f"safe.directory={source}", "-C", str(source),
            "status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching",
        ],
        text=True,
    )
    if status:
        raise SystemExit("source checkout contains tracked, untracked, or ignored material")


def safe_relative_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or ".." in path.parts
        or "." in path.parts
        or "\\" in value
        or "\0" in value
    ):
        raise SystemExit(f"unsafe repository path {value!r}")
    return path


def tracked_manifest(source: Path) -> list[list[object]]:
    raw = subprocess.check_output(
        [
            "git", "-c", f"safe.directory={source}", "-C", str(source),
            "ls-tree", "-r", "-z", "--full-tree", "HEAD",
        ]
    )
    records = []
    seen = set()
    for item in raw.split(b"\0"):
        if not item:
            continue
        metadata, encoded_path = item.split(b"\t", 1)
        mode, kind, object_id = metadata.decode().split()
        path = encoded_path.decode("utf-8", "strict")
        safe_relative_path(path)
        if path in seen:
            raise SystemExit("unsupported or duplicate tracked entry")
        seen.add(path)
        if kind == "commit" and mode == "160000":
            records.append([path, mode, object_id, None, 0])
            continue
        if kind != "blob" or mode not in {"100644", "100755", "120000"}:
            raise SystemExit("unsupported tracked entry")
        content = subprocess.check_output(
            [
                "git", "-c", f"safe.directory={source}", "-C", str(source),
                "cat-file", "blob", object_id,
            ]
        )
        records.append([path, mode, object_id, hashlib.sha256(content).hexdigest(), len(content)])
    if not records:
        raise SystemExit("empty tracked source manifest")
    return sorted(records)


def filesystem_manifest(root: Path) -> list[list[object]]:
    records = []
    for path in sorted(
        root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()
    ):
        if path.is_dir():
            continue
        relative = path.relative_to(root).as_posix()
        safe_relative_path(relative)
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            mode = "120000"
            content = os.readlink(path).encode()
        elif stat.S_ISREG(metadata.st_mode):
            mode = "100755" if metadata.st_mode & 0o111 else "100644"
            content = path.read_bytes()
        else:
            raise SystemExit(f"unsupported materialized entry {relative}")
        records.append([relative, mode, hashlib.sha256(content).hexdigest(), len(content)])
    return records


def materialize_tracked_source(source: Path, destination: Path) -> dict[str, object]:
    tracked = tracked_manifest(source)
    archive = subprocess.check_output(
        [
            "git", "-c", f"safe.directory={source}", "-C", str(source),
            "archive", "--format=tar", "HEAD",
        ]
    )
    archive_sha = hashlib.sha256(archive).hexdigest()
    destination.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as document:
        names = set()
        for member in document.getmembers():
            path = safe_relative_path(member.name.rstrip("/"))
            if str(path) in names:
                raise SystemExit("duplicate git archive path")
            names.add(str(path))
        document.extractall(destination, filter="data")
    expected = [
        [path, mode, digest, size]
        for path, mode, _oid, digest, size in tracked
        if mode != "160000"
    ]
    actual = filesystem_manifest(destination)
    if actual != expected:
        raise SystemExit("git archive materialization differs from tracked manifest")
    return {
        "tracked_manifest_sha256": json_digest(tracked),
        "tracked_entries": len(tracked),
        "archive_sha256": archive_sha,
        "materialized_manifest_sha256": json_digest(actual),
    }


def clean_environment(python: Path) -> dict[str, str]:
    """Construct an allowlisted child environment from no ambient values."""
    environment = dict(INVOCATION_ENVIRONMENT)
    environment["PATH"] = os.pathsep.join(
        (str(python.parent), "/usr/sbin", "/usr/bin", "/sbin", "/bin")
    )
    return environment


def validate_environment_document(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != ENVIRONMENT_KEYS:
        return False
    if (
        value.get("implementation") != "CPython"
        or type(value.get("version")) is not str
        or not value["version"].startswith("3.13.")
        or any(type(value.get(field)) is not str or not value[field] for field in ("executable", "prefix", "base_prefix"))
        or not Path(value["executable"]).is_absolute()
    ):
        return False
    distributions = value.get("distributions")
    entry_points = value.get("entry_points")
    pytest_environment = value.get("pytest_environment")
    runtime_environment = value.get("runtime_environment")
    toolchain = value.get("toolchain")
    if (
        not isinstance(distributions, list)
        or any(
            not isinstance(item, list)
            or len(item) != 2
            or any(type(part) is not str or not part for part in item)
            for item in distributions
        )
        or not isinstance(entry_points, list)
        or any(
            not isinstance(item, list)
            or len(item) != 4
            or any(type(part) is not str for part in item)
            for item in entry_points
        )
        or not isinstance(pytest_environment, dict)
        or set(pytest_environment) != PYTEST_ENVIRONMENT_KEYS
        or pytest_environment != {
            "PYTEST_ADDOPTS": None,
            "PYTEST_PLUGINS": None,
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        }
        or runtime_environment != {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TZ": "UTC",
            "PYTHONHASHSEED": "0",
            "PYTHONSAFEPATH": "1",
            "PYTHONPATH": "/work/tools",
            "PYTHONWARNINGS": None,
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        or not isinstance(toolchain, dict)
        or set(toolchain) != {"git", "openssl"}
        or any(
            not isinstance(record, dict)
            or set(record) != {"path", "sha256", "version", "package"}
            or type(record["path"]) is not str
            or not Path(record["path"]).is_absolute()
            or not HEX64.fullmatch(str(record["sha256"]))
            or type(record["version"]) is not str
            or not record["version"]
            or type(record["package"]) is not str
            or not record["package"]
            for record in toolchain.values()
        )
    ):
        return False
    if (
        distributions != sorted(distributions)
        or len({tuple(item) for item in distributions}) != len(distributions)
        or len(
            {
                re.sub(r"[-_.]+", "-", item[0]).lower()
                for item in distributions
            }
        )
        != len(distributions)
        or entry_points != sorted(entry_points)
        or len({tuple(item) for item in entry_points}) != len(entry_points)
        or len({(item[0], item[1]) for item in entry_points}) != len(entry_points)
    ):
        return False
    return True


def python_environment(python: Path, environment: dict[str, str]) -> dict[str, object]:
    """Return the collection interpreter/plugin environment as canonical JSON."""
    script = r'''
import hashlib, importlib.metadata as metadata
import json, os, pathlib, platform, shutil, subprocess, sys

def tool(name, version_args, package):
    path = pathlib.Path(shutil.which(name) or "").resolve()
    if not path.is_file():
        raise SystemExit(f"missing tool {name}")
    version = subprocess.check_output([str(path), *version_args], text=True).strip()
    package_version = subprocess.check_output(
        ["/usr/bin/dpkg-query", "-W", "-f=${Version}", package], text=True
    ).strip()
    return {
        "path": str(path),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "version": version,
        "package": f"{package}={package_version}",
    }

distributions = sorted(
    (distribution.metadata.get("Name", ""), distribution.version)
    for distribution in metadata.distributions()
)
entry_points = sorted(
    (entry.group, entry.name, entry.value, getattr(entry.dist, "name", ""))
    for entry in metadata.entry_points()
)
print(json.dumps({
    "implementation": platform.python_implementation(),
    "version": sys.version,
    "executable": sys.executable,
    "prefix": sys.prefix,
    "base_prefix": sys.base_prefix,
    "distributions": distributions,
    "entry_points": entry_points,
    "pytest_environment": {
        name: os.environ.get(name)
        for name in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTEST_DISABLE_PLUGIN_AUTOLOAD")
    },
    "runtime_environment": {
        name: os.environ.get(name)
        for name in ("LANG", "LC_ALL", "TZ", "PYTHONHASHSEED", "PYTHONSAFEPATH", "PYTHONPATH", "PYTHONWARNINGS", "PYTHONDONTWRITEBYTECODE")
    },
    "toolchain": {
        "git": tool("git", ["--version"], "git"),
        "openssl": tool("openssl", ["version"], "openssl"),
    },
}, sort_keys=True, separators=(",", ":")))
'''
    value = json.loads(
        subprocess.check_output([str(python), "-c", script], text=True, env=environment)
    )
    if not validate_environment_document(value):
        raise SystemExit("inadmissible collection interpreter/plugin environment")
    return value


def keyword_inventory(source: Path) -> list[list[object]]:
    """Return all exact explicit KEYWORDS entries, independent of inheritance."""
    entries: list[list[object]] = []
    for path in sorted((source / "sqlglot").rglob("*.py")):
        relative = path.relative_to(source).as_posix()
        tree = ast.parse(path.read_text(), filename=relative, type_comments=True)

        def visit(body: list[ast.stmt], owners: tuple[str, ...] = ()) -> None:
            for statement in body:
                if not isinstance(statement, ast.ClassDef):
                    continue
                owner = (*owners, statement.name)
                for item in statement.body:
                    targets = item.targets if isinstance(item, ast.Assign) else (
                        [item.target] if isinstance(item, ast.AnnAssign) else []
                    )
                    value = getattr(item, "value", None)
                    if (
                        len(targets) != 1
                        or not isinstance(targets[0], ast.Name)
                        or targets[0].id != "KEYWORDS"
                        or not isinstance(value, ast.Dict)
                    ):
                        continue
                    seen = set()
                    for index, (key, token) in enumerate(zip(value.keys, value.values)):
                        if (
                            not isinstance(key, ast.Constant)
                            or type(key.value) is not str
                            or not isinstance(token, ast.Attribute)
                            or not isinstance(token.value, ast.Name)
                            or token.value.id != "TokenType"
                        ):
                            continue
                        if key.value in seen:
                            raise SystemExit(f"duplicate explicit KEYWORDS key {relative}:{key.lineno}")
                        seen.add(key.value)
                        entries.append([
                            relative,
                            ".".join(owner),
                            item.lineno,
                            item.end_lineno or item.lineno,
                            index,
                            key.value,
                            token.attr,
                            ast.dump(token, include_attributes=False),
                        ])
                visit(statement.body, owner)

        visit(tree.body)
    if len(entries) != 716 or len({entry[5] for entry in entries}) != 616:
        raise SystemExit("KEYWORDS inventory is not the pinned 716/616 census")
    return sorted(entries)


def _attribute_chain(node: ast.AST) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def tokenizer_lineage(source: Path) -> list[list[object]]:
    """Bind every pinned class that is, defines, or derives a tokenizer."""
    lineage = []
    for path in sorted((source / "sqlglot").rglob("*.py")):
        relative = path.relative_to(source).as_posix()
        tree = ast.parse(path.read_text(), filename=relative, type_comments=True)

        def visit(body: list[ast.stmt], owners: tuple[str, ...] = ()) -> None:
            for statement in body:
                if not isinstance(statement, ast.ClassDef):
                    continue
                owner = (*owners, statement.name)
                bases = [ast.unparse(base) for base in statement.bases]
                defines_keywords = any(
                    any(
                        isinstance(target, ast.Name) and target.id == "KEYWORDS"
                        for target in (
                            item.targets
                            if isinstance(item, ast.Assign)
                            else [item.target] if isinstance(item, ast.AnnAssign) else []
                        )
                    )
                    for item in statement.body
                )
                if (
                    "Tokenizer" in statement.name
                    or defines_keywords
                    or any("Tokenizer" in base for base in bases)
                ):
                    lineage.append([
                        relative,
                        ".".join(owner),
                        statement.lineno,
                        bases,
                        defines_keywords,
                    ])
                visit(statement.body, owner)

        visit(tree.body)
    if len(lineage) != 42 or sum(bool(item[4]) for item in lineage) != 29:
        raise SystemExit("Tokenizer subclass lineage is not the pinned 42/29 census")
    return sorted(lineage)


def static_contract(source: Path) -> dict[str, object]:
    """Build a reviewable exact-use contract and reject broad escape channels."""
    reads = []
    pops = []
    hazards = []
    init_core = []
    core_assignments = []
    token_type_bindings = []
    reserved_hits = []
    reflection_calls = []
    inventory_paths = {entry[0] for entry in keyword_inventory(source)}
    dynamic_names = {
        "getattr", "setattr", "delattr", "vars", "dir", "globals", "locals",
        "eval", "exec", "__import__", "getsource", "getsourcelines", "findsource",
        "dumps", "dump", "loads", "load", "copy", "deepcopy",
    }
    for top in ("sqlglot", "tests"):
        for path in sorted((source / top).rglob("*.py")):
            relative = path.relative_to(source).as_posix()
            text = path.read_text()
            if RESERVED in text:
                reserved_hits.append(relative)
            tree = ast.parse(text, filename=relative, type_comments=True)
            if relative in inventory_paths:
                bindings = [
                    [node.module, alias.name, alias.asname]
                    for node in tree.body
                    if isinstance(node, ast.ImportFrom)
                    for alias in node.names
                    if alias.name == "TokenType" and alias.asname is None
                ]
                if len(bindings) != 1 or bindings[0][0] not in {
                    "sqlglot", "sqlglot.tokens", "sqlglot.tokenizer_core"
                }:
                    raise SystemExit(f"noncanonical TokenType binding in {relative}")
                token_type_bindings.append([relative, *bindings[0]])
            parents = {
                child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)
            }
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "_init_core":
                    init_core.append([relative, node.lineno])
                if isinstance(node, ast.Attribute) and node.attr == "KEYWORDS":
                    parent = parents.get(node)
                    kind = type(parent).__name__ if parent is not None else "None"
                    chain = _attribute_chain(node) or ""
                    record = [relative, node.lineno, node.col_offset, chain, kind]
                    if (
                        isinstance(parent, ast.Attribute)
                        and parent.value is node
                        and parent.attr == "pop"
                        and isinstance(parents.get(parent), ast.Call)
                        and parents[parent].func is parent
                    ):
                        pops.append(record)
                    else:
                        reads.append(record)
                if isinstance(node, ast.Name) and node.id == "KEYWORDS":
                    parent = parents.get(node)
                    if (
                        isinstance(parent, ast.Attribute)
                        and parent.value is node
                        and parent.attr == "pop"
                        and isinstance(parents.get(parent), ast.Call)
                        and parents[parent].func is parent
                    ):
                        pops.append([relative, node.lineno, node.col_offset, "KEYWORDS", "pop"])
                if (
                    isinstance(node, (ast.Assign, ast.AnnAssign))
                    and isinstance(getattr(node, "value", None), ast.Attribute)
                    and _attribute_chain(node.value) == "self.keywords"
                ):
                    core_assignments.append([relative, node.lineno, ast.dump(node, include_attributes=False)])
                if isinstance(node, ast.Call):
                    name = node.func.id if isinstance(node.func, ast.Name) else (
                        node.func.attr if isinstance(node.func, ast.Attribute) else ""
                    )
                    if name in dynamic_names:
                        reflection_calls.append([
                            relative,
                            node.lineno,
                            name,
                            ast.dump(node, include_attributes=False),
                        ])
                        folded = {
                            value
                            for value in ast.walk(node)
                            if isinstance(value, ast.Constant) and type(value.value) is str
                        }
                        if any(
                            marker in value.value
                            for value in folded
                            for marker in ("KEYWORDS", "keywords", "_core", "TokenizerCore")
                        ):
                            hazards.append([relative, node.lineno, name])
            code = compile(text, relative, "exec", dont_inherit=True, optimize=0)
            stack = [code]
            while stack:
                current = stack.pop()
                for constant in current.co_consts:
                    if isinstance(constant, type(code)):
                        stack.append(constant)
                    elif constant == RESERVED:
                        reserved_hits.append(f"{relative}:{current.co_qualname}")
                    elif type(constant) is str and any(
                        marker in constant
                        for marker in ("__dict__", "KEYWORDS", "keywords", "_core", "TokenizerCore")
                    ):
                        # Literal names are expected in ordinary source. The complete
                        # list is bound for an independent audit rather than ignored.
                        pass
    document = {
        "reads": sorted(reads),
        "pops": sorted(pops),
        "init_core": sorted(init_core),
        "core_assignments": sorted(core_assignments),
        "token_type_bindings": sorted(token_type_bindings),
        "hazards": sorted(hazards),
        "reflection_calls": sorted(reflection_calls),
        "reserved_hits": sorted(reserved_hits),
        "tokenizer_lineage": tokenizer_lineage(source),
    }
    init_tree = ast.parse((source / "sqlglot/__init__.py").read_text())
    canonical_reexports = [
        alias
        for node in init_tree.body
        if isinstance(node, ast.ImportFrom) and node.module == "sqlglot.tokens"
        for alias in node.names
        if alias.name == "TokenType" and alias.asname in (None, "TokenType")
    ]
    # Exact pinned expectations from the independent source review.
    if (
        len(reads) != 31
        or len(pops) != 24
        or init_core != [["sqlglot/tokens.py", 576]]
        or len(core_assignments) != 1
        or core_assignments[0][0:2] != [CORE_PATH, 988]
        or hazards
        or reserved_hits
        or not closed_core_lifecycle(source)
        or len(token_type_bindings) != 25
        or len(canonical_reexports) != 1
        or len(document["tokenizer_lineage"]) != 42
    ):
        raise SystemExit(
            "Tokenizer KEYWORDS static closure mismatch: "
            f"reads={len(reads)} pops={len(pops)} init={init_core} "
            f"core_aliases={len(core_assignments)} hazards={hazards[:1]}"
        )
    return document


def retrieval_operations(source: Path) -> list[list[object]]:
    """Return the exact four value-retrieval key-expression spans."""
    path = source / CORE_PATH
    tree = ast.parse(path.read_text(), filename=CORE_PATH, type_comments=True)
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    operations = []
    for node in ast.walk(tree):
        key = None
        shape = None
        if isinstance(node, ast.Subscript) and _attribute_chain(node.value) == "self.keywords":
            key, shape = node.slice, "self-subscript"
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.args
            and node.func.attr == "get"
        ):
            chain = _attribute_chain(node.func.value)
            if chain == "self.keywords":
                key, shape = node.args[0], "self-get"
            elif isinstance(node.func.value, ast.Name) and node.func.value.id == "keywords":
                key, shape = node.args[0], "alias-get"
        if key is None:
            continue
        operations.append([
            key.lineno,
            key.col_offset,
            key.end_lineno or key.lineno,
            key.end_col_offset,
            shape,
            type(parents.get(node)).__name__,
        ])
    expected = [
        [810, 53, 810, 60, "self-subscript", "Tuple"],
        [895, 44, 895, 48, "self-subscript", "Call"],
        [1047, 44, 1047, 93, "alias-get", "Assign"],
        [1191, 35, 1191, 80, "self-get", "IfExp"],
    ]
    if sorted(operations) != expected:
        raise SystemExit(f"TokenizerCore retrieval census mismatch: {operations!r}")
    return expected


def instrument_core(text: str, operations: list[list[object]]) -> str:
    lines, offsets = source_offsets(text)
    edits = []
    for start_line, start_col, end_line, end_col, _shape, _parent in operations:
        start = absolute_offset(lines, offsets, start_line, start_col)
        end = absolute_offset(lines, offsets, end_line, end_col)
        edits.extend(((end, ")"), (start, f"{RESERVED}(")))
    for position, replacement in sorted(edits, reverse=True):
        text = text[:position] + replacement + text[position:]
    ast.parse(text, filename=CORE_PATH, type_comments=True)
    return text


TRACKER = r'''from __future__ import annotations
import atexit, builtins, concurrent.futures, hashlib, importlib.util, json, os, sys, threading, time
from pathlib import Path

CHILD_DIR = Path(os.environ["TOKENIZER_KEYWORD_CHILD_DIR"])
CURRENT_TEST = os.environ.get("BR_PARENT_TEST")
TOKEN = None
STARTED = False
PROCESS_ID = os.getpid()
LOCK = threading.Lock()
ORIGINAL_SUBMIT = concurrent.futures.ProcessPoolExecutor.submit

def native_overlay():
    spec = importlib.util.find_spec("sqlglotc")
    if spec is None:
        return None
    expected = str(
        (Path(os.environ["TOKENIZER_KEYWORD_CORE_ORIGIN"]).resolve().parents[1] / "sqlglotc").resolve()
    )
    locations = {
        str(Path(location).resolve()) for location in (spec.submodule_search_locations or ())
    }
    return None if spec.loader is None and locations == {expected} else "present"

def importing():
    frame = sys._getframe(1)
    while frame is not None:
        spec = frame.f_globals.get("__spec__")
        if spec is not None and getattr(spec, "_initializing", False):
            return True
        frame = frame.f_back
    return False

def after_fork():
    global TOKEN, STARTED, CURRENT_TEST, PROCESS_ID, LOCK
    TOKEN = None
    STARTED = False
    CURRENT_TEST = os.environ.get("BR_PARENT_TEST")
    PROCESS_ID = os.getpid()
    LOCK = threading.Lock()

def start():
    global TOKEN, STARTED, PROCESS_ID
    if STARTED:
        return
    with LOCK:
        if STARTED:
            return
        if PROCESS_ID != os.getpid():
            after_fork()
        TOKEN = f"{os.getpid()}-{time.time_ns()}"
        attestation = {
            "token": TOKEN,
            "pid": os.getpid(),
            "executable": sys.executable,
            "version": sys.version,
            "environment_sha256": os.environ.get("TOKENIZER_KEYWORD_ENVIRONMENT_SHA256", ""),
            "core_origin": os.environ.get("TOKENIZER_KEYWORD_CORE_ORIGIN", ""),
            "core_class_module": "sqlglot.tokenizer_core",
            "sqlglotc_spec": native_overlay(),
        }
        (CHILD_DIR / f"{TOKEN}.started").write_text(
            json.dumps(attestation, sort_keys=True, separators=(",", ":"))
        )
        (CHILD_DIR / f"{TOKEN}.log.jsonl").write_text(
            json.dumps(["sentry", "process-start", CURRENT_TEST or "__NO_TEST__"], separators=(",", ":")) + "\n"
        )
        PROCESS_ID = os.getpid()
        STARTED = True

def complete():
    if STARTED and TOKEN is not None:
        log = CHILD_DIR / f"{TOKEN}.log.jsonl"
        payload = {
            "token": TOKEN,
            "pid": os.getpid(),
            "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
        }
        (CHILD_DIR / f"{TOKEN}.completed").write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":"))
        )

def append(payload):
    start()
    raw = json.dumps(payload, separators=(",", ":")).encode() + b"\n"
    path = CHILD_DIR / f"{TOKEN}.log.jsonl"
    descriptor = os.open(path, os.O_APPEND | os.O_WRONLY, 0o600)
    try:
        if os.write(descriptor, raw) != len(raw):
            raise RuntimeError("short tokenizer-keyword log write")
    finally:
        os.close(descriptor)

def integrity(boundary):
    if concurrent.futures.ProcessPoolExecutor.submit is not owned_submit:
        raise RuntimeError(f"tokenizer-keyword submit wrapper displaced at {boundary}")
    append(["sentry", boundary, CURRENT_TEST or "__NO_TEST__"])

def verify_core():
    core = sys.modules.get("sqlglot.tokenizer_core")
    actual_origin = None if core is None else str(core.__spec__.origin)
    actual_module = None if core is None else core.TokenizerCore.__module__
    native = native_overlay()
    if (
        core is None
        or actual_origin != os.environ.get("TOKENIZER_KEYWORD_CORE_ORIGIN")
        or actual_module != "sqlglot.tokenizer_core"
        or native is not None
    ):
        raise RuntimeError(
            "TokenizerCore origin/native attestation failed: "
            f"origin={actual_origin!r} expected={os.environ.get('TOKENIZER_KEYWORD_CORE_ORIGIN')!r} "
            f"module={actual_module!r} sqlglotc={native!r}"
        )

def record(value):
    verify_core()
    owner = "__IMPORT__" if importing() else (CURRENT_TEST or "__NO_TEST__")
    key = value if type(value) is str else "__NON_STRING__"
    append(["event", key, owner])
    return value

def owned_task(function, args, kwargs, task_owner, task_id):
    global CURRENT_TEST
    previous = CURRENT_TEST
    CURRENT_TEST = task_owner
    if task_owner:
        os.environ["BR_PARENT_TEST"] = task_owner
    else:
        os.environ.pop("BR_PARENT_TEST", None)
    try:
        integrity(f"task-start:{task_id}")
        return function(*args, **kwargs)
    finally:
        integrity(f"task-end:{task_id}")
        complete()
        CURRENT_TEST = previous
        if previous:
            os.environ["BR_PARENT_TEST"] = previous
        else:
            os.environ.pop("BR_PARENT_TEST", None)

def owned_submit(executor, function, /, *args, **kwargs):
    task_id = f"{os.getpid()}-{time.time_ns()}"
    integrity(f"submit-start:{task_id}")
    try:
        return ORIGINAL_SUBMIT(
            executor, owned_task, function, args, kwargs,
            CURRENT_TEST or os.environ.get("BR_PARENT_TEST"),
            task_id,
        )
    finally:
        integrity(f"submit-end:{task_id}")

concurrent.futures.ProcessPoolExecutor.submit = owned_submit

if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=after_fork)
atexit.register(complete)
builtins.__RESERVED__ = record
'''


PLUGIN = r'''from __future__ import annotations
import json, os
from pathlib import Path
import pytest
import _br_tokenizer_keyword_tracker as tracker

EXECUTED = set()

@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_protocol(item, nextitem):
    EXECUTED.add(item.nodeid)
    tracker.CURRENT_TEST = item.nodeid
    os.environ["BR_PARENT_TEST"] = item.nodeid
    tracker.integrity("test-start")
    try:
        yield
    finally:
        tracker.integrity("test-end")
        tracker.CURRENT_TEST = None
        os.environ.pop("BR_PARENT_TEST", None)

def pytest_sessionfinish(session, exitstatus):
    import importlib.util
    import sqlglot.tokenizer_core as core
    spec = importlib.util.find_spec("sqlglotc")
    expected = str((Path(core.__spec__.origin).resolve().parents[1] / "sqlglotc").resolve())
    locations = {
        str(Path(location).resolve()) for location in (spec.submodule_search_locations or ())
    } if spec is not None else set()
    native = None if spec is None or (spec.loader is None and locations == {expected}) else "present"
    plugin_identities = set()
    for _name, plugin in session.config.pluginmanager.list_name_plugin():
        if plugin is None:
            continue
        module_name = getattr(plugin, "__name__", None)
        if isinstance(module_name, str):
            plugin_identities.add(f"module:{module_name}")
        else:
            plugin_identities.add(
                f"type:{type(plugin).__module__}.{type(plugin).__qualname__}"
            )
    Path(os.environ["TOKENIZER_KEYWORD_PYTEST_MANIFEST"]).write_text(json.dumps({
        "exitstatus": exitstatus,
        "tests": sorted(EXECUTED),
        "pytest_plugins": sorted(plugin_identities),
        "core_origin": str(core.__spec__.origin),
        "core_class_module": core.TokenizerCore.__module__,
        "sqlglotc_spec": native,
    }, sort_keys=True, separators=(",", ":")))
'''


def canonical_process_logs(
    directory: Path,
    tests: set[str],
    expected_environment_sha256: str,
    expected_executable: str,
    expected_version: str,
    expected_core_origin: str,
    *,
    require_test_sentries: bool = True,
) -> tuple[dict[str, list[str]], list[list[str]], list[list[object]]]:
    events: dict[str, set[str]] = {}
    sentries: list[list[str]] = []
    starts = {path.name.removesuffix(".started") for path in directory.glob("*.started")}
    logs = {path.name.removesuffix(".log.jsonl") for path in directory.glob("*.log.jsonl")}
    completions = {
        path.name.removesuffix(".completed") for path in directory.glob("*.completed")
    }
    if not starts or starts != logs or starts != completions:
        raise SystemExit("relevant process lifecycle mismatch")
    known_files = {
        f"{token}{suffix}"
        for token in starts
        for suffix in (".started", ".log.jsonl", ".completed")
    }
    if {path.name for path in directory.iterdir()} != known_files:
        raise SystemExit("unknown process evidence file")
    processes: list[list[object]] = []
    expected_attestation_keys = {
        "token", "pid", "executable", "version", "environment_sha256",
        "core_origin", "core_class_module", "sqlglotc_spec",
    }
    for token in sorted(starts):
        match = TOKEN.fullmatch(token)
        if match is None:
            raise SystemExit("invalid process lifecycle token")
        pid = int(match.group(1))
        started = json.loads((directory / f"{token}.started").read_text())
        completed = json.loads((directory / f"{token}.completed").read_text())
        if (
            not isinstance(started, dict)
            or set(started) != expected_attestation_keys
            or started.get("token") != token
            or type(started.get("pid")) is not int
            or started["pid"] != pid
            or started.get("executable") != expected_executable
            or started.get("version") != expected_version
            or started.get("environment_sha256") != expected_environment_sha256
            or started.get("core_origin") != expected_core_origin
            or started.get("core_class_module") != "sqlglot.tokenizer_core"
            or started.get("sqlglotc_spec") is not None
            or completed != {
                "pid": pid,
                "token": token,
                "log_sha256": hashlib.sha256(
                    (directory / f"{token}.log.jsonl").read_bytes()
                ).hexdigest(),
            }
        ):
            raise SystemExit("invalid process attestation or completion")
        processes.append([token, pid])
    for path in sorted(directory.glob("*.log.jsonl")):
        if path.stat().st_size <= 0:
            raise SystemExit(f"empty process log {path}")
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise SystemExit(f"malformed event {path}:{number}") from error
            if (
                not isinstance(record, list)
                or len(record) != 3
                or record[0] not in {"event", "sentry"}
                or type(record[1]) is not str
                or type(record[2]) is not str
                or record[2] not in tests | {"__IMPORT__", "__NO_TEST__"}
            ):
                raise SystemExit(f"invalid event {path}:{number}")
            if record[0] == "event":
                events.setdefault(record[1], set()).add(record[2])
            else:
                sentries.append(record[1:])
    sentry_counts: dict[tuple[str, str], int] = {}
    for boundary, owner in sentries:
        sentry_counts[(boundary, owner)] = sentry_counts.get((boundary, owner), 0) + 1
    if require_test_sentries:
        for owner in tests:
            if (
                sentry_counts.get(("test-start", owner)) != 1
                or sentry_counts.get(("test-end", owner)) != 1
            ):
                raise SystemExit(f"missing exact test sentries for {owner}")
    if sum(
        count for (kind, _owner), count in sentry_counts.items()
        if kind == "process-start"
    ) != len(starts):
        raise SystemExit("missing or duplicate process-start sentry")
    task_lifecycle: dict[str, dict[tuple[str, str], int]] = {
        kind: {} for kind in ("submit-start", "submit-end", "task-start", "task-end")
    }
    for boundary, owner in sentries:
        if boundary in {"process-start", "test-start", "test-end"}:
            continue
        match = re.fullmatch(
            r"(submit-start|submit-end|task-start|task-end):([1-9][0-9]*-[1-9][0-9]*)",
            boundary,
        )
        if match is None:
            raise SystemExit(f"unknown lifecycle sentry {boundary!r}")
        key = (match.group(2), owner)
        target = task_lifecycle[match.group(1)]
        target[key] = target.get(key, 0) + 1
    if (
        any(count != 1 for records in task_lifecycle.values() for count in records.values())
        or len({frozenset(records) for records in task_lifecycle.values()}) != 1
    ):
        raise SystemExit("submit/task lifecycle identities are incomplete or duplicated")
    return (
        {key: sorted(owners) for key, owners in sorted(events.items())},
        sorted(sentries),
        processes,
    )


def canonical_events(directory: Path, tests: set[str]) -> dict[str, list[str]]:
    """Parse tracker-only adversarial fixtures without a pytest test census."""
    starts = list(directory.glob("*.started"))
    if not starts:
        raise SystemExit("missing tracker process")
    attestation = json.loads(starts[0].read_text())
    return canonical_process_logs(
        directory,
        tests,
        str(attestation.get("environment_sha256")),
        str(attestation.get("executable")),
        str(attestation.get("version")),
        str(attestation.get("core_origin")),
        require_test_sentries=False,
    )[0]


def bundle_payload(mode: str, files: list[tuple[str, bytes]]) -> bytes:
    if mode not in {"normal", "synchronous-worker"}:
        raise SystemExit("invalid raw bundle mode")
    records = []
    seen = set()
    for name, content in sorted(files):
        path = safe_relative_path(name)
        if name in seen or (
            name != "pytest-manifest.json"
            and (len(path.parts) != 2 or path.parts[0] != "children")
        ):
            raise SystemExit("unsafe or duplicate raw bundle path")
        seen.add(name)
        records.append(
            [
                name,
                hashlib.sha256(content).hexdigest(),
                len(content),
                base64.b64encode(content).decode("ascii"),
            ]
        )
    if "pytest-manifest.json" not in seen or not any(
        name.startswith("children/") for name in seen
    ):
        raise SystemExit("raw bundle lacks mandatory evidence")
    return json.dumps(
        {"schema": 1, "mode": mode, "files": records},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def write_raw_bundle(
    mode: str, children: Path, pytest_manifest: Path, output: Path
) -> None:
    files = [("pytest-manifest.json", pytest_manifest.read_bytes())]
    files.extend(
        (f"children/{path.name}", path.read_bytes())
        for path in sorted(children.iterdir())
    )
    output.write_bytes(bundle_payload(mode, files))


def replay_raw_bundle(bundle: Path, destination: Path) -> tuple[str, Path, Path]:
    raw = bundle.read_bytes()
    document = json.loads(raw)
    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "mode", "files"}
        or document.get("schema") != 1
        or document.get("mode") not in {"normal", "synchronous-worker"}
        or not isinstance(document.get("files"), list)
    ):
        raise SystemExit("malformed raw lifecycle bundle")
    files = []
    seen = set()
    for record in document["files"]:
        if (
            not isinstance(record, list)
            or len(record) != 4
            or type(record[0]) is not str
            or type(record[1]) is not str
            or type(record[2]) is not int
            or record[2] < 0
            or type(record[3]) is not str
        ):
            raise SystemExit("malformed raw bundle record")
        name, expected_sha, expected_size, encoded = record
        path = safe_relative_path(name)
        if name in seen or (
            name != "pytest-manifest.json"
            and (len(path.parts) != 2 or path.parts[0] != "children")
        ):
            raise SystemExit("unsafe or duplicate raw bundle path")
        seen.add(name)
        try:
            content = base64.b64decode(encoded, validate=True)
        except Exception as error:
            raise SystemExit("invalid raw bundle base64") from error
        if (
            base64.b64encode(content).decode("ascii") != encoded
            or len(content) != expected_size
            or hashlib.sha256(content).hexdigest() != expected_sha
        ):
            raise SystemExit("raw bundle record digest mismatch")
        files.append((name, content))
    if document["files"] != sorted(document["files"], key=lambda record: record[0]):
        raise SystemExit("raw bundle records are not canonical")
    destination.mkdir()
    for name, content in files:
        target = destination.joinpath(*PurePosixPath(name).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    pytest_manifest = destination / "pytest-manifest.json"
    children = destination / "children"
    if not pytest_manifest.is_file() or not children.is_dir():
        raise SystemExit("raw bundle mandatory files are absent")
    canonical = bundle_payload(document["mode"], files)
    if raw != canonical:
        raise SystemExit("raw bundle encoding is not canonical")
    return document["mode"], children, pytest_manifest


def main() -> None:
    args = arguments()
    if dict(os.environ) != INVOCATION_ENVIRONMENT:
        unknown = sorted(set(os.environ) - set(INVOCATION_ENVIRONMENT))
        missing = sorted(set(INVOCATION_ENVIRONMENT) - set(os.environ))
        raise SystemExit(
            f"collector invocation environment is not exact: unknown={unknown} missing={missing}"
        )
    source = args.source.resolve()
    python = args.python.expanduser().resolve()
    output, manifest, bundle = (
        args.output.resolve(), args.manifest.resolve(), args.bundle.resolve()
    )
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.image_id):
        raise SystemExit("--image-id must be an exact sha256:<64 lowercase hex> ID")
    validate_reviewed_source(source)
    revision = subprocess.check_output(
        ["git", "-c", f"safe.directory={source}", "-C", str(source), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    if revision != PINNED_SHA:
        raise SystemExit("wrong source revision")
    base_environment = clean_environment(python)
    python_version = subprocess.check_output(
        [str(python), "-c", "import sys; print(sys.version)"],
        text=True,
        env=base_environment,
    ).strip()
    if not python_version.startswith("3.13."):
        raise SystemExit("exact Python 3.13 is required")
    collection_environment = python_environment(python, base_environment)
    tests_raw = args.tests.read_bytes()
    if hashlib.sha256(tests_raw).hexdigest() != TESTS_SHA256:
        raise SystemExit("wrong tests manifest")
    test_ids = [test["id"] for test in json.loads(tests_raw)["tests"]]
    if len(test_ids) != EXACT_TEST_COUNT or len(set(test_ids)) != EXACT_TEST_COUNT:
        raise SystemExit("expected exact 1,620-test census")
    test_set = set(test_ids)
    skipped = set(json.loads(tests_raw).get("skipped", ()))
    if len(skipped) != 1 or skipped & test_set:
        raise SystemExit("expected the exact separate skipped-node census")
    executed_set = test_set | skipped
    inventory = keyword_inventory(source)
    contract = static_contract(source)
    operations = retrieval_operations(source)
    mode = "synchronous-worker" if args.synchronous_workers else "normal"
    pytest_arguments = [arg for arg in args.pytest_args if arg != "--"]
    collector_sha = file_digest(Path(__file__))
    dependency_sha = file_digest(Path(__file__).with_name("collect_dict_access.py"))
    lifecycle_dependency_sha = file_digest(
        Path(__file__).with_name("build_tokenizer_setting_flow.py")
    )
    class_attribute_dependency_sha = file_digest(
        Path(__file__).with_name("collect_class_attribute_reads.py")
    )
    builder_sha = file_digest(Path(__file__).with_name("build_tokenizer_keyword_model.py"))
    finalizer_sha = file_digest(
        Path(__file__).with_name("finalize_tokenizer_keyword_evidence.py")
    )
    signature_module_sha = file_digest(
        Path(__file__).with_name("tokenizer_keyword_signature.py")
    )
    signer_sha = file_digest(
        Path(__file__).with_name("sign_tokenizer_keyword_evidence.py")
    )
    review_public_key_sha = file_digest(
        Path(__file__).with_name("tokenizer_keyword_review_public.pem")
    )
    repository = Path(__file__).resolve().parents[1]
    requirements_sha = file_digest(repository / "requirements.lock")
    reflection_sha = file_digest(repository / "code_reflection_model.json.gz")
    selector_model_sha = file_digest(repository / "selector_model.json.gz")
    core_sha = file_digest(source / CORE_PATH)
    source_records = tracked_manifest(source)
    source_tree_sha = json_digest(source_records)
    inventory_sha = json_digest(inventory)
    static_sha = json_digest(contract)
    operations_sha = json_digest(operations)
    dockerfile_sha = file_digest(repository / COLLECTOR_DOCKERFILE)
    dockerfile = (repository / COLLECTOR_DOCKERFILE).read_text()
    if (
        source_tree_sha != REVIEWED_SOURCE_TREE_SHA256
        or core_sha != REVIEWED_CORE_SHA256
        or inventory_sha != REVIEWED_INVENTORY_SHA256
        or static_sha != REVIEWED_STATIC_SHA256
        or operations_sha != REVIEWED_OPERATIONS_SHA256
        or review_public_key_sha != REVIEW_PUBLIC_KEY_SHA256
        or f"FROM {BASE_IMAGE}\n" not in dockerfile
    ):
        raise SystemExit("reviewed source/static/container contract mismatch")
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest.parent.mkdir(parents=True, exist_ok=True)
    bundle.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="blast-radius-tokenizer-keyword-") as temporary:
        root = Path(temporary)
        work, support, children = root / "sqlglot", root / "support", root / "children"
        materialization = materialize_tracked_source(source, work)
        support.mkdir(); children.mkdir()
        base_materialized_sha = tree_digest(work)
        if args.synchronous_workers:
            synchronous_worker_tests(work)
        mode_source_tree_sha = tree_digest(work)
        core = work / CORE_PATH
        core.write_text(instrument_core(core.read_text(), operations))
        tracker = TRACKER.replace("__RESERVED__", RESERVED)
        (support / "_br_tokenizer_keyword_tracker.py").write_text(tracker)
        (support / "tokenizer_keyword_plugin.py").write_text(PLUGIN)
        (support / "sitecustomize.py").write_text("import _br_tokenizer_keyword_tracker\n")
        support_sha = file_set_digest(support, list(support.glob("*.py")))
        instrumented_tree_sha = tree_digest(work)
        pytest_manifest = root / "pytest-manifest.json"
        environment = base_environment.copy()
        environment_sha = json_digest(collection_environment)
        environment.update({
            "TOKENIZER_KEYWORD_CHILD_DIR": str(children),
            "TOKENIZER_KEYWORD_PYTEST_MANIFEST": str(pytest_manifest),
            "TOKENIZER_KEYWORD_ENVIRONMENT_SHA256": environment_sha,
            "TOKENIZER_KEYWORD_CORE_ORIGIN": str(core.resolve()),
            "PYTHONPATH": os.pathsep.join((str(support), str(work))),
            "SKIP_INTEGRATION": "0",
        })
        command = [str(python), "-m", "pytest", "-q", "-p", "tokenizer_keyword_plugin", *pytest_arguments]
        result = subprocess.run(command, cwd=work, env=environment, check=False)
        if result.returncode:
            raise SystemExit(f"pytest exited {result.returncode}")
        pytest_data = json.loads(pytest_manifest.read_text())
        if pytest_data.get("exitstatus") != 0 or (
            not pytest_arguments and set(pytest_data.get("tests", ())) != executed_set
        ):
            raise SystemExit("pytest inventory mismatch")
        run_set = set(pytest_data.get("tests", ()))
        if not run_set or not run_set <= executed_set:
            raise SystemExit("pytest executed an empty or unknown test inventory")
        if (
            set(pytest_data) != {
                "exitstatus", "tests", "pytest_plugins", "core_origin",
                "core_class_module", "sqlglotc_spec",
            }
            or
            Path(str(pytest_data.get("core_origin", ""))).resolve() != core.resolve()
            or pytest_data.get("core_class_module") != "sqlglot.tokenizer_core"
            or pytest_data.get("sqlglotc_spec") is not None
            or not isinstance(pytest_data.get("pytest_plugins"), list)
            or any(
                type(name) is not str or not name
                for name in pytest_data.get("pytest_plugins", [])
            )
            or pytest_data.get("pytest_plugins")
            != sorted(set(pytest_data.get("pytest_plugins", [])))
            or tuple(pytest_data.get("pytest_plugins", ())) != REVIEWED_PYTEST_PLUGINS
        ):
            raise SystemExit("TokenizerCore module-origin/native-overlay mismatch")
        events, sentries, processes = canonical_process_logs(
            children,
            run_set,
            environment_sha,
            str(collection_environment["executable"]),
            str(collection_environment["version"]),
            str(core.resolve()),
        )
        write_raw_bundle(mode, children, pytest_manifest, bundle)

    common = {
        "collector_sha256": collector_sha,
        "builder_sha256": builder_sha,
        "finalizer_sha256": finalizer_sha,
        "signature_module_sha256": signature_module_sha,
        "signer_sha256": signer_sha,
        "review_public_key_sha256": review_public_key_sha,
        "dependency_sha256": dependency_sha,
        "lifecycle_dependency_sha256": lifecycle_dependency_sha,
        "class_attribute_dependency_sha256": class_attribute_dependency_sha,
        "requirements_sha256": requirements_sha,
        "reflection_sha256": reflection_sha,
        "selector_model_sha256": selector_model_sha,
        "core_sha256": core_sha,
        "inventory_sha256": inventory_sha,
        "static_sha256": static_sha,
        "operations_sha256": operations_sha,
        "image_id": args.image_id,
        "base_image": BASE_IMAGE,
        "dockerfile_sha256": dockerfile_sha,
        "mode": mode,
        "python": python_version,
        "python_environment": collection_environment,
        "python_environment_sha256": json_digest(collection_environment),
        "source_sha": revision,
        "source_tree_sha256": source_tree_sha,
        "tracked_entries": materialization["tracked_entries"],
        "source_archive_sha256": materialization["archive_sha256"],
        "materialized_manifest_sha256": materialization[
            "materialized_manifest_sha256"
        ],
        "base_materialized_tree_sha256": base_materialized_sha,
        "mode_source_tree_sha256": mode_source_tree_sha,
        "raw_bundle_sha256": file_digest(bundle),
        "raw_bundle_size": bundle.stat().st_size,
        "instrumented_tree_sha256": instrumented_tree_sha,
        "support_sha256": support_sha,
        "test_digest": hashlib.sha256("\0".join(test_ids).encode()).hexdigest(),
        "executed_digest": hashlib.sha256("\0".join(sorted(run_set)).encode()).hexdigest(),
        "tests_sha256": TESTS_SHA256,
        "pytest_args_sha256": hashlib.sha256(json.dumps(pytest_arguments, separators=(",", ":")).encode()).hexdigest(),
        "tracker_version": TRACKER_VERSION,
        "core_origin_verified": True,
        "pytest_plugins": pytest_data["pytest_plugins"],
        "sentry_count": len(sentries),
        "sentry_sha256": json_digest(sentries),
        "collection_argv": list(sys.argv),
        "collection_argv_sha256": json_digest(list(sys.argv)),
    }
    trace = {**common, "events": events}
    raw = json.dumps(trace, sort_keys=True, separators=(",", ":"))
    output.write_text(raw)
    manifest.write_text(json.dumps({
        **common,
        "exitstatus": 0,
        "tests": sorted(run_set),
        "core_origin_suffix": "/sqlglot/tokenizer_core.py",
        "core_class_module": "sqlglot.tokenizer_core",
        "sqlglotc_spec": None,
        "child_complete": True,
        "child_starts": len(processes),
        "child_logs": len(processes),
        "child_completions": len(processes),
        "child_processes": processes,
        "child_tokens_sha256": hashlib.sha256("\0".join(item[0] for item in processes).encode()).hexdigest(),
        "trace_sha256": hashlib.sha256(raw.encode()).hexdigest(),
    }, sort_keys=True, separators=(",", ":")))
    print(f"READY-TO-BUILD/NO-SHIP: {mode}, {len(inventory)} entries, {len(operations)} value sites")


if __name__ == "__main__":
    main()
