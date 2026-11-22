#!/usr/bin/env python3
"""Build the pinned-source certificate for isolated new Python modules.

This reads only the pinned source archive, selector model, and test manifest.
It never inspects sample commits or answers.
"""

from __future__ import annotations

import argparse
import ast
import base64
import gzip
import hashlib
import json
import re
import tarfile
from pathlib import Path


PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"
BLOOM_BITS = 1 << 21
BLOOM_HASHES = 5
IDENTIFIER = re.compile(rb"(?a:[A-Za-z_][A-Za-z0-9_]*)")

EXACT_RISKY_CALLS = {
    "builtins.__import__": "dynamic-import",
    "importlib.import_module": "dynamic-import",
    "importlib.util.find_spec": "dynamic-import",
    "importlib.util.module_from_spec": "dynamic-import",
    "importlib.util.spec_from_file_location": "dynamic-import",
    "importlib.util.spec_from_loader": "dynamic-import",
    "importlib.resources.contents": "package-data",
    "importlib.resources.files": "package-data",
    "importlib.resources.is_resource": "package-data",
    "importlib.resources.open_binary": "package-data",
    "importlib.resources.open_text": "package-data",
    "importlib.resources.read_binary": "package-data",
    "importlib.resources.read_text": "package-data",
    "pkgutil.find_loader": "dynamic-import",
    "pkgutil.get_importer": "dynamic-import",
    "pkgutil.iter_importers": "dynamic-import",
    "pkgutil.iter_modules": "directory-listing",
    "pkgutil.walk_packages": "directory-listing",
    "os.listdir": "directory-listing",
    "os.scandir": "directory-listing",
    "os.walk": "directory-listing",
    "os.fwalk": "directory-listing",
    "os.open": "source-reader",
    "glob.glob": "directory-listing",
    "glob.iglob": "directory-listing",
    "inspect.getsource": "source-reader",
    "inspect.getsourcelines": "source-reader",
    "inspect.findsource": "source-reader",
    "inspect.getfile": "source-reader",
    "runpy.run_module": "dynamic-code",
    "runpy.run_path": "dynamic-code",
    "subprocess.run": "subprocess",
    "subprocess.Popen": "subprocess",
    "subprocess.call": "subprocess",
    "subprocess.check_call": "subprocess",
    "subprocess.check_output": "subprocess",
    "os.system": "subprocess",
    "os.popen": "subprocess",
    "os.execl": "subprocess",
    "os.execle": "subprocess",
    "os.execlp": "subprocess",
    "os.execlpe": "subprocess",
    "os.execv": "subprocess",
    "os.execve": "subprocess",
    "os.execvp": "subprocess",
    "os.execvpe": "subprocess",
    "os.posix_spawn": "subprocess",
    "os.posix_spawnp": "subprocess",
    "os.spawnl": "subprocess",
    "os.spawnle": "subprocess",
    "os.spawnlp": "subprocess",
    "os.spawnlpe": "subprocess",
    "os.spawnv": "subprocess",
    "os.spawnve": "subprocess",
    "os.spawnvp": "subprocess",
    "os.spawnvpe": "subprocess",
    "os.path.isfile": "path-probe",
    "os.path.isdir": "path-probe",
    "os.path.lexists": "path-probe",
    "os.path.samefile": "path-probe",
    "os.path.getsize": "path-probe",
    "os.path.getmtime": "path-probe",
    "multiprocessing.Pool": "subprocess",
    "multiprocessing.Process": "subprocess",
    "concurrent.futures.ProcessPoolExecutor": "subprocess",
    "pkg_resources.resource_exists": "package-data",
    "pkg_resources.resource_filename": "package-data",
    "pkg_resources.resource_listdir": "package-data",
}

RISKY_METHODS = {
    "iterdir": "directory-listing",
    "glob": "directory-listing",
    "rglob": "directory-listing",
    "exists": "path-probe",
    "is_file": "path-probe",
    "is_dir": "path-probe",
    "stat": "path-probe",
    "lstat": "path-probe",
    "read_text": "source-reader",
    "read_bytes": "source-reader",
    "open": "source-reader",
}

RISKY_BUILTINS = {
    "__import__": "dynamic-import",
    "open": "source-reader",
    "eval": "dynamic-code",
    "exec": "dynamic-code",
    "compile": "dynamic-code",
}

PROCESS_METHODS = {
    "submit",
    "map",
    "starmap",
    "apply",
    "apply_async",
    "imap",
    "imap_unordered",
}


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--selector-model", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def digest_json(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def write_deterministic_gzip(path: Path, data: bytes) -> None:
    """Write bytes without leaking the caller's output basename into gzip."""
    with path.open("wb") as raw_output:
        with gzip.GzipFile(
            filename="", fileobj=raw_output, mode="wb", compresslevel=9, mtime=0
        ) as compressed:
            compressed.write(data)


def bloom_positions(token: str):
    digest = hashlib.sha256(token.encode("ascii")).digest()
    for index in range(BLOOM_HASHES):
        start = index * 4
        yield int.from_bytes(digest[start : start + 4], "big") & (BLOOM_BITS - 1)


def archive_profile(path: Path) -> tuple[str, str, list[str], int, int]:
    manifest = []
    tokens: set[str] = set()
    parents: set[str] = set()
    file_count = 0
    with tarfile.open(path, "r:*") as archive:
        for member in sorted(archive.getmembers(), key=lambda item: item.name):
            if not member.isfile():
                continue
            relative = member.name.removeprefix("sqlglot/")
            extracted = archive.extractfile(member)
            if not relative or extracted is None:
                raise SystemExit(f"invalid archive member {member.name!r}")
            data = extracted.read()
            file_count += 1
            manifest.append([relative, hashlib.sha256(data).hexdigest(), len(data)])
            token_bytes = relative.encode("utf-8") + b"\0" + data
            for match in IDENTIFIER.finditer(token_bytes):
                token = match.group().decode("ascii")
                tokens.update((token, token.lower(), token.upper()))
            if relative.startswith("sqlglot/") and relative.endswith(".py"):
                parent = Path(relative).parent.as_posix()
                if f"{parent}/__init__.py" != relative:
                    parents.add(parent)

    bits = bytearray(BLOOM_BITS // 8)
    for token in tokens:
        for position in bloom_positions(token):
            bits[position >> 3] |= 1 << (position & 7)
    return (
        digest_json(manifest),
        base64.b64encode(bits).decode("ascii"),
        sorted(parents),
        file_count,
        len(tokens),
    )


def import_aliases(tree: ast.Module) -> dict[str, str]:
    aliases = {name: f"builtins.{name}" for name in RISKY_BUILTINS}
    aliases.update(
        {
            "dir": "builtins.dir",
            "vars": "builtins.vars",
            "getattr": "builtins.getattr",
            "hasattr": "builtins.hasattr",
        }
    )
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                aliases[local] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if alias.name != "*":
                    aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def qualified_name(node: ast.AST, aliases: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        prefix = qualified_name(node.value, aliases)
        return f"{prefix}.{node.attr}" if prefix else None
    return None


def module_reflection(
    call: ast.Call, called: str | None, aliases: dict[str, str]
) -> bool:
    if not call.args:
        return False
    if (
        called in {"builtins.getattr", "builtins.hasattr"}
        and len(call.args) >= 2
        and isinstance(call.args[1], ast.Constant)
        and isinstance(call.args[1].value, str)
    ):
        # A literal attribute cannot name an absent candidate because the
        # archive-wide word filter independently rejects that exact stem.
        return False
    first = call.args[0]
    name = qualified_name(first, aliases) or ""
    if name == "sqlglot" or name.startswith("sqlglot."):
        return True
    if isinstance(first, ast.Call):
        return qualified_name(first.func, aliases) == "importlib.import_module"
    if isinstance(first, ast.Subscript):
        return qualified_name(first.value, aliases) == "sys.modules"
    return False


def risky_inventory(sources: dict[str, str]) -> list[list[object]]:
    inventory = []
    for path, source in sorted(sources.items()):
        tree = ast.parse(source, filename=path, type_comments=True)
        aliases = import_aliases(tree)
        process_objects: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            if not isinstance(value, ast.Call):
                continue
            called = qualified_name(value.func, aliases)
            if called not in {
                "multiprocessing.Pool",
                "concurrent.futures.ProcessPoolExecutor",
            }:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            process_objects.update(
                child.id
                for target in targets
                for child in ast.walk(target)
                if isinstance(child, ast.Name)
            )

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            called = qualified_name(node.func, aliases)
            kind = EXACT_RISKY_CALLS.get(called or "")
            if kind is None and isinstance(node.func, ast.Attribute):
                kind = RISKY_METHODS.get(node.func.attr)
                if node.func.attr in PROCESS_METHODS:
                    root = qualified_name(node.func.value, aliases) or ""
                    if root in process_objects or root in {"pool", "executor", "self.pool"}:
                        kind = "subprocess"
            if kind is None and called and called.startswith("builtins."):
                kind = RISKY_BUILTINS.get(called.removeprefix("builtins."))
            if kind is None and isinstance(node.func, ast.Name):
                kind = RISKY_BUILTINS.get(node.func.id)
            if kind is None and called in {
                "builtins.dir",
                "builtins.vars",
                "builtins.getattr",
                "builtins.hasattr",
            } and module_reflection(node, called, aliases):
                kind = "package-reflection"
            if kind is not None:
                inventory.append(
                    [path, node.lineno, node.end_lineno or node.lineno, kind, called or ""]
                )
    return sorted(inventory)


def site_readers(model: dict, path: str, start: int, end: int) -> set[int]:
    entry = model.get("f", {}).get(path)
    if not isinstance(entry, dict):
        return set()
    line_sets = dict(entry.get("l", ()))
    readers = set()
    for line in range(start, end + 1):
        set_id = line_sets.get(line)
        if set_id is not None:
            readers.update(model["z"][set_id])
    if readers:
        return readers
    scopes = [
        scope
        for scope in entry.get("s", ())
        if scope[0] <= start <= scope[1] or start <= scope[0] <= end
    ]
    if scopes:
        scope = min(scopes, key=lambda item: item[1] - item[0])
        return set(model["z"][scope[3]])
    return set(model["z"][entry["f"]])


def main() -> None:
    args = arguments()
    with gzip.open(args.sources, "rt", encoding="utf-8") as source_file:
        sources = json.load(source_file)
    with gzip.open(args.selector_model, "rt", encoding="utf-8") as model_file:
        selector_model = json.load(model_file)
    tests = json.loads(args.tests.read_text())["tests"]
    test_digest = hashlib.sha256(
        "\0".join(test["id"] for test in tests).encode("utf-8")
    ).hexdigest()
    if selector_model.get("sha") != PINNED_SHA or selector_model.get("t") != [
        test["id"] for test in tests
    ]:
        raise SystemExit("selector model and test manifest are not the pinned inventory")

    source_digest, bloom, parents, file_count, token_count = archive_profile(args.archive)
    inventory = risky_inventory(sources)
    readers = set()
    for path, start, end, _kind, _called in inventory:
        readers.update(site_readers(selector_model, path, start, end))

    profile = {
        "b": bloom,
        "d": source_digest,
        "f": file_count,
        "i": inventory,
        "k": BLOOM_HASHES,
        "m": BLOOM_BITS,
        "a": parents,
        "r": sorted(readers),
        "w": token_count,
    }
    output = {
        "v": 1,
        "sha": PINNED_SHA,
        "t": test_digest,
        "n": len(tests),
        "p": digest_json(profile),
        **profile,
    }
    encoded = json.dumps(output, sort_keys=True, separators=(",", ":")).encode()
    write_deterministic_gzip(args.output, encoded)
    print(
        f"wrote {args.output}: {len(inventory)} risky sites, {len(readers)} readers, "
        f"{token_count} words from {file_count} files; profile {output['p']}"
    )
    print(f"source {source_digest}; inventory {digest_json(inventory)}")


if __name__ == "__main__":
    main()
