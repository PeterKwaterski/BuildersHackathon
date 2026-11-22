#!/usr/bin/env python3
"""Capture first-effect TokenizerCore branches during fresh test-module imports."""

from __future__ import annotations

import argparse
import concurrent.futures
import importlib
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path


PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"
TARGET = "sqlglot/tokenizer_core.py"
LINES = {908, 950, 1405}
MARKER = "TOKENIZER_BRANCH_CHILD="
IMPLEMENTATION_SHA256 = "21f618281b27ae6567a22d4f24e4b0514d64a4c8be30037212c52a8c74753677"
IMPLEMENTATION_PATTERN = re.compile(
    rb'(?m)^IMPLEMENTATION_SHA256\s*=\s*"[^"]*"'
)
EXPECTED_RUNTIME = {
    "cache_tag": "cpython-313",
    "compiler": "GCC 14.2.0",
    "environment": "49497bc3ebd9b53a764db3de05a75fc08d320ff50465756d1258121fd2a080e7",
    "executable": "73efccb6aa17a74869ef6f11e0a0118b0f27693ea85f36c7a3758c307fd8914f",
    "hexversion": 51188464,
    "implementation": "cpython",
    "machine": "x86_64",
    "platform": "Linux",
    "pytest": "9.2.0",
    "version": "3.13.18 (main, Nov  5 2026, 07:59:38) [GCC 14.2.0]",
    "version_info": [3, 13, 18, "final", 0],
}


def implementation_digest() -> str:
    source = Path(__file__).read_bytes()
    normalized, count = IMPLEMENTATION_PATTERN.subn(
        b'IMPLEMENTATION_SHA256 = "<normalized>"', source
    )
    if count != 1:
        raise SystemExit("collector implementation sentinel is missing")
    return hashlib.sha256(normalized).hexdigest()


def runtime_identity() -> dict:
    import pytest

    executable = hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()
    environment = hashlib.sha256(
        json.dumps(
            {
                "executable": executable,
                "packages": sorted(
                    (distribution.metadata["Name"], distribution.version)
                    for distribution in importlib.metadata.distributions()
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return {
        "cache_tag": sys.implementation.cache_tag,
        "compiler": platform.python_compiler(),
        "environment": environment,
        "executable": executable,
        "hexversion": sys.hexversion,
        "implementation": sys.implementation.name,
        "machine": platform.machine(),
        "platform": platform.system(),
        "pytest": pytest.__version__,
        "version": sys.version,
        "version_info": list(sys.version_info),
    }


def capture(tree: Path, module: str) -> tuple[list[int], list]:
    seen = set()

    def local(frame, event, _arg):
        if event == "line" and frame.f_lineno in LINES:
            seen.add(frame.f_lineno)
        return local

    def trace(frame, event, _arg):
        if event != "call":
            return None
        try:
            relative = Path(frame.f_code.co_filename).resolve().relative_to(tree).as_posix()
        except (OSError, ValueError):
            return None
        return local if relative == TARGET else None

    os.chdir(tree)
    sys.path.insert(0, str(tree))
    failure = []
    sys.settrace(trace)
    try:
        importlib.import_module(module)
    except BaseException as error:
        failure = [module, type(error).__qualname__, repr(error)]
    finally:
        sys.settrace(None)
    return sorted(seen), failure


def capture_pytest_collection(tree: Path) -> tuple[list[int], int]:
    """Trace the complete pytest collection lifecycle, not only imports."""
    import pytest

    seen = set()
    target_file = str((tree / TARGET).resolve())

    def local(frame, event, _arg):
        if event == "line" and frame.f_lineno in LINES:
            seen.add(frame.f_lineno)
        return local

    def trace(frame, event, _arg):
        return local if event == "call" and frame.f_code.co_filename == target_file else None

    os.chdir(tree)
    sys.path.insert(0, str(tree))
    sys.settrace(trace)
    try:
        code = pytest.main(["--collect-only", "-qq"])
    finally:
        sys.settrace(None)
    return sorted(seen), int(code)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tree", type=Path, required=True)
    parser.add_argument("--tests", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--child")
    parser.add_argument("--pytest-collect", action="store_true")
    parser.add_argument("--jobs", type=int, default=8)
    args = parser.parse_args()
    if implementation_digest() != IMPLEMENTATION_SHA256:
        raise SystemExit("collector implementation digest mismatch")
    if runtime_identity() != EXPECTED_RUNTIME:
        raise SystemExit(f"collector runtime mismatch: {runtime_identity()!r}")
    tree = args.tree.resolve()
    if args.pytest_collect:
        lines, code = capture_pytest_collection(tree)
        print(MARKER + json.dumps({"collection_lines": lines, "collection_exit": code}))
        raise SystemExit(code)
    if args.child:
        lines, failure = capture(tree, args.child)
        print(MARKER + json.dumps({"module": args.child, "lines": lines, "failure": failure}))
        raise SystemExit(bool(failure))
    if args.tests is None or args.output is None:
        parser.error("--tests and --output are required")
    tests = json.loads(args.tests.read_text(encoding="utf-8"))["tests"]
    modules = sorted({test["file"].removesuffix(".py").replace("/", ".") for test in tests})

    def run(module: str) -> tuple[str, list[int], list]:
        command = [
            sys.executable,
            str(Path(__file__).resolve()),
            "--tree",
            str(tree),
            "--child",
            module,
        ]
        try:
            result = subprocess.run(
                command,
                cwd=tree,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=180,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            return module, [], [module, type(error).__qualname__, repr(error)]
        records = [line[len(MARKER):] for line in result.stdout.splitlines() if line.startswith(MARKER)]
        if len(records) != 1:
            return module, [], [module, "MissingChildRecord", result.stdout[-1000:]]
        try:
            record = json.loads(records[0])
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            return module, [], [module, type(error).__qualname__, repr(error)]
        failure = record.get("failure") or ([] if result.returncode == 0 else [module, "ChildExit", result.returncode])
        return module, record.get("lines", []), failure

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        records = list(pool.map(run, modules))
    collection_command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--tree",
        str(tree),
        "--pytest-collect",
    ]
    collection_result = subprocess.run(
        collection_command,
        cwd=tree,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=180,
        check=False,
    )
    collection_records = [
        line[len(MARKER):]
        for line in collection_result.stdout.splitlines()
        if line.startswith(MARKER)
    ]
    collection_record = json.loads(collection_records[0]) if len(collection_records) == 1 else {}
    owners: dict[str, list[str]] = defaultdict(list)
    failures = []
    for module, lines, failure in records:
        if failure:
            failures.append(failure)
        for line in lines:
            owners[str(line)].append(module)
    payload = {
        "v": 1,
        "sha": PINNED_SHA,
        "target": TARGET,
        "lines": sorted(LINES),
        "modules": modules,
        "owners": dict(sorted(owners.items())),
        "failures": failures,
        "collection_lines": collection_record.get("collection_lines"),
        "collection_exit": collection_record.get("collection_exit"),
        "collector": IMPLEMENTATION_SHA256,
        "runtime": EXPECTED_RUNTIME,
    }
    args.output.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    print(f"modules={len(modules)} owners={payload['owners']} failures={len(failures)}")
    if failures or payload["collection_lines"] != [] or payload["collection_exit"] != 0:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
