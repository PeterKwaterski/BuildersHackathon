"""Fail-closed verifier for bounded edits to the pinned TPC-DS SQL fixture."""

from __future__ import annotations

import gzip
import hashlib
import importlib.metadata
import json
import math
import os
import ctypes
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PINNED_TREE = Path("/app/sqlglot-pinned")
FIXTURE = "tests/fixtures/optimizer/tpc-ds/tpc-ds.sql"
PINNED_FIXTURE = PINNED_TREE / FIXTURE
MANIFEST = ROOT / "broad_verify_manifest.json.gz"
CHILD = ROOT / "tpc_fixture_verify_child.py"
ARCHIVE = ROOT / "sqlglot-eb11aec.tar.xz"
REQUIREMENTS = ROOT / "requirements.lock"
TESTS = Path("/data/tests.json")

FIXTURE_SHA256 = "f584cd3a0dac63ca9654f74ef53011f4b9db7cad223f812de621dadb2ff982d4"
MANIFEST_SHA256 = "f46b813ae7add21faff295af03b009dcd30368c7e4264144f191e133d26a35cd"
ARCHIVE_SHA256 = "d51ca06c87658f35981016e2b8d27b291e3b2995ee263ab45e77b07b76d0aaa7"
REQUIREMENTS_SHA256 = "3c752cfa352064043d55ea97d874ed2b11c5860f8f089783c832d6a4e0d63e60"
TESTS_SHA256 = "21257a93c58f4b0646c5122586d2141b4b340ad85b2f0bb251af3746de3f0dc2"
CHILD_SHA256 = "42a8ba79cece3e8398f12979e08702b5a28d3f686a8c3c926ffe12ddd1c9110b"
MAX_CHANGED_PAIRS = 3
MAX_SOURCE_BYTES = 1_000_000
MAX_CPU_SECONDS = 18.0
MAX_WALL_SECONDS = 25.0
MAX_RESULT_BYTES = 16_384
MAX_BATCH_ATTEMPTS = 3
MAX_BATCH_CPU_SECONDS = 36.0
CHILD_UID = 65534
CHILD_GID = 65534

_pinned_source: str | None = None
_pinned_failed = False
_subreaper_ready: bool | None = None
_batch_attempts = 0
_batch_cpu = 0.0


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_pinned_source() -> str | None:
    global _pinned_source, _pinned_failed
    if _pinned_source is not None:
        return _pinned_source
    if _pinned_failed:
        return None
    try:
        raw_manifest = MANIFEST.read_bytes()
        if hashlib.sha256(raw_manifest).hexdigest() != MANIFEST_SHA256:
            raise ValueError("manifest digest")
        manifest = json.loads(gzip.decompress(raw_manifest))
        if (
            set(manifest) != {
                "v",
                "source_sha",
                "archive_sha256",
                "tests_sha256",
                "requirements_sha256",
                "builder_sha256",
                "entries",
            }
            or manifest.get("v") != 1
            or manifest.get("source_sha") != "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"
            or manifest.get("archive_sha256") != ARCHIVE_SHA256
            or manifest.get("tests_sha256") != TESTS_SHA256
            or manifest.get("requirements_sha256") != REQUIREMENTS_SHA256
            or sys.implementation.name != "cpython"
            or sys.version_info[:3] != (3, 13, 18)
            or os.geteuid() not in {0, CHILD_UID}
            or _sha256(ARCHIVE) != ARCHIVE_SHA256
            or _sha256(REQUIREMENTS) != REQUIREMENTS_SHA256
            or _sha256(TESTS) != TESTS_SHA256
        ):
            raise ValueError("runtime provenance")
        for requirement in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
            name, separator, version = requirement.partition("==")
            if not separator or importlib.metadata.version(name) != version:
                raise ValueError("installed dependency")
        entries = manifest.get("entries")
        if not isinstance(entries, list):
            raise ValueError("manifest schema")
        expected = {entry[0]: entry for entry in entries}
        observed = {
            path.relative_to(PINNED_TREE).as_posix(): path
            for path in PINNED_TREE.rglob("*")
            if "__pycache__" not in path.relative_to(PINNED_TREE).parts
        }
        if set(observed) != set(expected):
            raise ValueError("tree roster")
        for relative, entry in expected.items():
            if not isinstance(entry, list) or len(entry) != 5:
                raise ValueError("manifest entry")
            _name, kind, mode, size, payload = entry
            path = observed[relative]
            metadata = path.lstat()
            actual_kind = (
                "symlink"
                if stat.S_ISLNK(metadata.st_mode)
                else "dir"
                if stat.S_ISDIR(metadata.st_mode)
                else "file"
                if stat.S_ISREG(metadata.st_mode)
                else "other"
            )
            expected_mode = int(mode) if kind == "symlink" else int(mode) & ~0o022
            if (
                actual_kind != kind
                or stat.S_IMODE(metadata.st_mode) != expected_mode
                or (kind == "file" and (metadata.st_size != size or _sha256(path) != payload))
                or (kind == "symlink" and os.readlink(path) != payload)
            ):
                raise ValueError("tree content")
        if _sha256(PINNED_FIXTURE) != FIXTURE_SHA256:
            raise ValueError("fixture digest")
        if CHILD_SHA256 and _sha256(CHILD) != CHILD_SHA256:
            raise ValueError("child digest")
        source = PINNED_FIXTURE.read_text(encoding="utf-8")
        if len(source.encode()) > MAX_SOURCE_BYTES or "\r" in source:
            raise ValueError("fixture encoding")
    except (
        OSError,
        EOFError,
        UnicodeError,
        ValueError,
        TypeError,
        MemoryError,
        importlib.metadata.PackageNotFoundError,
    ):
        _pinned_failed = True
        return None
    _pinned_source = source
    return source


def _fixture_pairs(source: str) -> list[tuple[tuple[tuple[str, str], ...], str, str]] | None:
    """Mirror the pinned tests.helpers fixture parser without importing sqlglot."""
    try:
        filtered = "\n".join(
            line for line in source.splitlines() if line and not line.startswith("--")
        )
        statements = filtered.split(";")
        pairs = []
        for index in range(0, len(statements), 2):
            if index + 1 >= len(statements):
                continue
            sql = statements[index].strip()
            lines = sql.split("\n")
            meta: dict[str, str] = {}
            position = 0
            while position < len(lines) and lines[position].startswith("#"):
                key, separator, value = lines[position].partition(":")
                if not separator:
                    return None
                key = key.lstrip("#").strip()
                if not key or key in meta:
                    return None
                meta[key] = value.strip()
                position += 1
            sql = "\n".join(lines[position:])
            if set(meta) - {"execute"} or meta.get("execute") not in {None, "true"}:
                return None
            pairs.append((tuple(sorted(meta.items())), sql, statements[index + 1].strip()))
        return pairs
    except (TypeError, ValueError, MemoryError, RecursionError):
        return None


def _structure_ok(change: dict) -> bool:
    try:
        return not (
            type(change) is not dict
            or change.get("old") != FIXTURE
            or change.get("new") != FIXTURE
            or change.get("diff_old") != FIXTURE
            or change.get("diff_new") != FIXTURE
            or change.get("structural_invalid")
            or change.get("binary")
            or change.get("non_lf")
            or change.get("no_newline_marker")
            or change.get("new_file_mode") is not None
            or change.get("new_file_mode_count") != 0
            or change.get("old_marker_count") != 1
            or change.get("new_marker_count") != 1
            or change.get("index_count") != 1
            or change.get("new_file_index")
            or not isinstance(change.get("hunks"), list)
            or not change["hunks"]
        )
    except (KeyError, TypeError, ValueError, OverflowError, MemoryError):
        return False


def _apply_change(change: dict, original: str) -> str | None:
    try:
        if not _structure_ok(change):
            return None
        lines = original.splitlines()
        result: list[str] = []
        cursor = 0
        line_delta = 0
        for hunk in change["hunks"]:
            body = hunk.get("lines")
            if (
                type(hunk.get("old_start")) is not int
                or type(hunk.get("old_count")) is not int
                or type(hunk.get("new_start")) is not int
                or type(hunk.get("new_count")) is not int
                or hunk["old_count"] <= 0
                or hunk["new_count"] <= 0
                or hunk["new_start"] != hunk["old_start"] + line_delta
                or not isinstance(body, list)
                or sum(marker != "+" for marker, _text in body) != hunk["old_count"]
                or sum(marker != "-" for marker, _text in body) != hunk["new_count"]
            ):
                return None
            start = max(0, hunk["old_start"] if hunk["old_count"] == 0 else hunk["old_start"] - 1)
            if start < cursor or start > len(lines):
                return None
            result.extend(lines[cursor:start])
            cursor = start
            for marker, text in hunk["lines"]:
                if marker == "+":
                    result.append(text)
                    continue
                if marker not in {" ", "-"} or cursor >= len(lines) or lines[cursor] != text:
                    return None
                if marker == " ":
                    result.append(text)
                cursor += 1
            line_delta += hunk["new_count"] - hunk["old_count"]
        result.extend(lines[cursor:])
        prospective = "\n".join(result) + ("\n" if original.endswith("\n") else "")
        if len(prospective.encode()) > MAX_SOURCE_BYTES or "\r" in prospective:
            return None
        return prospective
    except (KeyError, TypeError, ValueError, OverflowError, MemoryError):
        return None


def classify(change: dict) -> tuple[str, list[int], bool] | None:
    if not _structure_ok(change):
        return None
    original = _load_pinned_source()
    if original is None:
        return None
    prospective = _apply_change(change, original)
    if prospective is None:
        return None
    before = _fixture_pairs(original)
    after = _fixture_pairs(prospective)
    if before is None or after is None or len(before) != len(after) or len(before) != 99:
        return None
    changed = [index for index, pair in enumerate(zip(before, after)) if pair[0] != pair[1]]
    if len(changed) > MAX_CHANGED_PAIRS:
        return None
    dynamic = any(before[index][:2] != after[index][:2] for index in changed)
    return prospective, changed, dynamic


def _drop_privileges() -> None:
    if os.geteuid() == 0:
        os.setgroups([])
        os.setgid(CHILD_GID)
        os.setuid(CHILD_UID)
    elif os.geteuid() != CHILD_UID or os.getegid() != CHILD_GID:
        raise PermissionError("unexpected verifier identity")
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_RESULT_BYTES, MAX_RESULT_BYTES))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    resource.setrlimit(resource.RLIMIT_CPU, (math.ceil(MAX_CPU_SECONDS), math.ceil(MAX_CPU_SECONDS) + 1))
    resource.setrlimit(resource.RLIMIT_AS, (3_000_000_000, 3_000_000_000))


def _terminate_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass


def _set_subreaper() -> bool:
    global _subreaper_ready
    if _subreaper_ready is not None:
        return _subreaper_ready
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
            raise OSError(ctypes.get_errno(), "prctl")
        value = ctypes.c_int()
        if libc.prctl(37, ctypes.byref(value), 0, 0, 0) != 0 or value.value != 1:
            raise OSError(ctypes.get_errno(), "prctl verify")
    except (OSError, ValueError, TypeError):
        _subreaper_ready = False
    else:
        _subreaper_ready = True
    return _subreaper_ready


def _group_members(group: int) -> set[int] | None:
    try:
        members = set()
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            raw = (entry / "stat").read_text(encoding="ascii")
            close = raw.rfind(")")
            fields = raw[close + 2 :].split()
            if close < 0 or len(fields) < 3:
                return None
            if int(fields[2]) == group:
                members.add(int(entry.name))
        return members
    except (OSError, UnicodeError, ValueError, IndexError):
        return None


def _group_cpu(group: int) -> float | None:
    try:
        ticks = os.sysconf("SC_CLK_TCK")
        total = 0
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                raw = (entry / "stat").read_text(encoding="ascii")
            except FileNotFoundError:
                continue
            close = raw.rfind(")")
            fields = raw[close + 2 :].split()
            if close < 0 or len(fields) < 13:
                return None
            if int(fields[2]) == group:
                total += int(fields[11]) + int(fields[12])
        return total / ticks
    except (OSError, UnicodeError, ValueError, IndexError):
        return None


def _cleanup_group(process: subprocess.Popen) -> bool:
    _terminate_group(process)
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        while True:
            try:
                pid, _status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            except OSError:
                return False
            if pid == 0:
                break
        members = _group_members(process.pid)
        if members is not None and not members:
            return True
        time.sleep(0.01)
    members = _group_members(process.pid)
    return members is not None and not members


def verify(change: dict) -> tuple[bool, float, str]:
    parent_started = time.process_time()
    classified = classify(change)
    if classified is None:
        return False, 0.0, "ineligible"
    prospective, changed, dynamic = classified
    if not dynamic:
        return True, max(0.0, time.process_time() - parent_started), "expected-only"
    global _batch_attempts, _batch_cpu
    if _batch_attempts >= MAX_BATCH_ATTEMPTS or _batch_cpu >= MAX_BATCH_CPU_SECONDS:
        return False, 0.0, "batch-budget"
    _batch_attempts += 1
    started = time.monotonic()
    usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    process = None
    cleaned = False
    if not _set_subreaper():
        return False, 0.0, "subreaper"
    try:
        with tempfile.TemporaryDirectory(prefix="br-tpc-fixture-") as temporary:
            private = Path(temporary)
            private.chmod(0o711)
            repo = private / "repo"
            shutil.copytree(PINNED_TREE, repo, symlinks=True, copy_function=os.symlink)
            fixture = repo / FIXTURE
            fixture.unlink()
            fixture.write_text(prospective, encoding="utf-8")
            fixture.chmod(0o444)
            scratch = private / "scratch"
            scratch.mkdir(mode=0o700)
            if os.geteuid() == 0:
                os.chown(scratch, CHILD_UID, CHILD_GID)
            result = scratch / "result.json"
            payload = scratch / "payload.json"
            payload.write_text(json.dumps({"indices": changed}, separators=(",", ":")), encoding="utf-8")
            if os.geteuid() == 0:
                os.chown(payload, CHILD_UID, CHILD_GID)
            payload.chmod(0o400)
            result.touch(mode=0o600)
            if os.geteuid() == 0:
                os.chown(result, CHILD_UID, CHILD_GID)
            environment = {
                "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                "PYTHONHASHSEED": "0",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
                "TMPDIR": str(scratch),
            }
            process = subprocess.Popen(
                [sys.executable, str(CHILD), str(repo), str(payload), str(result)],
                cwd=repo,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                preexec_fn=_drop_privileges,
            )
            deadline = time.monotonic() + MAX_WALL_SECONDS
            budget_failure = None
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    budget_failure = "timeout"
                    break
                group_cpu = _group_cpu(process.pid)
                if group_cpu is None:
                    budget_failure = "observation"
                    break
                if group_cpu > MAX_CPU_SECONDS:
                    budget_failure = "cpu-budget"
                    break
                time.sleep(0.02)
            if budget_failure is not None:
                cleaned = _cleanup_group(process)
                _batch_cpu += MAX_CPU_SECONDS
                return False, MAX_CPU_SECONDS, budget_failure
            returncode = process.returncode
            cleaned = _cleanup_group(process)
            if not cleaned or returncode != 0 or not result.is_file() or result.stat().st_size > MAX_RESULT_BYTES:
                return False, 0.0, "child-failure"
            document = json.loads(result.read_text(encoding="utf-8"))
            if document != {"ok": True, "indices": changed}:
                return False, 0.0, "mismatch"
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError, MemoryError, subprocess.SubprocessError):
        if process is not None:
            _terminate_group(process)
        return False, 0.0, "exception"
    finally:
        if process is not None and not cleaned:
            _cleanup_group(process)
    usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu = max(0.0, usage_after.ru_utime + usage_after.ru_stime - usage_before.ru_utime - usage_before.ru_stime)
    cpu += max(0.0, time.process_time() - parent_started)
    _batch_cpu += cpu
    wall = time.monotonic() - started
    if cpu > MAX_CPU_SECONDS or wall > MAX_WALL_SECONDS:
        return False, cpu, "budget"
    return True, cpu, "verified"
