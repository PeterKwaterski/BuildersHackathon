"""Conservative forked unittest verification on an exact patched overlay.

The pinned manifest contains ordinary ``unittest.TestCase`` methods. For a
small static candidate set, run those exact methods in a fresh child whose
source tree contains the complete patch. Every ambiguity, timeout, import or
setup error, and attribution problem returns the original candidates.
"""

from __future__ import annotations

import ast
import contextlib
import importlib
import importlib.util
import json
import os
import shutil
import signal
import struct
import sys
import time
import unittest
from pathlib import Path


PINNED_TREE = Path("/opt/sqlglot")
OVERLAY = Path("/tmp/blast-radius-verify")
MAX_RECORDED_SECONDS = 0.5
MAX_CANDIDATES = 16
MIN_TIMEOUT_SECONDS = 5.0
MAX_TIMEOUT_SECONDS = 12.0
PROCESS_POOL_TEST_FILES = {"tests/test_executor.py", "tests/test_optimizer.py"}

_overlay_ready = False
_overlay_poisoned = False
_warm_ready = False
_warm_failed = False
_warm_compatibility: dict[str, bool] = {}


def _module_name(path: str) -> str | None:
    candidate = Path(path)
    if path.startswith("/") or ".." in candidate.parts or candidate.suffix != ".py":
        return None
    return path[:-3].replace("/", ".").removesuffix(".__init__")


def _safe_source_path(path: str) -> Path | None:
    candidate = Path(path)
    if (
        candidate.is_absolute()
        or not candidate.parts
        or ".." in candidate.parts
        or candidate.parts[0] != "sqlglot"
        or candidate.suffix != ".py"
    ):
        return None
    return candidate


def _source_module(path: str) -> str | None:
    relative = _safe_source_path(path)
    if relative is None:
        return None
    return str(relative.with_suffix("")).replace("/", ".").removesuffix(".__init__")


def _warm_compatible_test(test_id: str) -> bool:
    test_path = test_id.split("::", 1)[0]
    if test_path in _warm_compatibility:
        return _warm_compatibility[test_path]
    compatible = test_path == "tests/dialects/test_dialect.py"
    try:
        tree = ast.parse((PINNED_TREE / test_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, SyntaxError, ValueError):
        tree = None
    if tree is not None and not compatible:
        validator_imports = [
            index
            for index, node in enumerate(tree.body)
            if isinstance(node, ast.ImportFrom)
            and node.module == "tests.dialects.test_dialect"
            and any(alias.name == "Validator" for alias in node.names)
        ]
        sqlglot_imports = [
            index
            for index, node in enumerate(tree.body)
            if (
                isinstance(node, ast.ImportFrom)
                and node.module is not None
                and (node.module == "sqlglot" or node.module.startswith("sqlglot."))
            )
            or (
                isinstance(node, ast.Import)
                and any(
                    alias.name == "sqlglot" or alias.name.startswith("sqlglot.")
                    for alias in node.names
                )
            )
        ]
        compatible = bool(validator_imports) and min(validator_imports) < min(
            sqlglot_imports, default=len(tree.body)
        )
    _warm_compatibility[test_path] = compatible
    return compatible


def _ensure_overlay() -> bool:
    global _overlay_ready
    if _overlay_poisoned:
        return False
    if _overlay_ready:
        return True
    if not PINNED_TREE.is_dir() or OVERLAY.exists():
        return False
    try:
        shutil.copytree(PINNED_TREE, OVERLAY, copy_function=os.symlink)
    except OSError:
        return False
    _overlay_ready = True
    return True


def _prepare_warm_parent() -> bool:
    """Import the common dialect-test substrate once before any patch install.

    Pytest imports test modules during collection before it runs tests.  Keeping
    this source-independent baseline state in the fork parent both mirrors that
    lifecycle and amortizes the expensive common imports.  A patch is eligible
    only when none of its modules were imported into this state.
    """
    global _warm_ready, _warm_failed
    if _warm_ready:
        return True
    if _warm_failed:
        return False
    pinned = str(PINNED_TREE)
    inserted = not sys.path or sys.path[0] != pinned
    if inserted:
        sys.path.insert(0, pinned)
    try:
        with open(os.devnull, "w", encoding="utf-8") as sink:
            with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
                common = importlib.import_module("tests.dialects.test_dialect")
                sqlglot = importlib.import_module("sqlglot")
        if not Path(common.__file__).resolve().is_relative_to(PINNED_TREE.resolve()):
            raise RuntimeError("test substrate did not come from pinned tree")
        if not Path(sqlglot.__file__).resolve().is_relative_to(PINNED_TREE.resolve()):
            raise RuntimeError("sqlglot did not come from pinned tree")
    except BaseException:
        _warm_failed = True
        return False
    finally:
        if inserted and sys.path and sys.path[0] == pinned:
            sys.path.pop(0)
    _warm_ready = True
    return True


def _redirect_package_paths() -> None:
    """Make future child imports resolve through the complete patched overlay."""
    for name, module in tuple(sys.modules.items()):
        if not (
            name == "sqlglot"
            or name.startswith("sqlglot.")
            or name == "tests"
            or name.startswith("tests.")
        ) or not hasattr(module, "__path__"):
            continue
        package = OVERLAY.joinpath(*name.split("."))
        if not package.is_dir():
            raise RuntimeError("loaded package is absent from overlay")
        module.__path__ = [str(package)]
        spec = getattr(module, "__spec__", None)
        if spec is not None:
            spec.submodule_search_locations = module.__path__


def _restore_sources(installed: list[tuple[Path, Path]]) -> bool:
    global _overlay_poisoned
    ok = True
    for destination, original in reversed(installed):
        try:
            destination.unlink(missing_ok=True)
            destination.symlink_to(original)
        except OSError:
            ok = False
    if not ok:
        _overlay_poisoned = True
    return ok


def _install_sources(sources: list[tuple[str, str]]) -> list[tuple[Path, Path]] | None:
    if not sources or len({name for name, _source in sources}) != len(sources):
        return None
    installed: list[tuple[Path, Path]] = []
    try:
        for name, source in sources:
            relative = _safe_source_path(name)
            if relative is None or type(source) is not str:
                raise ValueError("unsafe verification source")
            original = PINNED_TREE / relative
            destination = OVERLAY / relative
            if not original.is_file() or not destination.is_symlink():
                raise ValueError("verification path is not a pristine pinned file")
            cached = Path(importlib.util.cache_from_source(str(original)))
            try:
                header = cached.read_bytes()[:8]
            except OSError:
                raise ValueError("missing checked-hash bytecode cache") from None
            if len(header) != 8 or struct.unpack("<I", header[4:8])[0] & 3 != 3:
                raise ValueError("bytecode cache is not checked-hash validated")
            installed.append((destination, original))
            destination.unlink()
            destination.write_text(source, encoding="utf-8")
    except (OSError, UnicodeError, ValueError):
        _restore_sources(installed)
        return None
    return installed


def _case_for_id(test_id: str) -> unittest.TestCase | None:
    parts = test_id.split("::")
    if len(parts) != 3:
        return None
    module_name = _module_name(parts[0])
    if module_name is None:
        return None
    try:
        module = importlib.import_module(module_name)
    except BaseException:
        return None
    if any(
        hasattr(module, name)
        for name in (
            "pytestmark",
            "setup_module",
            "teardown_module",
            "setUpModule",
            "tearDownModule",
            "load_tests",
        )
    ):
        return None
    owner = getattr(module, parts[1], None)
    method = getattr(owner, parts[2], None) if isinstance(owner, type) else None
    if (
        not isinstance(owner, type)
        or not issubclass(owner, unittest.TestCase)
        or not callable(method)
        or hasattr(owner, "pytestmark")
        or hasattr(method, "pytestmark")
        or hasattr(method, "_pytestfixturefunction")
    ):
        return None
    try:
        return owner(parts[2])
    except (TypeError, ValueError):
        return None


def _child_run(write_fd: int, requested: list[str], source_modules: list[str]) -> None:
    payload: dict[str, object] = {"ok": False}
    try:
        os.setsid()
        with open(os.devnull, "wb", buffering=0) as sink:
            os.dup2(sink.fileno(), 1)
            os.dup2(sink.fileno(), 2)
        os.chdir(OVERLAY)
        sys.path.insert(0, str(OVERLAY))
        sys.dont_write_bytecode = True
        os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
        prior_pythonpath = os.environ.get("PYTHONPATH")
        os.environ["PYTHONPATH"] = (
            f"{OVERLAY}{os.pathsep}{prior_pythonpath}" if prior_pythonpath else str(OVERLAY)
        )
        if any(name in sys.modules for name in source_modules):
            raise RuntimeError("patched module was imported by warm parent")
        _redirect_package_paths()

        cases = []
        case_ids: dict[int, str] = {}
        for test_id in requested:
            case = _case_for_id(test_id)
            if case is None or id(case) in case_ids:
                raise RuntimeError("unmappable unittest case")
            cases.append(case)
            case_ids[id(case)] = test_id

        result = unittest.TestResult()
        unittest.TestSuite(cases).run(result)
        if result.testsRun != len(cases) or result.shouldStop:
            raise RuntimeError("incomplete unittest run")

        failed: set[str] = set()
        outcomes = [
            *(test for test, _traceback in result.failures),
            *(test for test, _traceback in result.errors),
            *result.unexpectedSuccesses,
        ]
        for outcome in outcomes:
            case = getattr(outcome, "test_case", outcome)
            test_id = case_ids.get(id(case))
            if test_id is None:
                raise RuntimeError("unattributed unittest failure")
            failed.add(test_id)
        payload = {"ok": True, "failed": sorted(failed)}
    except BaseException:
        payload = {"ok": False}
    try:
        os.write(write_fd, json.dumps(payload, separators=(",", ":")).encode())
    except OSError:
        pass
    os._exit(0)


def _kill_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _run_forked(
    requested: list[str], recorded_seconds: float, source_modules: list[str]
) -> set[str] | None:
    try:
        read_fd, write_fd = os.pipe()
    except OSError:
        return None
    try:
        pid = os.fork()
    except OSError:
        os.close(read_fd)
        os.close(write_fd)
        return None
    if pid == 0:
        os.close(read_fd)
        _child_run(write_fd, requested, source_modules)

    os.close(write_fd)
    timeout = min(
        MAX_TIMEOUT_SECONDS,
        max(MIN_TIMEOUT_SECONDS, recorded_seconds * 8.0 + 3.0),
    )
    deadline = time.monotonic() + timeout
    status = None
    while time.monotonic() < deadline:
        try:
            waited, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            waited = pid
            status = None
        if waited == pid:
            break
        time.sleep(0.005)
    else:
        _kill_group(pid)
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        os.close(read_fd)
        return None

    _kill_group(pid)
    try:
        encoded = b""
        while True:
            chunk = os.read(read_fd, 4096)
            if not chunk:
                break
            encoded += chunk
            if len(encoded) > 1_000_000:
                return None
    except OSError:
        return None
    finally:
        os.close(read_fd)
    if status is None or not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        return None
    try:
        result = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(result, dict) or result.get("ok") is not True:
        return None
    failed = result.get("failed")
    if not isinstance(failed, list) or any(type(item) is not str for item in failed):
        return None
    requested_set = set(requested)
    failed_set = set(failed)
    return failed_set if failed_set <= requested_set else None


def verify_candidates(
    sources: list[tuple[str, str]], candidates: list[dict]
) -> list[dict]:
    """Return observed failures, or original candidates on uncertainty."""
    if (
        not candidates
        or len(candidates) > MAX_CANDIDATES
        or len({test.get("id") for test in candidates}) != len(candidates)
        or any(
            type(test.get("id")) is not str
            or not test["id"].startswith("tests/")
            or not _warm_compatible_test(test["id"])
            or test["id"].split("::", 1)[0] in PROCESS_POOL_TEST_FILES
            or not isinstance(test.get("seconds"), (int, float))
            or test["seconds"] < 0
            for test in candidates
        )
    ):
        return candidates
    recorded_seconds = sum(float(test["seconds"]) for test in candidates)
    source_modules = [_source_module(name) for name, _source in sources]
    if (
        recorded_seconds > MAX_RECORDED_SECONDS
        or not _ensure_overlay()
        or not _prepare_warm_parent()
        or any(name is None or name in sys.modules for name in source_modules)
    ):
        return candidates
    installed = _install_sources(sources)
    if installed is None:
        return candidates
    try:
        requested = [test["id"] for test in candidates]
        failed = _run_forked(requested, recorded_seconds, source_modules)
    finally:
        restored = _restore_sources(installed)
    if failed is None or not restored:
        return candidates
    return [test for test in candidates if test["id"] in failed]
