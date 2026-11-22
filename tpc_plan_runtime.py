"""Bounded prospective verification for the pinned TPC optimizer workloads."""

from __future__ import annotations

import json
import os
import resource
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
RUNNER = ROOT / "run_prospective_executor_memo.py"
BASE_TREE = ROOT / "sqlglot-pinned"
PROFILE = ROOT / "tpc_plan_profile.json.gz"
MAX_ATTEMPTS = 3
MAX_BATCH_CPU = 42.0
MAX_BATCH_WALL = 60.0
MAX_PATCH_CPU = 16.0
MAX_PATCH_WALL = 24.0

_attempts = 0
_batch_cpu = 0.0
_batch_wall = 0.0


def enabled() -> bool:
    return os.environ.get("BLAST_RADIUS_TPC_PLAN", "1") == "1"


def verify_patch(patch: Path) -> tuple[dict[str, bool] | None, float]:
    """Return verified workload equalities and charged child CPU, or fail closed."""
    global _attempts, _batch_cpu, _batch_wall
    if (
        not enabled()
        or _attempts >= MAX_ATTEMPTS
        or _batch_cpu >= MAX_BATCH_CPU
        or _batch_wall >= MAX_BATCH_WALL
        or not patch.is_file()
        or not BASE_TREE.is_dir()
        or not PROFILE.is_file()
        or not RUNNER.is_file()
    ):
        return None, 0.0
    started = time.monotonic()
    usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    _attempts += 1
    try:
        completed = subprocess.run(
            [
                sys.executable,
                str(RUNNER),
                "--base-tree",
                str(BASE_TREE),
                "--patch",
                str(patch),
                "--artifact",
                str(PROFILE),
                "--deadline-s",
                str(MAX_PATCH_WALL - 1.0),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=MAX_PATCH_WALL,
            env={
                **os.environ,
                "HOME": "/tmp",
                "PYTHONHASHSEED": "0",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
        lines = completed.stdout.splitlines()
        document = json.loads(lines[-1]) if len(lines) == 1 else None
    except (OSError, subprocess.SubprocessError, UnicodeError, json.JSONDecodeError):
        document = None
        completed = None
    wall = max(0.0, time.monotonic() - started)
    usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu = max(
        0.0,
        (usage_after.ru_utime + usage_after.ru_stime)
        - (usage_before.ru_utime + usage_before.ru_stime),
    )
    if isinstance(document, dict) and type(document.get("process_tree_cpu_s")) in {int, float}:
        cpu = max(cpu, max(0.0, float(document["process_tree_cpu_s"])))
    _batch_cpu += cpu
    _batch_wall += wall
    if (
        completed is None
        or completed.returncode != 0
        or not isinstance(document, dict)
        or document.get("accepted") is not True
        or cpu > MAX_PATCH_CPU
        or wall > MAX_PATCH_WALL
        or _batch_cpu > MAX_BATCH_CPU
        or _batch_wall > MAX_BATCH_WALL
    ):
        return None, cpu
    verdicts = document.get("verdicts")
    keys = {"tpcds_executor", "tpcds_optimizer", "tpch_executor", "tpch_optimizer"}
    if (
        not isinstance(verdicts, dict)
        or set(verdicts) != keys
        or any(type(verdicts[key]) is not bool for key in keys)
    ):
        return None, cpu
    return verdicts, cpu
