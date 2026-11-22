#!/usr/bin/env python3
"""Run the exact numbered roster against combined directive-only patches."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


PLUGIN = r'''from __future__ import annotations
import json
import os
from pathlib import Path
import pytest

EXECUTED = []
FAILURES = set()
SUBTESTS = 0

@pytest.hookimpl(tryfirst=True)
def pytest_runtest_protocol(item, nextitem):
    EXECUTED.append(item.nodeid)

def pytest_runtest_logreport(report):
    if report.failed:
        FAILURES.add(report.nodeid)

def pytest_collectreport(report):
    if report.failed:
        FAILURES.add(report.nodeid)

def pytest_sessionfinish(session, exitstatus):
    Path(os.environ["BR_DIRECTIVE_RESULT"]).write_text(json.dumps({
        "executed": EXECUTED,
        "failures": sorted(FAILURES),
        "pytest_exitstatus": exitstatus,
    }, sort_keys=True, separators=(",", ":")))
'''


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--patch", action="append", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    test_ids = [test["id"] for test in json.loads(args.tests.read_text())["tests"]]
    with tempfile.TemporaryDirectory(prefix="directive-comments-") as temporary:
        root = Path(temporary)
        work = root / "sqlglot"
        support = root / "support"
        shutil.copytree(
            args.source,
            work,
            ignore=shutil.ignore_patterns(
                ".git", ".pytest_cache", ".coverage*", "__pycache__", "*.pyc"
            ),
        )
        for patch in args.patch:
            subprocess.run(
                ["git", "apply", "--recount", str(patch.resolve())],
                cwd=work,
                check=True,
            )
        support.mkdir()
        (support / "directive_plugin.py").write_text(PLUGIN)
        environment = os.environ.copy()
        environment.update({
            "BR_DIRECTIVE_RESULT": str(args.output.resolve()),
            "PYTHONPATH": os.pathsep.join(
                (str(support), str(work), environment.get("PYTHONPATH", ""))
            ).rstrip(os.pathsep),
            "SKIP_INTEGRATION": "0",
        })
        subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "directive_plugin", *test_ids],
            cwd=work,
            env=environment,
            check=False,
        )
    result = json.loads(args.output.read_text())
    exact = result.get("executed") == test_ids
    failures = result.get("failures")
    print(json.dumps({
        "exact_order": exact,
        "failures": failures,
        "patches": len(args.patch),
        "pytest_exitstatus": result.get("pytest_exitstatus"),
        "tests": len(test_ids),
    }, sort_keys=True))
    if not exact or failures or result.get("pytest_exitstatus") != 0:
        raise SystemExit("combined directive mutant did not pass exact roster")


if __name__ == "__main__":
    main()
