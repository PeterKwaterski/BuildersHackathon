#!/usr/bin/env python3
"""Run the exact numbered roster against one public registry-key mutant."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import selector
from tools.collect_dict_access import validate_source


PLUGIN = r'''from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


EXECUTED = set()
FAILURES = set()


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_protocol(item, nextitem):
    EXECUTED.add(item.nodeid)


def pytest_runtest_logreport(report):
    if report.failed:
        FAILURES.add(report.nodeid)


def pytest_collectreport(report):
    if report.failed:
        FAILURES.add(report.nodeid)


def pytest_sessionfinish(session, exitstatus):
    Path(os.environ["BR_MUTANT_RESULT"]).write_text(json.dumps(
        {
            "executed": sorted(EXECUTED),
            "failures": sorted(FAILURES),
            "pytest_exitstatus": exitstatus,
        },
        sort_keys=True,
        separators=(",", ":"),
    ))
'''


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--patch", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = arguments()
    source = args.source.resolve()
    validate_source(source, args.sources.resolve())
    roster = json.loads(args.tests.read_text())["tests"]
    test_ids = [test["id"] for test in roster]
    changes = selector.patch_changes(args.patch)
    if len(changes) != 1:
        raise SystemExit("mutant validator accepts exactly one changed file")
    change = changes[0]
    path = change.get("old")
    if type(path) is not str or change.get("new") != path:
        raise SystemExit("mutant validator accepts one in-place edit")
    changed = selector.patched_source(change, path)
    if changed is None:
        raise SystemExit("patch did not apply to pinned source")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="registry-key-mutant-") as temporary:
        root = Path(temporary)
        work = root / "sqlglot"
        support = root / "support"
        shutil.copytree(
            source,
            work,
            ignore=shutil.ignore_patterns(
                ".git", ".pytest_cache", ".coverage*", "__pycache__", "*.pyc"
            ),
        )
        (work / path).write_text(changed)
        support.mkdir()
        (support / "registry_mutant_plugin.py").write_text(PLUGIN)
        environment = os.environ.copy()
        environment.update({
            "BR_MUTANT_RESULT": str(args.output),
            "PYTHONPATH": os.pathsep.join(
                (str(support), str(work), environment.get("PYTHONPATH", ""))
            ).rstrip(os.pathsep),
            "SKIP_INTEGRATION": "0",
        })
        subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "registry_mutant_plugin", *test_ids],
            cwd=work,
            env=environment,
            check=False,
        )

    if not args.output.is_file():
        raise SystemExit("pytest did not produce a mutant result")
    result = json.loads(args.output.read_text())
    executed = set(result.get("executed", ()))
    expected = set(test_ids)
    raw_failures = result.get("failures", ())
    normalized_failures = set()
    unmapped_failures = []
    for failure in raw_failures:
        matches = [test_id for test_id in test_ids if failure == test_id or failure.startswith(test_id + " ")]
        if matches:
            normalized_failures.add(max(matches, key=len))
        else:
            unmapped_failures.append(failure)
    result.update({
        "complete_roster": executed == expected,
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "expected_count": len(expected),
        "failure_reports": raw_failures,
        "failures": sorted(normalized_failures),
        "patch": args.patch.stem,
        "python": sys.version,
        "unmapped_failures": sorted(unmapped_failures),
    })
    args.output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")))
    if executed != expected or unmapped_failures:
        raise SystemExit(
            f"mutant run omitted {len(expected - executed)} roster nodes and has "
            f"{len(unmapped_failures)} unmapped failure reports"
        )
    print(json.dumps({
        "elapsed_seconds": result["elapsed_seconds"],
        "failures": len(result["failures"]),
        "patch": result["patch"],
    }, sort_keys=True))


if __name__ == "__main__":
    main()
