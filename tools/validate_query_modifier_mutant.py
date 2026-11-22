#!/usr/bin/env python3
"""Run the exact numbered roster against one source-derived key deletion."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from collect_dict_access import validate_source


PLUGIN = r'''from __future__ import annotations
import json
import os
from pathlib import Path
import pytest

EXECUTED = []
FAILURES = set()

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
    Path(os.environ["BR_QUERY_MUTANT_RESULT"]).write_text(json.dumps({
        "executed": EXECUTED,
        "failures": sorted(FAILURES),
        "pytest_exitstatus": exitstatus,
    }, sort_keys=True, separators=(",", ":")))
'''


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    return parser.parse_args()


def main() -> None:
    args = arguments()
    source = args.source.resolve()
    validate_source(source, args.sources.resolve())
    roster = json.loads(args.tests.read_text())["tests"]
    test_ids = [test["id"] for test in roster]
    model = json.loads(gzip.decompress(args.model.read_bytes()))
    entry = model.get("d", {}).get(args.key) if isinstance(model, dict) else None
    if (
        not isinstance(entry, list)
        or len(entry) != 2
        or type(entry[0]) is not str
        or not isinstance(entry[1], list)
    ):
        raise SystemExit("key has no certified query-modifier model entry")

    relative = "sqlglot/expressions/core.py"
    original = (source / relative).read_text()
    line = f'    "{args.key}": False,\n'
    if original.count(line) != 1:
        raise SystemExit("key is not one canonical QUERY_MODIFIERS entry")
    changed = original.replace(line, "")
    if hashlib.sha256(changed.encode()).hexdigest() != entry[0]:
        raise SystemExit("mutant source does not match certified whole-file digest")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="query-modifier-mutant-") as temporary:
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
        (work / relative).write_text(changed)
        support.mkdir()
        (support / "query_mutant_plugin.py").write_text(PLUGIN)
        environment = os.environ.copy()
        environment.update({
            "BR_QUERY_MUTANT_RESULT": str(args.output.resolve()),
            "PYTHONPATH": os.pathsep.join(
                (str(support), str(work), environment.get("PYTHONPATH", ""))
            ).rstrip(os.pathsep),
            "SKIP_INTEGRATION": "0",
        })
        subprocess.run(
            [str(args.python), "-m", "pytest", "-q", "-p", "query_mutant_plugin", *test_ids],
            cwd=work,
            env=environment,
            check=False,
        )

    if not args.output.is_file():
        raise SystemExit("pytest did not produce a mutant result")
    result = json.loads(args.output.read_text())
    executed = result.get("executed")
    raw_failures = result.get("failures", ())
    normalized = set()
    unmapped = []
    for failure in raw_failures:
        matches = [
            test_id for test_id in test_ids
            if failure == test_id or failure.startswith(test_id + " ")
        ]
        if matches:
            normalized.add(max(matches, key=len))
        else:
            unmapped.append(failure)
    selected = set(entry[1])
    failure_indices = {index for index, test_id in enumerate(test_ids) if test_id in normalized}
    result.update({
        "complete_roster": executed == test_ids,
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "failure_indices": sorted(failure_indices),
        "failures": sorted(normalized),
        "key": args.key,
        "missed_failure_indices": sorted(failure_indices - selected),
        "selected_count": len(selected),
        "unmapped_failures": sorted(unmapped),
    })
    args.output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")))
    if executed != test_ids or unmapped or failure_indices - selected:
        raise SystemExit(
            f"inadmissible mutant certificate: exact_order={executed == test_ids} "
            f"unmapped={len(unmapped)} misses={len(failure_indices - selected)}"
        )
    print(json.dumps({
        "failures": len(failure_indices),
        "key": args.key,
        "selected": len(selected),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
