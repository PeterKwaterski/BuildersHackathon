#!/usr/bin/env python3
"""Run exactly the authenticated ordered Blast Radius roster on a mutant tree."""

from __future__ import annotations

import argparse
import hashlib
import gzip
import json
from pathlib import Path
import subprocess

import pytest
from _pytest.subtests import SubtestReport


PINNED_HEAD = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"
BASELINE_TOKENS_SHA256 = "93ea4dd996a6ffb9b61f77cc7900658351ca1d9b1d6cd40efddd233720d8e2be"
MUTANTS = {
    "9b62": {
        "setting": "DASH_COMMENT_REQUIRES_BOUNDARY",
        "tokens_sha256": "d0cb2ebc9881426abb275e0cd5e49afd7188b20f52a49c061d2e445ba49d7efa",
        "patch_sha256": "5686959543ba265a4e40e8180065120752a180eb116ff140b78886fe43eb3449",
    },
    "3ea4": {
        "setting": "COMMENTS_TERMINATE_AT_NEWLINE_ONLY",
        "tokens_sha256": "084df6fe92aff5361124690f4e320491fcf3deac4bd0d07545ed431925bba09a",
        "patch_sha256": "85d00e57c6d2661846ed6317e5aad65585009cd12f2c48fc80466824cc545229",
    },
    "97ef": {
        "setting": "STRING_ESCAPES_ALLOWED_IN_RAW_STRINGS",
        "tokens_sha256": "948cff8a308d082468bf47b065902db14574a4a9a8911da1785299562541dc77",
        "patch_sha256": "b60e713252b7651d8053ca539a1f72e0f8ccd9ed71208bef93b4f4b6d5b37779",
    },
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(source_root: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    return subprocess.run(
        ["git", "-c", f"safe.directory={source_root}", "-C", str(source_root), *arguments],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout


def authenticate_source(
    source_root: Path, mutant_id: str | None, patch: Path | None
) -> dict[str, str | None]:
    source_root = source_root.resolve()
    head = git(source_root, "rev-parse", "HEAD").decode("ascii").strip()
    if head != PINNED_HEAD:
        raise SystemExit(f"wrong source HEAD: {head}")
    status = git(
        source_root, "status", "--porcelain=v1", "--untracked-files=all"
    ).decode("utf-8")
    tokens_path = source_root / "sqlglot" / "tokens.py"
    tokens_sha256 = sha256_file(tokens_path)
    if mutant_id is None:
        if patch is not None:
            raise SystemExit("baseline may not supply --patch")
        if status:
            raise SystemExit(f"baseline source tree is dirty: {status!r}")
        if tokens_sha256 != BASELINE_TOKENS_SHA256:
            raise SystemExit("baseline tokens.py digest differs from pinned source")
        return {
            "head": head,
            "status": status,
            "tokens_sha256": tokens_sha256,
            "mutant_id": None,
            "patch_sha256": None,
        }
    spec = MUTANTS[mutant_id]
    if patch is None:
        raise SystemExit("mutant requires --patch")
    patch = patch.resolve()
    patch_sha256 = sha256_file(patch)
    if patch_sha256 != spec["patch_sha256"]:
        raise SystemExit("public patch digest differs from authenticated mutant")
    if status != " M sqlglot/tokens.py\n":
        raise SystemExit(f"mutant source has unexpected changes: {status!r}")
    if tokens_sha256 != spec["tokens_sha256"]:
        raise SystemExit("mutant tokens.py digest differs from authenticated result")
    try:
        git(source_root, "apply", "--reverse", "--check", "--whitespace=nowarn", str(patch))
    except subprocess.CalledProcessError as error:
        raise SystemExit(
            "authenticated public patch cannot be reversed from mutant source: "
            + error.stderr.decode("utf-8", errors="replace")
        ) from error
    return {
        "head": head,
        "status": status,
        "tokens_sha256": tokens_sha256,
        "mutant_id": mutant_id,
        "patch_sha256": patch_sha256,
    }


class ExactRosterPlugin:
    def __init__(self, expected: list[str]) -> None:
        self.expected = expected
        self.expected_set = set(expected)
        self.collected: list[str] = []
        self.executed: list[str] = []
        self.raw_failures: set[str] = set()
        self.collection_failures: set[str] = set()
        self.subtests = {"passed": 0, "failed": 0, "skipped": 0}

    def pytest_collection_modifyitems(self, session, config, items) -> None:
        self.collected = [item.nodeid for item in items]
        if self.collected != self.expected:
            pytest.exit("collected roster/order differs from authenticated tests.json", returncode=4)

    @pytest.hookimpl(tryfirst=True)
    def pytest_runtest_protocol(self, item, nextitem) -> None:
        self.executed.append(item.nodeid)

    def pytest_runtest_logreport(self, report) -> None:
        if isinstance(report, SubtestReport):
            if report.passed:
                self.subtests["passed"] += 1
            elif report.failed:
                self.subtests["failed"] += 1
            elif report.skipped:
                self.subtests["skipped"] += 1
        if report.failed:
            self.raw_failures.add(report.nodeid)

    def pytest_collectreport(self, report) -> None:
        if report.failed:
            self.collection_failures.add(report.nodeid)


def normalize_failures(raw: set[str], ids: list[str]) -> tuple[list[str], list[str]]:
    normalized = set()
    unmapped = []
    for failure in sorted(raw):
        matches = [
            test_id
            for test_id in ids
            if failure == test_id or failure.startswith(test_id + " ")
        ]
        if matches:
            normalized.add(max(matches, key=len))
        else:
            unmapped.append(failure)
    return sorted(normalized), unmapped


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", action="store_true")
    parser.add_argument("--mutant-id", choices=sorted(MUTANTS))
    parser.add_argument("--patch", type=Path)
    parser.add_argument("--source-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--setting")
    args = parser.parse_args()
    if args.baseline == (args.mutant_id is not None):
        raise SystemExit("choose exactly one of --baseline or --mutant-id")
    if args.mutant_id is not None and args.setting != MUTANTS[args.mutant_id]["setting"]:
        raise SystemExit("--setting does not match authenticated mutant")
    source = authenticate_source(args.source_root, args.mutant_id, args.patch)
    tests_sha256 = sha256_file(args.tests)
    tests = json.loads(args.tests.read_text(encoding="utf-8"))["tests"]
    ids = [test["id"] for test in tests]
    if len(ids) != 1620 or len(set(ids)) != len(ids):
        raise SystemExit("tests.json is not the exact unique 1620-test roster")
    digest = hashlib.sha256("\0".join(ids).encode("utf-8")).hexdigest()
    plugin = ExactRosterPlugin(ids)
    exit_code = int(pytest.main(["-q", "--tb=no", *ids], plugins=[plugin]))
    failures, unmapped = normalize_failures(plugin.raw_failures, ids)
    selected = None
    missed = []
    failure_indices = [index for index, test_id in enumerate(ids) if test_id in failures]
    if args.profile is not None or args.setting is not None:
        if args.profile is None or args.setting is None:
            raise SystemExit("--profile and --setting must be supplied together")
        profile = json.loads(gzip.decompress(args.profile.read_bytes()))
        entry = profile.get("d", {}).get(args.setting)
        if not (
            isinstance(entry, list)
            and len(entry) == 3
            and isinstance(entry[2], list)
            and all(type(index) is int for index in entry[2])
        ):
            raise SystemExit("setting has no certified reader entry")
        selected = entry[2]
        missed = sorted(set(failure_indices) - set(selected))
    payload = {
        "v": 1,
        "source": source,
        "tests_json_sha256": tests_sha256,
        "n": len(ids),
        "t": digest,
        "collected_n": len(plugin.collected),
        "collected_t": hashlib.sha256(
            "\0".join(plugin.collected).encode("utf-8")
        ).hexdigest(),
        "executed_n": len(plugin.executed),
        "executed_t": hashlib.sha256(
            "\0".join(plugin.executed).encode("utf-8")
        ).hexdigest(),
        "missing": [test_id for test_id in ids if test_id not in set(plugin.executed)],
        "unexpected": sorted(set(plugin.executed) - set(ids)),
        "failures": failures,
        "failure_indices": failure_indices,
        "selected_n": None if selected is None else len(selected),
        "missed_failure_indices": missed,
        "raw_failures": sorted(plugin.raw_failures),
        "unmapped_failures": unmapped,
        "collection_failures": sorted(plugin.collection_failures),
        "subtests": plugin.subtests,
        "exit": exit_code,
    }
    args.output.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    print("EXACT_ROSTER_RESULT=" + json.dumps(payload, sort_keys=True, separators=(",", ":")))
    if (
        plugin.collected != ids
        or plugin.executed != ids
        or payload["collected_t"] != digest
        or payload["executed_t"] != digest
        or payload["missing"]
        or payload["unexpected"]
        or payload["unmapped_failures"]
        or payload["missed_failure_indices"]
        or payload["collection_failures"]
        or (
            args.baseline
            and (
                payload["subtests"] != {"passed": 25440, "failed": 0, "skipped": 0}
                or payload["failures"]
                or exit_code != 0
            )
        )
        or exit_code not in {0, 1}
    ):
        raise SystemExit(5)


if __name__ == "__main__":
    main()
