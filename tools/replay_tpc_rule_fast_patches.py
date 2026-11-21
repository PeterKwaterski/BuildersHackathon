#!/usr/bin/env python3
"""Answer-free cached-input replay and process-tree CPU for optimizer patches."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import resource
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import selector
from tpc_rule_fast import TARGET, validate
from tpc_rule_fast_runtime import verify_fast_boundaries


def usage() -> float:
    row = resource.getrusage(resource.RUSAGE_CHILDREN)
    return row.ru_utime + row.ru_stime


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tree", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("patches", type=Path, nargs="+")
    args = parser.parse_args()
    raw = args.profile.read_bytes()
    profile = validate(json.loads(gzip.decompress(raw)))
    results = []
    for patch in args.patches:
        changes = selector.patch_changes(patch)
        resolved = selector.resolve_tpc_rule_patch(changes, profile)
        if resolved is None:
            results.append({
                "patch": str(patch.resolve()), "resolved": False,
                "equal": False, "cpu_s": 0.0,
            })
            continue
        evidence, sources = resolved
        owner = profile["owners"][evidence.owner_id]
        plan = {
            "tier": "competition-risk-fast",
            "proof": False,
            "owner_id": evidence.owner_id,
            "rule": owner["rule"],
            "target": TARGET,
            "readers": tuple(owner["readers"]),
            "barriers": tuple(owner["barriers"]),
            "profile": profile["collection_sha256"],
        }
        before = usage()
        equal = verify_fast_boundaries(
            sources, profile, plan, pinned_tree=args.tree.resolve()
        )
        cpu_s = usage() - before
        results.append({
            "patch": str(patch.resolve()),
            "patch_sha256": hashlib.sha256(patch.read_bytes()).hexdigest(),
            "resolved": True,
            "owner_id": evidence.owner_id,
            "rule": owner["rule"],
            "readers": len(owner["readers"]),
            "equal": equal,
            "cpu_s": cpu_s,
        })
    args.out.write_text(json.dumps({
        "format": "tpc-rule-fast-patch-replay-v1",
        "profile_sha256": hashlib.sha256(raw).hexdigest(),
        "results": results,
    }, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
