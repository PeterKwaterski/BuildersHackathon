# Guard-profile Git-link provenance re-audit

Verdict: **INVALIDATED BY FULL-NORMAL MEMORY FAILURE / NO-SHIP**

Scope: only the uncommitted provenance/materialization delta after Peter-only
source checkpoint `56baea8463ccc0c7ec8d12bcfac0a50e8b24e402`. No Docker,
full pytest, profile collection, model build, scorer, or sample answers were
used.

This provenance-only verdict was later invalidated by the first complete
normal trace at clean checkpoint
`42f37b0ecc0886215412cb6aa677388b594d39c5`. Its manifest SHA-256
`39e9ba1732848cf52058e3d3530075e609be2b3ecde9d2d63defd05c8ac05f52`
records exit status 1: the sole failure was the generator memory test retaining
2,408 bytes under tracemalloc against a 1,024-byte limit. The paired trace
SHA-256 is
`5641cbc75af11f34fbeb996575ccb27bd77de9560be5e8185b93ec0df5cc97b0`.
Both artifacts are rejected; no claim below admits them or authorizes a full
rerun before the separate memory re-audit. The current repair, limited exact
evidence, and independent **RE-AUDIT-READY** verdict are recorded in
`GUARD_PROFILE_MEMORY_REAUDIT.md`.

## Independent findings

The original repair correctly made the Git index inventory mode/OID-aware and
added fail-closed support for the pinned empty mode-`160000` Git link. The
re-audit found one release-blocking defect in that repair: the same digest
routine both verified pristine index blob OIDs and hashed the deliberately
rewritten synchronous-worker tree. The authorized rewrite of
`tests/test_executor.py` and `tests/test_optimizer.py` therefore always failed
with an index-object mismatch before a synchronous trace could start.

The repaired design now has two domain-separated operations:

- `materialized_digest` validates a pristine source/materialization against
  every tracked mode and blob OID;
- `executed_materialized_digest` retains the original path/mode/OID in its
  preimage and enforces file type, executable mode, safe symlink state, and an
  empty Git link, while hashing the current bytes after the independently
  bound synchronous transformation.

The builder independently creates the pristine copy, applies the exact bound
worker transformation, and recomputes the executed-tree digest for each mode.
An arbitrary transformation therefore cannot be admitted merely because the
collector reports its digest.

The re-audit also added explicit rejection of all-zero object IDs and
non-canonical path spellings. Existing checks reject malformed/non-UTF-8
entries, unsupported modes, nonzero merge stages, duplicates, parent/child
path collisions, absolute/parent-traversal paths, wrong executable state,
blob/symlink object mismatches, unsafe symlink targets, and missing,
initialized, contentful, symlinked, or wrong-type Git links.

## Threat audit

- `git ls-files --stage -z` is parsed as strictly terminated, nonempty
  NUL-delimited records and one tab-delimited path, so whitespace/newlines in
  canonical UTF-8 paths cannot alter metadata parsing. Missing terminators,
  embedded empty records, mixed object formats, and paths that do not
  round-trip through `Path.as_posix()` fail closed.
- Inventory and materialization digests use distinct domain tags and explicit
  NUL boundaries over canonical path, mode, OID, type marker, and payload.
- SHA-1 and SHA-256 Git blob formulas are selected only from the admitted OID
  length. Zero IDs and unsupported lengths/case are rejected.
- The clean-index check plus per-entry blob verification prevents staged,
  unstaged, assume-unchanged, and skip-worktree content from entering the
  pristine copy. A copy-time race either fails object verification or yields
  the same admitted object. Git-link contents are never copied; the source is
  revalidated after the destination, and both must be empty at their checks.
- The tracked-inventory digest is present in trace and manifest metadata,
  required equal across normal/synchronous modes, and recomputed by the
  builder. The builder separately reproduces each executed-tree digest and
  still binds collector, common classifier, support, worker-transform,
  environment, source revision/tree, test order, Python, and runtime image.

## Verification

- `python3 -m unittest -q tools.test_guard_profile`: **29/29 passed**
- `py_compile`: selector, collector, builder, common classifier, and tests
- all five generated support modules compile
- `git diff --check`: passed
- real pinned inventory: **365 entries** (`100644=360`, `100755=3`,
  `120000=1`, `160000=1`)
- inventory SHA-256:
  `d83639c3b69d4717f029ed1e6b9db88b6797b655a541909fb6c06a54fa8d80ad`
- pristine materialization SHA-256:
  `62b25b3f9488552fee8b2af812ed0115abda46c6edeb915356cc1eae612eb905`
- normal executed-tree SHA-256:
  `5607ce1382448c099a1d286190c1f6fc3e981adccdf4629be5ab45fde0cdd936`
- synchronous executed-tree SHA-256:
  `4336e3ddcf835a912ce6a3aea4ebff0406b83e956508569f91bbf1b8f04ac92a`
- the synchronous tree is rejected by the pristine OID validator at the first
  intentionally changed tracked test file, as required

The provenance repair is collect-ready. The overall guard feature remains
**NO-SHIP** until the repair is committed, both full exact-image traces pass,
the deterministic model is built and pinned, and full Docker/replay validation
passes.
