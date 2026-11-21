# Guard-profile memory-quarantine re-audit

Verdict: **FULL-RERUN-READY / NO-SHIP**

Scope: uncommitted repair based on clean checkpoint
`42f37b0ecc0886215412cb6aa677388b594d39c5`. This review covers only the
collector's self-observation of allocation-sensitive tests, its provenance and
builder admission, focused LIGHT adversarial tests, and one limited exact-image
normal-mode validation. It did not run either full 1,620-test trace, build a
profile, enable the selector, run replay, or use sample answers.

## Failure and invalidation

The first full normal trace reached the complete test manifest with complete
child/pool accounting, but pytest exited 1. The sole failure was
`TestGenerator.test_generator_memory` for base `Dialects.DIALECT`: retained
tracemalloc growth was 2,408 bytes, over the strict 1,024-byte bound. The old
truth hook retained `seen` and state owners before testing
`tracemalloc.is_tracing`; the None hook likewise retained `seen` and unsafe
owners while tracing. Quarantining the owner only in the pytest boundary hook
prevented exemptions but did not prevent those measured allocations.

Hard exit-zero admission correctly rejected both files. They remain diagnostic
only:

- failed manifest SHA-256:
  `39e9ba1732848cf52058e3d3530075e609be2b3ecde9d2d63defd05c8ac05f52`
- failed trace SHA-256:
  `5641cbc75af11f34fbeb996575ccb27bd77de9560be5e8185b93ec0df5cc97b0`
- failed-run collector SHA-256:
  `593791ebc7ffa1820f295ffe281dd6654da7f94e80e4f51c7b94cade9b3ef3f3`

No synchronous full trace was launched, and the rejected normal trace must
never be paired with a later synchronous trace or admitted by a whitelist.

## Fail-closed repair

The existing AST census identifies pinned test files importing `gc`,
`resource`, `tracemalloc`, or `weakref`. Before pytest starts, the collector now
resolves the exact owners in those files plus memory/tracemalloc/leak-named
owners from the immutable test manifest. The complete 1,620-test inventory
produces 27 sensitive owners across three source-sensitive files. The failing
generator-memory owner is included.

The generated tracker loads those owners into an immutable `frozenset` before
execution. Both observation hooks first test exact `CURRENT_TEST` membership
and return the identical operand immediately. For a sensitive owner they do not
query tracemalloc, classify the value, register a child, or mutate any event or
escape set. The patched `tracemalloc.start` also avoids a redundant mutable
escape-set insertion for an already quarantined owner.

The permanent quarantine is separate from dynamic `ESCAPED` state. Session
finish unions the full static set into every trace, so fork relabeling cannot
remove it and a sensitive task cannot leave a mutable disabled flag behind for
the next owner. The source-derived owner-list digest is carried in trace and
manifest metadata, required equal between modes, and independently recomputed
by the builder. Builder admission additionally requires every sensitive owner
to remain escaped in both normal and synchronous traces.

## Adversarial verification

The focused suite now has 31 tests. The new cases prove:

- 1,000 truth and 1,000 None calls under active tracemalloc retain less than
  1,024 bytes, return the identical object, and leave `EVENTS` and `ESCAPED`
  unchanged;
- an ordinary owner immediately afterward still records both hook families;
- sensitive-to-ordinary `run_owned_task` transitions do not leak disabled
  state;
- a fork/register-child shape that inherits a sensitive initial owner remains
  inert, then records the first ordinary persistent task and clears ownership;
- neither trace mode may omit any precomputed sensitive owner; and
- source-sensitive files and name-fallback owners are resolved deterministically.

After the final inherited-fork case was added,
`python3 -m unittest -q tools.test_guard_profile` passed 31/31 in five
consecutive fresh processes in the independent re-audit. Six-file `py_compile`
and `git diff --check` passed. The independent source/LIGHT reviewer found no
source-design blocker and returned **RE-AUDIT-READY**.

## Limited exact-image evidence

One corrected normal-mode run used immutable image
`sha256:736857c2a387ff1be1d4331e0cfa5d2a0a40b43eb98ce80119868ff280d2bdcb`,
Python 3.13.18, pinned source `eb11aec4be8cb2122afe713a4816662c3f0fb2fa`,
network none, a read-only root, the exact writable `/tmp` tmpfs, 3 CPUs, 4 GiB,
and 512 PIDs. It ran only the original memory owner and
`TestOptimizer.test_merge_subqueries`, the smallest existing normal-mode sanity
target that also exercises persistent-pool accounting.

The run passed 2 tests and 322 subtests in 35.06 seconds; collector/container
exit was 0, OOM was false, wall time was 37.86 seconds, and maximum host-side
RSS was 27,800 KiB. Every generator-memory dialect subtest passed the upstream
strict `<1024` retained-growth assertion; the upstream test does not print
passing numeric deltas. The manifest recorded 14/14 complete child logs, 147
complete pool tasks, and 5,457 instrumented sites. The sensitive owner is
escaped and appears in zero event memberships. The ordinary optimizer owner
appears in 2,374 event memberships across an admitted 1,081-site trace.

Evidence hashes:

- target manifest: `db2fa7219a1680bf7d6230e70e59282d5359c704d8ae28e3417e20f7f6ddd423`
- target trace: `b81227cd01c3ca0bf4f92d6c09b4c7621269358a875a7b0d8703bc6de1c09be4`
- target test inventory: `b9759b1c2303a72e7c2613790a1a52f5212c64c7f8e2d8aafbcd993686ef7585`
- repaired collector: `71dec8614ca7ebe88fa6700322f78289bce16529224e8933b29301583164efb9`
- generated support: `ceef79bb749db7fb68db484ed3d00b4e32bd6a72ca460ad5ea8de30baa2e05b1`

An earlier launch omitted the required writable `/tmp` tmpfs and stopped in
`tempfile.TemporaryDirectory` before materialization or pytest. It created no
manifest or trace and is not test evidence. Its preserved log SHA-256 is
`c860f789b9f3cc98d6f90d39c0922129bbbe60a0c44d5052d67d5961f44c2538`;
the successful-run log SHA-256 is
`f2d1df6cf0d480a634a6ed5cffa4e9372f9682d144383970f2a43c07ddcc9df2`.

## Residual boundaries and next gate

The exact targeted result proves the original failure path in the locked
runtime, but it is not a substitute for either full trace. All 27 sensitive
owners are intentionally over-quarantined, which can only reduce optimization
opportunity. Actual image identity remains an operator-verified launch fact,
and dynamically synthesized support tampering remains outside the trusted
fixed-suite boundary documented by the main audit.

The source/LIGHT repair is **RE-AUDIT-READY** and permits a separately
controlled fresh full normal trace followed by the full synchronous trace.
Until both exit 0 and pass all existing admission checks, the current status is
**NO-COLLECT / NO-SHIP**. Do not reuse the rejected evidence and do not commit
or enable the selector as part of this repair verdict.

## Fresh full-normal result and second admission invalidation

After the memory repair was frozen at
`750b4df7791face528985c9a4454ccd7a7d014e2`, one fresh complete normal-mode
collection ran with the same immutable image, network-none/read-only launch,
`/tmp` tmpfs, and 3-CPU/4-GiB/512-PID limits. The suite itself was fully green:
**1,620 passed, 1 skipped, 25,440 subtests passed** in 575.30 seconds. The
original generator-memory test passed every dialect subtest. Container OOM was
false; total wall time was 581.65 seconds and maximum host-side RSS was 27,660
KiB.

The collector nevertheless exited 1 after pytest, so this is not admitted
normal evidence and no synchronous trace was launched. The exact error was
`inadmissible suite manifest; 0 tests missing, 1 extra`. The extra protocol is
the pinned manifest's sole declared skip:
`tests/dialects/test_sqlite.py::TestSQLite::test_variadic_iif_execution`, which
is guarded by the source's SQLite-version `unittest.skipIf` condition. It is
not a generated or collection-only node. Both the earlier failed full trace and
this fresh trace recorded the same 1,621 unique protocols: all 1,620 runnable
IDs plus that exact declared skip.

The fresh files remain diagnostic only:

- manifest SHA-256:
  `4a3525e48928f8bdc36e791c2d8c4d9a2daeb10411fb59aad5f5db652bf321fb`
- trace SHA-256:
  `c933de77a62151ccd75939783499cc975337891acc07c9946b0e4b075285c751`
- manifest pytest exit status: 0; outer collector/container exit: 1
- child logs: 30/30 complete; pool tasks: 2,183 complete
- all 27 sensitive owners escaped; sensitive event memberships: 0
- generator-memory event memberships: 0

The trace self-hash and trace/manifest metadata match, and source/image/tree
provenance matches the locked run. Those facts diagnose the isolated roster
admission defect but do not override the hard outer exit-1 rejection.

## Strict skipped-roster repair pending independent review

The pinned test file intentionally has two disjoint inventories: 1,620 runnable
test records and one ordered declared-skip ID. The old collector and builder
parsed only `tests`, while pytest correctly invoked all 1,621 runtest protocols.
The uncommitted repair preserves the existing runnable digest
`31a019981e19c3d1b18d929066da7e118fcf3d57696a360f7b9d31ce3a87bc89`
and profile width `n=1620`, and separately provenance-binds the ordered skip
digest
`78e98e7eeb218780aab5e7ba228a5047cd742fd34598ece7570bc00d3568e6fe`.

The plugin now records three exact canonical rosters: runnable protocols,
declared-skip protocols, and actual skipped reports. It also records duplicate
protocol invocations and every XFAIL/XPASS report separately; collector and
builder admission require both exceptional rosters to be exactly empty. A declared-skip protocol
runs with `CURRENT_TEST=None` and without `BR_PARENT_TEST`; therefore any
setup/skip-time production observation is labeled `__NO_TEST__` and globally
poisons that site instead of manufacturing an owner outside the 1,620-bit
model. Collector and builder both require runnable equality and exact equality
of declared-skip protocols and actual skip reports to the pinned skip roster.
Missing, extra, duplicate, overlapping, unexpectedly passing, newly skipped,
XFAIL, and XPASS nodes all fail closed.

The focused suite is now 34 tests. It includes ordered-digest, malformed roster,
duplicate/overlap, missing/extra declared protocol, missing/extra actual report,
duplicate runnable and declared-skip runtime protocol, XFAIL/XPASS report,
plugin ownership, and unattributed-observation attacks. **34/34 passed in five
consecutive fresh processes**; six-file `py_compile`, all five generated-support
compilations, and `git diff --check` passed. The old full-normal files are
rejected by the new exact-roster gate.

Current uncommitted code hashes are:

- collector:
  `967178a9127367d5ec6bd35f43a943264e9a312e632e821ad13770f352d296cb`
- builder:
  `146760b56198d5cec0f024ba1de1191b25930599320b82bca0b9a69e4e26ed61`
- focused tests:
  `2a620e059db07411d3e2fe943e026e354211943c538bc8974a5c6c5096640804`
- generated support:
  `b8a24b5e5ee34ff5dff32c83dbc4a48f29efd23c8b43b48baadfba01385208d8`

The independent source/LIGHT re-audit found and repaired the runtime duplicate
protocol and XFAIL/XPASS census gaps, then returned **FULL-RERUN-READY**. This
second repair has not run in Docker. Do not reinterpret the earlier green
pytest summary as admitted evidence and do not reuse either failed full trace;
the next evidence must be a fresh normal collection followed by a fresh
synchronous collection from an explicitly authorized checkpoint.
