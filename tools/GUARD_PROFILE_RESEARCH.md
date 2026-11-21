# Per-test guard profiles

Status: **ARTIFACT BUILT AND PINNED; EXACT-IMAGE AUDIT PENDING**

## Final paired evidence

Fresh normal and synchronous-worker collections from frozen Peter-only commit
`c6f0ecbaebeb03ab9a4bec4bdffcd93f8a7c6bcc` both completed in the exact
Python 3.13.18 collector image `sha256:736857c2a387...`.  Each ran all 1,620
runnable tests, the exact separately declared skip, and 25,440 subtests with
pytest and outer-process exit 0.  Normal accounted for 29/29 child logs and
2,183 complete pool tasks; synchronous mode accounted for its one child and
zero pool tasks.  Both have empty duplicate-protocol and XFAIL/XPASS sets.
Every one of the 27 source-derived memory-sensitive owners remained escaped
with zero event memberships.

The two modes share all required provenance: pinned source commit/tree and
tracked inventory, ordered runnable and skipped-test digests, collector/common/
support/worker-transform code, materialized source, Python/image, environment,
and sensitive-owner census.  Their separately reproduced executed-tree hashes
are bound by mode.  Two builds with reversed input order are byte-identical:

- 5,457 total sites in 131 files;
- 4,825 safe, 515 unattributed, and 117 unobserved sites;
- gzip SHA-256 `31bc8832c304e14e0c75173d61379f8570975a0e93620e883f5a78d87463aecb`;
- decoded SHA-256 `2c1301936ca7da3f32f3b8a0ec36d48df2b8b657fc92e4b97caa1b9871b45cce`.

An answer-free scan of 117 public patches whose changed lines mention a guard
shape found 16 changed selections, all in validation set 4.  Relative to the
disabled artifact, the profile removes 411 selections and 13.991 aggregate
packed seconds.  This is capability evidence, not an official-score forecast.

Separate read-only leader-ablation containers overlapped the latter portions
of collection and contaminated wall-time measurements.  They did not share
files or cgroups with the guard containers; both guard runs were OOM-free and
all process-local allocation, roster, lifecycle, hash, and provenance gates
passed.  The collection wall times must not be used as selector performance
evidence.  Final selector CPU is measured separately.

The first audit's collect-ready verdict was invalidated when source-light
preflight found the pinned tree's uninitialized `sqlglot-integration-tests`
Git link could not be materialized. An uncommitted repair now binds exact Git
index modes/object IDs, permits only an empty mode-`160000` directory, and
binds that inventory through collector and builder provenance. Focused tests
pass. The independent follow-up in `GUARD_PROFILE_GITLINK_REAUDIT.md` found and
fixed a synchronous-tree validation blocker and restored collect-ready status.
That verdict was subsequently invalidated by the first full normal trace: the
guard hooks caused `TestGenerator.test_generator_memory` to retain 2,408 bytes
under tracemalloc against a 1,024-byte limit. The failed exit-1 evidence is
rejected. `GUARD_PROFILE_MEMORY_REAUDIT.md` documents the source-derived inert
quarantine repair, independent LIGHT re-audit, and limited exact-image exit-0
validation. A fresh full normal and synchronous pair is still required.
A subsequent frozen full-normal run made the suite fully green (1,620 passed,
1 skipped, 25,440 subtests) but correctly remained non-admitted because the
collector treated the pinned manifest's separately declared skip as an extra
protocol. `GUARD_PROFILE_MEMORY_REAUDIT.md` records the rejected evidence and
the uncommitted strict split-roster repair. Independent source/LIGHT review
closed duplicate-protocol and XFAIL/XPASS census gaps; a fresh full normal and
synchronous pair is now authorized from a frozen checkpoint.

This branch independently derives a conservative per-test observation model for
simple guard-form changes.  It does not contain a profile artifact, public
answer mapping, patch lookup table, or enabled selector shortcut.  The selector
kill switch remains empty until two fresh admitted traces produce a pinned
artifact.

## Supported proof families

For an identical operand expression in an `if`, `while`, or conditional
expression, the collector observes the already evaluated operand for these
forms:

- `x` and `not x`
- `x is None` and `x is not None`
- `x is False` and `x is not False`
- `x is True` and `x is not True`

It records five semantic classes: false non-bool, true non-bool, `None`,
`False`, and `True`.  Arbitrary objects and subclasses remain unknown; their
truth protocols are never invoked by the classifier.

For exact `x is None` / `x == None` and `x is not None` / `x != None`
operator swaps, the collector separately records tests for which equality or
inequality may execute user code.  Only an explicit allowlist of exact built-in
types is considered safe.  Operand side and source syntax must be identical.

At selection time the complete pinned and prospective ASTs must become equal
after replacing exactly one guard or canonicalizing exactly one operator.  The
gate then subtracts only tests proven equivalent from ordinary exact-line
coverage.  Unseen tests are never subtracted.  Multi-file patches, directives,
binding changes, import-expression hazards, source-reflection dependencies,
serialization code, malformed masks, and ambiguous matches fail closed.

## Collection integrity

`collect_guard_observations.py` copies the pinned source tree but does not
rewrite production source.  A temporary import hook compiles instrumented ASTs
in memory, preserving the source bytes seen by source-reading tests.  Each
wrapper evaluates its operand once and returns the identical object.

The trace is bound to the pinned Git commit and tree, the exact mode/OID Git
index inventory, the exact tracked-entry materialization (including the empty
uninitialized Git link), the separately reproduced synchronous-worker materialization,
ordered test-ID digest, collector, worker-transform and shared-classifier
digests, generated-support digest, a sanitized deterministic environment,
exact Python version, and declared immutable runtime-image identity. Import,
collection, and other unowned
observations are labeled `__NO_TEST__`.  Forked/spawned children use atomic
start/completion logs.  Persistent `ProcessPoolExecutor` work carries an
explicit submitting-test owner and has submitted/started/completed sentries;
inherited worker-start observations are relabeled unowned. Child documents are
flushed at every task boundary because multiprocessing commonly bypasses
Python `atexit`, and every pool submitter is conservatively quarantined because
result serialization occurs after the owned wrapper returns. External
processes, incomplete logs, and unknown owners are quarantined. Allocation and
lifetime-sensitive owners are derived from pinned source plus the exact test
inventory before execution; their hooks return the identical operand before
any tracemalloc query or event mutation. Their complete owner-set digest is
provenance-bound, and the builder requires every owner to remain quarantined in
both modes. Runtime hook/import-hook identity is checked at every test boundary.
Normal and synchronous-worker runs must agree on shared provenance and must
both be admitted.

Truth classification intentionally excludes mutable builtins and exact
`float`/`complex` values. A mutable container could change between the
collector's truth observation and the real branch, while signaling native
floating-point values can perturb floating status. These values remain
unknown. Captured original `type` and `bool` builtins prevent ordinary builtin
monkeypatching from changing classification. None-comparison classification
continues to allow exact builtin values because comparing those values with
`None` cannot dispatch to user code.

`build_guard_profile.py` validates both trace/manifest pairs, exact test
membership, child and pool completeness, canonical owner lists, complete site
inventory, current collector/common digests, Python 3.13, and the clean pinned
tree.  It emits deterministic gzip (`mtime=0`) containing only per-site masks
and provenance.

## Source census

An AST-only census of clean sqlglot commit
`eb11aec4be8cb2122afe713a4816662c3f0fb2fa` found 5,457 supported sites in 131
production files:

| Family | Form | Sites |
|---|---:|---:|
| truth | direct | 4,023 |
| truth | `not` | 636 |
| truth | `is None` | 169 |
| truth | `is not None` | 122 |
| truth | `is False` | 13 |
| truth | `is True` | 11 |
| singleton | `is None` | 245 |
| singleton | `is not None` | 238 |

The truth family totals 4,974 sites and the singleton family 483.  A coarse,
answer-independent syntax scan over 683 public validation patches found 23
patches mentioning `is None`, 25 mentioning `is not None`, 11 mentioning
`== None`, and 10 mentioning `!= None`.  These counts are only an applicability
upper bound; no patch identity or expected answer is used to construct or
activate the rule.

The public Hiresh repository motivated prioritizing this family: its README
reports a 16-change condition batch retaining all 1,412 failing patch/test pairs
while reducing simulated time from 366.631 to 142.194 seconds.  That is public
self-reported aggregate evidence, not isolated validation of this implementation
and not an artifact copied into it.

## Light and targeted verification performed

- Python compilation of selector, collector, builder, shared inventory, tests,
  and all five generated support modules
- 31 focused unit/adversarial tests covering state matrices, both singleton
  directions, operand side/syntax, whole-tree and directive rejection,
  malformed/unknown/unseen masks, exact-line subtraction, value identity and
  one-time evaluation, hostile/reflected protocols, custom metaclasses,
  mutable/native truth hazards, builtin monkeypatching, module/class contexts,
  tracked materialization, Git-link mode/OID binding and fail-closed states,
  path collisions, generated-support tampering, and process-pool pre-`atexit`
  flushing/quarantine, allocation-inert sensitive hooks, static quarantine
  completeness in both modes, and sensitive-to-ordinary fork/task transitions
- deterministic source census above
- `git diff --check`
- one limited locked-image normal run over the original generator-memory owner
  plus the optimizer pool sanity target: **2 passed, 322 subtests passed**, hard
  exit 0, 14/14 child logs, and 147 complete pool tasks

No replacement full trace, profile build, selector enablement, replay, or scorer
run has been performed. The prior full-normal exit-1 evidence remains rejected.

## Remaining exact-image admission

The first three gates are complete.  Do not submit until the final gate is
complete:

1. Complete fresh normal and synchronous-worker collection in the exact locked
   Python 3.13/runtime image with the pinned manifest. **Done.**
2. Build twice from admitted inputs and require byte identity. **Done.**
3. Pin the raw artifact and package it in the image. **Done in the candidate
   integration branch.**
4. Run the exact Docker sample plus adversarial/replay validation, checking every
   failing patch/test pair is retained and measuring the actual score impact.

The candidate now binds the artifact by raw SHA-256 and fails closed when it is
missing, malformed, or stale.  Exact-image verification remains the final
shipping gate.
