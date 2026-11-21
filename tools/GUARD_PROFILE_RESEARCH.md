# Per-test guard profiles

Status: **SOURCE/COLLECT-READY; NO-SHIP**

The first audit's collect-ready verdict was invalidated when source-light
preflight found the pinned tree's uninitialized `sqlglot-integration-tests`
Git link could not be materialized. An uncommitted repair now binds exact Git
index modes/object IDs, permits only an empty mode-`160000` directory, and
binds that inventory through collector and builder provenance. Focused tests
pass. The independent follow-up in `GUARD_PROFILE_GITLINK_REAUDIT.md` found and
fixed a synchronous-tree validation blocker and restored collect-ready status.

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
processes, incomplete logs, unknown owners, tracemalloc use, and memory/leak
tests are quarantined. Runtime hook/import-hook identity is checked at every
test boundary. Normal and synchronous-worker runs must agree on shared
provenance and must both be admitted.

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

## Light verification performed

- Python compilation of selector, collector, builder, shared inventory, tests,
  and all five generated support modules
- 29 focused unit/adversarial tests covering state matrices, both singleton
  directions, operand side/syntax, whole-tree and directive rejection,
  malformed/unknown/unseen masks, exact-line subtraction, value identity and
  one-time evaluation, hostile/reflected protocols, custom metaclasses,
  mutable/native truth hazards, builtin monkeypatching, module/class contexts,
  tracked materialization, Git-link mode/OID binding and fail-closed states,
  path collisions, generated-support tampering, and process-pool pre-`atexit`
  flushing/quarantine
- deterministic source census above
- `git diff --check`

No Docker run, full pytest run, profile collection, or scorer run was performed
while the shared machine was saturated, as required.

## Admission sequence and blockers

Do not enable this feature until all of the following are complete:

1. Commit the independently re-audited Git-link/executed-tree repair so future
   evidence binds one immutable source checkpoint.
2. Fresh normal and synchronous-worker collection in the exact locked Python
   3.13/runtime image, with the complete pinned 1,620-test manifest.
3. Two deterministic builds from the admitted inputs that are byte-identical.
4. Pin the resulting raw artifact SHA-256 in `selector.py` and include the
   artifact in the repository.
5. Run the full Docker suite and adversarial/replay validation, checking every
   failing patch/test pair is retained and measuring the actual score impact.

Until then `GUARD_PROFILE_SHA256 = ""` deliberately keeps the runtime path
disabled. The current verdict is therefore **COLLECT-READY / NO-SHIP**.
