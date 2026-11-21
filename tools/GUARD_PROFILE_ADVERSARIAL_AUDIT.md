# Guard-profile adversarial audit

Verdict: **COLLECT-READY / NO-SHIP**

Scope: uncommitted `research/per-test-guard-profiles` source, based on selector
commit `862545f`, including the selector gate, shared classifier/inventory,
normal and synchronous collectors, builder admission, and focused tests. This
audit did not run Docker, the full pytest suite, either full collection, the
official collector, or the scorer. The verdict from that audit was invalidated
by the concrete pinned-source materialization defect and repair below.

## Post-audit blocker and repair

The pinned tree contains the uninitialized Git link
`sqlglot-integration-tests` at object
`3000152841de3ae0c0fce2e6b383d61396363521`. The audited collector enumerated
only tracked path names and accepted only files or symlinks, so it rejected
this real index entry before collection could start. The prior
**COLLECT-READY** verdict was therefore incorrect.

The uncommitted repair now parses `git ls-files --stage -z`, binds every path
to its exact mode and object ID, includes that inventory in a domain-separated
digest, and includes mode and object ID in a separately domain-separated
materialization digest. Regular files and symlinks must reproduce their Git
blob object IDs and modes. Mode `160000` is the only permitted tracked
directory and must exist as an empty, uninitialized directory; initialized,
contentful, missing, wrong-type, unsupported-mode, unmerged, duplicate, and
path-colliding entries fail closed. Copying reproduces the empty directory.
The trace carries the tracked-inventory digest and the builder independently
re-enumerates and validates both inventory and materialization.

This repair changed audited collector, builder, and test code. Its independent
follow-up review is recorded in `GUARD_PROFILE_GITLINK_REAUDIT.md`. That review
found and fixed a synchronous-tree OID-validation blocker, expanded the focused
suite to 29 tests, and restored the **COLLECT-READY** verdict.

## Findings and disposition

### Selector exactness: pass

- A candidate is located by the pinned AST coordinates and structural path.
  Operand AST and exact source segment must match on both sides.
- Replacing the one guard test, or canonicalizing the one None operator, must
  make the complete original and prospective ASTs equal. A second executable
  change therefore fails closed. Directives fail closed.
- Only one admitted profile entry may match. Malformed, out-of-range,
  incomplete, unknown-owner, unattributed, and unobserved evidence cannot
  authorize subtraction.
- Repeated observations are conservative: state masks may overlap, and a test
  is retained if any observation is unknown or any observed state makes the
  two forms differ. Branch divergence after the guard cannot manufacture an
  exemption.
- The rule is attempted only for a single changed path and subtracts only from
  the ordinary precise-line coverage candidate set. Existing test-file,
  source/code-reflection, import, binding, fixture, serialization, and
  multi-change hazards remain additive or bypass the rule.

### Evaluation and Python protocol semantics: pass after hardening

- AST wrappers evaluate the operand once and return the identical object;
  attribute/call/subscript exceptions still happen before either hook.
- Unknown classes, subclasses, proxy/native values, NumPy-like values, custom
  metaclasses, and values with reflected `__eq__`/`__ne__`, `NotImplemented`,
  `__bool__`, or `__len__` behavior are never probed and remain unsafe.
- Exact immutable builtin truth states are sufficient for the eight supported
  truth forms. Mutable builtin containers were removed from truth
  classification because the hook plus real condition creates two observations
  with a mutation window. Exact float/complex values were removed because
  truth probing can perturb native floating status. Both families remain safe
  only for None equality/inequality, where exact builtin dispatch cannot reach
  user code.
- Original `type` and `bool` callables are captured before tests, so ordinary
  builtin monkeypatches do not alter classification. Direct references to
  support modules/hook names are rejected in every tracked Python source, and
  hook/import-hook identity is checked before and after every test.

### Import, construction, reflection, and memory contexts: pass for collection

- Site instrumentation is in-memory through `SourceFileLoader.get_code`; the
  copied tracked source bytes remain unchanged for `inspect`, loader, and
  linecache readers.
- Import/collection observations are owned by `__NO_TEST__`, which makes that
  site unusable. Selector precision/binding gates reject module, class-body,
  decorator, default, and definition-header edits. Existing code-reflection
  readers are added before guard subtraction.
- Test files importing `gc`, `resource`, `tracemalloc`, or `weakref`, plus
  memory/leak-named tests and any owner that starts tracemalloc, are
  quarantined. The pinned suite search found the relevant allocation/lifetime
  tests covered by this rule.

### Processes and ownership: pass after hardening

- Spawn/fork children inherit explicit ownership; first-task relabeling moves
  worker-start observations away from an inherited submitting test.
- Child start/data names include PID and nanosecond token, writes are atomic,
  and normal admission requires exact start/data and
  submitted/started/completed task equality. Unknown owners fail the builder.
- A concrete gap was fixed: multiprocessing workers commonly exit with
  `os._exit`, bypassing `atexit`. The child document is now flushed in every
  task `finally` block.
- Result pickling occurs after the owned wrapper clears its owner. Every
  submitting test is now quarantined in the root trace, so that post-wrapper
  interval cannot create an unsafe exemption. Missing-only serialization sites
  remain unobserved and cannot exempt anyone.
- External subprocess/exec/spawn use quarantines the owner; an instrumented
  child that disappears without a complete log fails admission.

### Evidence integrity: pass after independent Git-link re-audit

- The original inventory claim missed the pinned Git link and blocked real
  collection. The repaired inventory/materialization implementation and its
  separate executed-tree digest passed the independent follow-up review.
- The support digest binds tracker, plugin, classifier, import instrumenter,
  and sitecustomize. The synchronous-worker helper has a separate digest, and
  the builder independently reproduces and checks its post-transform tracked
  tree digest.
- The child environment is sanitized rather than inheriting arbitrary
  `PYTHONPATH` or pytest plugins. Hash seed, user-site loading, bytecode writes,
  and plugin autoload are fixed; the retained environment contract is hashed
  and must match both modes.
- Builder admission checks clean pinned commit/tree, ordered unique test IDs,
  complete test membership, exact site count, canonical owners, child/task
  completeness, trace digest, support/collector/classifier/transform digests,
  exact normal and synchronous materializations, Python 3.13, and immutable
  runtime-image digest syntax. The final raw gzip must additionally be pinned
  in the selector, so post-build model tampering disables the feature.

The runtime-image value is a declaration supplied to the collector; the script
cannot prove that its own process was launched from that digest. The collection
operator must record and verify the actual `docker image inspect`/launch digest
outside the script. This is an admission requirement, not a reason to block the
source from collection.

## Residual fail-closed boundaries

- A deliberately malicious pinned test could dynamically synthesize a reserved
  support name, replace a hook only inside the test body, and restore it before
  the boundary check. The fixed public suite is trusted input, direct markers
  are rejected, and the final two-mode/full-suite run must remain green. Any
  discovered dynamic tamper requires quarantining that complete test file.
- Root events after pytest's session-finish hook are not included. The pinned
  `sqlglot` and test sources contain no `pytest_unconfigure` or `atexit` hooks;
  third-party pytest plugin autoload is disabled. A future source/test revision
  would require repeating that census.
- Normal pool submitters are intentionally never exempted. This reduces score
  benefit for optimizer/executor tests but closes ownership and result-pickling
  ambiguity.

## Post-repair light verification performed

- `python3 -m py_compile` for selector, classifier, collector, builder, and tests
- compilation of all five generated support modules
- compilation of all five generated support modules
- `python3 -m unittest -q tools.test_guard_profile`: **29/29 passed**
- real pinned index: **365 entries** (`100644=360`, `100755=3`, `120000=1`,
  `160000=1`), including the expected empty Git link
- tracked-inventory SHA-256:
  `d83639c3b69d4717f029ed1e6b9db88b6797b655a541909fb6c06a54fa8d80ad`
- materialization SHA-256:
  `62b25b3f9488552fee8b2af812ed0115abda46c6edeb915356cc1eae612eb905`
- pinned-source inventory: **5,457 sites** (`truth=4,974`, `none=483`)
- `git diff --check`: passed

No Docker/full-suite/collector run was performed because the parent explicitly
reserved the machine while another collection was running.

## Exact blockers to shipping

1. Commit the independently re-audited provenance repair before Docker smoke
   or collection so every artifact binds one immutable source checkpoint.
2. Run both complete 1,620-test traces in the verified locked Python 3.13 image:
   normal persistent workers and the independently reproduced synchronous tree.
3. Require zero pytest failures, exact test membership, nonzero normal pool-task
   evidence, zero synchronous pool tasks, and complete child/task manifests.
4. Build twice from the admitted files and require byte-identical gzip output;
   inspect state counts and provenance, especially unattributed/malformed sites.
5. Add `guard_profile.json.gz`, set its exact raw SHA-256 in
   `GUARD_PROFILE_SHA256`, and rerun the 22 focused tests after that edit.
6. Run the full locked Docker suite plus adversarial/replay validation proving
   every failing patch/test pair is retained, then measure score impact.

Until all five blockers are cleared, the selector kill switch must stay empty
and the feature remains **NO-SHIP**.
