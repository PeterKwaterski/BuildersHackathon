# Module-assignment precision adversarial audit

Verdict: **COLLECT-READY for the reduced direct-module/class-tuple scope; not
SHIP.** Derived class-alias propagation is production-disabled. No artifact,
selector integration, push, or submission is justified until the two exact
full-suite traces, artifact rebuild, Docker evaluation, and a final stacked
audit all pass.

## Scope reviewed

The audit reviewed the complete uncommitted diff from `862545f`, including the
import/re-export graph, runtime instrumentation, artifact builder, prospective
selector gate, and focused tests. It used no sample or validation answer in the
mechanism. The public val11 descriptions were used only to describe candidate
syntax shapes and expected breadth.

## Fail-open findings and repairs

The initial source prototype was **not** collection-ready. This audit found and
repaired the following issues:

1. `hasattr` and `dir` of a derived class owner were exempted by the static
   threat analysis but were not instrumented.
2. `vars(cls)` and `cls.__dict__` returned an incomplete proxy rather than the
   original `mappingproxy`, changing type, identity and unsupported protocol
   behavior. They now return the original value and conservatively record all
   applicable aliases before access.
3. Attribute/getattr/inspect wrappers recorded after the reflected operation.
   A reader that raised could therefore disappear. Recording now precedes the
   operation.
4. Instance shadowing plus custom `__getattribute__` could hide a real class
   read from provenance. The research wrapper now conservatively records the
   MRO candidate before lookup.
5. Class aliases survived later rebinding/deletion, decorators, bases,
   metaclasses and direct class-body escape. Discovery now rejects all of those
   forms and nested class owners.
6. Instances and subclasses can escape under new identities and later enter
   native reflection. A complete identity graph is absent. Rather than accept
   this residual hole, `DERIVED_CLASS_ALIASES_ENABLED` is now `False` in both
   collector and builder production paths. Assignment of a module value into a
   class is consequently observed during import and fails closed as
   `import-read`. This intentionally keeps the SAFE_IDENTIFIER_RE/Generator
   shape broad.
7. A nested/conditional `__all__` assignment was incorrectly treated as an
   absent `__all__`. Any non-single-static mention now poisons the star surface.
8. `importlib.import_module`, `__import__`, and `sys.modules` could acquire a
   module outside the alias graph. Exact sqlglot dynamic imports now poison the
   relevant module; dynamic imports and `sys.modules` poison all candidates.
9. A locally shadowed `getattr`/`hasattr`/`vars`/`dir` could be rewritten as a
   builtin helper. Files with any such binding now skip that helper rewrite,
   and static analysis no longer exempts the corresponding call.
10. Collector helper-name collisions were unchecked. Collection now aborts if
    pinned source already uses an injected helper identifier.
11. Normal child workers can survive across test methods while retaining the
    creator's `BR_PARENT_TEST`. Child events now carry a sentinel; the builder
    conservatively expands them to every manifest test in each recorded
    creator file, closing the known class-wide optimizer/executor pool reuse.
12. Child logs used PID-only filenames and could overwrite after PID reuse.
    They now include `time_ns` and retain atomic replacement.
13. Traces were not cryptographically bound to their manifests. Each manifest
    now records source revision, ordered-test digest and trace SHA-256; the
    builder requires exactly one normal and one synchronous trace and validates
    every binding before reading events.
14. A malformed v2 `kind` could crash set membership, and an adversarially huge
    regex could consume excessive memory. The selector now requires a string
    kind, caps prospective pattern length, and catches memory/recursion errors.

## Remaining admitted scope

The collection candidate is deliberately limited to:

- uniquely bound immutable module literals;
- non-empty tuples of statically proved class bindings, where a prospective
  edit only removes, duplicates or reorders existing names;
- exact `re.compile` assignments only when their readers do not escape through
  a class alias or another static threat (the current public regex shape is
  expected to fail closed);
- direct names, explicit and proved star re-exports, qualified module
  attributes, and exact literal-name `getattr`/`hasattr` reads.

Mutable dictionaries remain unsupported. Dynamic/duplicate/mutated `__all__`,
import cycles, lazy module `__getattr__`, ambiguous/rebound aliases, dynamic
module acquisition, module reflection, import-time reads, opaque class flows,
unknown kinds and empty/incomplete observations all retain the broad fallback.

## Validation performed

- `python -m unittest tools.test_module_assignment_precision -v`: **26 tests
  pass, 3 disabled-feature tests skip**.
- `python -m py_compile` passes for `selector.py`, collector, builder and tests.
- `git diff --check` passes.
- The suite covers static/absent/dynamic/conditional/mutated `__all__`, cycles,
  explicit/star re-exports, rebinding and shadowing, dynamic module acquisition,
  exact/dynamic reflection, class tuple and regex candidate gates, wrapper value
  preservation and pre-error recording, construction hooks, and the explicit
  production disable for derived aliases.

A source-wide census was started but immediately stopped when concurrent
collectors reduced available RAM below 1 GiB. It produced no evidence and was
not used in this verdict. No Docker, full pytest, normal/synchronous collection,
artifact build, public validation execution, commit, push or submission was
performed.

## Required gates before SHIP

1. Run fresh normal and synchronous-worker collectors against the exact pinned
   Python 3.13 image only after memory headroom is available.
2. Require exit zero, all 1,620 tests, positive child accounting, source/test/
   trace digest bindings, no unknown labels/owners, and byte-identical repeated
   artifact builds.
3. Inspect the seven target module bindings: each must be `safe`, nonempty and
   plausibly narrow. The regex/class-alias and mutable-dict bindings must remain
   broad (`import-read`/unsafe/unsupported).
4. Run exact-image sample and public val11 evaluations. Require zero misses;
   validation labels may measure the result but must never enter an artifact or
   runtime branch.
5. Run a final independent stacked/compliance audit and a fresh exact Docker
   sample before any commit recommendation.

Until those gates pass, the correct status is **COLLECT-READY, NO-SHIP**.
