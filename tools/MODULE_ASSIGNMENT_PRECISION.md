# Module-assignment reader precision vertical

Status: independently audited v3 model with v4 task-attributed traces. Fresh
provenance-bound normal and synchronous-worker traces and a byte-identical
artifact rebuild have completed. No validation answer or patch identity is
used by the mechanism.

## Val11 diagnosis

The current selector chooses 1,615 tests for each of the nine public val11
patches: 14,535 selections for 146 labelled failures. The literal module model
already contains narrow reader observations for several affected bindings, but
marks them `static-unsafe`. The main concrete cause is a blanket rejection of
star-import exposure: `sqlglot.expressions.__init__` star-imports the expression
modules, so public constants such as `TABLE_PARTS` fall back even though their
reader identity can be followed through that re-export.

## Prototype changes

- Resolve public star exports transitively, honoring a single static
  `__all__`, final binding order, explicit aliases, and re-exports.
- Treat absent `__all__` as the normal public-name rule. Dynamic, duplicate,
  used/mutated `__all__`, module-level `__getattr__`, and cyclic star imports
  poison the candidate rather than producing an empty reader set.
- Reject module aliases that are ambiguous, rebound, deleted, or shadowed by a
  parameter/local binding.
- Trace exact `getattr(module, "NAME")` readers; unknown computed module names
  retain the prior conservative fallback.
- Admit only two computed assignment families in addition to literals:
  statically resolved non-empty tuples of class bindings, and an exact
  `re.compile(<literal string>[, <literal int flags>])` call whose `re` binding
  is the unique standard-module import.
- For prospective class tuples, allow only removal, duplication, or reordering
  of already-present proved class names. New names are rejected.
- Compile a prospective regular expression before using its profile, and still
  require the complete-AST single-value edit proof.
- Preserve provenance when a class attribute directly aliases a profiled
  module binding. Direct/MRO reads, `vars(owner)`, `owner.__dict__`, dynamic
  `getattr`, and `inspect.getmembers` are instrumented. Uninstrumented native
  reflection, `eval`/`exec`, and direct class-owner escape to opaque code poison
  the originating module binding.
- Emit artifact schema v3 with recursive entry/provenance validation. The
  selector authenticates compressed bytes before decompression; an absent or
  mismatched SHA-256 pin disables this proof family.
- Attribute every process-pool submission to its exact numbered owner and
  require submitted/completed ledger equality. Reads in a child process but
  outside an attributed submitted task are marked ambient and conservatively
  expanded to the creator's test file. Both trace modes bind the self-contained
  collector and the complete `sqlglot`/`tests` source inventory.

## Changed files

- `tools/collect_module_constant_reads.py`: candidate classification, stable
  import/re-export graph, unresolved-export poisoning, computed-reader and
  derived-class-alias instrumentation.
- `tools/build_module_constant_model.py`: v3 artifact encoding, expanded
  static threat audit, and derived-class opaque-escape rejection.
- `selector.py`: prospective validators for class tuples and regex patterns,
  plus hash-first v3 artifact loading and recursive validation.
- `tools/test_module_assignment_precision.py`: focused and adversarial source
  regressions.
- `tools/MODULE_ASSIGNMENT_PRECISION.md`: this report.

## Threat model and deliberate rejections

The optimization applies only when the assignment target is stable and the
complete old/new AST differs solely in its value. It rejects ambiguous or
rebound imports, local shadowing, dynamic or mutated export lists, star-import
cycles, lazy module attribute providers, unknown computed module names, new
class names, regex calls other than the exact proved constructor, empty reader
profiles, incomplete normal/synchronous traces, import-time reads that cannot
be converted to proved aliases, and native/opaque reflection or class-owner
escape. These rejections trade opportunities for avoiding a false negative.

## Public val11 shape applicability

This is shape analysis only; exact selected counts require new admissible
traces and an artifact rebuild.

| Commit | Changed binding | Prototype status |
| --- | --- | --- |
| `m2b3` | literal tuple `TABLE_PARTS` | supported |
| `m416` | literal string `SQLGLOT_META` | supported |
| `m49f` | `re.compile` binding `SAFE_IDENTIFIER_RE` | syntactically supported, expected to reject because the derived `Generator` owner escapes through `generator_class = Generator`; needs independent audit or deeper class-identity propagation |
| `m4bf` | class tuple `PERCENTILES` | supported |
| `m4d8` | class tuple `CONSTANTS` | supported |
| `m991` | mutable dict `QUERY_MODIFIERS` | unsupported; remains broad |
| `ma63` | class tuple `UNWRAPPED_QUERIES` | supported |
| `mcd9` | literal tuple `COLUMN_PARTS` | supported |
| `md3a` | class tuple `OPERATORS` | supported |

The final v3 artifact admits six shapes. `SAFE_IDENTIFIER_RE` and
`UNWRAPPED_QUERIES` remain `import-read`; mutable `QUERY_MODIFIERS` remains
unsupported. Exact answer-independent packed costs are: `PERCENTILES` 3.451s,
`OPERATORS` 3.275s, `CONSTANTS` 25.454s, `SQLGLOT_META` 6.475s,
`TABLE_PARTS` 26.040s, and `COLUMN_PARTS` 3.501s. Against their six 36.817s
fallbacks this is a 152.706s public simulated ceiling before selector CPU.

## Validation performed

`python tools/test_module_assignment_precision.py` passes 42 focused tests
with three deliberately disabled derived-alias cases. They cover star and explicit re-exports, static/absent/
dynamic/mutated `__all__`, re-export rebinding, alias ambiguity and local
shadowing, transitive unresolved exports, module `__getattr__`, star cycles, class-tuple resolution and
rebinding, exact regex construction, exact/dynamic computed readers, derived
class aliases, all supported reflection forms, authenticated executor/patch
sinks, task-ledger corruption, recursive artifact corruption, and raw/append/
recompressed artifact tampering. `py_compile` and `git diff --check` pass. A
two-test normal/synchronous smoke collection also passes with exact task and
child-process accounting.

Both exact full collectors, the deterministic artifact rebuild, exact image
runs, and the complete repository regression have been performed. No push,
leaderboard submission, or answer-file inspection has been performed.

## Artifact reproduction

After independent source review, the existing two-mode collection protocol is
required; it must not reuse the old traces because the candidate inventory and
instrumented reader sites changed:

```sh
python tools/collect_module_constant_reads.py \
  --source /path/to/pinned/sqlglot --python /path/to/python3.13 \
  --tests sample/tests.json --output /tmp/module-normal-v7.json \
  --manifest /tmp/module-normal-v7.manifest.json

python tools/collect_module_constant_reads.py \
  --source /path/to/pinned/sqlglot --python /path/to/python3.13 \
  --tests sample/tests.json --synchronous-workers \
  --output /tmp/module-sync-v7.json \
  --manifest /tmp/module-sync-v7.manifest.json

python tools/build_module_constant_model.py \
  --source /path/to/pinned/sqlglot --tests sample/tests.json \
  --manifest /tmp/module-normal-v7.manifest.json \
  --manifest /tmp/module-sync-v7.manifest.json \
  --trace /tmp/module-normal-v7.json --trace /tmp/module-sync-v7.json \
  --output module_constant_model.json.gz
```

The builder produces `module_constant_model.json.gz` with schema `v=3`.
Both manifests must cover all 1,620 tests, report successful exit status and
complete child/task accounting, bind the collector and source inventory, and
the artifact must remain pinned to sqlglot
`eb11aec4be8cb2122afe713a4816662c3f0fb2fa` plus the ordered test digest.

## Remaining risks

- Fresh full traces are mandatory after any collector-byte change; the builder
  rejects stale evidence through the collector digest and source inventory.
- The `SAFE_IDENTIFIER_RE` shape is expected to fail closed because
  `Generator` is copied into `Dialect.generator_class`; proving that identity
  flow safe would require a broader class-binding graph.
- Mutable container propagation (`QUERY_MODIFIERS`) remains intentionally out
  of scope.
- Candidate/build discovery reparses the source several times. This affects
  offline build cost, not selector runtime, but should be simplified if traces
  show material memory pressure.
- New traces must be checked for any `import-read`, `static-unsafe`,
  `incomplete`, or unexpectedly unobserved val11 target before integration.

## V3 authenticated cold-import boundary

The follow-up `research/module-assignment-v2` work closes three blanket threat
rules that otherwise marked every candidate unsafe, while retaining the same
fail-closed result for unknown shapes:

- Test files present in the authenticated 1,620-test manifest seed a complete
  static `tests.*` import closure. Pytest package/conftest setup and imported
  support modules remain in the threat surface even when they own no numbered
  test directly. Parent package initializers and conftest files are included at
  every active test-package level. Only unreachable unnumbered test modules are
  excluded.
- The collector invokes the exact ordered 1,620 node IDs rather than pytest
  discovery, records execution order without set/sort normalization, and both
  collector and builder require byte-for-byte roster-order equality. Extra,
  duplicate, missing, or reordered nodes invalidate the trace.
- A dynamic import with a literal f-string prefix poisons only modules below
  that prefix, including values re-exported onto any matching module surface.
  The exact pinned optimizer lazy loader, typing metadata test,
  and `serde._load` bodies are AST-hash authenticated. `serde._load` invokes
  its dynamic attribute as a class, while every admitted candidate kind is
  provably non-class and non-callable before and after the same-type runtime
  gate; a name collision therefore raises the same type-only `TypeError`.
- Direct or assigned aliases of `importlib.import_module` enter the same
  dynamic-import threat analysis. The sole pinned pass-through spy is admitted
  only under the full AST hash of its fixed Snowflake lookup test.
- `sys.modules` membership observes keys only. The AST-pinned `subclasses`
  helper observes values only through `inspect.isclass`, and the modeled
  literal, class-tuple and regex values are never classes. The pinned sqlglotc
  setup only shallow-copies/restores the module dictionary through
  `mock.patch.dict`. All other `sys.modules` uses still poison every candidate.
- The two pinned `is_compiled(_core_module)` calls are accepted only because
  the authenticated helper reads the fixed `__file__` attribute. Other bare
  module-object escapes remain unsafe.

Focused coverage is now 42 green tests with three deliberately disabled
derived-alias cases. After closing the imported-support-module hole, static
census admits all nine public val11 shapes; runtime evidence still marks the
mutable dictionary unsupported and must reject unobserved, import-read, or
incomplete entries. Version-4 traces distinguish exact submitted-task reads
from ambient child-process reads, so only ambient observations expand to every
test in the creator's file. The pinned source uses top-level
`concurrent.futures.ProcessPoolExecutor`; its sole standalone child is the fixed
`python -c` in `TestDialect.test_lazy_load`, so both modes require exactly one
standalone log. Normal mode passed 1,620 tests and 25,440 subtests with an exact
2,183/2,183 task ledger, six task workers, seven child logs, and one standalone
child. Synchronous mode passed the same roster/subtests with no pool tasks and
one standalone child. Both bind the self-contained collector bundle
`e409aa6114d0b1267d269a361a31afaac3890465a4cabc3d53ec3e51e115ade0`,
source inventory `c57e9c6fbda07a4dc88c54debe29d963831994f931d4d9eed727667630f8165b`,
and exact trace digests
`a943182e0a834472abd73921b084ed7bcd20f4f9ea3fcbf4bf7e7900667d14b6`
and `648f90cb09f7e43a7dbee57445576d45b66633971a87f092619bd71200017c80`.
The model rebuild is byte-identical at SHA-256
`521dc82a084a6890d68eda5ba6166fdf1d3cf7534673d6276402e1eadaf92ebe`.
The complete repository suite is 129 green with three intentional skips; two
exact image runs emitted the same 30-line output SHA-256
`4d8bc3d459b8e57e9906579c2d6ac90afbb269e0910ac7e05abb858f931f95b4`.
