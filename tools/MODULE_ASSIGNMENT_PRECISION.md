# Module-assignment reader precision vertical

Status: source/light-test prototype pending independent audit and rebuilt normal
plus synchronous-worker traces. No validation answer or patch identity is used
by the mechanism.

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
- Emit artifact schema v2 with the candidate kind; runtime accepts v1 and v2
  while remaining fail-closed on unknown kinds.

## Changed files

- `tools/collect_module_constant_reads.py`: candidate classification, stable
  import/re-export graph, unresolved-export poisoning, computed-reader and
  derived-class-alias instrumentation.
- `tools/build_module_constant_model.py`: v2 artifact encoding, expanded
  static threat audit, and derived-class opaque-escape rejection.
- `selector.py`: prospective validators for class tuples and regex patterns,
  plus v1/v2 artifact compatibility.
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

Seven shapes should therefore move from full-suite fallback to traced readers.
Using the existing artifact only as a scale indicator, the already-profiled
core bindings have tens of readers rather than 1,615. A conservative forecast
is roughly 3,200-3,600 total val11 selections if the regex and mutable-dict
commits remain broad, versus 14,535 currently. This is not a score claim.

## Validation performed

`python -m unittest tools.test_module_assignment_precision -v` passes 19
lightweight tests. They cover star and explicit re-exports, static/absent/
dynamic/mutated `__all__`, re-export rebinding, alias ambiguity and local
shadowing, transitive unresolved exports, module `__getattr__`, star cycles, class-tuple resolution and
rebinding, exact regex construction, exact/dynamic computed readers, derived
class aliases, all supported reflection forms, and opaque/native-reflection
fallback. `py_compile` and `git diff --check` pass.

No full collector, Docker, pytest suite, val11 selector execution, commit,
push, or submission has been performed.

## Expected artifact build

After independent source review, the existing two-mode collection protocol is
required; it must not reuse the old traces because the candidate inventory and
instrumented reader sites changed:

```sh
python tools/collect_module_constant_reads.py \
  --source /path/to/pinned/sqlglot --python /path/to/python3.13 \
  --tests sample/tests.json --output /tmp/module-normal-v2.json \
  --manifest /tmp/module-normal-v2.manifest.json

python tools/collect_module_constant_reads.py \
  --source /path/to/pinned/sqlglot --python /path/to/python3.13 \
  --tests sample/tests.json --synchronous-workers \
  --output /tmp/module-sync-v2.json \
  --manifest /tmp/module-sync-v2.manifest.json

python tools/build_module_constant_model.py \
  --source /path/to/pinned/sqlglot --tests sample/tests.json \
  --manifest /tmp/module-normal-v2.manifest.json \
  --manifest /tmp/module-sync-v2.manifest.json \
  --trace /tmp/module-normal-v2.json --trace /tmp/module-sync-v2.json \
  --output module_constant_model.json.gz
```

The builder should produce `module_constant_model.json.gz` with schema `v=2`.
Both manifests must cover all 1,620 tests, report successful exit status and
child-process accounting, and the artifact must remain pinned to sqlglot
`eb11aec4be8cb2122afe713a4816662c3f0fb2fa` plus the ordered test digest.

## Unresolved risks before collection

- The expanded instrumentation has only synthetic/light coverage; a separate
  reviewer should audit evaluation order, exception behavior, descriptors,
  MRO resolution, and proxy protocol completeness.
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
