# Typing reflection outcome equivalence

Status: **SHIP after independent adversarial review and exact-image validation**.

## Official signal

Practice receipt `BB-EA2E5902` at `f3f9b2a` selected zero missed commits but
regressed from 214.602 to 216.613 simulated seconds: exactly 2.011 seconds.
The complete code-reflection model has one reader, test index 1619,
`tests/test_typing.py::TestTyping::test_no_redundant_expression_metadata`, with
a recorded duration of 0.011 seconds. A singleton selection therefore costs
exactly 2.000 seconds of worker overhead plus 0.011 seconds of test time.

This aggregate is not used as a patch lookup. A source-derived reproduction
renames the local `this` binding to the fresh same-width name `that` in
`annotate_by_numeric_arg`. The pinned selector returns exactly `[1619]`; this
branch returns the empty set. The edit is independently accepted by the
general local-binding-rename proof.

## Test semantics

The reflection test scans typing metadata and compares callable annotators only
with `_same_code`. Its complete equality relation is:

```text
(co_code, co_names, co_varnames, co_consts)
```

It does not inspect line tables, exception tables, filenames, source text, or
other code fields. A local annotation accepted by the existing compiled
fingerprint proof leaves this tuple unchanged. A same-width local rename may
change `co_varnames`, so it is accepted only when every changed prospective
tuple is absent from a complete superset of pinned typing-package code tuples.
Such a tuple cannot become equal to any parent annotator and therefore cannot
create a newly redundant metadata entry. Existing collisions, newly colliding
tuples, unknown code-object identity, nested-code ambiguity, an unrecognized
proof family, a different reader set, or malformed evidence all retain index
1619.

The superset deliberately includes code objects the test cannot reach. This
loses opportunities but makes a uniqueness result sufficient without having
to reproduce metadata inheritance at runtime.

## Validation

Focused adversarial tests cover:

- the reproduced same-width local rename;
- an ignored local annotation with unchanged compiled fingerprint;
- a forced prospective fingerprint collision;
- two changed functions converging on the same novel prospective fingerprint;
- exact selector removal with a fail-closed missing-model control;
- an ordinary behavior change; and
- reader-model tampering.

Independent review found and repaired the multi-function prospective-collision
case by constructing the full prospective fingerprint multiset before testing
uniqueness. Exact Python 3.13.18 validation then passed all 6 focused tests,
the real prospective SQLGlot
`TestTyping.test_no_redundant_expression_metadata`, and the synthetic selector
check (`proven []`, missing-model fallback `[1619]`). A runtime-origin audit of
the real test traversal observed 149 compared annotator references / 90 unique
objects, with zero absent from the 124 compiled typing-package code objects.

The exact-image candidate and base sample outputs are byte-identical: 99 tests
over 30 commits and stdout SHA-256
`4d8bc3d459b8e57e9906579c2d6ac90afbb269e0910ac7e05abb858f931f95b4`.
The validated image is
`sha256:abcc1f32a967a9300bafb98febb454080ecfd319a64c54d11340c3fb63b064e9`
with Python base
`sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90`.
`py_compile` and `git diff --check` also pass.
