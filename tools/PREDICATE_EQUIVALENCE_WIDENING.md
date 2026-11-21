# Predicate equivalence widening

## Verdict

SHIP the runtime-gate widening for the existing version-2 predicate artifact.
It requires no new trace and does not weaken the artifact's operand, provenance,
source, or candidate-edit constraints.

The packaged artifact contains 146 complete source-site records: 120 safe, 12
unattributed, 8 unobserved, and 6 unsafe. Safe records retain the raw outcome of
all six profiled operators in this fixed order:

```text
Lt, LtE, Gt, GtE, Eq, NotEq
```

Across those records there are 107 directed source-site/operator pairs whose
old and prospective results agree at every recorded invocation. The former
adjacent-only runtime gate exposes 31. The widened gate exposes all 107 at the
outcome level, for 76 additional pairs: 70 ordering-to-`Eq`/`NotEq` pairs and 6
non-adjacent ordering-to-ordering pairs. Running every one through the complete
production AST, binding, directive, serialization, and import gates accepts
104 total: 28 old adjacent opportunities and all 76 incremental opportunities.
The three rejected opportunities are already-adjacent pairs rejected by
unchanged conservative outer gates.

## First-divergence proof

Assume a candidate admitted by the runtime gate changes the suite's behavior,
and take the first comparison invocation at which the original and candidate
executions diverge. Before that invocation their process and Python states are
identical by definition. Whole-file AST equality after replacing the one
operator with a sentinel proves that the operands, their evaluation order, and
all surrounding executable syntax are identical. Each operand is evaluated
once.

The collector admits an observation only when both runtime operands are exact
immutable builtins: `NoneType`, `bool`, `int`, `float`, `str`, `bytes`, or an
exact tuple recursively containing only those types. It evaluates the six
Python-nonmutating builtin comparisons on those same objects. The artifact says
the original and candidate operators returned the same exact `bool` for every
invocation reached by both complete passing suite modes. Therefore the two
executions return the same value at the supposed first divergent invocation,
a contradiction. By induction the same argument includes state carried across
tests and reused worker processes.

This widening is especially conservative about edge cases:

- `bool` and `int` are recorded as exact runtime types, and only the boolean
  result vector—not an inferred numeric relation—is trusted.
- Float infinities and NaNs need no algebraic assumption. Their actual six
  boolean outcomes are recorded. The floating-point-status gate below rejects
  the unordered vector that can hide a native flag difference.
- A site is `safe` only when all six operations returned an exact `bool`.
  Cross-type exceptions and malformed/error signatures fail closed.
- Empty observations, non-boolean values, wrong vector widths, unknown or
  identical operators, unsafe states, and ambiguous coordinates fail closed.

## Identity exclusion

`is` and `is not` are intentionally not added. Version 2 has no identity
outcome slots. Source rewriting may also alter code constants and interning, so
an identity relation observed in an instrumented copy is insufficient.

## Floating-point status flags

Builtin float comparison has a native side channel outside the returned
Python `bool`: in the pinned runtime, quiet-NaN ordering sets `FE_INVALID`,
while `Eq`/`NotEq` does not. Signaling NaN sets it for both classes. An
ordering-to-equality-class edit is therefore rejected if any observation is
the unordered vector `[False, False, False, False, False, True]`. That vector
also covers a recursively safe tuple containing a distinct NaN. The bundled
artifact has no such vector at an otherwise accepted site, so the defense does
not reduce the 76 incremental opportunities. `NotEq` cannot match an old
ordering result on this vector; ordering-to-ordering stays in one native class.

## Candidate integrity and provenance

The selector requires the artifact version, pinned SQLGlot SHA, test count and
ordered-test digest to match the main model. It validates the seven-field entry,
source operator, safe state, nonempty exact-boolean vectors and vector width.
It follows the source AST path into the complete changed file, normalizes only
the operator, and requires complete executable AST equality. Compile/function-
binding, code-reflection, directive, process-serialization and import-expression
safeguards remain active. The profile is complete-source-derived and contains
no prospective edit, test ownership, sample patch or answer information.

## Adversarial evidence and economics

`tools/test_predicate_profile.py` covers the opportunity census, real accepted
edits, differing outcomes, identity, unsafe/unobserved/malformed evidence,
changed operands and surrounding AST, unrelated edits, directives, NaN status,
and serialization quarantine. Independent audit re-derived all counts, passed
all 81 repository tool tests, and exhaustively probed 10,000 two-element tuple
pairs containing finite values, qNaNs, sNaNs, integers and signed zeros without
finding an unguarded ordering/equality FP-status difference.

Applying one synthetic candidate for each of the 76 incremental opportunities
makes the prior fallback select 10,541 tests in aggregate (1–1,615 per case)
for 557.797 simulated seconds. The widened proof selects zero. This is a
capability benchmark, not a hidden-frequency forecast.
