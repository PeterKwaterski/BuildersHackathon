# Key-sensitive `QUERY_MODIFIERS` research

Status: certified and selector-integrated for the exact public `where` removal.
No push or submission was performed.

## Opportunity and rejected shortcut

The public `m991` family removes one `False` entry from the module dictionary
`sqlglot.expressions.core.QUERY_MODIFIERS`. Its current broad cost is 36.817s.
The ordinary module read trace cannot support an aggressive result: its 18
numbered owners already cost 29.520s, before derived `arg_types` effects, so
that evidence can save at most 7.297s.

The specialized collector instead records only observations that can change
under one key deletion:

- truthy modifier effects in the exact parser and two generator consumers;
- exact key membership and wildcard topology observations of
  `SetOperation.arg_types`, `Select.arg_types`, and `Subquery.arg_types`;
- truthy use of the key propagated into `merge_subqueries.UNMERGABLE_ARGS`.

The three pinned parser/generator loops use an authenticated iterator that
bypasses only the generic tracker hook for those exact consumers. Their
semantic result is recorded by the paired value helper. Every other read,
iteration, shape observation or mutation of the source `QUERY_MODIFIERS`
dictionary remains a dependency; this retains reflection and monkeypatching
without broadening the known false-value loops.

The same rule applies to the five authenticated class-import derivations: the
three `**QUERY_MODIFIERS` copies, false-value `required_args` comprehension,
and `UNMERGABLE_ARGS` key-set construction bypass only tracker hooks on the
exact injected `TrackingDict`. Rebound/custom mappings at semantic consumers
emit a candidate-wide wildcard; unrelated dynamic classes with their own plain
`arg_types` cannot carry the source deletion. This matters in child processes, where a legitimate import inherits
the spawning test owner and would otherwise look like a runtime topology read.

The collector preserves the original operation result and evaluation order.
It retains the generic tracker for all class-dictionary operations and exact
normal-worker task attribution.

## Static theorem

The builder authenticates the pinned SQLGlot revision and complete source
bundle, then proves:

- `QUERY_MODIFIERS` is one module assignment with 23 unique literal string
  keys, each mapped to the exact singleton `False`;
- exactly `SetOperation`, `Select`, and `Subquery` unpack it into `arg_types`;
- the only qualified consumers are the pinned parser and generator sites;
- the only additional class-time propagation is the pinned
  `UNMERGABLE_ARGS = set(exp.Select.arg_types) - {...}` construction;
- the complete pinned package/test corpus has exactly 18 direct `arg_types`
  loads, all at authenticated tracker-covered operations, and no literal-name
  `arg_types` reflection channel; and
- the integration lane's module-object escape theorem remains a prerequisite.

That final prerequisite is material. A dictionary subclass does not observe
exact-type checks, native `PyDict_*` access, or an object that escapes without
a dictionary operation. The direct-load census closes the ordinary Python
surface for the three propagated dictionaries; module/import/reflection escape
proof and full mutant containment remain separate shipping gates. The model is
not sound merely because the instrumented suite passes.

For each key the builder derives the SHA-256 of the complete pinned core source
after deleting exactly that canonical dictionary line. The runtime gate
therefore accepts an exact source-derived deletion without using patch IDs,
validation answers, or expected failures.

## Provenance boundary

Each trace manifest binds the pinned source digest and revision, ordered-roster
digest/count, trace digest, Python 3.13 environment, submitted/completed task
counts, and a framed digest over both the specialized collector and its generic
dictionary-collector dependency. The model also binds both trace/manifest
digests and its builder bytes.

Import-time `**QUERY_MODIFIERS`, `Expr.__init_subclass__` required-argument
derivation, and `UNMERGABLE_ARGS` construction are admitted only at their exact
pinned call sites. Every other unnumbered event rejects the affected key.

## Current validation

- `py_compile` and `git diff --check` pass.
- Five focused suites cover collector consumer-shape drift, recursive
  artifact/provenance corruption, malformed trace/task types, whole-file
  runtime mismatch, and the complete pinned source theorem.
- A normal smoke of set-operation precedence and SQLite subquery modifiers
  passed 2 numbered tests and 49 subtests.
- The smoke confirms exact membership keys replace the prior membership
  wildcard; no truthy parser/generator modifier effect was fabricated.
- A first full normal trace was deliberately stopped at 80% after adversarial
  review found that the initial builder dropped source-dictionary wildcards;
  that evidence is inadmissible and will not be used. The repaired collector
  includes every non-authenticated source event and has green regression tests.
- Final normal evidence passed 1,620 tests and 25,440 subtests in 288.56s,
  with all 2,183 process-pool submissions completed across six workers and
  seven child logs. Synchronous-worker evidence passed the same roster and
  subtests in 266.04s.
- Two independent builds produced byte-identical gzip artifacts with SHA-256
  `cd800758e5768d595534f956f2ef499fa62fd7c39f9eefa125fa09c2b7604230`.
- The public patch-only corpus identifies `m991` as deleting exactly
  `"where": False`. Its certificate retains ten readers at 6.723 packed
  seconds, saving 30.094 seconds from the 36.817-second fallback.
- Independent full-roster mutation containment executed all 1,620 tests in
  exact manifest order and all 25,440 subtests with zero missed or unmapped
  failures. The runtime still returns the ten answer-independent traced
  readers; it does not encode the mutation run's outcome.

`tools/validate_query_modifier_mutant.py` reproduces the containment gate: it
creates one source-derived key deletion, executes the exact ordered 1,620-test
roster, normalizes subtest failures to numbered owners, and rejects any failure
outside the certified reader set.
