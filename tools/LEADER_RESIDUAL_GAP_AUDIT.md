# Leader residual gap audit

Status: **EXACT-IMAGE-READY for the two narrow proofs in this branch** and
**NO-SHIP for a general `NARROW_SHARED_ARGS` port**.  Validation here is
source/light only by assignment: no answers, Docker, full suite, scorer,
submission, or push were used.

The audit compared the selector at `8fa44ee` with clean-room observations of
the public Epicepicdemic v3.5 behavior over all 683 public validation patch
descriptions.  It first measured selector outputs without consulting outcomes,
then subtracted Kashimo's existing semantic, local-binding, fixture, verifier,
dictionary, class-table, generator, and identity proofs.

## `NARROW_SHARED_ARGS` residual

An answer-free ablation of the public leader changed 36 of 683 selector
outputs.  Twenty-five changes reduced a nominal 1,620-test selection by more
than 30 packed seconds.  The public sample's two changes are already subsumed:
Kashimo selects zero tests for `5y72` through its fresh-alias proof and one test
for `6ze8` through its generator-dispatch proof.

A clean-room reconstruction generated transitive write/escape summaries for
5,258 functions in 184 modules.  The artifact was 1.2 MB and took 8.125 CPU
seconds to build.  Its behavior explains the leader's improvement: call
arguments are mapped to callee parameter slots; a fixed point retains only
arguments whose slots can transitively write or escape; resolvable shared
origins then receive binding-reader masks rather than the full suite.

That mechanism is not directly incremental to the current Kashimo selector.
It primarily narrows a conservative shared-write expansion which Kashimo does
not perform.  Most of the leader's 36 changed cases are already as narrow or
narrower under existing Kashimo proofs.  The conspicuous parser-table cases
(`ibag`, `nkwn`, `bqdk`, `d6jj`, and `u9gd`) overlap the separately assigned
class-table lane.  A remaining multi-call shape, `fvn9`, would require the full
interprocedural shared-write model and has no narrow fail-closed certificate.
Adding that model merely to recover from a newly introduced broadening has no
defensible selector economy, so the general port is **NO-SHIP** in this branch.

## Incremental safe residuals

### Non-Python directive routing

The selector treated any added comment containing `type:`, `noqa`, and similar
text as a Python directive before fixture routing.  SQL fixture comments can
contain exactly those strings.  The fix restricts the directive proof to
`.py` paths; non-Python changes are still observed through their exact fixture
reader masks and are never discarded as inert.

| public patch | baseline tests / packed | fixed tests / packed | removed |
| --- | ---: | ---: | ---: |
| `val1/p2yv` | 1,620 / 36.817 | 1 / 2.395 | 1,619 / 34.422 |
| `val1/qfxw` | 1,620 / 36.817 | 2 / 3.411 | 1,618 / 33.406 |
| `val9/ys5q` | 1,620 / 36.817 | 3 / 3.497 | 1,617 / 33.320 |

This removes 4,854 selections and 101.148 aggregate packed seconds across
three public validation descriptions.  These are capability measurements, not
an official-score prediction.

### Position-preserving formatting

A second proof accepts replacement-only whitespace changes only when all of
the following remain identical: physical line count, complete token
`(type, text)` stream including comments, AST including type comments, and the
recursive compiled-code fingerprint including line tables and every
instruction position.  It rejects directives, typing (whose tests read source
bytes), process-serialization code, test files, insertions, and all parse or
resource failures.  Reflection readers are retained.

The 683-description census accepts exactly two patches:

| public patch | baseline tests / packed | fixed tests / packed | removed |
| --- | ---: | ---: | ---: |
| `val5/mnvv` | 37 / 3.360 | 0 / 0 | 37 / 3.360 |
| `val5/msua` | 1 / 2.001 | 0 / 0 | 1 / 2.001 |

It deliberately rejects formatting patches such as `rv83` and `593v`, where
whitespace moves executable source positions, and `n8m5`, whose typing source
bytes are observable.  This removes another 38 selections and 5.361 packed
seconds.

Together the narrow changes remove 4,892 selections and 106.509 aggregate
packed seconds across five answer-free public validation descriptions.

## Verification

```text
python -m unittest tools.test_formatting_equivalence -v
17 tests passed

python -m unittest tools.test_semantic_noops \
  tools.test_typing_reflection_outcome tools.test_selector_ast_index -q
43 tests passed

python -m py_compile selector.py tools/test_formatting_equivalence.py
git diff --check
```

Adversarial coverage includes moved executable positions, changed comment
text, directives, encoding comments, type comments, docstrings, insertions,
typing, test and serialization paths, resource exhaustion, SQL `# type:
ignore` / `# noqa` routing, and Python directive fail-closed behavior.
