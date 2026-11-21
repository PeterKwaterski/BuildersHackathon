# Interprocedural shared-argument write/escape research

Status: **COLLECTED / DEFAULT-OFF**.  The source model and candidate gate are
deterministic, but the ownership/non-escape proof described below is not yet
closed strongly enough to enable narrowing.

## Answer-independent model

`shared_arg_write_model.json.gz` is built solely from the pinned
`semantic_sources.json.gz`.  It maps actual arguments to formal slots for
positional-only, positional-or-keyword, keyword-only, defaults, bound methods,
`*args`, and `**kwargs`, then propagates write, escape, and unknown effects to a
fixed point.  Unresolved calls, reflection, descriptors, dynamic protocols,
closures, global/container stores, iteration, context managers, and ambiguous
binding remain unsafe.

Call results do not alias their inputs merely because the inputs were read.
Return-alias summaries are computed separately.  Exact constructors produce a
fresh result only when source MRO resolution finds no custom `__new__`; wrapper
results preserve freshness only through exact return-formal identity.  Exact
fresh classes then resolve receiver calls.  Returned lambdas have separate
ordinary and captured slots; `Callable` annotations provide exact receiver
domains where unambiguous.

Two independent builds produced identical bytes:

```text
sha256 07c63674343c93c4b53c60f8b0dee38ffc87e48b932206c00514aac039f559e5
5,282 functions; 9,199 formal slots; 10,772 propagation edges
37 exact fresh local classes; 19 exact fresh-receiver calls
30 immediate returned-callable invocations; 11 captured formal slots
```

The pinned source artifact is byte-identical on candidate bases `3ded8e6` and
`511a3b4`, so the builder is source-compatible with both.

## Exact public residual

The model proves that `Parser._parse_at_time_zone` constructs local
`at_time_zone` as an exact fresh `exp.AtTimeZone`, through the identity return
of `Parser.expression`, and resolves the call at line 7186 to
`Expression.set`.  The ordinary precise-coverage and binding gates map this
line to:

- `tests/dialects/test_presto.py::TestPresto::test_time` (0.027 s)
- `tests/dialects/test_trino.py::TestTrino::test_format_datetime` (0.006 s)

The second file in the same public change is already handled by ordinary
precise coverage (not the `Generator.TRANSFORMS` certificate):

- `tests/dialects/test_snowflake.py::TestSnowflake::test_snowflake` (0.662 s)

The composed candidate is therefore 3 tests, 0.695 raw test seconds and 2.695
packed seconds.  The current selector is 1,615 tests / 36.817 packed seconds,
so the exact marginal ceiling is **34.122 packed seconds**.

An answer-free census of all 683 public validation patches finds exactly one
candidate mutation, the parser half of `val1/fvn9`.  No patch or answer IDs are
present in either runtime code or the artifact.

## Admission theorem and remaining gap

The runtime recognizer requires a one-line replacement in one exact resolved
fresh-receiver call; unchanged call target, argument layout, function binding,
and control/tree shape; one same-kind immutable scalar argument edit; a unique
pre-call local assignment; no intervening receiver alias/load; exact source and
artifact hashes; and fail-closed parsing/model validation.  Target changes,
aliases, stars, ambiguous calls, tampering, and malformed sources reject.

That is not by itself a complete ownership theorem.  A freshness-preserving
wrapper can return the same object after storing it externally.  For the public
candidate, `Parser.expression` and `validate_expression` return exact formal
identity, while receiver uses mutate/read that object.  However, the current
context-insensitive summaries still conservatively mark the wrapper formal and
`Expression.set` receiver as ESCAPE/UNKNOWN because of dynamic attribute and
protocol paths.  Enabling the gate would suppress a function-wide ownerless
import expansion, so this false-positive cannot simply be ignored: the source
fixed point must prove that the fresh root does not escape before the changed
mutation (or retain every reader of such an escape), including descriptor and
reflection fallbacks.

For that reason `SHARED_ARG_WRITE_ENABLED` remains `False`.  With it off,
selection is unchanged.  A diagnostic enable produces the exact 3-test
composition above, but is not a ship recommendation until the remaining
identity/non-escape summary is independently closed and audited.
