# Interprocedural shared-argument write/escape research

Status: **SHIP-CANDIDATE / ENABLED**.  The source model, ownership proof, and
runtime gate are deterministic and fail closed.

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
sha256 6ebc3828c4c4cb020fd4625df98f5869ec8881c06bf284f9c95c24bee4d1d4b4
5,282 functions; 9,199 formal slots; 10,772 propagation edges
37 exact fresh local classes; 19 exact fresh-receiver calls
2 ownership-contained fresh-receiver calls
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

## Admission theorem

The runtime recognizer requires a one-line replacement in one exact resolved
fresh-receiver call; unchanged call target, argument layout, function binding,
and control/tree shape; one same-kind immutable scalar argument edit; a unique
pre-call local assignment; no intervening receiver alias/load; exact source and
artifact hashes; and fail-closed parsing/model validation.  Target changes,
aliases, stars, ambiguous calls, tampering, and malformed sources reject.

The builder additionally runs a context-sensitive ownership fixed point.  It
tracks exact-formal identity through assignments and exact calls, carries
immutable defaults and exact receiver classes, and admits a wrapper only when
every normal return is the original formal. Calls on or passages of that formal
must resolve to source functions whose corresponding formal is also proven
non-storing. Receiver-local field/container writes and parent links stay inside
the owned graph; module/class/global/nonlocal stores, closures, callbacks,
external containers, nonidentity returns, unknown dispatch, reflection,
ambiguous descriptors, starred binding, and recursive uncertainty reject.

This proves `Parser.expression(instance)` and
`Parser.validate_expression(expression)` as exact identity wrappers for the
fresh `AtTimeZone`, proves their receiver operations non-escaping, and proves
the default `Expression.set("session_zone", <bool>)` path mutates only that
fresh graph. Adversarial variants that globally store, close over, callback
with, or append the formal to an external container all fail admission.
