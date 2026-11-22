# TPC prospective graph hardening

## Result

The TPC prospective verifier now compares an answer-free, identity-aware binary
encoding of each optimized expression graph. It no longer relies on
`Expression.dump()`, whose representation does not bind all cached and aliasing
state used by an `Expression`.

The profile format is `kashimo-tpc-plan-profile-v2`, the graph format is
`kashimo-expression-graph-v2`, and the exact Python 3.13 profile artifact SHA-256
is `d929551c3041efcde8eb955768e0f8173cfafd6828c4d8a5762703346f31b1ce`.
Two independent builds under `PYTHONHASHSEED=0` produced that same digest.

## Closed representation

The encoder binds:

- the exact module-qualified class of every expression node;
- ordered argument names and typed argument values;
- expression identity through stable discovery-order references, including
  shared identities reachable from types and metadata;
- both directions of parent, argument-key, and list-index topology;
- comments, `_type`, `_meta`, and the exact `None`/integer state of `_hash`;
- exact scalar/container types, with length-delimited binary fields.

It rejects graph values outside its explicit domain, escaping parents, invalid
backlinks, expressions hidden in unsupported nested argument containers, and
the impossible single-parent topology produced by reusing a child in two args.
It does not call expression equality or hashing.

Only the 57 executable TPC-DS entries receive graph digests. The 22 TPC-H
entries are all non-executable in the pinned fixture, so their graphs are never
compared at runtime. This also avoids pretending that a detached TPC-H subtree
whose type parent escapes the root is in the closed domain.

## Exact-runtime economics

The image and profile were built and measured on the pinned `python:3.13-slim`
runtime, with two CPUs, the production memory limit, and `PYTHONHASHSEED=0`.
Paired full prospective-run measurements were:

| public case | old dump CPU (s) | hardened CPU (s) |
| --- | ---: | ---: |
| `pn4m` | 5.036 | 7.109 |
| `v4sw` | 6.410 | 7.604 |
| `yrbp` | 4.991 | 5.388 |

All three hardened runs returned accepted executor equality, remained below the
16-second per-patch cap, and retained a positive 1.2x verifier-cost margin
against their known prospective savings. CPU timing on this shared machine was
frequency-sensitive (individual reruns varied substantially), so the table is
a paired checkpoint rather than a claim of cycle-level repeatability.

## Adversarial checks

`tools/test_tpc_graph_digest.py` covers independent graph stability, shared vs.
duplicated identity, parent/key/index corruption, reverse-backlink corruption,
comments, type, metadata, cached hash state, argument order, scalar type, nested
arg containers, and inconsistent shared children. All seven tests pass.

## Function-owner coverage research

An answer-free `sys.setprofile` collector over the 57 executable pinned queries
found the exact changed owner for `yrbp`,
`unnest_subqueries.decorrelate`, is reached only by fixture indices
`1, 6, 10, 35, 69, 81`. The exact owners for the current normalize,
isolate-table-selects, eliminate-CTEs, and pushdown-predicates cases are each
reached by all 57 queries.

Six-query replay therefore has real upside for the decorrelate case, but is not
integrated here. A sound implementation must additionally certify that skipped
unchanged queries establish no persistent state consumed by a later retained
query. The current runtime snapshots only the changed module and executor ENV;
that is not a broad enough certificate to justify skipping sequential prefixes.
