# Per-rule TPC replay audit

Status: **COLLECT-READY, NO-SHIP**.  This branch is research-only and makes no
selection change.  `selector.py` does not import the new module, no profile is
shipped, and `BR_TPC_RULE_REPLAY` defaults off.

## Public opportunity

Kashimo's five economic public TPC-DS selections reduce to three optimizer
boundaries:

| patch | changed owner | top-level rule | packed delta |
| --- | --- | --- | ---: |
| `val1/sfj3` | `qualify_columns._convert_columns_to_dots` | `qualify` | 13.006 s |
| `val2/nn8s` | `isolate_table_selects.isolate_table_selects` | `qualify` | 18.799 s |
| `val2/appd` | `unnest_subqueries.decorrelate` | `unnest_subqueries` | 18.627 s |
| `val4/yrbp` | `unnest_subqueries.decorrelate` | `unnest_subqueries` | 18.627 s |
| `val6/46cx` | `unnest_subqueries.decorrelate` | `unnest_subqueries` | 18.355 s |

The first two owners are helpers below `qualify`; the other three are below
`unnest_subqueries`.  A rule-boundary collector therefore has a much smaller
behavioral search space than a whole-test fingerprint, without adopting the
leader's sparse-query architecture.

## Exact evidence contract

`tpc_rule_replay.py` pins the exact fourteen-rule order from SQLGlot
`eb11aec4be8cb2122afe713a4816662c3f0fb2fa`.  Each boundary hashes the serde
graph, root class, and rendered SQL.  A future authenticated profile must have
one unique input/output row for every rule, query, target, and fresh-forward,
fresh-reverse, and warm-forward history.  It also binds
the SQLGlot tree, tests, fixtures, lock file, collector, owner source and call
graph.  Unknown fields, missing rows, duplicate rows, bad hashes, rule-order
changes, and malformed economics fail closed.

The serde graph binds node classes and ordered argument edges, including
serialized comments, types and metadata.  Parent/argument/index links are
derived by a successful pinned round trip.  A production collector must reject
any boundary that does not round-trip byte-for-byte through the pinned serde.

## What equality can and cannot remove

If a prospective rule output equals its authenticated baseline output, the
remaining optimizer suffix can be reused only after proving that the changed
owner has no effects outside the returned query-local graph.  Rule I/O
equality alone cannot remove parse, parent-to-worker pickle round trips, fresh
imports and initializer work, official persistent-worker predecessor state,
table-reader state, stdout/warnings/exceptions, or native state.

The executable tests contain two decisive counterexamples.  One changed rule
returns an identical expression while incrementing process state later queries
can observe.  Another produces different output only after an earlier query
arms shared state, so isolated direct-reader replay passes while an official
persistent-worker history fails.  Exact output also misses observable stdout.

## Tiers

* **Strong:** exact boundary census plus a transitive source-derived
  state-independence certificate and all spawn obligations closed.  The
  skeleton can form a plan only at this tier, only with the explicit kill
  switch, and only when projected CPU is below packed saving.
* **Competition-risk:** empirical equality across the five histories without a
  complete state theorem.  This has its own `BR_TPC_RULE_REPLAY_RISK` switch,
  plan function, explicit `proof: false` label, retained barrier list, and
  exact prospective-slice comparator.  It cannot be silently promoted to the
  strong tier.

The current complex owners mutate expression/scope structures and call broad
helper graphs.  None has a strong certificate.  The next useful experiment is
to collect exact per-rule CPU and boundary digests for all 99 TPC-DS queries,
then measure a fresh-process prospective `qualify`/`unnest_subqueries`
boundary replay.  This quantifies the competition-risk lane; it does not close
the worker-state proof.

Exact uncontended CPU collection command (JSON stays outside the repository):

```sh
PYTHONPATH=. python tools/benchmark_tpc_rule_boundaries.py \
  --tree /home/silverdisk/BuildersHackathon-tokenizer-poison-source-standalone \
  --repeats 7 > /tmp/tpc-rule-cpu.json
sha256sum tools/benchmark_tpc_rule_boundaries.py /tmp/tpc-rule-cpu.json
```

Adding `--snapshots` measures the deliberately expensive complete boundary
serialization separately.  It should be run after the rule-only collection,
not mixed into the replay economics.

