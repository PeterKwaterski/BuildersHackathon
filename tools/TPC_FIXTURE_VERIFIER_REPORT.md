# TPC-DS fixture verifier

This clean-room verifier was developed from Kashimo-owned commit
`06334e825b8950ed35b9093c43536b9c230e3d14` and integrated independently onto
the frozen `59ea2cce19cca6de69a9a41298aef13f5ac1e7e0` candidate. Its runtime substrate and pinned
archive are Peter-authored Kashimo artifacts; no competitor code is present.

The integrated image's existing `/app/sqlglot-pinned` tree was mechanically
compared with all 393 typed manifest entries: roster, file bytes, modes, and
symlink targets matched exactly. The original authenticated tar.xz artifact is
still shipped and digest-checked; no second source extraction is added.

## Admission

The verifier accepts only one regular same-path edit to
`tests/fixtures/optimizer/tpc-ds/tpc-ds.sql`. The exact 99-pair positional
roster must remain intact, at most three pairs may differ, and metadata must be
either empty or exactly `execute: true`.

An expected-output-only change cannot affect `test_execute_tpcds`, which ignores
the expected half of each pair, so it is admitted statically. An input SQL or
metadata change is isolated in an unprivileged child and must satisfy all of:

- the SQL remains the same ordered SQLGlot AST graph except for literal values;
- node, function, and physical table sets remain within the pinned TPC-DS set;
- execution crosses the same `spawn`/pickle boundary as the pinned test;
- Python executor results match the DuckDB reference under pristine, last-row,
  and repeated post-query reader states;
- persistent input table columns, rows, and column ranges remain byte-identical;
- the child exits cleanly under aggregate CPU, wall, address-space, file, and
  descriptor limits, and every descendant is reaped.

The pinned class setup is retained for TPC-DS. Its independent TPC-H schema
loop is temporarily empty because `test_execute_tpcds` never reads the separate
TPC-H connection, tables, fixture list, or cache entries; the module binding is
restored before spawning the executor worker.

The complete source tree, fixture, archive, test roster, Python runtime,
dependency lock, child runtime, and manifest are digest-bound. Any ambiguity,
timeout, warning condition in the verifier, process-observation failure, shape
change, structural edit, or economic shortfall retains the executor test.

## Economics and corpus result

A synthetic valid change of query 1's `LIMIT 100` to `LIMIT 99` changes the
selected plan from 25.454 to 5.596 packed seconds, a 19.858-second gross saving.
Scorer-like one-CPU runs measured roughly 10.6--15.1 verifier CPU-seconds before
the final three-history reduction. Acceptance requires the exact realized
saving to exceed 1.2 times measured verifier CPU.

The sample output remains byte-identical at 253 selected tests. The complete
713-patch public corpus also remains byte-identical at 270,734 selected tests.
Its only fixture-only TPC-DS patch deletes the whole fixture and correctly
fails admission. Thus this mechanism has no demonstrated public admission and
is useful only if hidden patches contain bounded fixture-pair edits.

## Validation

- Exact-image focused suite covers static expected edits, dynamic literal edits,
  metadata removal, AST-shape attacks, four-pair overflow, structural edits,
  artifact tampering, spawned execution, and DuckDB equality.
- The pinned baseline is covered by the previously authenticated full-suite
  result (1,620 passed, one skipped, 25,440 subtests). The final focused image
  additionally executes changed query 1 through both spawned Python execution
  and DuckDB; a redundant one-CPU full-test rerun was stopped because the
  pinned test asks `ProcessPoolExecutor` for the host's default worker count,
  creating 180 cgroup-throttled processes rather than reproducing scorer
  economics.
- Sample and 713-patch outputs were compared byte-for-byte to exact 063 output;
  no answers file was read, statted, or hashed.
