# Prospective TPC plan candidate

Status: **COMPETITION-RISK / not a semantic proof**.

This candidate is derived only from Kashimo's pinned SQLGlot source and passing
baseline execution. It uses no answer file, patch identity, expected hidden
failure, or other team's code.

The runtime gate accepts exactly one token replacement in one ordinary,
undecorated synchronous function body below `sqlglot/optimizer/`. Ordinary
identifier replacements, `and`/`or`, multi-token edits, imports, inserted
statements, signature changes, new/deleted files, mixed patches, syntax errors,
and edits outside the function body fail closed. The existing compiled-binding
gate must also remain equal.

For an economically useful static selection, the verifier creates a complete
symlink overlay, applies the patch, and starts one fresh spawn worker. It parses
and optimizes the 57 executable TPC-DS queries in fixture order with
`leave_tables_isolated=True`. Every prospective expression must have the same
canonical serde graph as the deterministic Python 3.13 baseline profile. The
changed optimizer module and `executor.env.ENV` are fingerprinted before and
after every query; persistent state changes fail closed. Optimizer test
removals are disabled. The TPC-H executor test is removable only because every
pinned TPC-H row omits the `execute` flag, so its worker returns before calling
the optimizer.

The selector measures complete child-tree CPU with `RUSAGE_CHILDREN`, permits
at most three attempts and 42 CPU seconds per batch, and removes tests only
when the realized packed-plan reduction exceeds 1.2 times measured verifier
CPU. Missing files, malformed output, timeout, nonzero exit, profile tamper, or
budget exhaustion retain the original selection.

## Economics

An equal public literal case takes roughly 7 process-tree CPU seconds in the
inner verifier and about 12 seconds including copy/apply/launch accounting.
The TPC-DS target records 21.454 seconds, leaving a best-case net around nine
seconds before packing interactions. A first-query mismatch fails early. The
exact official dynamic pool was also measured: it used 12 processes and
121.182 CPU seconds, so theorem-grade prospective execution is uneconomic.

## Unclosed boundary

Expression equality plus selected Python-visible state is not complete
observational equivalence. A one-token patch may still alter an unmodeled
module/class/native cache, transient state restored before the snapshot, or a
worker-history-dependent channel while returning equal graphs. A false
removal costs 300 seconds. This branch is therefore an explicit empirical-risk
candidate for a practice-board measurement, not a proof-backed final candidate.
