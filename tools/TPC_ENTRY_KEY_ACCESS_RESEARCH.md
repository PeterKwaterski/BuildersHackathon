# TPC/schema table-entry key-access certificate

## Verdict: SHIPPABLE NONEMPTY, narrow prospective class

One sound answer-free subset survives: in pinned `tests/helpers.py`, replace
exactly one existing double-quoted string value under exactly one existing
`TPCH_SCHEMA` or `TPCDS_SCHEMA` table/column path, without changing any key,
order, container shape, binding, formatting or other byte. Select every
`TestExecutor` method plus the matching `TestOptimizer.test_tpch` or
`test_tpcds`: **61 tests, 25.454 packed seconds**.

The pinned source exposes 486 eligible literal sites: 61 columns across eight
TPCH tables and 425 columns across 24 TPCDS tables.

The current candidate and current zero-reader model both fall back to all
1,620 tests / 36.817s for this patch class. The exact gross marginal is therefore
**11.363s per applicable patch** beyond both current mechanisms. This branch is
default-off and disconnected. It does not change candidate/main, use answers,
run Docker, push or submit.

## Exact prospective patch language

`tpc_entry_key_access.py` admits a patch only when all of these hold:

1. path is exactly `tests/helpers.py` and the original bytes match SHA-256
   `c0dc285fccd1b8bee4a451f5962118fe771de005843b56e3af4c7136f74c3ed3`;
2. both files parse, with unique module-level `TPCH_SCHEMA` and `TPCDS_SCHEMA`
   dictionary assignments at the same module-body ordinals;
3. all nested dictionaries retain the exact literal string keys, order,
   uniqueness and shape;
4. exactly one leaf differs, at path `(table, column)`, and old/new are each a
   single ordinary double-quoted string literal;
5. replacing that one token is byte-for-byte sufficient to produce the new
   file, and replacing the changed schema statement in the AST makes the two
   complete modules identical; and
6. the 1,620 ordered manifest IDs match digest
   `31a019981e19c3d1b18d929066da7e118fcf3d57696a360f7b9d31ce3a87bc89`
   and contain exactly the 60 expected executor methods and one matching
   optimizer method.

This deliberately rejects two leaf changes, table/column key changes, key
reordering, add/delete, dict unpacking, duplicate keys, list/tuple/other shape
changes, aliases, calls, f-strings, concatenated strings, alternate quote forms,
comments, imports, reassignment, class/global observers, persistent mutations,
CRLF and any source/manifest drift. A syntactically valid prospective patch
cannot introduce an additional read, write, import or side effect because the
entire changed byte string must equal one literal-token substitution.

## Complete pinned reader closure

`tpc_entry_reader_provenance.json.gz` is rebuilt from the complete pinned
`sqlglot/**/*.py` and `tests/**/*.py` graph. Its compressed SHA-256 is
`2c336f8dd94a2788e84b1e4d5261d57692decae7e3bbc24333e0b52ec1ef7e9d`;
its signed-profile SHA-256 is
`764d50b84c970aeac683fe7a33509c9ee8bce4be3800c19eec7ca2f64b646ec5`.
It binds the pinned revision, compressed selector-model digest, manifest digest,
three source digests, collected-file list, all definition/import/name/attribute/
string events, exact owners and fixture-model provenance.
Those bindings are revision
`eb11aec4be8cb2122afe713a4816662c3f0fb2fa`, selector-model SHA-256
`d61c504e9a4a1006217e6702e1c6f05c04846b3dd5a09ec5572523fd8b2cb382`,
and the manifest digest stated above.

The complete graph has these relevant observations:

- `tests/test_executor.py` imports both objects. `TestExecutor.setUpClass`
  iterates both with `.items()` and uses every table name, column key and type
  value to create DuckDB views and in-memory tables. This wildcard/class-setup
  observer widens either edit to all 60 methods. The two `_mp_execute` calls and
  spawned-process serialization are already inside that class-wide owner set.
- `tests/test_optimizer.py` imports both objects and passes each complete mapping
  to exactly one corresponding fixture method. Mapping construction/iteration
  is treated as wildcard, so the matching method is always selected; no query-
  or key-level narrowing is claimed.
- `tests/gen_fixtures.py` defines distinct local objects with the same names. It
  is absent from the 58 collected manifest files and no pinned module imports
  it. Its two top-level loads therefore do not alias `tests.helpers`.
- There are no `tests.helpers` star/module imports, schema-name attributes,
  schema-name string/reflection references or other loads in the complete graph.
  Direct `from` binding itself evaluates only the already-safe literal object;
  no value can affect import/collection.

Wildcard iteration, `.items()`, `.values()`, `.keys()`, `len`, copy,
serialization, reflection, class/setup and persistent-state readers are never
treated as key-specific. Any such reachable observer is a wildcard owner. Here,
executor setup and optimizer mapping consumption are the two wildcard closures;
the certificate includes them rather than omitting them. Any future reader makes
the pinned source/profile digests fail closed.

## Fixture and model provenance

The selector fixture model independently maps:

- `optimizer/tpc-h/tpc-h.sql` to executor `test_agg_order`, executor
  `test_execute_tpch`, and optimizer `test_tpch`; and
- `optimizer/tpc-ds/tpc-ds.sql` to executor `test_agg_order`, executor
  `test_execute_tpcds`, and optimizer `test_tpcds`.

The schema owner set is intentionally larger than either three-reader fixture
set because `TestExecutor.setUpClass` consumes every schema entry before every
class method. The current zero-reader artifact contains no `tests/helpers.py`
entry, correctly reflecting that these dictionaries have wildcard consumers.
The new certificate is not a zero-reader claim; it is a complete-owner claim.

Pinned source digests are:

- `tests/helpers.py`:
  `c0dc285fccd1b8bee4a451f5962118fe771de005843b56e3af4c7136f74c3ed3`
- `tests/test_executor.py`:
  `270a844a7b0b84045efde017135e6208ca07d7d93eba395be17c20c6e918923d`
- `tests/test_optimizer.py`:
  `35c02d71cacfa5d8e24319ef245963da3c1151b891281bac1864a00fa183cbf7`

## Economics, overlap and public applicability

The public longest-first packer puts either 61-owner set on two workers at
25.454s, versus 36.817s for candidate global selection. This is an 11.363s
gross saving. It has no overlap with the zero-reader dictionary lane because
that artifact has no helpers entry, and no overlap with fixture-path handling
because the changed path is Python source rather than a fixture. It is additive
to the binary-fixture certificate but cannot fire on the same changed section.

Across 30 sample patches plus all 683 public val1–14 patches, no patch mentions
`tests/helpers.py`, `TPCH_SCHEMA` or `TPCDS_SCHEMA`. Exact answer-free public
applicability is therefore **0 / 713 patches, 0.000s public marginal**. The
opportunity is hidden/practice-facing. Public leaderboard evidence describing
an entry-key mechanism motivated the audit only; no competitor implementation,
artifact or answer data was used.

## Adversarial validation

Seven focused tests cover TPCH/TPCDS acceptance and exact 61-owner attribution;
multiple values; key/order/shape/table mutations; aliases/calls/f-strings/
unpacks/duplicates; comments/imports/reassignment/class/persistent side effects;
and path/source/manifest/default-off tampering. `py_compile` and
`git diff --check` pass. The provenance builder is deterministic and
answer-free.
