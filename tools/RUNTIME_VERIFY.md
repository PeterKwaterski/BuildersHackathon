# Restricted warm verifier

The runtime verifier is a second proof layer after the conservative static
selector. It does not discover candidates: it may only remove an already
selected, inexpensive test after the exact test passes against the complete
patched source tree. It contains no sample commit, prospective replacement,
failure label, or edit-kind-to-test lookup.

## Pinned runtime tree

`vendor/sqlglot-eb11aec.tar.xz` is an archive of the official sqlglot checkout
at `eb11aec4be8cb2122afe713a4816662c3f0fb2fa`, including its tests and fixtures.
The image extracts it to `/opt/sqlglot` and compiles checked-hash bytecode. At
runtime a symlink overlay in `/tmp` initially represents that exact tree. A
prospective patch replaces only its changed source symlinks; restoration is
mandatory after each verifier child.

## Eligibility

`selector.runtime_body_patch_source` requires all of the following:

- one existing `sqlglot/*.py` path and one removed/added source line;
- a valid complete patched module;
- every changed line is executable inside one undecorated function body;
- the compiled argument/local/cell/free-variable layout and code flags match;
- replacing that complete function body with a sentinel makes the old and new
  module ASTs identical; and
- no directive, definition header, docstring, import-time fragment, or
  non-emitting source line is involved.

`runtime_verify.verify_candidates` additionally requires no more than 16
distinct candidates whose recorded duration totals at most 0.5 seconds. It
rejects executor/optimizer process-pool tests. Every test must be an ordinary
`unittest.TestCase` method with no pytest marker, fixture, module hook, or custom
`load_tests` hook.

The warm parent imports `tests.dialects.test_dialect`. A candidate test file is
eligible only when it is that exact module, or when its top-level
`from tests.dialects.test_dialect import Validator` precedes every top-level
sqlglot import. All ten other accepted files in the pinned tree have the
Validator import as their literal first statement. This makes module and
dialect-registry construction order identical to a fresh import. A prospective source module
already present in `sys.modules` is always rejected.

## Isolation and verdicts

The child creates its own process group, redirects stdout and stderr, points
every loaded sqlglot/tests package path at the complete overlay, and imports the
candidate modules normally. Failures, errors, unexpected successes, and failing
subtests retain their parent manifest ID. Setup/class/module errors, incomplete
runs, duplicate or unattributed cases, malformed payloads, nonzero child exits,
and any exception return the original static candidates.

Timeout kills the entire child process group. The parent always reaps the child
and restores every source symlink. A failed restore also returns the original
selection and permanently disables verification for the remainder of the
batch. Each source is registered for rollback before its symlink is removed, so
partial installation failures have the same behavior. The read-only image and
64 MB `/tmp` scorer constraints are used in the exact-image check.

## Validation

The final audited image produced 30 valid output lines and:

```text
selected 99 tests across 30 commits
Simulated: 95.673 s
Misses:    0
```

Synthetic checks cover an ordinary pass, failing subtest attribution,
`setUpClass` failure, malformed IDs, stdout suppression, repeated patched-source
restoration, and a timeout whose test forks a grandchild. The timeout returns
the static candidates and leaves no descendant process. `py_compile`,
`git diff --check`, `make check`, and the exact-image sample must all pass before
integration.
