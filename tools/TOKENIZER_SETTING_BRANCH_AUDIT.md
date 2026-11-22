# Tokenizer setting first-effect certificate

Verdict: **candidate-ready for three exact base boolean flips**.

The certificate admits only `Tokenizer` flips of:

- `DASH_COMMENT_REQUIRES_BOUNDARY` (first effect: `tokenizer_core.py:908`),
- `COMMENTS_TERMINATE_AT_NEWLINE_ONLY` (first effect: line 950), and
- `STRING_ESCAPES_ALLOWED_IN_RAW_STRINGS` (first effect: line 1405).

Every other Tokenizer setting, every subclass edit, non-boolean value, second
edit, path/header anomaly, source mismatch, artifact mismatch, and malformed
profile falls back to the existing selector.

## Proof boundary

The builder pins the complete `tokens.py` and `tokenizer_core.py` bytes. It
proves the unique base assignment and `_TokenizerBase` annotation, the exact
`Tokenizer._init_core` keyword transfer, the unique `TokenizerCore.__init__`
field store, and the complete field-use shape. The two comment booleans are
read directly at their first semantic branches. The raw-string boolean is
copied at line 1325, but that immutable local has exactly one effectful load,
at line 1405; collection may execute the copy without observing the value.

The repository-wide exact-name census permits no attribute observer outside
the three `self.SETTING` handoffs and no string-valued setting name that could
feed `getattr`, native code, or a computed observer. `TokenizerCore` has a
closed lifecycle: construction and `_core` access are confined to
`tokens.py`, and its `self` is never passed, reflected, copied, serialized, or
sent to a native call. The generic reflection sites in the pinned tree were
also inspected: generator dispatch is typed to `Generator`; expression class
enumeration is confined to expression modules/classes; `object_to_dict` has no
call sites; dialect module/class reflection requests unrelated exact keys; and
the one Tokenizer-base `__dict__` check requests only
`BYTE_STRING_ESCAPES`. None can observe these values.

Generic reflection is gated dynamically as well as reviewed statically. The
byte-pinned class-attribute collector rewrites every `.__dict__`, `vars`,
`getattr`, `getmembers`, and related reflection site, including
`exp.convert`'s `value.__dict__.items()` and `object_to_dict`'s
`vars(obj).items()`. Such whole-namespace observation records a `reflect`
event for every literal setting. The complete normal and synchronous traces
for each admitted setting contain exactly `read` and no `reflect` or
`mutation` event; the builder enforces this, and the model pins the collector,
trace, manifest, and builder bytes. Native/computed exact-name access is
separately rejected by the compiled-string and AST census.

The coverage direction is baseline-safe. Before each certified line the old
and new executions have identical state because the setting has had no earlier
effect. At line 908, a changed outcome requires `comment_start == "--"`, so
the baseline necessarily evaluates the setting operand. Line 950 assigns the
negated setting unconditionally on the line-comment path. At line 1405, the
only changed case is a raw string (the `not raw_string` alternative otherwise
makes the group true), so the baseline necessarily evaluates the same
condition before any tokenization state can diverge. Consequently every test
whose outcome can change covers the certified line in the old tree.

Full normal and synchronous-worker class traces are byte-pinned in the model.
Both modes cover the roster, have child-process accounting, contain read-only
events for all three settings, and are exactly mode-identical. Runtime readers
come from the byte-pinned selector line model, built by merging the ordinary
process-pool coverage with its synchronous-pool pass. The latter assigns code
that ran with empty context in a worker back to the numbered test that
submitted the task. Readers are taken at the first-effect lines, not from the
much broader class-assignment read set.

Collection is handled independently. `capture_tokenizer_setting_branches.py`
imports each of the 58 numbered-test modules in a fresh process and also runs
the complete pytest `--collect-only` lifecycle while tracing the three
first-effect lines. All 58 imports and pytest collection succeeded and none
executed any of the branches. A separate diagnostic trace found that the
raw-string field-copy line does execute during dialect test imports, which is
the counterexample that invalidates the older field-load proof and motivates
the stronger first-effect theorem.

The collection document authenticates the normalized collector bytes and the
exact CPython 3.13.18 runtime. The runtime identity includes implementation,
cache tag, `sys.hexversion`, complete version/compiler strings, OS and machine,
the Python executable hash, pytest version, and a digest of the executable plus
the full installed-distribution inventory. The model also pins the collection
document bytes and normalized builder bytes; runtime loading pins all of those
values and fails closed on any mismatch.

## Deliberate exclusions

`NESTED_COMMENTS` is also read by `anonymize.py`, `DROP_UNKNOWN_ESCAPES` by
`generator.py`, and `HINT_START` participates in subclass construction and
keyword/comment maps. The set-valued and heredoc settings have separate shape
and propagation concerns. They are not admitted by this certificate.

## Public economics

Candidate11 selected 1,563 tests and cost 36.817 packed seconds for each exact
public mutant. The new exact selections are:

| Public ID | Setting | Tests | Packed seconds | Saved seconds |
|---|---|---:|---:|---:|
| `9b62` | dash-comment boundary | 75 | 7.206 | 29.611 |
| `3ea4` | CR comment termination | 33 | 2.821 | 33.996 |
| `97ef` | escapes in raw strings | 72 | 7.173 | 29.644 |
| **Total** | | | | **93.251** |

Exact public patches are exercised by the integration test. The public
mutants for nested comments, unknown escapes, and numeric escapes remain on
the broad path. No answer file is read by the collector, builder, runtime, or
tests.

As an independent mutation check, an authenticated runner invoked the exact
ordered 1,620 node IDs from `tests.json` against the pinned baseline and each
of the three public mutants. The baseline collected and executed all 1,620 in
order and passed exactly 25,440 subtests. Public mutant `9b62` produced eight
failing parent tests, all within its 75 readers; `3ea4` produced one, within
its 33 readers; and `97ef` produced one, within its 72 readers. No run had a
missing, unexpected, unmapped, or collection failure. The runner binds the
roster order/digest and complete `tests.json` bytes, pinned Git commit, exact
clean/one-file status, exact baseline/mutant `tokens.py` bytes, exact public
patch bytes, and reverse applicability of that patch. It records every pytest
phase and normalizes subtest reports only by an unambiguous roster-parent
prefix. The four machine-readable result documents are included at repository
root. These runs used only patches and pytest outcomes, never validation
answers.
