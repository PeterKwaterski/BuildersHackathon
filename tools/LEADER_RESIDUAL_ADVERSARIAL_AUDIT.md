# Independent residual-proof adversarial audit

Status: **SHIP after the CPU prefilter repair in this audit branch**.

This review compared `964b6083911bc25158c47078b8eb3356e7633a3d`
against its `8fa44ee` base without reading validation answers.  It used only
patch text, the pinned source/test tree, bundled answer-independent models, and
selector outputs.  It did not use Docker, a scorer, a full suite, a push, or a
submission.

## Non-Python directive routing

The original selector applied its special Python-directive fallback before
fixture routing regardless of file type.  Restricting that special case to
`.py` paths is safe: a known non-Python fixture still selects its exact
committed fixture-reader mask, and an unseen `tests/fixtures/**` path still
selects the complete suite.  A Python-suffixed fixture remains on the Python
fail-closed path.  Renames and unknown paths are handled earlier by the path
dependency cone and cannot use this change to bypass an unknown-path fallback.

The three changed public descriptions exercise both a single SQL fixture and
multi-file unions.  The production-plus-two-fixture case still unions all
three independent selections.  This audit added regressions for unseen
non-Python fixtures and Python-suffixed fixtures in addition to the existing
known-fixture `# type: ignore` / `# noqa` cases.

No new directive is treated as inert.  SQL fixture comments remain real file
content and all tests which read those exact paths remain selected.

## Position-preserving formatting

The authoritative proof is fail closed.  It requires:

- an existing `sqlglot/**/*.py` source, excluding tests, serialization code,
  and the source-observed `sqlglot/typing` package;
- replacement-only edits with unchanged physical line count;
- an identical complete token `(type, text)` stream, including comments;
- identical complete ASTs with type comments enabled; and
- identical recursive code fingerprints including bytecode, constants,
  bindings, exception tables, line tables, and every instruction position.

The exact pinned manifest contains no docs or leakcheck node.  A complete
source scan found no `inspect.getsource`, `getsourcelines`, `findsource`,
`linecache`, loader-source/data, traceback-formatting, or `open(__file__)`
reader.  The only direct production Python-source read is
`tests/test_typing.py`, and the proof excludes that entire package.  The three
`test_sqlglotc.py` byte reads target files created in its temporary directory,
not prospective package source.  Ordinary fixture readers are unrelated.

The proof rejects directive/comment-text changes, type comments, encoding
comments, docstrings, executable token changes, changed instruction columns,
line insertions, malformed parses, missing source, and resource exhaustion.
Observed code-object readers remain selected even though the complete code
fingerprint is equal.

## Audit repair: mandatory cheap prefilter

The reviewed commit initially invoked two whole-file tokenizations, AST
parses, compiles, and recursive fingerprints for every ordinary Python
replacement.  On the 30-case sample, the gate ran 35 times, accepted none,
and consumed about 0.168 process CPU seconds.  That overhead was material for
a proof whose validation opportunity is small.

The audit adds a necessary, non-authoritative prefilter: hunks must have
ordinary replacement ordering, and each paired changed line may differ only
in trailing whitespace or whitespace immediately before an unchanged inline
comment.  False positives still face the complete proof; false negatives only
lose an optimization.  This rejects identical-line moves and internal token
spacing before whole-file work.  Both admitted validation shapes pass.  The
same 35 sample calls then consumed about 0.001 CPU seconds.  Across all 753
file changes in the 683-description corpus, only the two ultimately accepted
cases reached tokenization; the complete gate consumed about 0.101 CPU
seconds.  Adversarial tests prove ordinary token changes, internal spacing,
and moved identical lines return before tokenization.

## Verification

- An independent static-selector replay over all 683 public descriptions
  reproduced exactly five changed outputs and no additions: `p2yv`
  1,620→1, `qfxw` 1,620→2, `ys5q` 1,620→3, `mnvv` 37→0, and `msua` 1→0.
  Packed costs reproduced as 36.817→2.395, 36.817→3.411,
  36.817→3.497, 3.360→0, and 2.001→0 respectively.
- 22 focused formatting/directive tests pass.
- 43 existing semantic-noop, typing-reflection, and AST-index tests pass.
- `py_compile` and `git diff --check` pass.
- The integrated source tree and commit metadata remain Peter-only.
- Merging this branch into guard-integration commit `aad8b94` was
  conflict-free.  The combined selector passes 99/99 guard, formatting,
  semantic-noop, typing-reflection, and AST-index tests plus `py_compile` and
  `git diff --check`.

No unresolved safety defect was found after the prefilter repair.  Exact-image
sample and combined guard-stack checks remain integration gates for the parent
candidate, not source-light blockers for this isolated commit.
