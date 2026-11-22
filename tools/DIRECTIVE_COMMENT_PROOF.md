# Runtime-inert directive comment proof

## Verdict

SHIP the narrow standalone `# noqa` / `# type: ignore` proof. The public
patch-only census admits nine changes that the frozen selector currently sends
to all 1,620 tests. Each costs 36.817s before this proof and 0s after it, for a
331.353s aggregate public reduction. The mechanism uses no failure labels or
answer data.

## Runtime gate

The gate accepts only added, standalone comment lines in an existing `.py`
file under `sqlglot/` or `tests/`. Every added line must be exactly `# noqa` or
`# type: ignore`, ignoring indentation, whitespace, and case. It rejects
encoding declarations, directive suffixes, formatter/coverage pragmas,
non-comment edits, paths under `sqlglot/typing/`, and `tests/test_typing.py`.
The full unified diff must apply to the authenticated pinned source.
The envelope additionally requires identical old/new diff and marker paths,
one canonical existing-`100644` index line, exactly one old/new marker, no
new/deleted/mode/copy/rename/symlink/binary/CRLF/no-newline metadata, and
strictly count- and coordinate-consistent add/context hunks. Any structural
ambiguity rejects before source normalization.

Both complete sources are parsed with `type_comments=True`. After discarding
only `Module.type_ignores`, which CPython retains for static-analysis consumers
but does not execute, their complete attribute-free ASTs must match.

The sources are also recursively compiled. The fingerprint compares bytecode,
constants and nested code, argument/binding metadata, names, flags, stack and
local counts, decoded line-table positions, and exception tables. Prospective
line positions and `co_firstlineno` are mapped back through the exact inserted
line coordinates before comparison. This proves the only accepted code-object
difference is the source-line displacement caused by inserting the comment.
Two tempting public cases fail this stricter compiled fingerprint and remain
selected by the pre-existing conservative paths.

## Source and position observers

The authenticated 1,620-test import closure contains no numbered reader of
source positions, line tables, tracebacks, or source text for admitted paths.
The only direct Python-source parse/read is the pinned `tests/test_typing.py`
check, which is confined to `sqlglot/typing`; both that source tree and the test
itself are rejected by the runtime gate. `tests/test_sqlglotc.py` reads only
temporary extension outputs, not the changed Python source. Fixture readers
open SQL/JSON data, and tokenizer references operate on SQL strings rather
than Python source. No linter, type checker, formatter, or coverage collector
runs in the numbered roster.

The evidence is bound to pinned SQLGlot
`eb11aec4be8cb2122afe713a4816662c3f0fb2fa`, ordered-roster digest
`31a019981e19c3d1b18d929066da7e118fcf3d57696a360f7b9d31ce3a87bc89`,
compressed source bundle SHA-256
`f453c6266c20edcc9ba7127ebedde0bdf45d44633279352c2daafe1fa123da5f`,
and decoded source-inventory digest
`b3ef3f210e33f5a57a17669a68a4ac0e1ee2c175283dd5b8004499af318ec029`.
The runtime consumes the already authenticated pinned source bundle; no new
mutable artifact or patch-key table is introduced. Malformed diffs, source
mismatch, parse/compile failures, corrupt line coordinates, or fingerprint
drift all fail closed into the ordinary selector.

This is the same fixed-roster position-observer boundary already used by the
authenticated docstring/comment proofs, but with a smaller directive grammar
and an additional recursive compiled fingerprint.

## Validation

- Nine admitted public patches: `ey6d`, `h2n8`, `wiya`, `a2bc`, `ee6b`,
  `uepk`, `aw9b`, `dpg5`, and `uccw`.
- The combined eleven-patch adversary (including both compiled-fingerprint
  rejects) passed the exact ordered 1,620-test roster and all 25,440 subtests.
- Twelve focused tests cover ordinary-comment compatibility, exact `noqa` and
  type-ignore admission, encoding/formatter/pragma/suffix/typing rejection,
  executable changes, and corrupt line attribution.
- The complete repository suite is 204 green with ten intentional skips, and
  two exact-image sample runs remain
  byte-identical to the frozen candidate output SHA-256 `56db9765…`.
- On the eleven-patch adversarial batch, three metered frozen runs used
  1.964/3.107/3.197 process CPU seconds and three proof runs used
  5.065/5.220/4.088 seconds. The median CPU increment is 1.958s, leaving a
  329.395s net public reduction across the nine admitted patches.

Unknown or unmodeled tests remain selected by the selector's existing roster
mapping. Any proof failure falls through to the ordinary conservative logic.
