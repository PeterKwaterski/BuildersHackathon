# Exact import/runtime split certificate

## Opportunity census

An answer-free scan of all 713 public patches found 115 patches whose current
selection includes a conservative import dependency. Removing only broad
empty-context/definition ranges had a 242.291-second aggregate ceiling. The
prototype targets the two highest-value behavioral cases that pass the exact
certificate:

| patch | old packed cost | certified cost | reduction |
| --- | ---: | ---: | ---: |
| `rws4` (`Parser._parse_case`) | 36.817 s | 2.003 s | 34.814 s |
| `gzx8` (`Parser._parse_window`) | 36.817 s | 2.719 s | 34.098 s |

The combined public reduction is 68.912 seconds. The next two nominal cases,
`ejws` and `k5a2`, reject: their exact changed JSONPath lines execute while
numbered test modules import.

## Authenticated import-state evidence

`capture_import_line_profile.py` ran inside the pinned Python 3.13 scorer image.
Before tracing it compared every packaged SQLGlot source against the bundled
authenticated source snapshot. It then imported every module in the exact
1,620-test roster in its own fresh Python process while recording exact parser
line events. This fresh-per-module union is independent of pytest collection
order and conservatively includes each module's complete first-import closure.
The compact
artifact binds the pinned revision, ordered-roster digest, module inventory,
fresh-process mode, and a zero-failure result. It also certifies that numbered
test sources contain neither target-method references nor reflection rooted at
`sqlglot.Parser`. Its compressed bytes have a selector-pinned SHA-256 digest.
The frozen artifact digest is
`7c95117f6c5bee66bf0931a1ee2668367f1d9f937df41066efd07fa7a6fe2a74`.
The capture contains 58 test modules and 3,132 executed `parser.py` lines.

The broad coverage model says both target functions execute during collection,
but the exact profile proves the changed statements do not: parser lines 8467
and 9079 are absent. This is the distinction the old whole-function import
range could not express.

The source gate admits only a one-removed/one-added same-line replacement in
two exact owner paths. Both public parser owners are undecorated methods on
the undecorated, base-less `Parser` class. The changed statement must have an
exact emitted line event and must be absent from the import profile. Compiled
old/new function binding fingerprints must preserve arguments, locals,
variable names, cells, free variables, and flags. Thus the module/class binding
key and alias topology are unchanged. A package-wide AST census over the
authenticated sources requires every `_parse_case` and `_parse_window`
attribute load to be an immediate call and rejects string lookup of either
name. The only differing persistent object is therefore the expected function
code object, with no import-time package or numbered-test reader. The roster's
sole generic code comparison is confined to `sqlglot.typing`.

Because the changed statement is not executed, it cannot mutate Python or
native state, invoke an import hook, access a descriptor, or alter a metaclass
operation during collection. Malformed source, decorators, other owners,
multi-line/multi-statement edits, line shifts, unknown profiles, capture
failures, source/roster/digest mismatches, and changed binding topology all fail
closed. Comment/directive-bearing replacements and replacements containing
code/source-observer tokens (`__code__`, `co_*`, `inspect`, `dis`, `getsource`,
`marshal`, `linecache`, or source-file readers) also reject.

## Post-import readers

The ordinary selector model retains exact changed-line readers from both the
normal process-pool run and the synchronous-pool coverage run. The import split
only suppresses the reverse-importer union; it does not suppress these line
readers or any other dependency family. Tests absent from the authenticated
roster remain selected.

Focused adversarial tests cover both admitted public shapes, an import-executed
statement, a forged executed-line profile, a missing profile, and an
uncensused method owner. Full-mutant cross-product results are recorded at the
research checkpoint before any production recommendation. The fresh `rws4`
run passed all 1,620 tests and 25,440 subtests in the pinned Python 3.13 image
(338.32 seconds test wall time). An earlier run interrupted by a Docker/WSL
failure is explicitly excluded from the evidence. The complete `gzx8` run had
exactly the two retained readers fail (`TestOracle.test_oracle` and
`TestSnowflake.test_snowflake`): 1,618 passed, 2 failed, and 24,724 subtests
passed in 416.16 seconds. No nonselected test failed.
