# Runtime directive-comment proof

Status: **SHIP-FOR-EXACT-IMAGE-AUDIT / NO-SHIP**

This isolated source-light prototype narrows comment-only insertions containing
runtime-inert lint, type-checker, coverage, or formatter directives. It does
not enable a general comment/source equivalence rule and does not claim a
submission-ready result. The authoritative repository is unchanged.

## Accepted envelope

The selector considers only an existing pinned Python path and a patch with
one or more added nonempty lines, no removed line, and every nonempty added
line beginning with `#`. Every line must contain one of these directive
families:

- `type: ignore`
- `noqa`
- `pragma`
- `fmt:`
- `pyright`
- `mypy`

PEP 263 `coding:` declarations, ordinary comments, inline comments attached
to executable text, non-Python paths, new files, and all `sqlglot/typing`
paths fail closed. The typing package is excluded because the pinned
`TestTyping.test_no_redundant_expression_metadata` reads every typing source
file directly; that source-observer family is outside the code-reflection
artifact.

For the complete reconstructed file, the gate requires both:

1. identical default Python ASTs without source coordinates; and
2. identical recursive code-object fingerprints over every executable field:
   names, qualified names, arguments, locals, stack size, flags, bytecode,
   constants and nested code, names/variables/free/cell variables, and
   exception tables.

Only `co_firstlineno`, line tables, and instruction positions are omitted.
Those are the deliberate observable boundary. The ordinary selector still
retains scope-coverage owners, while this proof additionally retains every
observed code-object reader in the complete changed file. A missing or invalid
reflection model returns the complete candidate set. Test-file changes also
retain every test collected from that file through the existing test-file
rule.

## Independent adversarial findings and repairs

The first prototype had two fail-closed defects:

- `ast.dump` or recursive fingerprint resource failures occurred outside the
  exception boundary and could terminate the selector instead of retaining
  tests. The complete comparison now catches syntax, value, type, overflow,
  memory, and recursion failures.
- The proof could narrow a class/module comment when the reflection artifact
  was absent, and the range lookup retained only a containing function even
  though an insertion can shift later code objects. The selector now requires
  the validated reflection artifact and retains every observed code reader in
  the file.

The audit also added explicit regressions for Python 3.13 class
`__firstlineno__` effects, the `TypeIgnore` AST difference, encoding and
ordinary-comment rejection, executable inline-comment rejection, resource
failure, later-function code readers, invalid reflection evidence, and the
source-observed typing-package exclusion.

Class-body and module insertions that change Python 3.13's executable
`__firstlineno__` setup are rejected by the code fingerprint. A comment inside
parenthesized syntax is accepted only if the exact whole-file compile proves
that no executable field changes. Future imports, malformed continuations,
exception edges, nested code, class construction, and source-shape changes
therefore fail closed rather than relying on comment spelling alone.

The pinned production package contains no `ast.parse`, source-file open/read,
or inspect-source path over its own Python files. The pinned tests have one
real production-source reader: `tests/test_typing.py` reads
`sqlglot/typing/*.py`, which is why that complete package is excluded. The
other test `read_bytes` sites operate on temporary SQLGlot-C build outputs,
not the prospective production source. The reflection artifact's source audit
rejects untracked frame, traceback, disassembly, inspect-source, native, and
dynamic code-object channels; its exact bundled profile remains hash-pinned by
the production selector.

## Source-light evidence

On host Python 3.14.4 and separately on Python 3.13.15:

```text
tools.test_semantic_noops
tools.test_typing_reflection_outcome
tools.test_selector_ast_index
43/43 passed
```

The focused semantic-noop file alone passes 30/30. Both interpreters pass
`py_compile`; `git diff --check` passes. Exact bundled artifact hashes used by
the audit are:

```text
8891bd314a2d4eab581c1cad979af7fab828cbda254f84dc57dbc73bfd16a200  code_reflection_model.json.gz
d61c504e9a4a1006217e6702e1c6f05c04846b3dd5a09ec5572523fd8b2cb382  selector_model.json.gz
f453c6266c20edcc9ba7127ebedde0bdf45d44633279352c2daafe1fa123da5f  semantic_sources.json.gz
```

An answer-free scan of all 683 public validation patches found 29
comment-directive changes; 19 changes across 18 patches pass the exact Python
3.13.15 source certificate. Comparing selector outputs for those 18 patches
changes all 18, removing 20,872 selections and 375.694 aggregate simulated
seconds across independent per-patch outputs. The stricter pure-add subset is
9 of 88 patches, removing 11,966 selections and 189.553 aggregate seconds.
These are capability measurements only: no validation `answers.json`, failing
test label, or prospective result was inspected.

## Remaining admission gates

Before integration, run the 43 focused checks in the immutable Python 3.13.18
production image, then an independent exact production-image sample A/B.
Require byte-identical output, zero misses, and no material process-tree CPU
regression. Exercise all 19 admitted public source shapes through the packaged
selector and separately confirm that an invalid/tampered reflection artifact
restores global fallback. A final independent combined-stack review must check
precedence with the guard, membership, tokenizer-keyword, code-reflection, and
warm-verifier layers.

Until those gates pass, the verdict remains **SHIP-FOR-EXACT-IMAGE-AUDIT /
NO-SHIP**.
