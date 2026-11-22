# Pinned-roster docstring breadth proof

This research extends the optimizer-only certificate to three source-derived
lanes while preserving every unknown test:

1. undecorated module-level functions in `sqlglot/**/*.py`, excluding
   `sqlglot/typing/`;
2. module docstrings in the same source boundary; and
3. undecorated methods of the pinned, plain `Generator` class only.

The gate still requires one unchanged source path, a patch no larger than 64
KiB, valid LF-only structure, no encoding/type/formatter directive, and exact
old/new AST equality after normalizing only the admitted docstrings. It rejects
identifier-like strings that CPython may intern. Class docstrings, nested
functions, generic methods, decorated functions, typing modules and all
executable differences remain conservative.

## Roster census

The authenticated roster has 1,620 IDs and digest
`31a019981e19c3d1b18d929066da7e118fcf3d57696a360f7b9d31ce3a87bc89`.
`tests/test_docs.py` has no numbered ID. The only numbered code-object observer
is `tests/test_typing.py::TestTyping::test_no_redundant_expression_metadata`;
its source scan and comparisons are confined to `sqlglot.typing`, which the
gate excludes. The numbered roster and its import closure contain no relevant
`sys.intern`, pydoc/help, source reader, or function/module doc reader. The
unnumbered `tests/test_docs.py` and `tests/leakcheck.py` are explicitly outside
the roster. The only sqlglot `__doc__` access sets class docs in
`expressions/core.py` and cannot observe an admitted module/function/method doc.

The other pinned uses of `inspect` are `signature`, `getfullargspec`,
`getmembers` and `isclass`; none reads docstrings or code constants. No numbered
test observes source line positions, warning line numbers or traceback text.
Consequently changed line tables cannot change a numbered pass/fail result.

## Class-creation boundary

Generic class and method changes are deliberately not admitted. A base,
metaclass, class/function decorator or descriptor can observe metadata while a
class is built. The sole method lane is `sqlglot/generator.py::Generator`, whose
pinned definition has no base, metaclass keyword or class decorator. The
admitted `_replace_line_breaks` method is undecorated; a whole-source census
finds no `__doc__`/reflection reader. Exact AST equality preserves the complete
remaining class body and every subclass.

## Answer-free public economics

Across 709 available patches, the frozen optimizer lane admits four cases
worth 78.369 simulated seconds. The breadth lanes add exactly:

* seven top-level function cases worth 70.016 seconds;
* three module-doc cases worth 110.451 seconds; and
* one censused `Generator` method case worth 27.454 seconds.

The breadth increment is 207.921 seconds; all fifteen doc cases total 286.290
seconds against the frozen selector output. These figures use only patch shape,
the public test durations and the selector output, never an answer file.

Any runtime test absent from the authenticated selector model remains selected.
