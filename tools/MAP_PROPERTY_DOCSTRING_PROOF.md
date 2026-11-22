# Censused `Map.values` property-docstring certificate

The pinned `sqlglot.expressions.array.Map.values` getter is decorated only by
the canonical built-in `property`. Adding a function docstring changes the
getter's `__doc__`, its code metadata/line table, and the `property.__doc__`
copied by `property(fget)`, but not its executable AST.

The runtime gate accepts only one unchanged
`sqlglot/expressions/array.py` path. It authenticates the exact pinned owner
shape (`class Map(Expression, Func)` with no class keywords/decorators), the
exact `values` method, and its sole `@property` decorator. The old getter must
have no docstring, the new getter must have one non-identifier-like docstring,
and deleting only that new string expression must make the complete old/new
module ASTs identical. Directives, malformed/non-LF patches, path/mode changes,
other methods, and every executable change reject.

`Expression.__init_subclass__` reads the class name, `arg_types`, and the class
docstring; it does not inspect descriptors or getter/property documentation.
The numbered 1,620-test roster and its import closure contain no relevant
`__doc__`, `fget`, pydoc/help, doctest, source-reader, warning-line, traceback,
or code-constant observer. `tests/test_docs.py` is not numbered, and any future
test absent from the authenticated roster remains selected. The only numbered
`co_consts` comparison is confined to `sqlglot.typing`.

The answer-free public case `g6be` currently selects 1,615 modeled tests for a
36.817-second packed cost. This certificate reduces the modeled selection to
empty, a 36.817-second public reduction. Its complete independent all-roster
Python 3.13 validation passed 1,620 tests and 25,440 subtests (407.85 seconds
of test wall time) in the pinned scorer image.
