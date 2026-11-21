# Local annotation identity proof

The pinned `sqlglot` tree contains 613 annotated assignments whose nearest
lexical definition is a function, across 69 files. Of those, 599 have values
and 14 are annotation-only; 513 target names and 100 target attributes. These
sites are a closed Python-language class: unlike module and class annotated
assignments, their annotation expression is neither evaluated nor retained in
`__annotations__`.

`selector.local_annotation_only_edit` admits a patch only when all of the
following hold:

1. It is one well-formed hunk, removes pinned source, and contains no selector
   directive.
2. A changed pinned line overlaps an `AnnAssign.annotation` whose nearest
   module, class, or function ancestor is a function.
3. The patched module parses and the matching AST path is also an `AnnAssign`.
4. Replacing only those two annotation subtrees with the same sentinel makes
   the complete module ASTs identical. This rejects target/value/binding and
   neighboring syntax changes.
5. Recursive compiled-code fingerprints are identical, including bytecode,
   nested code, constants, names, local/cell/free bindings, exception tables,
   line tables, first lines, and every `co_positions()` entry.

Malformed patches, multiple hunks, class/module/parameter annotations, moved
executable source positions, and ambiguous AST paths fall through to the
ordinary dependency selector. `tools/test_local_annotation_proof.py` exercises
all of those boundaries, including nested functions and attribute targets.

Source observation is handled separately. Code-object/reflection owners are
added before the identity proof. A static scan of the pinned source and tests
finds no `inspect.getsource`, `inspect.getsourcelines`, `inspect.findsource`, or
`linecache` reader. The sole test that directly reads `sqlglot` Python source is
`tests/test_typing.py`; its AST reader returns only the parent module named by
an `ImportFrom` statement. Since the normalized full-AST equality permits no
change outside the one local annotation, that result is invariant.

`tests/test_docs.py` would discover docstrings through `doctest.DocTestSuite`,
and `tests/leakcheck.py` reads module documentation, but neither file, a doctest
node, nor leakcheck appears in the pinned `sample/tests.json` manifest. They do
not justify broad docstring elision; definition annotations and docstrings stay
on the conservative path.
