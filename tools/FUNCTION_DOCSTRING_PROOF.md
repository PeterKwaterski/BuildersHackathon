# Optimizer function-docstring certificate

`selector.tpc_function_docstring_only` recognizes a deliberately narrow patch
class: one existing `sqlglot/optimizer/*.py` path whose parsed old and new
modules become identical after replacing only ordinary function docstring
contents with a sentinel. Module and class docstrings, methods, nested
functions, decorated functions, added or removed docstrings, syntax failures,
path changes, file-mode changes, and any executable AST difference are
rejected. Encoding/type-checker/formatter directives, structurally invalid
diffs and non-LF patch payloads are rejected before parsing.
Patches larger than 64 KiB and changed identifier-like docstrings are also
rejected. The latter prevents an otherwise invisible CPython string-intern-table
side effect from becoming observable through future tests.

For this pinned challenge roster, such a patch cannot change a numbered test's
pass/fail outcome:

* The only suite-wide docstring consumer is `tests/test_docs.py`, and none of
  its tests occur in the 1,620-entry numbered roster.
* The only numbered code-object comparison is
  `tests/test_typing.py::TestTyping::test_no_redundant_expression_metadata`.
  It imports and compares functions under `sqlglot.typing`; the certificate is
  restricted to `sqlglot.optimizer`.
* A complete source census finds no other `__doc__`, `doctest`, `pydoc`,
  `inspect.getdoc`, source-reader, or `co_consts` observer in the pinned tests.
* CPython compiles a changed function docstring into metadata and may shift
  later source positions, but the function's executable AST is identical.
  The roster scores pytest status, not traceback text, and contains no source
  position observer for optimizer functions.
* A complete source/test census also finds no `sys.intern` call or string
  literal identity comparison. The certificate nevertheless rejects
  identifier-like changed docstrings, which CPython may intern at compile time.

Therefore the selector emits no modeled numbered tests for an accepted patch;
any test absent from the authenticated model roster remains selected. This is a
structural certificate over the supplied patch and the pinned roster, not a
patch-ID or expected-answer lookup. Any failed proof condition falls back to
the ordinary selector.
