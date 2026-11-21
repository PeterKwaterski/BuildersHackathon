# Semantic no-op proof audit

This work was derived from Python semantics and the pinned sqlglot source/test
inventory. It does not use sample answers or patch-kind answer tables. The three
families have independent selector kill switches.

## 1. Function-local binding rename — SHIP (same width only)

`local_binding_rename` accepts only a concrete token stream whose differences
are same-width `NAME` substitutions. Whitespace, comments, directives, strings,
attributes, parameters and every other token remain byte-for-byte fixed. A
complete paired AST walk then permits differences only in `Name.id` and
`ExceptHandler.name`, with identical source positions.

Files under `tests/` are categorically rejected so pytest collection, assertion
rewriting and plugin inspection remain on the selector's ordinary test-file
safety path.

The name relation must be a one-to-one global bijection. Lexical resolution
classifies each occurrence in function, nested function, comprehension and
except-handler scopes. Parameters, module/class bindings, globals, nonlocals,
builtins, unresolved free names and attributes fail closed. Free occurrences
must resolve to a renamed enclosing local binding. Comprehension targets are
handled in their implicit scope, while their first iterable is resolved in the
containing scope.

The proof rejects source-local dynamic observation (`locals`, `vars`, `eval`,
`exec`, dynamic `getattr`/`attrgetter`/`__getattribute__`, frames, tracebacks,
monitoring/tracing, code/source inspection and aliased imports of those APIs)
across the whole module. Dynamic attribute access is intentionally rejected even
when one visible call currently uses a harmless name: the same helper could be
fed the renamed function and a constructed `"__" + "code__"` string. It also
rejects deletes, conditionally initialized
locals, generators, generator expressions and async/coroutine scopes. Those
cases can expose a renamed binding via an unbound-variable message or a public
suspended frame. An except-as name may be used only directly inside its handler;
capturing the automatically-cleared exception cell fails closed.

Finally, old and new modules are compiled and compared recursively. Bytecode,
constants, global/attribute name state (`co_names`), arguments, flags, exception
tables, line tables and every `co_positions()` entry must be identical. Only a
tuple entry in `co_varnames`, `co_freevars` or `co_cellvars` may differ, and only
by an AST-proven pair at the same slot. Parameter slots are compared raw.

An initial audit found and reproduced a computed-string hole in the first
version of this gate: nested `getattr` calls could construct `__code__` and
`co_varnames` without containing either marker as one literal. The hardened
gate rejects the dynamic primitive itself, its module-qualified forms, import
aliases, `operator.attrgetter`, `inspect.getattr_static`/`getmembers`, and public
frame/traceback accessors. The exact counterexample and alias variants are
regressions in `test_computed_and_aliased_reflection_rejected`.

External code/source readers are not dismissed by the local scan. The selector
adds `code_reflection_indices` before applying this no-op proof. The full-suite
reflection collector instruments direct function-code access, rejects unsupported
inspect/dis/source access, and now performs a separate static audit of every
pinned test module for computed dynamic code/frame access. The two unresolved
test-side `getattr` names are proven confined to a schema object and a mock
logger; all other unresolved dynamic attribute names fail collection. Its
bundled model is pinned to the source/test digests. In particular,
`tests/test_typing.py` compares `co_varnames`; its reader
(current test index 1619) is retained. The integration regression
`test_selector_retains_reflection_reader_before_skipping_coverage` proves the
ordering: a modeled reflection reader remains selected while ordinary execution
coverage is dropped.

This certificate is intentionally scoped to the fixed pinned test inventory the
scorer executes, not arbitrary downstream Python callers. The model's source SHA
and complete test-ID digest are runtime-validated. The complete path/range/state/
reader payload is also bound to SHA-256
`f62a0b161fa6d372766d8e290ee6450b368c4deee9bfcfd306f5aa184392298c`;
changing even one reader invalidates the model. An invalid or missing
reflection model makes every function edit select the complete test inventory
before the semantic gate can skip ordinary coverage.

The hardened builder was replayed over both complete normal and synchronous
reflection traces. It audited all 66 pinned test Python files, rebuilt 5,258
function entries (37 observed, 5,221 unobserved), and reproduced the committed
gzip artifact byte-for-byte at SHA-256
`8891bd314a2d4eab581c1cad979af7fab828cbda254f84dc57dbc73bfd16a200`.

Different-width renames remain **NO-SHIP**. They can change later column offsets,
`co_positions()`, formatted tracebacks and source slices even when bytecode is
otherwise equivalent. Retaining known code/source readers is necessary but does
not close every exception/traceback channel, so the current gate deliberately
requires identical token spans.

The final hardened pinned-source census found 1,173 independently synthesized
same-width edits (4,259 changed occurrences across 102 files) that pass the
complete production proof: 1,020 ordinary locals, 152 comprehension locals and
1 except-as local. There are 1,410 binding names that clear the scope,
introspection and definite-binding gates independent of width. Thus 1,173 is a
verified same-width lower bound; the remaining structurally safe names include
compiled slot-order failures as well as the differing-width research envelope.

## 2. External import reorder — NO-SHIP

The recognizer requires one contiguous module-body permutation with the exact
same statement multiset and unique bound names. Relative, star, `__future__`,
`sqlglot`, `tests`, test-file, duplicate-binding and visible import machinery
(`sys.modules`, import hooks, reload/import-module calls) cases are rejected.

That is not a semantic proof: independent external modules can have mutually
visible initialization, warning, registry, logging or import-hook side effects.
No source-only predicate proves those initializers commute. Shipping this family
requires a fresh-process, forward/reverse import-state certificate that also
accounts for import-time test-module effects. Its selector switch remains off.
The pinned source contains only two qualifying runs (five statements, three
adjacent swaps).

## 3. Plain definition reorder — NO-SHIP

The recognizer permits one contiguous permutation in a module/class body with
unique names. Decorators, type parameters, annotations, nonconstant defaults,
bases/metaclasses, test files and direct namespace/source reflection are rejected.
All AST outside the run is fixed.

Even plain function creation changes module/class dictionary insertion order and
code/source line identity. Class namespaces can also be observed during class
construction. A complete namespace-order and source/code reader certificate is
not bundled, so this selector switch remains off.
The pinned source contains only two qualifying class-body runs (five definitions,
three adjacent swaps).

## Reproduction

Run:

```sh
python -m unittest discover -s tools -p 'test_*.py' -v
python tools/measure_semantic_noop_opportunities.py --workers 4
make sample
```

The opportunity script synthesizes fresh names from the pinned source and feeds
every counted same-width edit back through the production proof. Its counts are
source-derived and answer-independent. Import/definition counts are reported
separately and are not enabled by their presence.
