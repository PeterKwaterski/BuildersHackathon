# Isolated new test-module proof

## Boundary

The proof recognizes one newly added top-level `tests/test_<identifier>.py`
file that is absent from both the authenticated source bundle and the exact
numbered-test roster. The scorer invokes the ordered numbered node IDs rather
than pytest discovery, so a fresh, unreferenced test module is never imported
or collected and cannot change an existing numbered test's outcome.

The patch must be a single regular `100644` new file with one exact add-only
hunk, canonical `/dev/null`, index, path and marker metadata, LF source no
larger than 64 KiB, and valid Python. Nested test packages, helpers,
`conftest.py`, package initializers, plugins, existing source/roster paths,
mode/symlink/copy/rename metadata, malformed counts, multiple hunks or files,
and syntax failures reject. The new module stem, dotted module name, and path
must not occur anywhere in the complete pinned source inventory, closing
explicit imports, string lookups, and optional-import branches.

The numbered import closure contains no `pytest_plugins` declaration and no
test-package directory walker. The unnumbered `tests/test_docs.py` walker is
outside the 1,620-node roster and walks only `sqlglot`; the numbered typing
walker is confined to `sqlglot/typing`. The pinned `importlib` consumers target
only sqlglot dialect/optimizer modules, and the sole numbered `runpy` call
executes fixed `sqlglotc/setup.py`. There are no `tests.__path__`, pathlib/glob,
`os.walk`/listdir/scandir, or module-enumeration consumers over `tests/`.
Any runtime test absent from the authenticated selector model remains selected
by the existing unmapped-test fallback.

The proof requires the already authenticated new-module discovery artifact:
source digest `b7f798c9e8015db63d6e160ab73f59828e445cef8739cfb383aba44d5de5f5f0`,
inventory digest `b30749cd488217746916b61c0eb138d46ab9f3543b32e0dbbd4688c0ac9ee12b`,
and profile digest `1b24ab53483bb1932d8139b80fa17e797a1974ee3078157a110c0f25b28f4e10`.
Those bind pinned SQLGlot
`eb11aec4be8cb2122afe713a4816662c3f0fb2fa`, ordered-roster digest
`31a019981e19c3d1b18d929066da7e118fcf3d57696a360f7b9d31ce3a87bc89`,
and the complete discovery/source-reader census. No patch identity, expected
failure, or new mutable artifact is used.

## Public economics and validation

The public patch-only census admits `qd3d`, `w8gd`, and `wer5`. `qd3d` and
`w8gd` are byte-identical transformations. The frozen selector sends each to
all 1,620 tests at 36.817s; the proof emits no modeled test, for 110.451s
aggregate gross upside before selector CPU.

The two unique transformations were applied together and passed the exact
ordered 1,620-test roster plus all 25,440 subtests with zero failures. Focused
tests cover admission, selector precedence, top-level path/name/source/roster
collisions, discovery-evidence corruption, plugin content, mode/symlink/copy/
rename metadata, multiple hunks/files, size and syntax failure. Malformed or
ambiguous input always falls through to the ordinary selector.

The complete combined repository suite is 211 green with ten intentional
skips. Two official-limit sample runs remain byte-identical at SHA-256
`56db9765…`, and the three-case public image run emits zero modeled tests.
Three metered repaired-base runs used 0.535/1.302/1.769 process CPU seconds;
three proof runs used 1.318/1.275/1.786 seconds. The median increment is 0.016s,
leaving 110.435s measured net public upside.
