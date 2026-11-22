# Isolated new SQL-fixture proof

## Boundary

This proof recognizes one fresh regular `100644` file below
`tests/fixtures/` whose final suffix is `.sql`.  The unified diff must be a
single canonical new-file section: `/dev/null`, matching `diff --git` and
marker paths, one zero-old-lines add-only hunk starting at new line one,
exactly one new-file mode and index record, LF-only bytes with a terminal LF,
and no rename, copy, mode-change, binary, symlink, no-newline, second-hunk, or
second-file metadata.  Empty files and payloads larger than 64 KiB reject.
The exact pinned checkout root must exist as a directory, and `os.path.lexists`
must prove the sanitized destination absent below it.  Existing regular files,
directories, symlinks (including broken symlinks), or a missing checkout root
therefore reject before the proof can narrow selection.

The full path, fixture-relative path, basename, and qualified forms without
the `.sql` suffix must be absent from the complete pinned Python source
inventory.  This excludes fixed direct loads and constructed qualified
fixture paths.  Unqualified generic stems are not used as an unsafe exclusion:
every file open and directory-discovery owner is retained instead.

The proof returns all 125 readers from the existing authenticated discovery
artifact.  It therefore retains every numbered owner of the complete pinned
census of source/native opens, `pathlib` `open`/`read_*` and
`glob`/`rglob`/`iterdir`, `glob`, `os.listdir`/`scandir`/`walk`/`fwalk`,
`pkgutil` enumeration, `importlib.resources`, path probes, dynamic code and
imports, and subprocess/process-pool/shell/native escape points.  The pinned
sources contain 42 such sites: 13 source readers, nine dynamic imports, nine
path probes, five subprocess sites, three dynamic-code sites, two directory
enumerators, and one package-reflection site.  The only directory enumerators
present are `pkgutil.walk_packages(sqlglot.__path__)` in `tests/test_docs.py`
and `pkgutil.iter_modules([sqlglot/typing])` in `tests/test_typing.py`; neither
walks `tests/fixtures`.  Direct fixture consumers use exact caller-supplied
paths through `tests/helpers.py`; executor TPC table reads and JSONPath data
also use fixed named paths.  Any uncertainty remains in the retained reader
set.

Admission authenticates the complete census rather than trusting a caller's
reader list.  The source digest is
`b7f798c9e8015db63d6e160ab73f59828e445cef8739cfb383aba44d5de5f5f0`,
the inventory digest is
`b30749cd488217746916b61c0eb138d46ab9f3543b32e0dbbd4688c0ac9ee12b`,
and the complete profile digest is
`1b24ab53483bb1932d8139b80fa17e797a1974ee3078157a110c0f25b28f4e10`.
These bind pinned SQLGlot `eb11aec4be8cb2122afe713a4816662c3f0fb2fa`
and the exact ordered numbered roster.  There is no patch identity or answer
lookup.

## Public economics and validation

The answer-free public patch census admits `n7b7`, `bagi`, `c5ib`, `g39k`,
`iu4j`, `s5kd`, `via8`, and `wftd`.  `c5ib`/`g39k` and `iu4j`/`s5kd` are
byte-identical pairs, leaving six unique transformations.  Each case moves
from the 1,620-test 36.817-second fallback to 125 retained readers packed at
27.381 seconds.  Aggregate gross public upside is 75.488 seconds.

All six unique fixture additions were applied together to the pinned tree and
passed the exact ordered 1,620-test roster plus all 25,440 subtests with zero
failures in 275.98 seconds.  Eight focused tests cover admission, selector
precedence, authenticated-census corruption, name/path collision, path shape,
terminal LF, size, mode/symlink/copy/rename/binary metadata, mismatched paths
and markers, multiple hunks, multiple files, missing source roots, existing
unreferenced files, and broken destination symlinks.  The complete repository
test suite is 222 green with ten intentional skips.

The exact image selects 125 readers for every one of the eight public patches.
Two official-limit sample runs remain byte-identical at SHA-256
`56db9765528f66a3881ba613b9790996b2229cbe3668624c03868c04c9721ca3`.
Three metered repaired-base public runs used 3.305205, 2.956696, and 2.936042
process CPU seconds.  Three proof runs used 1.909333, 2.579793, and 1.775873
seconds.  The median drops by 1.047363 seconds, so measured net public upside
is 76.535 seconds.
