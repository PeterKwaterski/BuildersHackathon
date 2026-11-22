# Isolated renamed test-module proof

## Boundary

This proof recognizes one canonical, metadata-only, 100%-similarity rename of
an existing numbered `tests/**/test_<identifier>.py` module to the same
directory as `moved_test_<identifier>.py`.  The target does not match pytest's
test-file pattern.  The old path must be a regular, non-symlink file in the
exact pinned checkout and have a nonempty owner set in the authenticated
numbered roster; the target must not lexically exist.  Deletions, content
changes, cross-directory moves, discoverable target names, target collisions,
and any noncanonical Git metadata reject.

The selector retains every numbered node ID owned by the old file.  Those
explicit node IDs fail closed because their requested file no longer exists.
The scorer invokes the numbered node IDs rather than unconstrained discovery,
so the nondiscoverable renamed file is not an additional requested test.

Every other pinned Python source is audited for the old and new filesystem
paths, dotted module names, stems, static imports/from-imports, relative
imports, and exact string constants.  Any inbound reference rejects.  The
proof additionally retains all 125 readers from the authenticated complete
discovery/source/subprocess inventory, covering computed import, directory
enumeration, source open, runpy, reflection, process, and native escape sites.
Admission binds source digest
`b7f798c9e8015db63d6e160ab73f59828e445cef8739cfb383aba44d5de5f5f0`,
inventory digest
`b30749cd488217746916b61c0eb138d46ab9f3543b32e0dbbd4688c0ac9ee12b`,
and profile digest
`1b24ab53483bb1932d8139b80fa17e797a1974ee3078157a110c0f25b28f4e10`.
No patch identity or expected outcome is used.

## Public economics and validation

The answer-free public census admits `val5/tgp9`, `val5/dpcf`, and
`val5/br9s`, renaming the Teradata, RisingWave, and errors test modules.  Their
retained unions contain 153, 127, and 138 tests and pack at 27.437, 27.384,
and 27.381 seconds, respectively, versus 36.817 seconds each.  Aggregate gross
public upside is 28.249 seconds.

All three renames were applied together.  Every one of the other 1,572
numbered tests executed in exact order and passed, along with all 25,160
subtests, with zero failures in 365.54 seconds.  Seven focused regressions
cover rename/deletion distinction, selector precedence, discoverable and
cross-directory targets, existing targets, old/new static references,
missing roster or source files, symlinks, and corrupt census evidence.
The complete repository suite is 245 green with ten intentional skips.  The
exact image emits the expected 153/127/138-test unions, and the 30-case sample
remains byte-identical at SHA-256
`56db9765528f66a3881ba613b9790996b2229cbe3668624c03868c04c9721ca3`.

Three metered candidate11 public runs used 3.792283, 2.831020, and 3.555049
process CPU seconds.  Three optimized proof runs used 2.589671, 3.109293, and
4.119222 seconds.  The median drops by 0.445756 seconds, leaving 28.695
seconds measured net public upside.
