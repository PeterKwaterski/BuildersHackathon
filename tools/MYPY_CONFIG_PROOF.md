# Isolated mypy configuration proof

## Boundary

The proof recognizes one canonical existing-file text patch to the pinned
repository's top-level `setup.cfg`.  It reads that exact regular, non-symlink
file below `/app/sqlglot-pinned` and requires SHA-256
`399372875088fb648f820f409d715aa28219d1886fba957dfc2848ecc5631942`.
The canonical patch envelope is reapplied against those bytes; context or line
coordinate mismatches reject.  Both source and result are limited to 16 KiB.

The prospective file must parse with strict, non-interpolating
`ConfigParser`, have no defaults, and contain only nonempty sections named
`mypy` or `mypy-<pattern>`.  A second independent lexical gate admits only
exact ASCII section headers and simple scalar option assignments, eliminating
cross-parser interpretations of indented or continuation text.  A `pytest`, `tool:pytest`, packaging, coverage,
tox, default, duplicate, malformed, renamed, multi-file, mode, binary, or
symlink shape therefore falls through to the ordinary selector.

Pytest only treats `setup.cfg` as test configuration when it contains its
dedicated pytest section.  Setuptools ignores the mypy-owned sections.  The
exact numbered test sources contain no `setup.cfg`, config-file, or mypy CLI
reader.  Their only ordinary subprocess runs a fixed `python -c` dialect
import; the remaining process boundaries are fixed optimizer/executor worker
functions.  `tests/test_sqlglotc.py` changes to a fresh temporary directory
before creating its `Distribution`, and its patched `setuptools.setup` reads
`sqlglotc/setup.py`, not the repository config.

Admission additionally authenticates the complete pinned source and risky-call
census already used by the module/fixture proofs: source digest
`b7f798c9e8015db63d6e160ab73f59828e445cef8739cfb383aba44d5de5f5f0`,
inventory digest
`b30749cd488217746916b61c0eb138d46ab9f3543b32e0dbbd4688c0ac9ee12b`,
and complete profile digest
`1b24ab53483bb1932d8139b80fa17e797a1974ee3078157a110c0f25b28f4e10`.
This binds the 363 pinned Python sources, every source/directory/subprocess
escape site, pinned SQLGlot `eb11aec4be8cb2122afe713a4816662c3f0fb2fa`,
and the exact 1,620-test roster.  No patch identity or expected outcome is
used.

## Public economics and validation

The answer-free public census admits `val5/edp9` and `val5/mtyb`, which are
byte-identical toggles of `disallow_untyped_calls` in `[mypy]`.  Each currently
selects all 1,620 tests at 36.817 seconds; the proof selects none, for 73.634
seconds aggregate gross upside before selector CPU.

The unique mutation passed the exact ordered 1,620-test roster and all 25,440
subtests with zero failures in 246.82 seconds.  Eight focused regressions cover
admission, selector precedence, non-mypy sections, malformed configuration,
ambiguous cross-parser syntax, wrong/multiple paths,
missing/symlink/tampered pinned files, and corrupt source census evidence.  The
complete repository suite is 238 green with ten intentional skips.  The exact
image selects zero tests for both public patches, while the 30-case sample
remains byte-identical at SHA-256
`56db9765528f66a3881ba613b9790996b2229cbe3668624c03868c04c9721ca3`.

Three metered candidate10 runs over the two public cases used 1.208659,
2.309470, and 1.849749 process CPU seconds.  Three proof runs used 2.048518,
1.615354, and 1.629724 seconds.  The median drops by 0.220025 seconds, leaving
73.854 seconds measured net public upside.
