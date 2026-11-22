# Binary and copy patch classifier research

## Verdict: NONEMPTY for exact in-place binary fixtures; EMPTY for copies

A narrow sound subset survives: one or more existing, same-path, same-mode
binary replacements whose exact pinned blob preimages and complete fixture
reader sets are authenticated. Arbitrary non-code assets, copies, additions,
deletions, moves, renames and mode changes remain global.

This branch is research-only and default-off. It used the pinned SQLGlot tree,
Kashimo's own models, public patch text and the public test manifest. It did not
inspect answers, run Docker, change candidate/main, push or submit. Flare
`fcadd4f` was inspected only for its public commit-message behavior/evidence;
no implementation or artifact was copied.

## Why b8ae selects everything

The candidate parser recognizes textual `---`/`+++` paths and rename headers,
but not binary or copy metadata. A section containing `GIT binary patch` or
`Binary files ... differ` therefore has unresolved old/new paths, and
`selected_indices` conservatively selects all 1,620 tests. A pure copy is also
misread as an unresolved rename/addition and becomes global.

## Complete Git-shape disposition

| Shape | Result | Reason |
|---|---|---|
| Existing same-path `GIT binary patch` | Admit only exact pinned fixture preimage, regular `100644`, authenticated reader set | Content is observable only by complete fixture owners |
| Existing same-path `Binary files ... differ` | Same narrow admission | Both marker paths, diff paths and full index must agree |
| Binary addition/deletion | Global | Namespace and directory-name observation not closed |
| Pure copy (`copy from` / `copy to`) | Global | Source remains; destination is an addition, not a rename |
| Copy with edits/dissimilarity | Global | Addition plus untrusted content |
| Rename/move | Global under this proof | Source disappearance and destination appearance must both be modeled |
| Mode-only or executable-bit change | Global | `stat`, access and subprocess behavior are not fixture-content reads |
| Symlink `120000` | Global | Target resolution can redirect arbitrary observations |
| Gitlink `160000`, native artifact, package/config/plugin path | Global | Collection/import/distribution/native effects |
| Mixed binary/text or multiple uncertain sections | Global | Every section must certify independently |
| Quoted, spaced, backslash, absolute, traversal or malformed path | Global | Parser identity is uncertain |
| Unknown fixture or non-code image/document | Global | No authenticated complete reader/listing proof |

Code, package, test-code, configuration, distribution, pytest/plugin and native
paths are never admitted by this certificate, regardless of extension.

## Reader proof

The accepted path must exist in the pinned Git tree, match its full 40-hex blob
preimage, live below `tests/fixtures/`, be non-Python, and have an exact reader
set in `selector_model.x`. The model is bound to revision
`eb11aec4be8cb2122afe713a4816662c3f0fb2fa`, 1,620 manifest IDs and test-ID
digest `31a019981e19c3d1b18d929066da7e118fcf3d57696a360f7b9d31ce3a87bc89`.
The compressed selector-model SHA-256 is
`d61c504e9a4a1006217e6702e1c6f05c04846b3dd5a09ec5572523fd8b2cb382`.
The independently rebuilt 62-path preimage/size artifact is
`fixture_binary_preimages.json.gz`, compressed SHA-256
`10a70ad881f5b273b3277bd0cca553fcf6996485211c3b7544429c2e06d9bd5f`
and signed-profile SHA-256
`aaf46b0238b7640e16f92f88ccbe391d3b206e0054f80835ef0d1f8c827bf2b0`.
It is reproduced by `tools/build_fixture_binary_preimages.py` from the pinned
tree and selector model and stores full Git blob IDs and exact byte sizes.

Pinned source/test filesystem consumers are limited to:

- `tests.helpers` opening explicitly named fixture paths;
- `TestExecutor.setUpClass` constructing every TPC table filename from the
  schemas and opening it;
- `TestJsonpath.test_cts_file` opening its exact JSON fixture;
- test-local temporary/sqlglotc outputs; and
- package enumeration confined to `sqlglot.__path__` or `sqlglot.typing`.

There is no fixture-directory listing in the collected suite. Nevertheless,
unknown paths remain global because the committed artifact authenticates known
fixture reads, not every arbitrary filesystem/name observer.

TPC CSVs require an extra owner expansion. Any table replacement can fail
`TestExecutor.setUpClass`, so all 60 `TestExecutor` methods are selected, not
just the three entries in the ordinary fixture map. The result is 61 tests:
the complete executor class plus the mapped optimizer TPC parent. This closes
setup-error attribution and deliberately overselects an optimizer parent that
does not open the CSV.

## Exact economics and applicability

Using the public manifest and candidate packer:

| Case | Before | After | Gross saving |
|---|---:|---:|---:|
| Existing TPC CSV binary replacement | 36.817s / all 1,620 | 25.454s / 61 | **11.363s** |
| Existing `tests/fixtures/jsonpath/cts.json` binary replacement | 36.817s | 2.089s / 1 | **34.728s** |

Exact per-path owners, IDs, packed costs and savings for all 62 authenticated
fixtures are in `fixture_binary_economics.json.gz` (compressed SHA-256
`8568ad78dd4051e7d0d4ae78992a278dc2f03c918d1521b571b40af16a125290`,
profile SHA-256
`89b2222edf94a60402adbc39cc0ab996f988614d4476fea453a1a75404ccd7a7`).
It is answer-free and reproduced by `tools/build_fixture_binary_economics.py`.

| Fixture class | Paths | Owners/path | Packed/path | Saving/path |
|---|---:|---:|---:|---:|
| TPC-DS/TPC-H table `.csv.gz` | 32 | 61 | 25.454s | 11.363s |
| TPC-DS suite SQL | 1 | 3 | 25.454s | 11.363s |
| TPC-H suite SQL | 1 | 3 | 7.582s | 29.235s |
| `identity.sql` | 1 | 2 | 2.835s | 33.982s |
| Exact single-owner fixture | 27 | 1 | 2.003–3.963s | 32.854–34.814s |

Across the 30 sample patches and 683 public val1–14 patches there are exactly
zero `GIT binary patch`, `Binary files ... differ`, `copy from`, or `copy to`
sections. Answer-free public applicability and packed marginal are therefore
**0 patches / 0.000 seconds**. The opportunity is hidden/practice-facing.

The public Flare evidence reports the expected class-level consequence for a
TPC binary table replacement. This independently derived certificate reaches
the same conservative executor-class boundary from pinned source and
Kashimo's fixture model.

## Audit of the separate exact `sqlglot.png` prototype

The pinned root image blob is
`63b11bfe0dc088ef89c2b72c3d4fec78cf53eca0`. A read-only audit found no pinned
source/test open, stat, resource, root-directory-listing or package-data path to
it. `pkgutil` walks only package directories; README references are not rendered
by a collected test. Exact-preimage, same-path, unchanged-`100644` content
replacement is therefore inert.

Parser hardening implemented in this isolated prototype:

1. bind both `Binary files` marker paths to the diff paths;
2. decode Git base85, enforce line sizes/alphabet, inflate both zlib streams,
   bind declared lengths, validate delta instructions and cross-check
   forward/reverse old/new sizes;
3. reject a second index or structural header after the marker; and
4. continue requiring one marker, full preimage, changed new blob, no hunks,
   no CRLF/no-newline marker and no copy/rename/mode metadata.

## Stacking theorem

Independently certified existing in-place replacements may stack by unioning
their reader sets. An inert `sqlglot.png` section contributes no owners and can
stack with a certified fixture section. Every section must validate; one
unknown section falls back through the ordinary global logic. The per-section
parser accepts exactly one section. `fixture_binary_union` accepts a nonempty
list only when every member certifies, rejects duplicate paths and unions the
reader sets.

Copy/add/delete/move cannot yet stack safely. A copy leaves its source intact
and adds the destination name; without a complete destination-directory and
package/config discovery certificate, even apparently inert images/documents
remain global.

## Prototype and adversarial validation

`binary_copy_patch.py` is default-off and disconnected from `selector.py`. It
requires exact full blob preimage, changed new blob, regular mode, same normalized
path, one binary marker, no textual/structural metadata, pinned-path membership,
model identity and valid reader indices. Literal chunks additionally bind
their actual Git blob hashes to the index line; delta chunks are structurally
validated and size-bound in both directions.

Sixteen focused tests cover both binary encodings, base85/zlib/literal/delta
malformation, complete TPC expansion, safe union and duplicate rejection,
copy/rename/add/delete/move/mode attacks, symlink/gitlink/text/mixed sections,
quoted/traversal/absolute/backslash/marker-path mismatches, unknown assets,
preimage/new-blob/payload/mode/profile tampering, model corruption and the
default-off kill switch. `py_compile` and `git diff --check` pass.
