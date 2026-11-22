# Static no-op and unused-new-code research

## Verdict: SHIPPABLE NONEMPTY (new modules only)

The AST-refactor and new-class-member portions are empty for the public corpus.
The isolated-new-module portion is nonempty and remains conservative: it retains
every pinned test that can reach a generic discovery, reflection, filesystem,
dynamic-code, or subprocess channel.

This checkpoint is based exactly on `b8ae9ac5f49c2bf941f9c7023adff81201c12703`.
It is research-only and has not been pushed or submitted.

## Answer-free public economics

The census used `sample/commits` and the public `validation/val1` through
`validation/val14` patch corpora. It did not read any `answers.json` file.

Six public patches satisfy the complete new-module certificate:

| corpus | patch | new path |
|---|---|---|
| val1 | `7m83` | `sqlglot/dialects/newdb.py` |
| val1 | `d9tz` | `sqlglot/utils_extra.py` |
| val1 | `gqj4` | `sqlglot/optimizer/extra_rule.py` |
| val2 | `m3pm` | `sqlglot/optimizer/extra_rule.py` |
| val5 | `c3bv` | `sqlglot/typing/newdb.py` |
| val5 | `rf5d` | `sqlglot/newdb.py` |

Each currently selects all 1,620 tests, packed at 36.817 seconds. The certificate
selects 125 discovery readers, packed at 27.381 seconds. The exact answer-free
gross is therefore 9.436 seconds per patch and **56.616 seconds total**.

The sample30 output is byte-for-byte unchanged from b8: 101 selected tests over
30 patches. None of the sample patches enters the new-module lane.

## AST-refactor and member result

The public same-file Python census found seven patches accepted as equivalent by
the public gooey refactor recognizer (`3pfd`, `593v`, `msua`, `s4id`, `rv83`,
`mnvv`, and `n8m5`, all in val5). Every hit is only whitespace or a comment and
is already handled by Kashimo's existing inert-comment/AST behavior. Incremental
public opportunity is **0 patches / 0.000 seconds**.

No public patch adds only an unused member to an existing production class. The
only added method definitions are inside entirely new test modules. A generic
member theorem is intentionally rejected: metaclasses, `__init_subclass__`,
descriptors, class dictionaries, reflection, serialization, and dynamically
constructed dispatch can observe a member without a literal direct call.

## New-module theorem

Admission requires one and only one diff section which creates one regular
`100644` Python leaf below an already-existing `sqlglot` package directory. The
patch must have exact unquoted `a/` and `b/` paths, exactly one zero-preimage
index, one `/dev/null` old marker, one new marker, one addition-only hunk whose
declared and parsed counts agree, LF framing, and compilable Python source.

The candidate stem must be an ASCII Python identifier which is absent from an
archive-wide word certificate. The archive certificate covers 363 pinned files
and 192,226 original/lower/upper word forms. This rejects every existing import,
fixture, configuration, serialized name, path literal, and direct candidate
reference.

Absence of a literal name is not by itself the proof. The model inventories all
42 generic observation sites in the pinned executable source/test graph:

- dynamic imports and dynamic code;
- package and module reflection;
- directory iteration, globbing, path probes, and source/package-data reads;
- subprocess and process-pool entry points.

The union of every test covering those sites is 125 indices. Those readers are
retained for every admitted module. Files outside the traced executable graph
(benchmarks, setup helpers, documentation tooling) remain covered transitively:
their entry requires one of the retained import/open/subprocess gateways, while
their literal names and bodies are included in the full archive word digest.

Any new ancestor package, test/conftest name, dunder name, existing archive word,
mixed patch, rename/copy, mode edit, binary body, symlink, malformed hunk,
ambiguous framing, artifact mismatch, or invalid source falls back to the normal
global selector behavior.

## Artifact authentication

- pinned SQLGlot commit: `eb11aec4be8cb2122afe713a4816662c3f0fb2fa`
- compressed artifact SHA-256:
  `75d9464b15061483356a8284f369df4888f0c043a6e535ca164c242a0b7f1f56`
- profile digest:
  `1b24ab53483bb1932d8139b80fa17e797a1974ee3078157a110c0f25b28f4e10`
- archive/source manifest digest:
  `b7f798c9e8015db63d6e160ab73f59828e445cef8739cfb383aba44d5de5f5f0`
- risky-site inventory digest:
  `b30749cd488217746916b61c0eb138d46ab9f3543b32e0dbbd4688c0ac9ee12b`

Regeneration produced a byte-identical gzip artifact. Runtime validation checks
the exact key set, pinned/test digests, counts, parent set, inventory entries,
reader bounds, Bloom dimensions, and all three fixed digests before admission.

## Adversarial verification

`python -m unittest discover -s tools -p 'test_*.py' -q` passes all 28 tests.
Focused cases cover:

- mixed/multiple changes and new ancestors;
- symlink/non-regular mode, copy/rename/mode metadata, and duplicate modes;
- forged or missing zero-preimage index and duplicate path markers;
- quoted paths, CRLF, no-final-newline markers, malformed counts, and trailing
  unparsed payload;
- archive-name collisions, pytest/conftest names, syntax errors, and model
  tampering;
- computed and aliased import/list/open/eval/subprocess channels;
- enabled, disabled, missing-artifact, and invalid-artifact fallback behavior.

The public gooey checkpoint is unscored, so this document claims only a
source-derived prospective saving, not leaderboard validation.
