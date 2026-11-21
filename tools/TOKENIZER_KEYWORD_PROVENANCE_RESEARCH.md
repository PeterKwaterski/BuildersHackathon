# Tokenizer keyword exact-value provenance

Status: **COLLECTED, REPLAYED, AND INTEGRATED**. The complete normal and
synchronous-worker traces, detached signature, byte-identical A/B/independent
replay models, runtime gate, and isolated selector integration passed final
adversarial review. See `TOKENIZER_KEYWORD_FINAL_AUDIT.md` for exact hashes and
the current SHIP verdict.

Base: `c0d9c9ec508dc9fd5fe666345ea0afca613e821e` at pinned SQLGlot revision
`eb11aec4be8cb2122afe713a4816662c3f0fb2fa`.

## Source-derived inventory

The pinned package contains 41 class assignments named `KEYWORDS` or
`SINGLE_TOKENS`: 29 `KEYWORDS`, 12 `SINGLE_TOKENS`, and 36 dictionary literal
assignments. The literal assignments contain:

- 716 explicit `KEYWORDS` entries whose key is an exact string literal and
  whose value is a direct `TokenType.<member>` attribute;
- 616 distinct keyword strings across those entries;
- zero duplicate explicit keys within an assignment;
- 55 analogous explicit `SINGLE_TOKENS` entries.

The 716 keyword entries span 26 tokenizer owners. The largest owners are base
`Tokenizer` (310), MySQL (70), Postgres (46), ClickHouse (40), DuckDB (37),
Snowflake (33), TSQL (26), StarRocks (25), Teradata (23), and BigQuery (18).
Most dialect dictionaries copy an ancestor with `**...KEYWORDS` and then
override explicit keys. There are also import-time `.copy()` and `.pop()`
operations. A source entry therefore flows into multiple effective dialect
dictionaries unless a descendant overrides or removes it.

## Narrow admissible edit

The first version should accept only one value replacement in one existing
explicit keyword entry:

```python
"literal": TokenType.OLD
```

to:

```python
"literal": TokenType.NEW
```

`OLD` and `NEW` must be distinct, existing members of the exact pinned
`TokenType` enum, reached through the uniquely resolved canonical `TokenType`
binding. The key, dictionary shape and order, containing assignment, file, and
every other AST node must remain identical. Require one file, one hunk, one
entry, and one changed expression.

Do not admit key additions, removals, renames, dictionary unpack changes,
`.pop()` changes, nonliteral keys, computed values, aliases, or edits to
`SINGLE_TOKENS` in version one.

## First-divergence argument

`_TokenizerBase.__init_subclass__` derives `_KEYWORD_TRIE` only from keyword
keys, comments, quotes, format strings, and the set of single-token keys. A
keyword value-only replacement cannot change that trie. Import-time ancestor
unpacking copies the value and descendant overrides/removals may stop its
propagation, but copying does not observe the value semantically.

The effective `KEYWORDS` dictionary is passed unchanged into
`TokenizerCore.keywords`. In the pinned pure-Python core, all semantic value
observations are exact keyed operations: membership followed by subscription,
subscription, or `.get()`. Before the first retrieval of the edited literal
key, baseline and prospective executions are identical. Therefore a test that
never retrieves that key in the baseline cannot be the first divergent test.

The artifact can conservatively union readers by literal key across *every*
dialect and source entry. It does not need to prove which source assignment won
each chain of `**` copies. This deliberately loses precision for the 64 keyword
strings defined in multiple owners, but closes the fragile origin/override
boundary.

Membership events may also be recorded, but changing a value with the key
preserved cannot alter membership. Value retrieval is the required reader.

## Why `SINGLE_TOKENS` is excluded initially

Base `Tokenizer.SINGLE_TOKENS.values()` is consumed at import time to derive
`Parser.RESERVED_TOKENS`. A value replacement can therefore change persistent
parser class state before any runtime tokenizer lookup. Derived single-token
dictionaries also participate in `_KEYWORD_TRIE` key checks. The latter is
unchanged by value-only edits, but the former requires a separate exact
import-state/value-flow proof. Until that derivation and every descendant copy
are certified, all `SINGLE_TOKENS` edits must fall back.

## Required static closure

The builder must reparse every pinned package and test source and fail closed
unless all observations of `KEYWORDS` and `TokenizerCore.keywords` are in this
closed set:

1. exact class-body literal construction;
2. exact ancestor dictionary unpack/copy and explicit override/removal;
3. key-only import-time uses (`HINT_START in KEYWORDS`, iteration of keys for
   `_KEYWORD_TRIE`, and `"(+)" in ...KEYWORDS`);
4. the exact `Tokenizer._init_core` handoff;
5. assignment to the one `TokenizerCore.keywords` slot; and
6. exact internal keyed queries whose key expression is trace-instrumented.

Reject `.values()`, `.items()`, whole-dictionary comparison, truth/length,
representation, serialization, copying outside the canonical import graph,
mutation after class construction, escaped methods, opaque/native calls,
unknown aliases, dynamic class namespace access, `vars`, `dir`, `__dict__`,
`sys.modules`, `getattr`/`setattr`/`delattr`, eval/exec, loader/source/code
inspection, and folded/computed attribute names. Reject any external escape of
`TokenizerCore`, any `_init_core` override, and any whole-core reflection.

The exact dependency lock contains no `sqlglotc` package, and the pinned
`tokenizer_core.py` is Python. The artifact and runtime gate must bind the
requirements lock and core source so a native overlay cannot silently cross
this boundary.

Independent source/code-reflection readers must be unioned before this proof
narrows ordinary execution readers. A keyword edit can be observed as source
text even when no SQL query retrieves that keyword.

## Required dynamic evidence

Instrument key *expressions*, not the dictionary object. Replacing the object
with a subclass changes exact type, C-API, pickling, identity, and dispatch and
is inadmissible. Source rewriting should turn only canonical core operations
into equivalents such as:

```python
self.keywords[_record(key)]
self.keywords.get(_record(key), default)
_record(key) in self.keywords
```

`_record` returns the same exact `str`, preserves evaluation order and query
count, and appends immediately to a PID-specific log. Non-exact-string queries
poison the proof. Any event during module initialization or without a known
test owner poisons that literal key globally.

Collect the complete 1,620-test suite twice under exact Python 3.13:

1. normal executors and real spawned children;
2. the already-audited synchronous-worker rewrite.

Both manifests must prove zero exit status, exact test inventory, exact source
and test digests, implementation digest, child-log accounting, and complete
instrumented-site census. Child processes inherit the parent node ID. Unknown
owners, malformed records, missing children, abrupt teardown ambiguity, or a
site absent from either mode fail closed.

The deterministic model should map each literal keyword string to the union of
reader indices across both modes. It should additionally bind the complete
716-entry source inventory, static-use audit, transfer/core implementation,
trace and manifest digests, selector model, reflection model, and requirements
lock. Build twice from fresh inputs and require byte equality.

## Runtime recognizer

Reconstruct original and prospective source from the patch, verify the exact
pinned source, locate exactly one inventoried entry by path/owner/assignment
span/key/value AST, validate both enum members, replace both RHS nodes with one
sentinel, and require whole-file AST equality. Reject comment directives,
serialization-sensitive paths, malformed hunks, multiple changes, and every
model discrepancy. Return the model's per-key reader set; the existing
reflection selection remains unioned.

## Answer-independent economics

No sample answers were read. Three real-shaped synthetic value replacements
were passed through the current exact container selector:

| source edit | current selected | packed test cost |
| --- | ---: | ---: |
| base `Tokenizer.KEYWORDS["ALL"]` | 1,615 | 102.931 s |
| ClickHouse `KEYWORDS["ATTACH"]` | 145 | 8.342 s |
| Postgres `KEYWORDS["BEGIN"]` | 1,620 | 103.047 s |

These are exposure measurements, not claimed savings. Exact savings cannot be
stated until complete per-key traces exist. Nevertheless, the gap between a
single literal's likely exact query readers and the current file/import cones
is large enough to justify collection after the active overload trace.

The broad static line model is not a substitute: across the 716 explicit
entries its assignment-scope packed cost has median 2.399 s, while base entries
are charged 95.789 s before later selector stages. Real end-to-end behavior can
be broader, as the table shows.

## Adversarial obligations

Tests must include descendant override/removal, duplicate literal strings in
different dialects, inherited base values, import-time dictionary copies,
query-before/after control flow, `.get` defaults, multiword and punctuation
keys, unknown/non-string queries, direct and computed reflection, class
namespace reads, whole-dict iteration/value reads, mutation/restore, aliases,
`_init_core` override, core escape, pickle/copy, source/code inspection,
native overlay, child ownership, missing child logs, trace/model/source tamper,
second edits, key edits, additions/removals, enum alias/shadowing, syntax/import
failure, and malformed patches.

## Implemented disconnected v0

`collect_tokenizer_keyword_values.py` binds the exact 716/616 inventory,
31-read/24-pop static census, 42-class tokenizer lineage, canonical TokenType
bindings, sole core lifecycle, exact alias and four value sites, source/tests/
lock/models/support/instrumented trees, Python distributions and pytest entry
points, module origin, and relevant PID start/log/completion accounting. It
rejects malformed/unknown owners and records import/no-owner retrievals and
non-string queries as poison.

`build_tokenizer_keyword_model.py` requires exact normal and synchronous
manifests (1,620 scored plus the separate skipped node). A literal survives
only when neither complete mode contains any retrieval event for it. Thus no
changed value can be the first divergence or seed module, class, cache, or
persistent-worker state in a later test. Any observed key is excluded; no
downstream closure for observed keys is attempted.

Host audit:

```bash
PYTHONPATH=tools python3 -m unittest tools/test_tokenizer_keyword_values.py -v
```

## Red-team hardening and external trust root

The hardened collector never executes from the ambient checkout. It requires
the entire pinned checkout to be clean, enumerates every tracked blob, symlink,
mode, fixture, and root configuration through `git ls-tree`, and materializes
only `git archive HEAD`. The tracked manifest, archive, materialized tree,
synchronous rewrite, and instrumented tree are all independently bound.

The dedicated image pins its Python base digest and exact Git, OpenSSL, and CA
package versions. Its entrypoint starts from `env -i` with a fixed locale,
timezone, hash seed, safe path, trusted tool path, and trusted module path.
Unknown `GIT_*`, loader, Python, pytest, tracker, or blast-radius variables are
therefore absent. Evidence records exact Git/OpenSSL paths, binaries, versions,
packages, normalized distribution names, entry-point identities, pytest plugin
inventory, interpreter, core origin, and absence of a native overlay.

Every `ProcessPoolExecutor.submit` uses a picklable per-task wrapper. Unique
task identities must appear exactly once at submit-start, submit-end,
task-start, and task-end with the same owner. Unknown sentry names, a submitted
but unstarted task, a displaced wrapper, stale owner, abrupt child, orphan,
empty log, or final-log digest mismatch rejects the run. Each process uses an
exact `pid-positive_time_ns` identity and exact start/log/completion census.

Each mode also emits a canonical raw lifecycle bundle containing the pytest
manifest and all process artifacts. The finalizer hashes and sizes both
bundles, traces, manifests, exact argv, source/tools/dependencies, image ID, and
environment into an unsigned index. A separate reviewer command signs the
canonical index statement with Ed25519. The private key is mode `0600` outside
the repository and is never mounted into the image or output. The builder has
no public-key or trust-path override: it verifies against the tracked public
key and independently replays both raw bundles before accepting summaries.

Current pre-collection gates:

- 21/21 host static, source-isolation, spawn/fork ownership, lifecycle,
  environment, signature, raw-bundle tamper, and repeatability tests pass;
- normal and synchronous-worker targeted collections pass in image
  `sha256:736857c2a387ff1be1d4331e0cfa5d2a0a40b43eb98ce80119868ff280d2bdcb`;
- the targeted unsigned index digest is
  `e38084cb7977060d3eb1caf8f202026fa7cca38e6f2e49d9e2b2387b70899dbc`;
- missing signatures and tampered raw bundles reject;
- two fresh targeted builds are byte-identical at
  `749a2741972882ebec32818476b3fad0426acc93ebf9bcd093c6de96d006f81e`;
- targeted evidence always emits `TARGETED-SMOKE/NO-SHIP` with zero safe keys.

These targeted smokes are not substitutes for either required full trace.

## Exact collection and build commands

Run from this isolated worktree. `SOURCE` must be a standalone, clean checkout;
a linked worktree whose Git common directory is not mounted will not work. The
image entrypoint supplies the exact environment, so do not add `-e`, replace
the entrypoint, or mount the repository over `/work`.

```bash
docker build --pull \
  -f tools/tokenizer_keyword_collector.Dockerfile \
  -t br-tokenizer-keyword-collector:review .
IMAGE_ID="$(docker image inspect --format '{{.Id}}' br-tokenizer-keyword-collector:review)"
OUT="$(mktemp -d /home/silverdisk/tokenizer-keyword-evidence.XXXXXX)"
SOURCE=/home/silverdisk/BuildersHackathon-tokenizer-keyword-source-standalone
SIGNING_KEY=/home/silverdisk/.blast-radius-evidence-review/tokenizer-keyword-ed25519-private.pem

test "$(git -C "$SOURCE" rev-parse HEAD)" = eb11aec4be8cb2122afe713a4816662c3f0fb2fa
test -z "$(git -C "$SOURCE" status --porcelain=v1 --untracked-files=all --ignored=matching)"
test "$(stat -c %a "$SIGNING_KEY")" = 600

docker run --rm --network none --read-only --tmpfs /tmp:rw,exec,nosuid,size=8g \
  -v "$SOURCE:/source:ro" -v "$OUT:/out:rw" "$IMAGE_ID" \
  /work/tools/collect_tokenizer_keyword_values.py \
  --source /source --tests /work/sample/tests.json --image-id "$IMAGE_ID" \
  --output /out/normal.trace.json --manifest /out/normal.manifest.json \
  --bundle /out/normal.bundle.json

docker run --rm --network none --read-only --tmpfs /tmp:rw,exec,nosuid,size=8g \
  -v "$SOURCE:/source:ro" -v "$OUT:/out:rw" "$IMAGE_ID" \
  /work/tools/collect_tokenizer_keyword_values.py \
  --source /source --tests /work/sample/tests.json --image-id "$IMAGE_ID" \
  --synchronous-workers --output /out/sync.trace.json \
  --manifest /out/sync.manifest.json --bundle /out/sync.bundle.json

docker run --rm --network none --read-only --tmpfs /tmp:rw,exec,nosuid,size=1g \
  -v "$OUT:/out:rw" "$IMAGE_ID" \
  /work/tools/finalize_tokenizer_keyword_evidence.py \
  --trace /out/normal.trace.json --trace /out/sync.trace.json \
  --manifest /out/normal.manifest.json --manifest /out/sync.manifest.json \
  --bundle /out/normal.bundle.json --bundle /out/sync.bundle.json \
  --purpose full --output /out/evidence-index.json

python tools/sign_tokenizer_keyword_evidence.py \
  --index "$OUT/evidence-index.json" --private-key "$SIGNING_KEY" \
  --output "$OUT/evidence-index.signature.json"

sha256sum "$OUT"/{normal.trace.json,sync.trace.json,normal.manifest.json,sync.manifest.json,normal.bundle.json,sync.bundle.json,evidence-index.json,evidence-index.signature.json}
```

The reviewer must inspect all artifacts, recompute the image/environment/argv
statement, and invoke the signer only after review. The signer derives its
public key and refuses a key that differs from the tracked review key. Build
twice in the same image:

```bash
for NAME in a b; do
  docker run --rm --network none --read-only --tmpfs /tmp:rw,exec,nosuid,size=4g \
    -v "$SOURCE:/source:ro" -v "$OUT:/out:rw" "$IMAGE_ID" \
    /work/tools/build_tokenizer_keyword_model.py \
    --source /source --tests /work/sample/tests.json \
    --trace /out/normal.trace.json --trace /out/sync.trace.json \
    --manifest /out/normal.manifest.json --manifest /out/sync.manifest.json \
    --bundle /out/normal.bundle.json --bundle /out/sync.bundle.json \
    --evidence-index /out/evidence-index.json \
    --signature /out/evidence-index.signature.json \
    --output "/out/model-$NAME.json.gz"
done
cmp "$OUT/model-a.json.gz" "$OUT/model-b.json.gz"
sha256sum "$OUT/model-a.json.gz" "$OUT/model-b.json.gz"
```

## Verdict and next action

**COLLECT-READY / NO-SHIP.** The narrow KEYWORDS value-only collector/builder
has passed the targeted collection, external-signature, independent raw replay,
and deterministic-build gates. It is ready for independent approval followed
by the two complete exact-image traces. `SINGLE_TOKENS` is not part of this
candidate. Do not wire a selector gate until the full evidence model and
runtime recognizer receive an independent SHIP verdict.
