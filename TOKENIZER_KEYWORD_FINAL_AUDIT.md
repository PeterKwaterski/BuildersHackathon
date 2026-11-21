# Tokenizer keyword final audit

## Verdict

**SHIP** the isolated integration candidate for review and commit. The proof artifact, runtime gate, and selector wiring are fail-closed under the exact pinned inputs. This verdict is limited to the tokenizer-keyword feature and the light-test stage requested for this audit; no full scorer or full Docker build was run.

The candidate is an uncommitted worktree based on `862545f3e65e1c791bba8c98ec25499c6956d008` at:

`/home/silverdisk/BuildersHackathon-tokenizer-final`

## Inputs audited

- Provenance source commit: `057a0b245d7409fc656b76215f4548092633e8cf`
- Disconnected runtime gate commit: `e63013d5fa7d408255e75f998487949b833bd872`
- Full evidence directory: `/home/silverdisk/BuildersHackathon-tokenizer-keyword-evidence-full`
- Exact compressed model SHA-256: `28a5241f3d8006f075f283ac8e59f46793be482457bece67de97a4ecdd3db230`
- Exact semantic source archive SHA-256: `f453c6266c20edcc9ba7127ebedde0bdf45d44633279352c2daafe1fa123da5f`
- Pinned sqlglot source: `eb11aec4be8cb2122afe713a4816662c3f0fb2fa`
- Pinned test census: 1,620 tests, digest `31a019981e19c3d1b18d929066da7e118fcf3d57696a360f7b9d31ce3a87bc89`
- Pinned collector image: `sha256:736857c2a387ff1be1d4331e0cfa5d2a0a40b43eb98ce80119868ff280d2bdcb`

## Independent artifact checks

The detached Ed25519 signature verified against the tracked public key whose SHA-256 is `f0f956bbebd967a450e025fb1c18a52562ac123554024770d84e28a2d125b4c4`. The signed index is schema 1, purpose `full`, and binds both collection modes, the exact image, environment, collection argv, source, tests, collector, builder, finalizer, support modules, static census, operation census, raw bundles, traces, and manifests.

The full builder was replayed independently in the exact pinned collector image with no network and read-only source/evidence mounts. It replayed both raw bundles and emitted a third model byte-identical to model A and model B:

```text
READY-FOR-AUDIT/NO-SHIP: 54 zero-retrieval keys / 616
model-c SHA-256 28a5241f3d8006f075f283ac8e59f46793be482457bece67de97a4ecdd3db230
cmp model-c model-a: identical
```

Normal and synchronous-worker event maps are exactly equal: 8,275 queried keys, 34,117 attributed retrievals, canonical event-map digest `bfe44c58880c57ec7413d02d045a48f3871f83afff615ba365da60843fe032c6`. Neither mode contains any of the 54 safe keys. Model state counts independently agree:

- Rows: 613 observed, 49 poison, 54 safe-zero (716 total)
- Distinct keys: 516 observed, 46 poison, 54 safe-zero (616 total)
- `global_poison`: false

The runtime rejects altered status/version/count/test digest, builder digest, inventory, row contents, safe-key list, static digest/hazards, operations digest, evidence purpose, image ID, process census, Python environment, model hash, source hash, malformed gzip/JSON, and wrong source/binding/enum state. The signed model status remains exactly `READY-FOR-AUDIT/NO-SHIP`; integration upgrades the shipping decision without rewriting the signed payload, and the runtime accepts only that exact status plus the exact model SHA pinned by `selector.py`.

## Safe-key census

The independently confirmed 54 keys are:

```text
ADD ARCHIVE
ADD ARCHIVES
ADD FILES
ADD JARS
BIGSERIAL
CURRENT_USER_ID
FIXED
FLOAT32
INT2
NONCLUSTERED INDEX
NTEXT
SHORT
SMALLSERIAL
VARBYTE
_ARMSCII8
_ASCII
_BIG5
_BINARY
_CP1250
_CP1251
_CP1256
_CP1257
_CP850
_CP852
_CP866
_CP932
_DEC8
_EUCJPMS
_EUCKR
_GB18030
_GB2312
_GBK
_GEOSTD8
_GREEK
_HEBREW
_HP8
_KEYBCS2
_KOI8R
_KOI8U
_LATIN2
_LATIN5
_LATIN7
_MACCE
_MACROMAN
_SJIS
_SWE7
_TIS620
_UCS2
_UJIS
_UTF16
_UTF16LE
_UTF32
_UTF8
_UTF8MB3
```

Every one of the 54 real source rows was independently changed to a different canonical existing `TokenType` member and accepted by the gate. Representative observed and poison rows were rejected.

## Runtime and integration audit

The runtime gate accepts only one change in one existing Python file, one hunk, one removed line, one added line, equal old/new counts and starts, canonical patch metadata, an exact existing `KEYWORDS` row, an unchanged string key, and a direct `TokenType.OLD -> TokenType.NEW` value replacement where `NEW` is a distinct existing enum member. It reconstructs the complete patched source from the pinned archive, reparses both modules, verifies the exact per-file inventory and canonical import binding, substitutes one sentinel at the candidate AST value, and requires the two whole-module ASTs to be otherwise identical.

The following fail closed to ordinary selector behavior: multiple files, multiple hunks, multiple edits, key changes, missing/tampered artifacts, noncanonical imports, aliases, subscripts, `getattr`, nonexistent enum members, comments/directives, parenthesized alternate shapes, source inventory changes, patch metadata tampering, malformed inputs, and AST changes outside the single certified value.

The gate is placed after syntax/directive and reflection handling, so any independently known code-reflection reader remains selected before the keyword proof can skip coverage. It is placed before coverage/fixture/generic fallback. A missing or invalid context does not activate the gate and therefore retains the existing conservative selector path. The feature never reads sample labels, validation answers, or scorer output.

The Dockerfile now copies both `tokenizer_keyword_runtime.py` and `tokenizer_keyword_model.json.gz`; every Docker `COPY` source exists. No Docker build was run because the task explicitly deferred full Docker/scorer work pending the separate guard/resource audit.

## Public validation observation

Only `validation/val10/meta.json` descriptions were inspected; `answers.json` was not read. Its 19 public cases contain 14 tokenizer key-renames and five parser-registry key-renames. There are zero safe-key overlaps and zero value-only edits eligible for this gate. This observation was not used to construct or widen the proof.

## Light tests run

- Provenance/adversarial suite: 21/21 passed
- Runtime and selector-integration suite: 13/13 passed
- Selector AST, typing-reflection, and semantic-noop regressions: 36/36 passed
- Python compilation checks for selector, runtime, and focused tests: passed
- Direct full-model load: 716 rows across 25 paths, 449 enum members, 54 safe rows
- Independent all-safe runtime exercise: 54/54 accepted; observed and poison controls rejected

No commit was created. No full Docker build, scorer, or submission was run.
