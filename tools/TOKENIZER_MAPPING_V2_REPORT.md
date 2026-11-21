# Tokenizer mapping candidates after KEYWORDS v1

Status: **REPORT ONLY / NO-SHIP**. This does not broaden the KEYWORDS v0
collector, model, or selector. Counts and line numbers below are for pinned
SQLGlot `eb11aec4be8cb2122afe713a4816662c3f0fb2fa`.

The same first-divergence theorem can apply to an existing mapping key whose
value alone changes: if both complete modes have no value-retrieval event for
that key, execution cannot diverge before a nonexistent first retrieval.
Membership and whole-map truth checks do not observe a value when the key set
is unchanged. Each mapping nevertheless needs its own static transfer and
external-observer closure.

| source mapping | explicit literal census | transfer | exact value retrievals | disposition |
| --- | ---: | --- | --- | --- |
| `KEYWORDS` | 716 entries / 616 keys | `tokens.py:579` to `keywords` | `tokenizer_core.py:810,895,1047,1191` | v1 only |
| `NUMERIC_ESCAPES` | 23 entries / 5 keys in 11 assignments | `tokens.py:606` to `numeric_escapes` | `.get(key)` at `tokenizer_core.py:1219,1240` | strongest v2 candidate |
| `NUMERIC_LITERALS` | 6 entries / 6 keys in 4 assignments | `tokens.py:596` to `numeric_literals` | alias `.get(key)` nested in `tokenizer_core.py:1047` | second v2 candidate |
| `SINGLE_TOKENS` | 55 entries / 31 keys in 12 assignments | `tokens.py:578` to `single_tokens` | alias subscriptions at `tokenizer_core.py:899` plus membership sites | blocked |
| `UNESCAPED_SEQUENCES` | 40 entries / 18 keys in 12 assignments | dialect object at `tokens.py:605` | alias `.get(key)` at `tokenizer_core.py:1376` | blocked |

## NUMERIC_ESCAPES closure to prove

`TokenizerCore` has two semantic value retrievals, both exact `.get()` calls.
The alias at `tokenizer_core.py:1323` and truth check at line 1362 must be in
the site census, but a same-key value replacement cannot alter map truth.
Outside the core, `dialects/dialect.py:404-411` chooses an output escape format
from key membership only; `generator.py:1723` uses map truth and line 3283 uses
membership of `"x"`. These are key-set observers, not value observers, and
must be bound as such.

The v2 recognizer should admit only one tuple-to-tuple replacement with the
same four exact integer elements/shape rules, instrument only the key
expressions at lines 1219 and 1240, union by literal key across all dialect
owners, and reuse the normal+synchronous zero-retrieval rule. Snowflake's
three entries (`"x"`, `"u"`, `"0"`) are inside this envelope. Remaining work
is an exact repository-wide read/pop/copy/inheritance census, compiled-name
reflection audit, and independent review; no v2 collector exists yet.

## Other mappings and blockers

`NUMERIC_LITERALS` reaches one nested lookup:
`keywords.get(numeric_literals.get(numeric_literal.upper(), ""))`. Its source
inheritance/unpack graph and the interaction with the KEYWORDS lookup need a
separate exact audit, but a zero retrieval of the numeric-literal key closes
that interaction by first divergence.

`SINGLE_TOKENS` is not eligible for this narrow method because
`parser.py:689-690` consumes `Tokenizer.SINGLE_TOKENS.values()` at import time
to create persistent `Parser.RESERVED_TOKENS`. A value change can therefore
seed shared parser class state before a core retrieval.

`UNESCAPED_SEQUENCES` is not eligible because the dialect metaclass consumes
all values through `.items()` at `dialects/dialect.py:383-399` and persists
derived `ESCAPED_SEQUENCES` and `IDENTIFIER_ESCAPED_SEQUENCES`. Every value is
observed during import, so a runtime zero-read trace cannot certify it.

Derived maps (`_QUOTES`, `_IDENTIFIERS`, `_FORMAT_STRINGS`, `_COMMENTS`, and
`_KEYWORD_TRIE`) are also deferred: their source values are transformed and
persisted in `__init_subclass__`, rather than transferred unchanged from an
editable source dictionary.

## Reproduction

Run the v1 host audit (it also binds the transfer/lifecycle implementation):

```bash
PYTHONPATH=tools python3 -m unittest tools/test_tokenizer_keyword_values.py -v
```

The counts above were produced by parsing every assignment under `sqlglot/`
and counting exact string keys in literal dictionaries named by the source
mapping. No sample answers or full Docker traces were used.
