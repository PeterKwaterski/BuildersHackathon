# Tokenizer KEYWORDS key-rename profile

Verdict: **EXACT-IMAGE-READY**.

This profile recognizes one exact literal `KEYWORDS` entry rename
`OLD -> NEW` when its direct `TokenType` value is unchanged. Both names match
`[A-Z_][A-Z0-9_]*`, `NEW` strictly extends `OLD`, and `NEW` cannot be any
literal key in the global pinned inventory. All malformed, colliding, popped,
poisoned, nonliteral, parser-map, multi-edit, source-mismatched, or
provenance-mismatched cases fall back. `BR_TOKENIZER_KEY_RENAME=0` is the
independent runtime kill switch; the audited candidate default is enabled.

## Evidence and proof

- The artifact comes from the authenticated full normal and synchronous
  traces. Their complete sparse maps are exactly mode-identical: 8,275
  attempted keys and 34,117 owner edges. There are 1,620 scored tests, one
  skipped test, 22 normal child starts, and one synchronous child start.
- The deterministic 89,163-byte artifact rebuilds byte-identically from either
  authenticated base model. It pins both traces, manifests, bundles, signed
  index, signature, source archive, inventory, static contract, and roster.
- The static census reproduces all 31 `KEYWORDS` reads and 24 literal pops.
  Every read is a dialect dict spread, exact `.copy()`, `_KEYWORD_TRIE`
  construction, `self.KEYWORDS` transfer, `HINT_START` membership, or `(+)`
  membership. There are no unclassified iteration, `keys/items/len`, copy,
  reflection, metaclass, or whole-map observers.
- Allowed identifiers cannot enter `_KEYWORD_TRIE`: the pinned construction
  includes only keys containing whitespace or a `SINGLE_TOKENS` string, and
  every runtime `SINGLE_TOKENS` key contains punctuation forbidden by the gate.
  Thus the uninstrumented line-893 trie membership guard is unreachable for
  the admitted OLD/NEW shape. `_scan_var` reaches the instrumented final
  `keywords.get(full.upper(), VAR)` for the complete identifier.
- The additional `NEW.startswith(OLD)` and terminal-prefix owner union is
  defense in depth. It retains OLD, exact NEW when present, and every existing
  identifier terminal prefix of NEW at least as long as OLD. Any poisoned
  terminal fails closed. Global literal-pop rejection closes effective maps
  where OLD could disappear.
- Source/code reflection readers are accumulated before this gate. The gate is
  disabled for the patch if the reflection profile is missing, so profile
  composition fails closed as well as each individual artifact.

## Answer-free public atlas

The gate accepts 15 of 683 public patches and returns `None` for the other 668.
For those 668, downstream control flow and output are unchanged. Exact
base-versus-enabled selection on the 15 accepted patches is:

| Validation | Cases | Base tests | Profile tests | Base packed s | Profile packed s | Saved s |
|---|---:|---:|---:|---:|---:|---:|
| val1 | 2 | 3,230 | 108 | 73.634 | 10.962 | 62.672 |
| val2 | 3 | 425 | 82 | 21.553 | 19.957 | 1.596 |
| val5 | 1 | 132 | 27 | 6.519 | 6.698 | -0.179 |
| val10 | 9 | 14,535 | 722 | 331.353 | 144.332 | 187.021 |
| **Total** | **15** | **18,322** | **939** | **433.059** | **181.949** | **251.110** |

The small val2/val5 broadenings are deliberate: the complete attempted-key
owner set can be larger than ordinary line coverage. The 9 val10 suffix
renames are TIMESTAMP, TEXT, STRUCT, BIGINT, DECIMAL, BOOLEAN, INTERVAL, DATE,
and JSON. Import-poisoned INT, VARCHAR, DOUBLE, MAP, and ARRAY cases fall back.

Source-process cost for all 19 val10 patches was 5.24 CPU seconds enabled versus
5.44 seconds base (noise-level). The accepted-15 isolated run was 1.89+0.26 CPU
seconds enabled versus 0.86+0.08 base because it validates the signed profile
and source archive once.

## Verification

The adversarial suite covers absent and present NEW keys, multiple prefixes,
NEW as a prefix of a longer key, poison, literal collision, unrelated names,
parser `LOG`, value changes, multi-edits, transport tampering, artifact and
provenance tampering, mode pins, static/pop closure, missing reflection
evidence, selector fallback, and exact owner selection. No answer file is read
by the builder, runtime, tests, or atlas harness.
