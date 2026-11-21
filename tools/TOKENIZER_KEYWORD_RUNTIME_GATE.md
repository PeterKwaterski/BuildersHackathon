# Tokenizer KEYWORDS runtime gate

Status: **SHIP (exact full model integrated; light audit passed)**

Base commit: `c0d9c9ec508dc9fd5fe666345ea0afca613e821e`

This runtime is now connected to `selector.py` with the exact independently
replayed full model and is copied into the submission image. See
`TOKENIZER_KEYWORD_FINAL_AUDIT.md` for the final evidence hashes, replay,
fail-closed review, integration design, and light-test results.

## Accepted edit theorem

`tokenizer_keyword_patch` returns an empty exact-reader set only when all of the
following hold:

1. The input contains exactly one changed file and one hunk.
2. The hunk contains exactly one removed line and one added line, with no other
   byte difference after replacing `TokenType.OLD` and `TokenType.NEW` by the
   same sentinel.
3. The file and exact class/assignment/dictionary index/key/old value occur in
   the 716-entry model inventory.
4. The key is globally `safe-zero` in the full two-mode model.
5. Both values use the canonical `TokenType` binding, are distinct, and are
   members of the pinned 449-member enum.
6. The changed file's complete explicit `KEYWORDS` inventory and canonical
   import agree with the signed model's static certificate.
7. Replacing just the two RHS AST nodes by one sentinel makes the complete old
   and new module ASTs identical.

Everything else returns `None`, leaving the ordinary conservative selector in
control. Code/source-reflection readers must still be unioned before this gate
when it is eventually integrated.

## Model and source trust

`load_context` requires the caller's exact final compressed-model SHA-256 and
the hard-pinned semantic-source archive SHA-256. It rejects targeted-smoke
models and accepts only builder status `READY-FOR-AUDIT/NO-SHIP` with purpose
`full`. It validates:

- the complete 716-entry / 616-key inventory and state consistency;
- the signed collection's stable builder, collector, finalizer, Docker image,
  source, test, dependency, reflection, lifecycle, signer, and public-key pins;
- both normal and synchronous-worker per-run evidence records;
- exact Python 3.13 distribution, entry-point, environment, and toolchain
  evidence shape and digest;
- static-contract and four-retrieval-operation document digests;
- the full semantic source archive digest, `TokenType` enum census, and every
  inventoried old enum member.

The returned context copies and freezes sources, path entries, bindings, and
enum members so later caller mutation cannot alter the proof.

## Adversarial verification

Host Python 3.14:

```bash
python3 -m unittest tools/test_tokenizer_keyword_runtime.py -v
```

Result: 10/10 passed. `py_compile` and `git diff --check` also pass.

Final full-model host suite:

```bash
python -m unittest -v \
  tools.test_tokenizer_keyword_runtime \
  tools.test_tokenizer_keyword_integration
```

Result: 13/13 passed.

The suite covers base/dialect acceptance, observed-key rejection, aliases,
subscripts, `getattr`, invalid enum members, key edits, comments and extra
syntax, multiple values/hunks/files, malformed diff metadata, missing and
tampered model fields, targeted-smoke artifacts, wrong artifact hashes,
inventory/binding/enum source attacks, malformed runtime objects, and post-load
mutation.

Measured host costs:

- exact model + source context load: 0.092 seconds;
- 100 accepted recognitions: 0.434 seconds (about 4.3 ms each).

Current implementation hashes:

- `tokenizer_keyword_runtime.py`:
  `639d83de1dd9abd185b4246076c7d8ecf6880971b6348990ee20d5ec5b3f505c`
- `tools/test_tokenizer_keyword_runtime.py`:
  `33db931c6601672a5fb33a7d18c3dab3afc719391bc04bdeaf52c7969bcca933`

## Final integration

All five former ship gates passed in the isolated final-audit worktree. The
full model is pinned at
`28a5241f3d8006f075f283ac8e59f46793be482457bece67de97a4ecdd3db230`.
The gate runs after reflection-reader selection and before generic fallback;
missing or invalid artifacts retain the generic selector path. Full Docker and
scorer execution remain intentionally deferred to the parent integration
workflow.
