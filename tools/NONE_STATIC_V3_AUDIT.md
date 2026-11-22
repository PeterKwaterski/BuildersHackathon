# None comparison static certificate v3

This profile admits only the exact one-line `is not None` to `!= None`
validation patches at:

- `sqlglot/executor/table.py:109` (`columns`: exact `tuple | None`)
- `sqlglot/optimizer/pushdown_projections.py:496` (`journal`: exact `list | None`)

The complete pinned `sqlglot/**/*.py` and `tests/**/*.py` tree is bound. The
builder mechanically checks constructor/caller closure, imports/re-exports,
aliases, callable containers, optimizer `RULES`, `check_file`/fixture keyword
origins, `**kwargs`, reflection, monkeypatches, namespace/subscript writes and
computed journal keys. Simplify line 1743 and eliminate-joins line 84 are
deliberately absent because their public APIs admit hostile values.

The runtime matcher accepts one file, one hunk, one removed line and one added
line. Exact full-file hashes and normalized ASTs prove the sole prospective
change is `IsNot` to `NotEq`; comments, formatting and extra hunks/files fail
closed. The previous broad `proven_identity_equality` selector path is removed.

Stable identities:

- source commit: `eb11aec4be8cb2122afe713a4816662c3f0fb2fa`
- source tree: `6606fc5229c882bd0cf8f9ba79503e9e10d084f7`
- proof: `698a7f5430c5cdfc241359550f083b406d109de73816c17f18aa71f28dc97983`
- gzip artifact: `3332998e622431ed753891f1dcf176570c0320150e370b19dd59dad226316d1f`
- public packed cost avoided per exact patch: 25.454 s
- combined public packed cost avoided: 50.908 s

Non-authoritative corroboration (not used by the selector): the exact pinned
tree with only `type(journal) is list or None` and
`type(columns) is tuple or None` assertions passed the complete suite under
image `br-base:511`, `PYTHONHASHSEED=0`, one CPU and 3584 MiB: 1620 passed, one
skipped, 25,440 subtests, exit 0 in 724.15 s. Instrumented file SHA-256 values
were `0a0991eee2526b9dd10b1ec0bcf292533a041cecb1977aca3295e035378bf1cd`
for pushdown and
`c5fb0bc105dd96428952e0b93d024f8329907f584b2980a31358d0beef8563d9`
for table.
