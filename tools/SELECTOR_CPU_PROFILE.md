# Selector AST-index CPU profile

Status: implementation, adversarial equivalence audit, and uncontended
exact-image process-tree CPU benchmarking complete.

## Change

`selector.py` now constructs one cached breadth-first index for each pinned AST
that is actually queried. The index preserves the exact node order produced by
`ast.walk` and records parents, statements, definitions, and functions in the
same pass. Hot structural gates reuse this index instead of
walking the same complete pinned module repeatedly. Prospective source is still
parsed and indexed independently.

Structural paths are reconstructed on demand from the parent map instead of
retaining a root-to-node tuple for every node. Only the rare function/annotation
target requests one.

The two gates that temporarily normalize a cached pinned node use `try/finally`
to restore it. Memory/recursion failures fail closed and cannot poison later
decisions. The cache is bound to the exact AST object, so tests or future code
that clear/rebuild `_SOURCE_TREES` automatically rebuild the associated index.

## Host profile

The 30 public patches were evaluated with the dynamic unittest verifier stubbed
so this profile measures selector analysis only. The before/after JSONL is
byte-identical.

| Metric | Base `230575c` | Indexed |
| --- | ---: | ---: |
| cProfile calls | 12,800,793 | 4,900,414 |
| cProfile wall | 6.972 s | 2.095 s |
| `ast.walk` cumulative | 2.895 s | 0.085 s |
| `runtime_body_patch_source` cumulative | 2.588 s | 0.590 s |

The indexed column predates removal of eager structural-path tuples and is a
conservative profile for the current implementation.

Five interleaved runs pinned to one host CPU while other research jobs were
active showed median user CPU of approximately 3.58 s for the base and 1.83 s
for the indexed implementation (about 49% lower). These are noisy host results,
not the final scorer-style measurement. Peak RSS increased by roughly 2.4 MiB
on the 30-patch run before the eager path tuples were removed; the refined
implementation retains less state and has not yet been remeasured for RSS.

## Equivalence and adversarial evidence

- All 30 static selector output lines are byte-identical.
- All nine sample warm-verifier eligibility decisions and patched-source hashes
  are byte-identical.
- All 521 deterministic generator-dispatch mutations reproduce the exact same
  compressed benchmark artifact (SHA-256
  `66570496073d12dcf41f8cb1e47ca3058b95ca4b556029d677af81ab70ed4ba1`).
- The 64-case execution corpus is also byte-identical (SHA-256
  `49a05fcdd56c72310f4710375a8829994b51111184511ba434db53d77139dbfb`).
- Every one of the 250 pinned source indexes exactly matches `ast.walk` node
  order, the former parent-map construction, and statement/definition/function
  categories.
- Existing generator-dispatch and local-annotation regressions pass.
- New tests cover order/parents/paths, cache invalidation, cached-body
  restoration, restoration after `ast.dump` failure, local-annotation
  restoration after success and failure, bounded stale-cache replacement, and
  malformed-source fallback.

## Exact-image command plan

Use the already audited `br-generator-dispatch-audit` image. Run its packaged
selector as the base, then bind-mount this worktree's `selector.py` read-only at
`/app/selector.py`. Both runs use the exact Makefile limits and mounts. A Python
wrapper records `RUSAGE_SELF + RUSAGE_CHILDREN` user/system CPU to stderr after
calling `selector.main()`. Require byte-identical JSONL, 95.673 simulated
seconds, zero misses, and lower median process-tree CPU across at least five
interleaved runs before integration.

The exact run shape is:

```bash
sample_dir="$PWD/sample"
indexed_file="$PWD/selector.py"
common=(
  --rm --platform linux/amd64 --network none --cpus 2
  --memory 4096m --memory-swap 4096m --pids-limit 256 --read-only
  --tmpfs /tmp:rw,size=64m,mode=1777 --cap-drop ALL
  --security-opt no-new-privileges --user 65534:65534 --env HOME=/tmp
  --volume "$sample_dir/commits:/data/commits:ro"
  --volume "$sample_dir/tests.json:/data/tests.json:ro"
  --entrypoint python
)
wrapper=$'import resource, runpy, sys\nsys.path.insert(0, "/app")\ndef cpu(kind):\n u = resource.getrusage(kind)\n return u.ru_utime + u.ru_stime\nbefore_self = cpu(resource.RUSAGE_SELF)\nbefore_children = cpu(resource.RUSAGE_CHILDREN)\ntry:\n runpy.run_path("/app/selector.py", run_name="__main__")\nfinally:\n self_cpu = cpu(resource.RUSAGE_SELF) - before_self\n child_cpu = cpu(resource.RUSAGE_CHILDREN) - before_children\n print(f"SELF_CPU={self_cpu:.9f} CHILD_CPU={child_cpu:.9f} PROCESS_TREE_CPU={self_cpu + child_cpu:.9f}", file=sys.stderr)'
docker run "${common[@]}" br-generator-dispatch-audit -c "$wrapper" \
  > /tmp/selector-base.jsonl 2> /tmp/selector-base.time
docker run "${common[@]}" --volume "$indexed_file:/app/selector.py:ro" \
  br-generator-dispatch-audit -c "$wrapper" \
  > /tmp/selector-indexed.jsonl 2> /tmp/selector-indexed.time
cmp /tmp/selector-base.jsonl /tmp/selector-indexed.jsonl
python3 score.py sample sample/answers.json /tmp/selector-indexed.jsonl
```

The initial contended exact-image check confirms byte-identical output (SHA-256
`4d8bc3d459b8e57e9906579c2d6ac90afbb269e0910ac7e05abb858f931f95b4`)
and 95.673 simulated seconds with zero misses. Timing is not yet decisive: three
base-first pairs favored base (median 3.208 s versus 3.607 s), while three
indexed-first pairs favored indexed (median 3.174 s versus 2.383 s). The strong
order/load interaction requires an uncontended alternating-order confirmation;
do not integrate based on these timings.

After the path-memory refinement, eight alternating-order pairs produced a
2.915 s base median and 2.298 s indexed median (21.2% lower), with indexed
winning all eight pairs. However, an external TPC collection container started at
approximately the same time, so this is also contended evidence rather than the
required final confirmation.

The final Docker-clear eight-pair alternating-order confirmation reproduced the
result: base process-tree CPU median 2.822 s, indexed median 2.227 s (21.1%
lower), and indexed won all eight pairs. Parent-process medians were 2.586 s and
2.074 s respectively. Every one of the sixteen outputs had SHA-256
`4d8bc3d459b8e57e9906579c2d6ac90afbb269e0910ac7e05abb858f931f95b4`
and scored 95.673 simulated seconds with zero misses.

No commit, push, submission, or production-worktree edit is authorized by this
profile.
