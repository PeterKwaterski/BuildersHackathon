# Selector cyclic-GC CPU audit

## Change and safety boundary

The selector disables cyclic garbage collection at entry to `main` and
restores its prior enabled state after emitting the complete batch.  Python
reference counting remains active throughout.  The selector creates large
acyclic JSON dictionaries/lists, ASTs, code objects, and one-way AST indexes;
all long-lived models remain strongly reachable until process exit.  It has no
cycle-owned finalizers, weak-reference correctness gate, or dependence on the
timing of unreachable-cycle collection.  Verifier subprocesses start their
own interpreters and retain normal GC behavior.

Disabling before model loading is material: nested JSON/model allocation
otherwise triggers repeated generation scans while the immutable graph is
still growing.  A later disable immediately before patch traversal preserved
outputs but reduced the six-pair sample median by only about 0.12 process CPU
seconds, so the final implementation uses the earlier safe boundary.  Normal
return restores the caller's original GC state; an initially disabled caller
remains disabled.

No proof gate, model, patch parser, scheduling rule, test set, or output
serialization changes.  The 30-case sample remains byte-identical at SHA-256
`56db9765528f66a3881ba613b9790996b2229cbe3668624c03868c04c9721ca3`.
The representative 64-patch public `val5` batch is byte-identical with and
without the optimization at SHA-256
`8cf5e5cac3d9d71644865031c39f8621eb6bbb18bba70de7f1d026c54e108669`.

## Alternating-order measurements

All runs used separate exact images under the official two-CPU, 4 GiB,
read-only, no-network container limits.  Process CPU is user plus system from
`resource.getrusage`; orders alternate base/proof then proof/base.

Six sample pairs:

- base: 4.500919, 6.150658, 4.156454, 4.079178, 4.209580, 3.806424 s;
- proof: 3.957744, 3.845379, 3.841124, 3.792094, 3.549695, 3.824655 s;
- median base 4.183017 s; median proof 3.832890 s; reduction 0.350127 s;
- the proof won all six paired comparisons.

Four representative public-batch pairs were noisier because other concurrent
containers shared the host, but preserved the same direction in three of four
pairs:

- base: 4.440920, 19.886614, 22.125720, 15.077831 s;
- proof: 5.169056, 5.783719, 14.182526, 13.507406 s;
- median base 17.482223 s; median proof 9.645563 s; reduction 7.836660 s.

An initial six-pair wrapper experiment disabling GC before selector import also
won five pairs and lost one by 0.006 seconds, with medians about 6.36 versus
4.59 seconds.  The
exact-image measurements above are authoritative.

## Other profiled avenues

`cProfile` on the sample attributes most remaining selector time to candidate-
specific compile/AST work.  JSON decoding is roughly 0.35 profiled seconds;
changing artifact formats would duplicate the authenticated model surface and
increase repository/build risk.  Repeated stable hashing and binary-preimage
validation together are roughly 0.25 profiled seconds before profiler
overhead, below the threshold for another invasive cache/provenance path.  No
additional optimization was retained.
