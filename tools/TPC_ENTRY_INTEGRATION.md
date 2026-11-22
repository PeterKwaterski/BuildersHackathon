# TPC schema-entry selector integration

## Verdict: SHIP on isolated b8ae9ac base

This branch starts exactly at candidate `b8ae9ac5f49c2bf941f9c7023adff81201c12703`
and integrates the corrected research checkpoint through `4abcf945`. The
certificate is default-on, but only one exact pinned `tests/helpers.py` schema
leaf edit can return its 61-owner set. Every other edit that touches
`tests/helpers.py`, every multi-section patch involving that file, and any
artifact/source/model/manifest failure returns all 1,620 modeled tests.

`selector.py` loads the provenance once, after loading the pinned selector
model. `load_provenance` authenticates:

- compressed artifact SHA-256
  `5e1049132f3c88793fed8d0fed7a12c76e541cd1dce2598b668e1d88ec25eaf4`;
- compressed selector-model SHA-256
  `d61c504e9a4a1006217e6702e1c6f05c04846b3dd5a09ec5572523fd8b2cb382`;
- inner revision, model and manifest bindings;
- profile SHA-256
  `0d3b6fdc2ca925e10528e362e44a38a1232db404d4d429fbe6ca859d0bce5c30`;
- all 258 source hashes, the 365-entry tracked-index digest and empty reachable
  uncollected-reader import set; and
- exact recomputation of both 61-index owner lists from ordered manifest IDs.

The Docker image copies both `tpc_entry_key_access.py` and the authenticated
provenance artifact.

## End-to-end and regression results

- Full `tools/test_*.py` discovery: **30 tests passed** in 74.508s.
- TPC-focused research/integration suite: **11 tests passed**.
- `py_compile` and `git diff --check`: passed.
- Linux/amd64 Docker build under the scoring Dockerfile: passed.
- Synthetic real Git diff changing one TPCH type leaf: **61 tests / 2 workers**.
- Synthetic two-leaf helpers edit: **1,620 tests / 4 workers**.
- Missing/tampered artifact, comments, imports, function changes, key changes,
  two leaf changes and mixed sections all select global in end-to-end tests.

No sample patch is eligible. Pristine b8ae9ac and this integration produced
byte-identical answer-free sample stdout:

- stdout SHA-256:
  `164cc2c0021896ce1a8b039dedcffddfafb7792421f88b7fe4120e944f81d115`
- selections: 101 tests across 30 patches in both images
- `cmp`: exact byte equality

No answers were opened or used.

## CPU overhead

Twelve alternating in-process, process-CPU measurements each ran all 30 sample
patches using the pristine b8 selector and integrated selector in the same
interpreter environment. Outputs had equal selection totals. Median batch CPU
was 1,311.767ms for b8 and 1,131.432ms integrated; mean was 1,238.965ms and
1,069.530ms respectively. The paired delta was -121.705ms median
(-169.434ms mean), so no positive selector overhead was measurable above host
and cache noise.

The independently measurable fixed authentication cost is **2.226ms mean** per
artifact load over 200 loads. Production performs that load once per selector
process, not per patch. The per-patch non-helpers path adds only a scan of the
already-parsed change records; the full sample comparison shows no output or
observable CPU regression.
