# Next candidate evidence

Status: **LOCAL / NOT PUSHED / NOT SUBMITTED**

This branch stacks two independently audited hidden-precision layers on the
known-good `862545f3e65e1c791bba8c98ec25499c6956d008` baseline:

- tokenizer `KEYWORDS` value precision (`40c872ba677fe3acd7e52aaf925053e562f4c0cf`);
- runtime-inert directive comments (`93cab82f35abfd40f482b4facffc8afd3920d658`).

The exact linux/amd64 production-image run passed all 30 sample patches at
95.673 simulated seconds, zero misses, and 99 selected tests. Its output is
byte-identical to the baseline:

`4d8bc3d459b8e57e9906579c2d6ac90afbb269e0910ac7e05abb858f931f95b4`

The built image ID was:

`sha256:fa3e714c162b903811e6891df91bc1d271cfd6f1fe2e3681503c0a5252573c92`

Five alternating exact-image CPU pairs produced medians of 2.210774 seconds
for main and 2.383390 seconds for this branch. The paired median cost was about
0.173 seconds, with substantial host noise; every one of the ten outputs had
the same SHA-256 above. The hidden precision upside is therefore expected to
dominate the small runtime cost, but the branch remains unsubmitted pending the
guard-profile integration and a final combined audit.

No leaderboard submission is authorized by this report.
