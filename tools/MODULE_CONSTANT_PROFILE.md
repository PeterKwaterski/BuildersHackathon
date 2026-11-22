# Owner-aware module-constant profile

`module_constant_model.json.gz` records reader coverage for every unique
module-body assignment whose value is accepted by `ast.literal_eval` in the
pinned source. It is an unfiltered source profile: immutable safe,
import-read, mutable, statically unsafe, incomplete, and unobserved assignments
are all represented. It contains no sample commit, candidate edit, expected
failure, or replacement value.

`collect_module_constant_reads.py` rewrites direct global Name loads,
from-import aliases and re-exports, and module-qualified Attribute loads in a
temporary checkout. Each read is attributed to the owning pytest node.
Import-time reads are kept as unattributed and force fallback. Real
subprocesses inherit their owning pytest node and write child logs; a second
run makes optimizer/executor worker paths synchronous.

```sh
python tools/collect_module_constant_reads.py \
  --source /path/to/sqlglot --python /path/to/python3.13 \
  --tests sample/tests.json --output /tmp/module-normal.json \
  --manifest /tmp/module-normal.manifest.json

python tools/collect_module_constant_reads.py \
  --source /path/to/sqlglot --python /path/to/python3.13 \
  --tests sample/tests.json --synchronous-workers \
  --output /tmp/module-sync.json \
  --manifest /tmp/module-sync.manifest.json

python tools/build_module_constant_model.py \
  --source /path/to/sqlglot --tests sample/tests.json \
  --manifest /tmp/module-normal.manifest.json \
  --manifest /tmp/module-sync.manifest.json \
  --trace /tmp/module-normal.json --trace /tmp/module-sync.json \
  --output module_constant_model.json.gz
```

The builder pins the source revision, ordered test digest, complete successful
normal and synchronous manifests, child-process accounting, and every literal
assignment. Mutable values always fall back. Static auditing also rejects
rebinding, mutation/reflection ambiguity, star-import exposure, and reads
through nested imports that the top-level alias rewriter cannot own safely.

At runtime the optimization is available only for an immutable safely
observed entry. Both complete files must differ in exactly one existing
literal value of the same exact type; replacing only that value by a sentinel
must make their ASTs identical. The ordinary parse, compile, directive,
pinned-source, and test-digest gates remain active. Every uncertainty falls
back to the broader coverage and assignment dependency cones.
