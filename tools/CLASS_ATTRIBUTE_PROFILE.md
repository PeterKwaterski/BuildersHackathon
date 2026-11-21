# Owner-aware class-attribute profile

`class_attribute_model.json.gz` records reader coverage for every unique,
literal-valued class assignment in the pinned source. It is deliberately an
unfiltered source profile: safe, import-read, mutated, incomplete, statically
unsafe, and unobserved assignments are all represented. It contains no sample
commit, candidate edit, expected failure, or replacement value.

`collect_class_attribute_reads.py` rewrites attribute loads in a temporary
checkout so each read is resolved through the runtime object's actual MRO to
the exact class namespace that owns it. Inherited assignments with the same
attribute name therefore remain separate. Direct `getattr` and reflective
namespace operations are traced as well. Class namespace proxies distinguish
key/shape access from value access, and import-context reads or mutations force
fallback. Real subprocesses inherit their owning pytest node and write child
logs; a second run makes optimizer/executor worker paths synchronous.

```sh
python tools/collect_class_attribute_reads.py \
  --source /path/to/sqlglot --python /path/to/python3.13 \
  --tests sample/tests.json --output /tmp/class-normal.json \
  --manifest /tmp/class-normal.manifest.json

python tools/collect_class_attribute_reads.py \
  --source /path/to/sqlglot --python /path/to/python3.13 \
  --tests sample/tests.json --synchronous-workers \
  --output /tmp/class-sync.json \
  --manifest /tmp/class-sync.manifest.json

python tools/build_class_attribute_model.py \
  --source /path/to/sqlglot --tests sample/tests.json \
  --manifest /tmp/class-normal.manifest.json \
  --manifest /tmp/class-sync.manifest.json \
  --trace /tmp/class-normal.json --trace /tmp/class-sync.json \
  --output class_attribute_model.json.gz
```

The builder pins the source revision, ordered test digest, complete successful
normal and synchronous manifests, child-process accounting, static mutation
audit, and every literal assignment. At runtime an optimization is available
only for a safely observed entry. Both complete files must differ in exactly
one existing literal value of the same exact type; replacing it by a sentinel
must make their ASTs identical. Compile, directive, import-expression,
serialization, source, and test-digest gates remain active. Every uncertainty
falls back to the ordinary coverage and assignment dependency cones.
