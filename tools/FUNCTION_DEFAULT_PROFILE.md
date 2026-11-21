# Owner-aware function-default profile

`function_default_model.json.gz` is an unfiltered profile of every safe literal
default in the pinned source. It records the tests which call the exact runtime
function while omitting that parameter. Ambiguous, decorated, import-read,
incomplete, and unobserved definitions remain in the artifact with explicit
fallback states. It contains no sample patch, replacement value, or expected
failure.

The collector returns the original callable unchanged before evaluating its
arguments, so direct calls keep their evaluation order and caller frame. A
small entry probe matches the caller's exact CPython `CALL` instruction to the
runtime function identity. This resolves direct names, bound methods,
class/staticmethods, aliases, re-exports, module attributes, constructors, and
partials. Starred calls conservatively read every default. Operator dispatch,
native callbacks, and every other unmatched entry also read every default for
that exact invocation. The two pinned signature-inspection sites are traced as
value reads. Direct `__defaults__`/`__kwdefaults__` access and custom decorators
force fallback.

Lazy module imports are a separate lifecycle boundary: a default consumed
while a test imports a dialect can initialize module or registry state that a
later test observes. A third trace therefore imports every SQLGlot module in a
fresh process, then exercises base-warm dialect loading in both orders. Every
default consumed by that trace is globally `import-read`; an explicitly bound
parameter is not. Import-global readers are never assigned only to the test
which happened to trigger the import.

```sh
python tools/collect_function_defaults.py \
  --source /path/to/sqlglot --python /path/to/python3.13 \
  --tests sample/tests.json --output /tmp/default-normal.json \
  --manifest /tmp/default-normal.manifest.json

python tools/collect_function_defaults.py \
  --source /path/to/sqlglot --python /path/to/python3.13 \
  --tests sample/tests.json --synchronous-workers \
  --output /tmp/default-sync.json \
  --manifest /tmp/default-sync.manifest.json

python tools/collect_function_default_imports.py \
  --source /path/to/sqlglot --python /path/to/python3.13 \
  --output /tmp/default-import.json \
  --manifest /tmp/default-import.manifest.json

python tools/build_function_default_model.py \
  --source /path/to/sqlglot --tests sample/tests.json \
  --manifest /tmp/default-normal.manifest.json \
  --manifest /tmp/default-sync.manifest.json \
  --trace /tmp/default-normal.json --trace /tmp/default-sync.json \
  --import-manifest /tmp/default-import.manifest.json \
  --import-trace /tmp/default-import.json \
  --output function_default_model.json.gz
```

The runtime selector requires one existing default to change to a different
literal of the same exact safe type. Replacing that default in both complete
module ASTs by a sentinel must make the trees identical. Every model, source,
digest, reflection, directive, serialization, or AST mismatch falls back to
the ordinary coverage/import cones.
