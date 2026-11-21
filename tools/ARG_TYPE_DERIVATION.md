# `arg_types` derivation certificate

`arg_type_derivation_model.json.gz` narrows boolean value edits in expression
class `arg_types` dictionaries to value-observing direct readers and to the
exact `required_args` invocations where that key's requiredness can matter.
The evidence is
answer-independent: sample patches, commit IDs, and expected failures are not
inputs.

`collect_arg_type_derivations.py` wraps pinned module and class dictionaries,
then instruments the exact pinned `Expr.__init_subclass__` derivation and the
sole `Expression.error_messages` consumer. A strong identity map retains each
derived set and its source dictionary label; reads are credited only after an
`id` and object-identity check. This covers inherited dictionaries and dynamic
subclasses without joining on class names. At every validated consumer call,
the collector records which source keys are missing, `None`, or an empty list.
A present nonempty key behaves identically whether optional or required.
Key-presence operations such as `k in arg_types` are recorded separately from
value reads because the runtime gate proves all keys unchanged. Ordinary exact
value and value-wide dictionary operations remain conservative. Process children inherit the
owning pytest node and write mergeable logs.

The pinned suite also contains exactly four calls to the sole
`required_args` consumer with ordinary sets that were not produced by the
instrumented derivation: the Snowflake aggregate test, both generator fallback
function tests, and the optimizer function-annotation test. The collector's
strong map retains the result object itself, its source label, and the derived
attribute. A read is mapped only when its `id`, object identity, and attribute
all match that retained tuple. Therefore an unmapped read cannot belong to any
identity-linked source label. The builder requires this exact four-test set and
rejects any missing or additional unmapped reader.

Run the complete pinned Python 3.13 suite once with real workers and once with
the optimizer/executor pools made synchronous, then build the model:

```sh
python tools/collect_arg_type_derivations.py \
  --source /path/to/sqlglot --python /path/to/python3.13 \
  --tests sample/tests.json --output /tmp/arg-normal.json \
  --manifest /tmp/arg-normal.manifest.json

python tools/collect_arg_type_derivations.py \
  --source /path/to/sqlglot --python /path/to/python3.13 \
  --tests sample/tests.json --synchronous-workers \
  --output /tmp/arg-sync.json --manifest /tmp/arg-sync.manifest.json

python tools/build_arg_type_derivation_model.py \
  --source /path/to/sqlglot --tests sample/tests.json \
  --manifest /tmp/arg-normal.manifest.json \
  --manifest /tmp/arg-sync.manifest.json \
  --trace /tmp/arg-normal.json --trace /tmp/arg-sync.json \
  --output arg_type_derivation_model.json.gz
```

The builder pins the source revision, ordered runtime test digest, successful
normal and synchronous manifests, child-log accounting, exact derivation hook,
sole derived-set consumer, and every production `arg_types` load. Dictionaries
with module/class-time consumers or unsupported events are excluded. Any
value-wide dictionary event outside an owning pytest test, including one
recorded as `__NO_TEST__`, rejects that source label rather than being filtered
from its owner set.

Changing membership in a Python set can reorder its other members. The builder
therefore finds every invocation where a currently required key is missing and
retains that owner for every key of the source dictionary, even when the edited
key itself is present. This preserves observable error-message ordering without
turning all derived-set reads into value-wide consumers.

At runtime both complete files are parsed. Acceptance requires exactly one
certified class dictionary assignment, identical literal collision-free keys,
only existing `bool` constants changing, and complete AST equality after
replacing those values with sentinels. Directive, process-serialization,
binding, annotation, import-expression, source, and test-digest checks still
apply. Every ambiguity falls back to the ordinary coverage cone.
