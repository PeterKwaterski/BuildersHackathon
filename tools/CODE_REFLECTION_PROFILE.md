# Function-code reflection profile

`code_reflection_model.json.gz` is an unfiltered pinned-source inventory of
every Python function, method, nested function, and lambda in `sqlglot`.
Entries record the tests that read the exact function's `__code__` object
without necessarily executing its body. This closes a gap that ordinary line
and function coverage cannot observe.

`collect_code_reflections.py` rewrites every direct `.__code__` load in the
temporary source and test tree. The helper returns the original code object
and records its pinned filename, first line, name, and owning pytest node.
Real subprocesses inherit their owner and emit child logs; a second run makes
the executor and optimizer worker paths synchronous. Unsupported code-reading
APIs, writes to `__code__`, and tracer-name collisions abort collection rather
than silently producing an incomplete profile.

```sh
python tools/collect_code_reflections.py \
  --source /path/to/sqlglot --python /path/to/python3.13 \
  --tests sample/tests.json --output /tmp/code-normal.json \
  --manifest /tmp/code-normal.manifest.json

python tools/collect_code_reflections.py \
  --source /path/to/sqlglot --python /path/to/python3.13 \
  --tests sample/tests.json --synchronous-workers \
  --output /tmp/code-sync.json \
  --manifest /tmp/code-sync.manifest.json

python tools/build_code_reflection_model.py \
  --source /path/to/sqlglot --tests sample/tests.json \
  --manifest /tmp/code-normal.manifest.json \
  --manifest /tmp/code-sync.manifest.json \
  --trace /tmp/code-normal.json --trace /tmp/code-sync.json \
  --output code_reflection_model.json.gz
```

The builder requires the pinned revision, both complete suite modes, child
process accounting, known function labels, and known test owners. At runtime,
readers from every containing reflected function range are added before any
semantic or coverage shortcut. This includes outer functions whose constants
contain a changed nested code object. The entire artifact is structurally
validated against its revision, test count, and ordered-test digest. Invalid
or stale provenance falls back to all tests for changes inside functions.
