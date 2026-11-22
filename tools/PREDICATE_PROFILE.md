# Predicate execution profile

`predicate_profile.json.gz` is a complete source execution profile for every
single-operator comparison. Every source site is present, including
unobserved, unsafe, incompletely observed, and unattributed sites that force a
runtime fallback. Safely observed sites retain typed operand domains and all
ten raw result-or-exception outcomes;
the artifact is not filtered by a prospective edit and stores no replacement
operator, test ownership, patch, sample ID, or failure answer.

The collector instruments only a single `ast.Compare` operator and comparator
from `Lt`, `LtE`, `Gt`, `GtE`, `Eq`, `NotEq`, `Is`, `IsNot`, `In`, and
`NotIn`. Nested comparisons are rendered recursively. The wrapper preserves
left-then-right evaluation and evaluates each operand and the original
operator once. It records all ten comparison outcomes only when both operands
are exact immutable builtins: `NoneType`, `bool`, `int`, `float`, `str`,
`bytes`, `type`, or recursively safe exact tuples. Unsafe operands, a
non-`bool` original result, unattributed execution, unknown owners, failed
suites, and a non-exact runtime roster cannot produce a certificate.

Collect ordinary and synchronous-worker runs under official hash seed 0, then
an ordinary complete-suite run under an adverse seed. Process-pool submissions
inherit the owning pytest node, write process-local logs at each task boundary,
and create expected/completed task markers. Any missing task invalidates the
run.

The collector deselects every non-numbered node listed in `tests.json`'s
`skipped` inventory before execution. Each manifest must contain the exact
ordered 1,620 numbered-node roster, exactly 25,440 passed subtest reports, and
zero failed or skipped subtests; an extra setup/skip node is not admissible.

```sh
python tools/collect_predicate_values.py \
  --source /path/to/clean/sqlglot \
  --python /path/to/python3.13 \
  --tests sample/tests.json \
  --output /tmp/predicate-normal.json \
  --manifest /tmp/predicate-normal.manifest.json

python tools/collect_predicate_values.py \
  --source /path/to/clean/sqlglot \
  --python /path/to/python3.13 \
  --tests sample/tests.json \
  --synchronous-workers \
  --output /tmp/predicate-sync.json \
  --manifest /tmp/predicate-sync.manifest.json

PYTHONHASHSEED=1 python tools/collect_predicate_values.py \
  --source /path/to/clean/sqlglot \
  --python /path/to/python3.13 \
  --tests sample/tests.json \
  --output /tmp/predicate-adverse.json \
  --manifest /tmp/predicate-adverse.manifest.json

python tools/build_predicate_profile.py \
  --source /path/to/clean/sqlglot \
  --tests sample/tests.json \
  --manifest /tmp/predicate-normal.manifest.json \
  --manifest /tmp/predicate-sync.manifest.json \
  --manifest /tmp/predicate-adverse.manifest.json \
  --trace /tmp/predicate-normal.json \
  --trace /tmp/predicate-sync.json \
  --trace /tmp/predicate-adverse.json \
  --output predicate_profile.json.gz
```

The builder pins the sqlglot revision, requires the exact runtime roster in
every successful manifest, authenticates Python 3.13.18, hash seeds, source-site
counts, trace digests, process-task accounting, and owners, emits every source
site, and writes deterministic gzip (`mtime=0`). It does not decide which edits
are equivalent. At runtime the selector applies the candidate operator
generically to the complete raw profile and can skip only when every recorded
observation has the same old and new result triple and the original result is
an exact `bool`.

At runtime the selector independently parses both complete files and locates
the certified source coordinate by its AST path. It requires the exact directed
operator pair, unchanged operands, and equality of the entire executable AST
after normalizing that one operator. Function binding, compile,
import-expression, directive, and model/source/test-digest gates must also
pass. Every ambiguity falls back to the broad coverage selector.

The operator-only proof is inductive over executions of the patched suite.
Before the first edited comparison, program state and operand evaluation are
identical. Exact-builtin comparison operations are side-effect free; the
profile requires the replacement to return the identical Boolean for every
operand domain/outcome observed in every complete run. State is therefore
identical after that comparison, and the argument repeats for later visits.
Custom rich comparisons, mutable containers, literal or operand edits,
exception-producing original operations, and unseen runtime shapes are
outside the certificate and fall back.

Equal phase values are not assumed to imply equal observability. The runtime
gate also requires the whole-file AST to differ at only one operator, and the
collector rejects every operand capable of invoking a custom rich comparison,
iteration hook, or mutation. For the admitted exact builtins, both operators
produce one unobservable primitive comparison result; recursively exact tuple
comparisons may perform different internal work, but cannot call user code.
Because the replacement Boolean is identical, surrounding `and`/`or` and
conditional short-circuit decisions, later comparison-call counts, exceptions,
and program state remain identical by induction. Any observer/callback-bearing
operand is `unsafe` and falls back.

Identity/value transformations receive a stricter theorem gate because
allocation and interning can change between process histories. Only
`is`↔`==` and `is not`↔`!=` are considered, and every observed domain pair
must involve exact `NoneType`, exact `type` (whose metaclass equality is
identity), or two exact `bool` operands. Exact int, float, string, bytes, and
tuple domains are rejected even when one trace happened to intern or reuse the
same object. Tuple admission elsewhere still requires recursive exact-safe
elements in the trusted collector; the compact artifact deliberately records
only the top-level exact tuple type.
