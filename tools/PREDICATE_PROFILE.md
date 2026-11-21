# Predicate execution profile

`predicate_profile.json.gz` is a complete source execution profile for all
literal-boundary ordering comparisons. Every source site is present, including
unobserved, unsafe, incompletely observed, and unattributed sites that force a
runtime fallback. Safely observed sites retain all six raw boolean outcomes;
the artifact is not filtered by a prospective edit and stores no replacement
operator, test ownership, patch, sample ID, or failure answer.

The collector instruments only a single `ast.Compare` operator and comparator
from `Lt`, `LtE`, `Gt`, and `GtE`, with at least one `ast.literal_eval`
operand. The wrapper preserves left-then-right evaluation and evaluates each
operand once. It records all six comparison outcomes only when both operands
are exact immutable builtins: `NoneType`, `bool`, `int`, `float`, `str`,
`bytes`, or recursively safe exact tuples. Unsafe operands, exceptions,
non-`bool` results, unattributed execution, unknown owners, failed suites, and
missing runtime tests cannot produce a certificate.

Collect one ordinary run, then a second run with optimizer/executor process
pools made synchronous. Real subprocesses inherit the owning pytest node and
write process-local logs which the plugin merges and counts in each manifest.

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

python tools/build_predicate_profile.py \
  --source /path/to/clean/sqlglot \
  --tests sample/tests.json \
  --manifest /tmp/predicate-normal.manifest.json \
  --manifest /tmp/predicate-sync.manifest.json \
  --trace /tmp/predicate-normal.json \
  --trace /tmp/predicate-sync.json \
  --output predicate_profile.json.gz
```

The builder pins the sqlglot revision, requires every runtime test ID in both
successful manifests, validates process-log accounting and owners, emits every
source site, and writes deterministic gzip (`mtime=0`). It does not decide
which edits are equivalent. At runtime the selector applies the candidate
operator generically to the complete raw profile and can skip only when every
recorded observation has the same old and new result.

At runtime the selector independently parses both complete files and locates
the certified source coordinate by its AST path. It requires two distinct
operators recorded by the artifact (`<`, `<=`, `>`, `>=`, `==`, or `!=`), a
literal boundary, unchanged operands, and equality of the entire executable
AST after normalizing that one operator. The old and new raw boolean outcomes
must agree at every recorded invocation. Identity operators remain excluded:
their outcomes are not recorded, and source instrumentation can perturb
constant interning. Function binding, compile, import-expression, directive,
and model/source/test-digest gates must also pass. Every ambiguity falls back
to the broad coverage selector.
