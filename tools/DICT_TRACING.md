# Dictionary access trace provenance

`collect_dict_access.py` produces the answer-independent input used by the
exact-key reader certificate. It validates the pinned sqlglot revision, copies the
checkout to a temporary directory, wraps simple module/class dictionary
literals, and runs the pinned suite. It never reads sample patches or answers.

The wrapper records exact-key operations separately from key-, shape-, and
value-wide observations. The collector also:

- runs the executor and optimizer worker paths synchronously so their events
  remain attributed to the owning test;
- propagates a pytest node ID into direct subprocesses and merges their
  process-local event logs;
- writes a manifest containing every executed node ID and the pytest exit
  status; and
- rejects a full trace if any runtime test ID was not executed.

With the environment from `requirements.lock`, collect the trace with:

```sh
python tools/collect_dict_access.py \
  --source /path/to/sqlglot-at-eb11aec4 \
  --sources semantic_sources.json.gz \
  --python /path/to/locked-venv/bin/python \
  --tests sample/tests.json \
  --output /tmp/dict-access.json
```

The corresponding `/tmp/dict-access.manifest.json` is provenance evidence.
The trace itself is intentionally not committed: it is large and the compact
certificate contains only source labels, literal-key syntax, and exact owning
test indices. Empty owner lists retain the previous zero-reader proof.

The collector is deliberately observational rather than a proof by itself.
The certificate builder rejects value-wide observations, unresolved
identity flow, native/opaque consumers, exact-type checks, copies, and any key
seen in an import context. Key-presence operations are recorded separately
because the runtime proves the keys and their order are identical; they do not
observe a changed value. Its source analysis uses scope-qualified
symbols for module/class assignments and function parameters, while retaining
the older global analysis only for already-audited zero-reader entries. A
nonzero reader set requires the owner-aware scoped proof. Dynamic class
attributes flow through a shared attribute node; explicit class references
flow only from definitions with that exact class name, including module-qualified
class references. Neither proof can override a recorded value-wide read.

Dictionary unpack entries are retained in the runtime structure comparison but
are never certified as keys. The runtime selector allows a certified explicit
key to change only when its old and new values are literals, same-signature
default-free lambdas, or when both are
same-shape calls with literal arguments to the same statically proved pure
closure factory. Such a factory may only define one undecorated, default-free
nested function and return it; evaluated annotations, decorators, side-effecting
arguments, asynchronous factories, and any extra statement force fallback.
The complete old and patched ASTs must otherwise match after replacing the one
value with a sentinel. All uncertainty falls back to the broader dependency
model.
