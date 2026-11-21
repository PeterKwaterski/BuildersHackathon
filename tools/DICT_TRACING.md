# Dictionary access trace provenance

`collect_dict_access.py` produces the answer-independent input used by the
zero-reader certificate. It validates the pinned sqlglot revision, copies the
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
  --python /path/to/locked-venv/bin/python \
  --tests sample/tests.json \
  --output /tmp/dict-access.json
```

The corresponding `/tmp/dict-access.manifest.json` is provenance evidence.
The trace itself is intentionally not committed: it is large and the compact
certificate contains only source labels and keys proved to have no reader.

The collector is deliberately observational rather than a proof by itself.
The certificate builder must reject value-wide observations, unresolved
identity flow, native/opaque consumers, exact-type checks, copies, and any key
seen in a test or import context. The runtime selector then re-proves that a
patch changes only literal values of those certified keys; all uncertainty
falls back to the broader dependency model.
