# PythonExecutor result memo (research, default off)

`executor_result_memo.py` implements a deliberately closed cache for the pinned
TPC-DS executor workload. It is not imported by `selector.py`; a `MemoStore`
also misses unless its caller explicitly passes `enabled=True`.

The key binds the complete optimized SQLGlot expression object graph (including
argument insertion order, parent links, metadata, type and cached hash state),
the schema and complete selected table graphs, the exact query/test identity,
execution options, the fixed Python hash seed/runtime/platform, every Python
file below `sqlglot/`, the target test/helper, and every TPC-DS fixture byte.
Unsupported values fail closed.

The recorder permits only input-table reader/range mutations, records those
post-state transitions, and replays them on a hit. Any row, schema, identity,
or other table mutation rejects the entry. Results use a typed scalar encoding;
unknown result values reject rather than falling back to `repr` or pickle.
Artifacts are canonical JSON in deterministic gzip streams and contain a
payload digest.

The committed `executor_result_memo.json.gz` was built twice in the exact
Docker runtime as user `nobody` under the documented no-network, read-only,
2-CPU/4-GiB limits. It is inert unless an explicit prospective verifier opens
it; the ordinary selector never imports this module.

Build one artifact with an explicit seed:

```sh
PYTHONHASHSEED=0 python3.13 tools/build_executor_result_memo.py \
  --tree /path/to/pinned/sqlglot --output /tmp/tpc-memo.json.gz
```

Normal uncached execution is the required fallback for a disabled store, a
miss, stale provenance, malformed data, an unsupported input, or a mutation
outside the replayable state.
