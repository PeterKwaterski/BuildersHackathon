# Fresh inline table alias profile

`fresh_alias_profile.json.gz` is an unfiltered profile of every pinned-source
call shaped as `exp.alias_(exp.table_(one_argument), ...)`. It contains both
source sites, including the one without an explicit `copy` keyword; it is not
filtered by a candidate patch and contains no replacement value, sample commit,
expected failure, or patch-to-test answer.

The collector installs a line trace only in files containing candidate sites.
For every execution it records the owning pytest node, the exact runtime type
of the table-name argument, and whether the module plus both called functions
still have their canonical bindings. Real subprocesses inherit the owning node
and write child logs. A second complete suite run makes optimizer and executor
worker paths synchronous.

```sh
python tools/collect_fresh_alias_profile.py \
  --source /path/to/sqlglot --python /path/to/python3.13 \
  --tests sample/tests.json --output /tmp/fresh-normal.json \
  --manifest /tmp/fresh-normal.manifest.json

python tools/collect_fresh_alias_profile.py \
  --source /path/to/sqlglot --python /path/to/python3.13 \
  --tests sample/tests.json --synchronous-workers \
  --output /tmp/fresh-sync.json \
  --manifest /tmp/fresh-sync.manifest.json

python tools/build_fresh_alias_profile.py \
  --source /path/to/sqlglot --tests sample/tests.json \
  --manifest /tmp/fresh-normal.manifest.json \
  --manifest /tmp/fresh-sync.manifest.json \
  --trace /tmp/fresh-normal.json --trace /tmp/fresh-sync.json \
  --output fresh_alias_profile.json.gz
```

The builder pins the source revision, ordered test digest, two successful full
manifests, and child-process accounting. A site is safe only when both traces
observed canonical bindings and only exact `str` arguments under attributed
tests. In every other state runtime selection falls back.

At runtime a cheap lexical gate first requires one `copy=True`/`copy=False`
token change on an otherwise identical removed/added line. The authoritative
check then matches the complete profiled call AST, verifies the only changed
AST value is that boolean, and applies the existing compile, binding, import,
directive, and single-file-change gates. Since `table_(str)` constructs a new
`Table` and new `Identifier` before `alias_` runs, its optional second deep copy
has no externally reachable pre-copy object and is observationally irrelevant.
