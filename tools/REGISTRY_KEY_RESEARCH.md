# Parser registry-key certificate

The enabled registry-key lane admits one public validation patch:
`val10/k65d`, which renames `Parser.FUNCTION_PARSERS["EXTRACT"]` while
preserving its value. The current selector chooses 1,518 tests at 36.817
seconds; the certificate chooses 36 tests at 25.454 seconds, saving 11.363
simulated seconds. The measured median incremental CPU across all 683 public
patches is 0.515 seconds including artifact loading, for 10.848 seconds net.

The answer-free census scanned all 683 public patches. `val10/k8ea` (`CAST`)
was rejected after independent mutant validation exposed cold-import fan-out:
module-level parsing fails while 34 test modules are collected. Every key with
a collection-time reader is therefore excluded from the safe old-key domain.
`TRY_CAST` is separately excluded because `TeradataParser` reads it directly
during class construction. `CONCAT` and `LOG` are shadowed by the dynamic
`FUNCTIONS` prefix and fail the duplicate-effective-key proof.

## Evidence and proof boundary

The model is built from the pinned source bundle, selector model, exact
1,620-node roster, and two complete Python 3.13.18 traces:

- normal process pools: 1,620 passed, 25,440 subtests passed, 2,183 submitted
  tasks matched by 2,183 completions across six workers;
- synchronous optimizer/executor pools: 1,620 passed and 25,440 subtests
  passed; and
- both modes instrumented 1,306 dictionaries and authenticated every trace
  hash, source digest, source inventory, roster ID, collection owner, child
  log, and task completion.

The static proof closes 52 `FUNCTIONS`/`FUNCTION_PARSERS` assignments,
including 23 `FUNCTION_PARSERS` copies or filtered comprehensions. An old key
is safe only if it is unique, not generated, not filtered, not a direct
class-construction dependency, and never read during collection. A new key is
forbidden if it is explicit, generated, filtered, or a direct dependency.
Opaque calls, copies outside certified assignments, aliases that escape their
function, reflection, parser metaclasses/descriptors, `__init_subclass__`, and
parser `__dict__` access fail the build.

Runtime requires the exact pinned source digest, one unambiguous class
assignment, one literal string-key change, identical values and dictionary
shape, a fresh non-forbidden key, exact source bytes outside the key token,
and the pinned normalized whole-module AST digest. Malformed artifacts,
directives, extra edits, duplicate keys, invalid indices, or roster/source
mismatch fall back to the ordinary selector.

The deterministic gzip artifact is `registry_key_research_model.json.gz`,
SHA-256 `952b276049efbbdcea47bee9858249b9e08ff9f9341d35c8e7d7baf6ffe94a70`.
Two builds with different output names were byte-identical.

Independent full-roster mutation of `k65d` produced 20 failing parent nodes;
all 20 were contained in the 36-reader certificate. The preserved module
type-tuple fallback was also rebuilt as the required second screen and admits
zero entries: all five source candidates escape through the expressions
module.
