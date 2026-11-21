# Blast Radius selector

A test-impact selector for the Blast Radius track. It combines per-test coverage,
fixture ownership, import-time execution, dialect usage and static assignment
dependencies, then packs the selected tests onto the cheapest worker count.

The committed model is derived only from the pinned sqlglot source and passing
baseline test runs. It does not read or encode `sample/answers.json`. That file
is used only by the supplied scorer after the selector has produced its output.

## The problem

Your image gets a batch of code changes to [sqlglot](https://github.com/tobymao/sqlglot) at commit `eb11aec4be8cb2122afe713a4816662c3f0fb2fa`. For each change, print which tests to run and how to split them across up to 8 workers.

| | |
| --- | --- |
| `/data/commits/<id>.patch` | One unified diff against the pinned commit. Each stands alone: none builds on another. |
| `/data/tests.json` | Every test, numbered, with its file and the seconds it took us to run. |
| stdout | One JSON line a commit: `{"commit": "k7q2", "workers": [[12, 845, 901], [3, 77]]}` |

Each inner list is one worker's test numbers. `"workers": []` runs nothing, which is the right answer for a change that breaks nothing.

## Scoring

Lower is better. [SCORING.md](SCORING.md) has the exact rules; in short:

- A commit costs the recorded seconds of its busiest worker, plus 2 seconds for every worker.
- A commit where you left out a test that fails adds 300 seconds.
- The CPU seconds your program uses are added. Running sqlglot's tests while you decide is allowed, and you pay for the time.
- Your image runs 3 times and the middle total counts.

"Fails" means pytest reports a failure, an error or a timeout for the test, or the test's file cannot be imported. A test with subtests is one test: one failing subtest fails it.

## Try it

You need Docker, make and Python 3.9 or newer. The kit unpacks into the folder you are in, so unpack it into an empty one.

```sh
make sample   # build, run once on the 30 sample commits under the scorer's limits, and score
make check    # the output's format only
```

`make sample` prints your simulated seconds and misses, which are exact for that output. The board adds the CPU seconds your container used and takes the middle of 3 runs, so expect it a little higher. Your program never sees `sample/answers.json`: only the patches and `tests.json` are mounted.

`sample/answers.json` lists the tests each sample commit breaks and the kind of change it is. The practice and final commits are hidden, and so is everything your program prints when it runs on them. A rejected submission tells you which rule it broke and nothing more, so reproduce problems here.

The current exact-image sample result is **95.673 simulated seconds with zero
misses**. The static selector selects 102 tests at 97.830 seconds; the restricted
warm verifier removes three observed passing tests and selects 99. Process CPU
is charged separately, so both simulated time and process-tree CPU are measured
before accepting a verifier change. Model collection used the pinned Python
3.13 image and the locked dependencies. Ordinary coverage is merged with a
coverage-only synchronous process-pool pass so both serialization paths and
optimizer/executor bodies are represented. `tools/build_model.py` compacts
those answer-independent inputs into `selector_model.json.gz`; runtime test IDs
are resolved against `/data/tests.json` rather than assuming fixed test
numbers.

`runtime_verify.py` adds a fail-closed dynamic proof after ordinary static
selection. For a small, cheap candidate set it forks from a pinned warm parent,
imports an exact patched-source overlay, and runs the requested unittest methods.
Only binding-stable one-line function-body edits in modules absent from the warm
parent are eligible. Candidate test modules must reproduce the warm parent's
import order: the shared dialect Validator is either the test module itself or
its literal first top-level statement. Checked-hash bytecode prevents stale
source execution. Import/setup errors, subtest attribution uncertainty,
timeouts, process leaks, source-restore failures, process-pool tests, and every
unsupported shape retain the complete static selection. The design and audit
gates are documented in `tools/RUNTIME_VERIFY.md`.

At runtime, a general semantic analyzer derives identity/equality equivalence
from the committed pinned source. It is used only when a one-line patch changes
`is` to `==` (or the negative equivalents) and complete assignment flow proves
an Enum singleton or an object-identity class. Ordinary added comments are
skipped only when applying their full unified diff produces the same Python AST
(including type comments); directives and compile errors stay conservative.
These are source analyses, not sample-patch or answer lookups.

`tools/collect_fresh_alias_profile.py` and
`tools/build_fresh_alias_profile.py` reproduce the complete inline
`exp.alias_(exp.table_(...))` execution profile documented in
`tools/FRESH_ALIAS_PROFILE.md`. A `copy=` toggle is skipped only at a site
where both complete suite modes observed exact string inputs and the canonical
`exp`, `alias_`, and `table_` bindings. The inner call then allocates the
complete expression graph, so no reference to the pre-copy graph can escape.
Runtime use normalizes only the boolean keyword and requires whole-file AST,
function-binding, import, directive, source, and test-digest equivalence.

Import-time edits are checked in both the old and patched trees. The selector
accounts for deleted side effects, evaluated annotations, later uses in the
same module or class, literal container shape, and attributes consumed by
`__init_subclass__`. Function-body line coverage is used only when the AST and
compiled binding layout prove that executing the changed line reaches the edit
without changing local or closure bindings.

`tools/collect_dict_access.py` reproduces the complete pinned-suite access trace
described in `tools/DICT_TRACING.md`; `tools/build_zero_reader_model.py` turns it
into an exact-key reader certificate. Static identity flow must prove
that a dictionary reaches only keyed readers or key/shape-only operations; an
unknown call, copy, value-wide operation, native boundary, relevant
import-context read, or value-observing trace wildcard rejects it. Scope-qualified
flow keeps unrelated modules, classes, and function parameters distinct; an
explicit class reference and a dynamic `self` attribute remain conservative.
At runtime this certificate is used only for an existing literal key with an
exact certified reader set, identical old/new key order, and a whole-file AST that becomes
identical when the changed value is replaced by a sentinel. Values must be
literals, default-free same-signature lambdas, or calls to a statically proved
side-effect-free closure factory with literal arguments. Unchanged dictionary unpacking is permitted, but an unpack
entry can never itself be certified. Every uncertainty falls back to the ordinary
assignment dependency cone. The certificate is derived from pinned sources and
tests and contains no sample commit, patch, or answer information.

`tools/collect_generator_dispatch.py`,
`tools/collect_generator_provenance.py`, and
`tools/build_generator_dispatch_model.py` reproduce the exact deferred
`Generator.TRANSFORMS` dispatch certificate. The source-derived inventory binds
1,350 entries across 37 generator classes, while forward and reverse import
orders independently resolve inherited origins. Runtime narrowing is limited
to one default-free lambda body in one unchanged dictionary: keys, lambda
arguments, assignment coordinates, every AST node outside the lambda, and the
single-hunk structure must remain identical. Import-time observation, table
mutation, ineffective entries, JSONPath order-sensitive cleanup, dynamic
subclasses, missing child evidence, or stale provenance all fall back to the
ordinary selector. The packaged model contains 521 safe deferred handlers and
is bound to the pinned source, test manifest, complete inventory, and exact
profile digest.

`tools/collect_arg_type_derivations.py` and
`tools/build_arg_type_derivation_model.py` reproduce the source-derived class
dictionary certificate documented in `tools/ARG_TYPE_DERIVATION.md`. It
identity-links every `required_args` set to the exact `arg_types` dictionary
that produced it, so inherited and dynamic subclasses are covered without a
class-name join. Runtime use accepts only boolean value edits in an otherwise
identical certified dictionary and selects exact value readers plus only those
derived-set invocations where that key's requiredness can affect validation.
Key-presence operations remain separately recorded but do not observe a value
edit; missing-required-key owners are retained globally to preserve possible
set-order effects. Both complete passing suite modes are required.

`tools/collect_predicate_values.py` and
`tools/build_predicate_profile.py` reproduce the still narrower ordering
predicate execution profile documented in `tools/PREDICATE_PROFILE.md`. It
contains every instrumented source site and all six observed boolean outcomes;
unsafe, unobserved, incomplete, or unattributed sites explicitly force fallback.
It is not filtered by a candidate edit and contains no replacement operators or
test ownership. Runtime use requires two distinct recorded comparison operators
whose old and new outcomes match across the raw profile, plus whole-file AST
equality after normalizing only that operator,
plus the ordinary compile, directive, import and function-binding gates.

`tools/collect_class_attribute_reads.py` and
`tools/build_class_attribute_model.py` reproduce the complete owner-aware
class-attribute reader profile documented in `tools/CLASS_ATTRIBUTE_PROFILE.md`.
Runtime MRO identity keeps same-named attributes on unrelated classes separate.
Only an otherwise identical same-type literal value edit at a safely observed
assignment can select its exact readers; import-time reads, mutation,
reflection ambiguity, or stale provenance force the ordinary broad fallback.

`tools/collect_module_constant_reads.py` and
`tools/build_module_constant_model.py` reproduce the complete owner-aware
module-literal reader profile documented in `tools/MODULE_CONSTANT_PROFILE.md`.
It resolves direct global reads, from-import aliases and re-exports, and
module-qualified reads in normal and synchronous-worker runs. Only an
otherwise identical same-type immutable literal edit at a safely observed
assignment selects its exact readers; mutable values, import-time reads,
rebinding, unresolved reflection/imports, or stale provenance force fallback.

`tools/collect_code_reflections.py` and
`tools/build_code_reflection_model.py` reproduce the unfiltered function-code
reflection profile documented in `tools/CODE_REFLECTION_PROFILE.md`. It adds
tests that inspect a function's code object even when they never execute the
changed body. Both normal and synchronous-worker traces are required, nested
function ranges compose conservatively, and stale or malformed provenance
falls back to all tests for function changes.

Local annotated assignments have a separate compile-backed proof. Python does
not evaluate or retain their annotation expressions, so an edit can be skipped
only when replacing that one annotation with a sentinel makes both complete
ASTs identical and their recursively compiled executable fingerprints match.
The fingerprint includes traceback/source positions as well as bytecode,
constants, names, bindings, and exception tables. Targets, values, directives,
class/module annotations, malformed or multi-hunk patches, and every other
simultaneous syntax change therefore retain the ordinary conservative path.
Function code-object readers are selected before this proof. The pinned suite's
only direct `sqlglot` source-text reader is `tests/test_typing.py`; it parses
typing modules solely to derive the parent `ImportFrom` module, which the full
AST comparison proves unchanged. `inspect.getsource`, `getsourcelines`, and
`findsource` are statically rejected by the reflection-profile builder.

## Submit

Push to a public GitHub repository with the `Dockerfile` at its top, then enter the repository and the commit hash on the track page. The final scores the commit you pick. If you pick none, your best practice submission counts.

## Rules

- Submit your own team's repository. A submission with the same repository, commit or archive as another team's is disqualified, the later one.
- Your build may download only from public package registries: PyPI, npm, Docker Hub, GitHub releases at a fixed tag, and sqlglot’s own repository at the pinned commit. Nothing from an address your team controls. The final rebuilds every image after the cutoff, so anything else could change a submission after the deadline.
- No answers worked out ahead of time and looked up by patch: no table from a patch, or from a kind of edit, to the tests it breaks. Maps built from the pinned commit (coverage, imports, fixtures) are allowed. Top entries are read.
- Only the final counts. The practice board carries no prize.

## How your image runs

- The build has the network, 4 cores, 8 GB of memory and 10 minutes. It may clone sqlglot at the pinned commit, install it and run its tests to make coverage or import maps.
- Your repository may hold 20 MB. Git submodules and Git LFS files are not fetched: clone sqlglot in the `Dockerfile` and commit maps as plain files.
- The run has no network, 2 cores, 4 GB of memory and 3 minutes for the whole batch (4.5 in the final, which has about one and a half times as many commits).
- The disk is read-only. `/tmp` holds 64 MB and is empty at the start of every run.
- The container runs as user `nobody`, with `HOME=/tmp` and at most 256 processes.
- stdout may hold 2 MB. More rejects the run.

## Things that will catch you

- Logs go to stderr. Any line on stdout that is not an answer rejects the run.
- `score.py` names a broken rule by its code, as in `Rejected: not_json on line 1`. The table in SCORING.md says what each code means.
- Files your program needs must be readable by `nobody`. A map written by `root` during the build with mode 600 is not.
- pytest 9 prints a test as `PASSED` beside `SUBFAILED` lines when one of its subtests fails. That test failed.
- sqlglot skips its executor tests unless `SKIP_INTEGRATION=0` is set. We labeled with it set, so those tests can fail.
- `requirements.lock` is every package in the environment we labeled in, on the image the `Dockerfile` starts from. To run sqlglot's tests the way we did, `pip install -r requirements.lock` and put the sqlglot checkout on `PYTHONPATH`; sqlglot's own `pip install -e .[dev]` picks newer versions.
- The scorer is linux/amd64. On an Apple Silicon Mac, build and run with `--platform linux/amd64`, as the Makefile does, or your timings and wheels will differ.
- A change that only adds a comment is not promised to be harmless.
