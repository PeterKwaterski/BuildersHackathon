#!/usr/bin/env python3
"""Build the unfiltered owner-aware literal function-default profile."""

from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import json
import subprocess
from collections import defaultdict
from pathlib import Path

from collect_dict_access import validate_source
from collect_function_defaults import safe_literal, source_labels
from collect_function_default_imports import module_names, tasks as import_tasks


PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"

SUITE_MANIFEST_KEYS = {
    "child_complete",
    "child_logs",
    "child_starts",
    "child_tokens_sha256",
    "collector_sha256",
    "dependency_sha256",
    "exitstatus",
    "instrumented",
    "instrumented_tree_sha256",
    "mode",
    "pytest_args_sha256",
    "python",
    "source_sha",
    "support_sha256",
    "test_digest",
    "tests",
    "trace_sha256",
}
SYNC_INSTRUMENTATION_DELTA = 11


def sha256_text(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def valid_suite_provenance(
    record: dict,
    collector_digest: str,
    dependency_digest: str,
    pytest_args_digest: str,
) -> bool:
    return (
        isinstance(record, dict)
        and set(record) == SUITE_MANIFEST_KEYS
        and record.get("collector_sha256") == collector_digest
        and record.get("dependency_sha256") == dependency_digest
        and type(record.get("instrumented")) is int
        and record["instrumented"] > 0
        and sha256_text(record.get("instrumented_tree_sha256"))
        and record.get("pytest_args_sha256") == pytest_args_digest
        and sha256_text(record.get("support_sha256"))
    )


def expected_instrumented_sites(
    source: Path, root_names: tuple[str, ...] = ("sqlglot", "tests")
) -> int:
    calls = 0
    for root_name in root_names:
        for path in sorted((source / root_name).rglob("*.py")):
            tree = ast.parse(path.read_text(), filename=path.as_posix(), type_comments=True)
            calls += sum(isinstance(node, ast.Call) for node in ast.walk(tree))
    entry_sites = {
        (
            record["id"].split(":", 2)[0],
            int(record["id"].split(":", 2)[1]),
            record["id"].split(":", 2)[2].rsplit(".", 1)[-1],
        )
        for record in source_labels(source).values()
    }
    return calls + len(entry_sites)


def valid_instrumentation_counts(
    normal: dict, synchronous: dict, expected_normal: int
) -> bool:
    return (
        type(normal.get("instrumented")) is int
        and type(synchronous.get("instrumented")) is int
        and normal["instrumented"] == expected_normal
        and synchronous["instrumented"]
        == expected_normal + SYNC_INSTRUMENTATION_DELTA
    )


def valid_import_provenance(
    record: dict,
    collector_digest: str,
    dependency_digest: str,
    instrumenter_digest: str,
    expected_instrumented: int,
) -> bool:
    return (
        isinstance(record, dict)
        and record.get("collector_sha256") == collector_digest
        and record.get("dependency_sha256") == dependency_digest
        and type(record.get("instrumented")) is int
        and record["instrumented"] == expected_instrumented
        and record.get("instrumenter_sha256") == instrumenter_digest
        and sha256_text(record.get("instrumented_tree_sha256"))
        and sha256_text(record.get("support_sha256"))
    )


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, action="append", required=True)
    parser.add_argument("--trace", type=Path, action="append", required=True)
    parser.add_argument("--import-manifest", type=Path, required=True)
    parser.add_argument("--import-trace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def write_model(output: Path, payload: dict) -> None:
    """Write a path-independent, byte-reproducible gzip artifact."""
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    with output.open("wb") as raw_output:
        with gzip.GzipFile(
            filename="", fileobj=raw_output, mode="wb", compresslevel=9, mtime=0
        ) as compressed:
            compressed.write(raw)


def inventory(source: Path):
    runtime = source_labels(source)
    for path in sorted((source / "sqlglot").rglob("*.py")):
        relative = path.relative_to(source).as_posix()
        module = relative.removesuffix("/__init__.py").removesuffix(".py").replace("/", ".")
        tree = ast.parse(path.read_text(), filename=relative, type_comments=True)

        def visit(body: list[ast.stmt], prefix: tuple[str, ...], owner_decorated=False):
            for statement in body:
                if isinstance(statement, ast.ClassDef):
                    yield from visit(
                        statement.body,
                        (*prefix, statement.name),
                        owner_decorated or bool(statement.decorator_list),
                    )
                    continue
                if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                qualname = ".".join((*prefix, statement.name))
                runtime_record = runtime.get((module, qualname))
                decorators = {
                    decorator.id
                    for decorator in statement.decorator_list
                    if isinstance(decorator, ast.Name)
                }
                custom_decorator = bool(statement.decorator_list) and (
                    len(decorators) != len(statement.decorator_list)
                    or not decorators.issubset({"staticmethod", "classmethod"})
                )
                positional = [*statement.args.posonlyargs, *statement.args.args]
                aligned = [None] * (len(positional) - len(statement.args.defaults)) + list(
                    statement.args.defaults
                )
                defaults = [
                    (
                        argument,
                        default,
                        "positional-only"
                        if index < len(statement.args.posonlyargs)
                        else "positional",
                        index,
                    )
                    for index, (argument, default) in enumerate(zip(positional, aligned))
                    if default is not None
                ]
                defaults.extend(
                    (argument, default, "keyword", None)
                    for argument, default in zip(
                        statement.args.kwonlyargs, statement.args.kw_defaults
                    )
                    if default is not None
                )
                for argument, default, kind, index in defaults:
                    try:
                        value = ast.literal_eval(default)
                    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                        continue
                    if not safe_literal(value):
                        continue
                    label = None
                    if runtime_record:
                        label = next(
                            (
                                parameter["label"]
                                for parameter in runtime_record["params"]
                                if parameter["name"] == argument.arg
                                and parameter["kind"] == kind
                                and parameter["index"] == index
                            ),
                            None,
                        )
                    yield (
                        relative,
                        statement,
                        qualname,
                        argument.arg,
                        default,
                        label,
                        owner_decorated or custom_decorator,
                    )
                yield from visit(
                    statement.body,
                    (*prefix, statement.name, "<locals>"),
                    owner_decorated or custom_decorator,
                )

        yield from visit(tree.body, ())


def main() -> None:
    args = arguments()
    if len(args.manifest) < 2 or len(args.trace) < 2:
        raise SystemExit("normal and synchronous-worker traces are required")
    source = args.source.resolve()
    validate_source(source)
    revision = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    if revision != PINNED_SHA:
        raise SystemExit(f"source is {revision}, expected {PINNED_SHA}")
    collector_digest = hashlib.sha256(
        Path(__file__).with_name("collect_function_defaults.py").read_bytes()
    ).hexdigest()
    dependency_digest = hashlib.sha256(
        Path(__file__).with_name("collect_dict_access.py").read_bytes()
    ).hexdigest()
    pytest_args_digest = hashlib.sha256(b"[]").hexdigest()
    expected_instrumented = expected_instrumented_sites(source)
    expected_import_instrumented = expected_instrumented_sites(
        source, ("sqlglot",)
    )
    test_document = json.loads(args.tests.read_text())
    tests = test_document["tests"]
    test_ids = [test["id"] for test in tests]
    test_index = {test_id: index for index, test_id in enumerate(test_ids)}
    expected = set(test_ids)
    skipped = set(test_document.get("skipped", ()))
    expected_executed = expected | skipped
    test_digest = hashlib.sha256("\0".join(test_ids).encode()).hexdigest()
    manifests = [json.loads(path.read_text()) for path in args.manifest]
    manifest_by_mode = {
        manifest.get("mode"): (path, manifest)
        for path, manifest in zip(args.manifest, manifests)
    }
    if set(manifest_by_mode) != {"normal", "synchronous-worker"} or len(manifests) != 2:
        raise SystemExit("exactly both trace modes are required")
    for path, manifest in manifest_by_mode.values():
        if (
            not valid_suite_provenance(
                manifest, collector_digest, dependency_digest, pytest_args_digest
            )
            or manifest.get("exitstatus") != 0
            or set(manifest.get("tests", ())) != expected_executed
            or not isinstance(manifest.get("child_logs"), int)
            or manifest["child_logs"] < 0
            or manifest.get("child_complete") is not True
            or manifest.get("child_starts") != manifest["child_logs"]
            or not isinstance(manifest.get("child_tokens_sha256"), str)
            or len(manifest["child_tokens_sha256"]) != 64
            or manifest.get("source_sha") != revision
            or manifest.get("test_digest") != test_digest
            or not isinstance(manifest.get("python"), str)
            or not manifest["python"].startswith("3.13.")
            or not isinstance(manifest.get("trace_sha256"), str)
            or len(manifest["trace_sha256"]) != 64
        ):
            raise SystemExit(f"inadmissible manifest {path}")
    if sum(manifest["child_logs"] for _, manifest in manifest_by_mode.values()) <= 0:
        raise SystemExit("trace pair lacks relevant child-process evidence")
    if len({manifest["python"] for _, manifest in manifest_by_mode.values()}) != 1:
        raise SystemExit("trace Python runtimes differ")
    if not valid_instrumentation_counts(
        manifest_by_mode["normal"][1],
        manifest_by_mode["synchronous-worker"][1],
        expected_instrumented,
    ):
        raise SystemExit("trace instrumentation count relation mismatch")
    if len({manifest["support_sha256"] for _, manifest in manifest_by_mode.values()}) != 1:
        raise SystemExit("trace support implementations differ")

    documents = []
    for path in args.trace:
        raw_trace = path.read_bytes()
        document = json.loads(raw_trace)
        mode = document.get("mode") if isinstance(document, dict) else None
        manifest_record = manifest_by_mode.get(mode)
        if (
            manifest_record is None
            or document.get("collector_sha256") != collector_digest
            or document.get("dependency_sha256") != dependency_digest
            or document.get("instrumented") != manifest_record[1].get("instrumented")
            or document.get("instrumented_tree_sha256")
            != manifest_record[1].get("instrumented_tree_sha256")
            or document.get("pytest_args_sha256") != pytest_args_digest
            or document.get("source_sha") != revision
            or document.get("support_sha256")
            != manifest_record[1].get("support_sha256")
            or document.get("test_digest") != test_digest
            or document.get("python") != manifest_record[1].get("python")
            or hashlib.sha256(raw_trace).hexdigest() != manifest_record[1]["trace_sha256"]
        ):
            raise SystemExit(f"trace/manifest provenance mismatch for {path}")
        documents.append(document)
    if {document.get("mode") for document in documents} != {"normal", "synchronous-worker"}:
        raise SystemExit("trace modes are incomplete")
    known_labels = {
        parameter["label"]
        for record in source_labels(source).values()
        for parameter in record["params"]
    }

    # A separate, fresh-process trace closes the lifecycle gap where a lazy
    # module import happens under a test owner and initializes shared module or
    # dialect-registry state.  Every default touched by import is globally
    # unsafe, regardless of the owner sets in the two suite traces.
    import_manifest_path = args.import_manifest.resolve()
    import_trace_path = args.import_trace.resolve()
    import_manifest = json.loads(import_manifest_path.read_text())
    import_trace_raw = import_trace_path.read_bytes()
    import_trace = json.loads(import_trace_raw)
    import_collector = Path(__file__).with_name("collect_function_default_imports.py")
    import_collector_digest = hashlib.sha256(import_collector.read_bytes()).hexdigest()
    instrumenter_digest = hashlib.sha256(
        Path(__file__).with_name("collect_function_defaults.py").read_bytes()
    ).hexdigest()
    declared_import_tasks = import_tasks(source)
    import_tasks_digest = hashlib.sha256(
        json.dumps(
            declared_import_tasks, sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()
    import_modules_digest = hashlib.sha256(
        "\0".join(module_names(source)).encode()
    ).hexdigest()
    import_tokens = sorted(
        hashlib.sha256(
            json.dumps(task, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        for task in declared_import_tasks
    )
    if set(import_manifest) != {
        "child_complete",
        "child_logs",
        "child_starts",
        "child_tokens_sha256",
        "collector_sha256",
        "dependency_sha256",
        "instrumented",
        "instrumenter_sha256",
        "instrumented_tree_sha256",
        "mode",
        "modules_sha256",
        "python",
        "source_sha",
        "support_sha256",
        "tasks_sha256",
        "trace_sha256",
    } or (
        not valid_import_provenance(
            import_manifest,
            import_collector_digest,
            dependency_digest,
            instrumenter_digest,
            expected_import_instrumented,
        )
        or import_manifest["child_complete"] is not True
        or import_manifest["child_logs"] != len(declared_import_tasks)
        or import_manifest["child_starts"] != len(declared_import_tasks)
        or import_manifest["child_tokens_sha256"]
        != hashlib.sha256("\0".join(import_tokens).encode()).hexdigest()
        or import_manifest["mode"] != "import-context"
        or import_manifest["modules_sha256"] != import_modules_digest
        or import_manifest["python"]
        != next(iter(manifest["python"] for manifest in manifests))
        or import_manifest["source_sha"] != revision
        or import_manifest["tasks_sha256"] != import_tasks_digest
        or import_manifest["trace_sha256"]
        != hashlib.sha256(import_trace_raw).hexdigest()
    ):
        raise SystemExit(f"inadmissible import manifest {import_manifest_path}")
    if set(import_trace) != {
        "collector_sha256",
        "dependency_sha256",
        "events",
        "instrumented",
        "instrumenter_sha256",
        "instrumented_tree_sha256",
        "mode",
        "modules_sha256",
        "python",
        "source_sha",
        "support_sha256",
        "tasks_sha256",
    } or (
        import_trace["collector_sha256"] != import_collector_digest
        or import_trace["dependency_sha256"] != dependency_digest
        or import_trace["instrumented"] != import_manifest["instrumented"]
        or import_trace["instrumenter_sha256"] != instrumenter_digest
        or import_trace["instrumented_tree_sha256"]
        != import_manifest["instrumented_tree_sha256"]
        or import_trace["mode"] != "import-context"
        or import_trace["modules_sha256"] != import_modules_digest
        or import_trace["python"] != import_manifest["python"]
        or import_trace["source_sha"] != revision
        or import_trace["support_sha256"] != import_manifest["support_sha256"]
        or import_trace["tasks_sha256"] != import_tasks_digest
        or not isinstance(import_trace["events"], dict)
        or not set(import_trace["events"]).issubset(known_labels)
    ):
        raise SystemExit(f"inadmissible import trace {import_trace_path}")
    allowed_kinds = {"call", "reader", "entered", "opaque", "reflect"}
    for label, events in import_trace["events"].items():
        if (
            not isinstance(events, dict)
            or not events
            or not set(events).issubset(allowed_kinds)
            or any(owners != ["__IMPORT__"] for owners in events.values())
        ):
            raise SystemExit(f"malformed import events for {label}")
    import_labels = set(import_trace["events"])

    for path, document in zip(args.trace, documents):
        if not isinstance(document, dict) or set(document) != {
            "collector_sha256",
            "dependency_sha256",
            "events",
            "instrumented",
            "instrumented_tree_sha256",
            "mode",
            "pytest_args_sha256",
            "python",
            "source_sha",
            "support_sha256",
            "test_digest",
        }:
            raise SystemExit(f"trace envelope mismatch in {path}")
        events_document = document["events"]
        if not isinstance(events_document, dict) or set(events_document) != known_labels:
            raise SystemExit(f"trace label inventory mismatch in {path}")
        for label, events in events_document.items():
            if not isinstance(events, dict) or not set(events).issubset(allowed_kinds):
                raise SystemExit(f"invalid event kinds for {label} in {path}")
            for kind, owners in events.items():
                if (
                    not isinstance(owners, list)
                    or any(type(owner) is not str for owner in owners)
                    or owners != sorted(set(owners))
                ):
                    raise SystemExit(f"malformed {kind} owners for {label} in {path}")
    unknown = {
        owner
        for document in documents
        for events in document["events"].values()
        for owners in events.values()
        for owner in owners
        if owner != "__NO_TEST__" and owner not in expected_executed
    }
    if unknown:
        raise SystemExit(f"trace contains {len(unknown)} unknown test owners")

    # The pinned tree has no direct default-tuple access. Calls spelled as
    # ``*.signature`` or ``*.getfullargspec`` are runtime-instrumented by the
    # collector; reject imported/aliased spellings which could evade it.
    reflective = []
    reflection_strings = {"__defaults__", "__kwdefaults__", "__signature__"}
    for root_name in ("sqlglot", "tests"):
        for path in sorted((source / root_name).rglob("*.py")):
            text = path.read_text()
            tree = ast.parse(text, filename=path.as_posix(), type_comments=True)

            # CPython folds string expressions such as ``"__" + "defaults__"``.
            # Inspect recursive code constants as well as the source AST so a
            # computed getattr/native reflector cannot hide a default reader.
            def compiled_strings(code):
                for constant in code.co_consts:
                    if type(constant) is str:
                        yield constant
                    elif isinstance(constant, type(code)):
                        yield from compiled_strings(constant)

            code = compile(text, path.as_posix(), "exec", dont_inherit=True, optimize=0)
            if any(
                marker in value
                for value in compiled_strings(code)
                for marker in reflection_strings
            ):
                reflective.append((path, 0, "compiled-default-name"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr in {
                    "__defaults__", "__kwdefaults__"
                }:
                    reflective.append((path, node.lineno, node.attr))
                if (
                    isinstance(node, ast.Constant)
                    and type(node.value) is str
                    and node.value in {"__defaults__", "__kwdefaults__", "__signature__"}
                ):
                    reflective.append((path, node.lineno, node.value))
                if isinstance(node, ast.ImportFrom) and node.module == "inspect" and any(
                    alias.name in {"signature", "getfullargspec"} for alias in node.names
                ):
                    reflective.append((path, node.lineno, "inspect-alias"))
                if (
                    isinstance(node, (ast.Assign, ast.AnnAssign))
                    and isinstance(node.value, ast.Attribute)
                    and node.value.attr in {"signature", "getfullargspec"}
                ):
                    reflective.append((path, node.lineno, "inspect-rebind"))
                if isinstance(node, ast.Call):
                    mock_consumer = (
                        isinstance(node.func, ast.Name)
                        and node.func.id
                        in {"Mock", "MagicMock", "NonCallableMock", "create_autospec", "patch"}
                    ) or (
                        isinstance(node.func, ast.Attribute)
                        and node.func.attr
                        in {"Mock", "MagicMock", "NonCallableMock", "create_autospec"}
                    ) or (
                        isinstance(node.func, ast.Attribute)
                        and node.func.attr == "object"
                        and isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "patch"
                    )
                    if (
                        isinstance(node.func, ast.Attribute)
                        and node.func.attr in {"from_callable", "create_autospec"}
                    ) or (
                        isinstance(node.func, ast.Name)
                        and node.func.id in {"help", "create_autospec"}
                    ):
                        reflective.append((path, node.lineno, "signature-consumer"))
                    if not mock_consumer:
                        continue
                    for keyword in node.keywords:
                        if keyword.arg not in {"spec", "spec_set"}:
                            continue
                        try:
                            spec = ast.literal_eval(keyword.value)
                        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                            spec = None
                        if not (
                            isinstance(spec, (str, list, tuple, set, frozenset))
                            and all(type(item) is str for item in ([spec] if type(spec) is str else spec))
                        ):
                            reflective.append((path, node.lineno, "mock-function-spec"))
    if reflective:
        raise SystemExit(f"direct function-default reflection exists: {reflective[0]}")

    autospec_names = set()
    for path in sorted((source / "tests").rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=path.as_posix(), type_comments=True)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            autospec = next(
                (keyword.value for keyword in node.keywords if keyword.arg == "autospec"),
                None,
            )
            if autospec is None:
                continue
            if not isinstance(autospec, ast.Constant) or autospec.value is not True:
                raise SystemExit(f"unsupported autospec expression at {path}:{node.lineno}")
            target = None
            if (
                len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and type(node.args[1].value) is str
            ):
                target = node.args[1].value
            elif (
                node.args
                and isinstance(node.args[0], ast.Constant)
                and type(node.args[0].value) is str
            ):
                target = node.args[0].value.rsplit(".", 1)[-1]
            if not target:
                raise SystemExit(f"unresolved autospec target at {path}:{node.lineno}")
            autospec_names.add(target)

    profile: dict[str, list[list]] = defaultdict(list)
    states = defaultdict(int)
    for relative, function, qualname, name, default, label, static_unsafe in inventory(source):
        observations = [
            document["events"].get(label) if label else None
            for document in documents
        ]
        owners = set()
        kinds = set()
        for events in observations:
            if not events:
                continue
            kinds.update(events)
            for values in events.values():
                owners.update(values)
        if label in import_labels:
            state = "import-read"
        elif static_unsafe or qualname.rsplit(".", 1)[-1] in autospec_names:
            state = "static-unsafe"
        elif label is None:
            state = "ambiguous"
        elif any(events is None for events in observations):
            state = "incomplete" if owners else "unobserved"
        elif "__NO_TEST__" in owners:
            state = "import-read"
        elif not owners or "call" not in kinds:
            state = "unobserved"
        else:
            state = "safe"
        readers = sorted(
            test_index[owner]
            for events in observations
            if events
            for owner in events.get("reader", ())
            if owner in test_index
        )
        profile[relative].append([
            default.lineno,
            default.end_lineno or default.lineno,
            function.lineno,
            qualname,
            name,
            ast.dump(default, include_attributes=False),
            state,
            sorted(set(readers)),
        ])
        states[state] += 1

    ordered = {
        path: sorted(values, key=lambda entry: (entry[0], entry[3], entry[4]))
        for path, values in sorted(profile.items())
    }
    profile_digest = hashlib.sha256(
        json.dumps(ordered, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    payload = {
        "d": ordered,
        "n": len(test_ids),
        "p": profile_digest,
        "sha": revision,
        "t": hashlib.sha256("\0".join(test_ids).encode()).hexdigest(),
        "v": 1,
    }
    write_model(args.output, payload)
    print(
        f"wrote {sum(map(len, ordered.values()))} function-default entries: "
        + ", ".join(f"{key}={value}" for key, value in sorted(states.items()))
    )
    print(f"profile {profile_digest}")


if __name__ == "__main__":
    main()
