#!/usr/bin/env python3
"""Synthetic regressions for function-default call-site token matching."""

from __future__ import annotations

import ast
import types

from collect_function_defaults import (
    CALLABLE_NAME,
    ENTER_NAME,
    REFLECT_NAME,
    TRACKER_TEMPLATE,
    Instrumenter,
)


SOURCE = """
import functools

def candidate(x=5, y=7): return x + y
def keyword(x=2, *, flag=True): return x if flag else 0
def positional_only(x=4, /, **kwargs): return x
def raises(): raise ValueError()
def dispatch(target, argument):
    try: return target(argument())
    except (ValueError, TypeError): return None
def recursive(n, marker=None): return marker if n == 0 else recursive(n - 1)

class Methods:
    def bound(self, x=1): return x
    @classmethod
    def classed(cls, x=1): return x
    @staticmethod
    def static(x=1): return x

class Meta(type):
    def __call__(cls, *args, **kwargs): return super().__call__()
class Constructed(metaclass=Meta):
    def __init__(self, item=3): self.item = item

class PartialSubclass(functools.partial):
    def __call__(self, *args, **kwargs): return self.func()

def explicit_cases():
    candidate(1, 2); keyword(2, flag=False); positional_only(2)
    methods = Methods()
    methods.bound(2); methods.classed(2); methods.static(2)
def omitted_cases():
    candidate(); keyword(); recursive(2)
    methods = Methods()
    methods.bound(); methods.classed(); methods.static()
def positional_only_cases():
    positional_only(x=9); functools.partial(positional_only, x=9)()
def starred_cases():
    arguments = (1, 2); candidate(*arguments)
def stale_native_cases():
    dispatch(candidate, raises)
    native = functools.partial(sorted, key=candidate)
    dispatch(native, lambda: [2, 1])
def constructor_case(): Constructed(99)
def partial_subclass_case(): PartialSubclass(candidate)(99)
"""


PARAMETERS = {
    "candidate": (("x", "positional", 0), ("y", "positional", 1)),
    "keyword": (("x", "positional", 0), ("flag", "keyword", None)),
    "positional_only": (("x", "positional-only", 0),),
    "recursive": (("marker", "positional", 1),),
    "Methods.bound": (("x", "positional", 1),),
    "Methods.classed": (("x", "positional", 1),),
    "Methods.static": (("x", "positional", 0),),
    "Constructed.__init__": (("item", "positional", 1),),
}


def definitions(tree: ast.Module):
    result = []

    def visit(body, prefix=()):
        for node in body:
            if isinstance(node, ast.ClassDef):
                visit(node.body, (*prefix, node.name))
            elif isinstance(node, ast.FunctionDef):
                qualname = ".".join((*prefix, node.name))
                if qualname in PARAMETERS:
                    result.append((node, qualname))
                visit(node.body, (*prefix, node.name, "<locals>"))

    visit(tree.body)
    return result


def main() -> None:
    tree = ast.parse(SOURCE)
    ids = {}
    records = {}
    for function, qualname in definitions(tree):
        function_id = f"synthetic.py:{function.lineno}:{qualname}"
        ids[(function.lineno, function.name)] = function_id
        records[("synthetic", qualname)] = {
            "id": function_id,
            "params": [
                {
                    "label": f"{qualname}:{name}",
                    "name": name,
                    "kind": kind,
                    "index": index,
                }
                for name, kind, index in PARAMETERS[qualname]
            ],
        }

    tracker = TRACKER_TEMPLATE.replace("__FUNCTIONS__", repr(records))
    tracker = tracker.replace("__CALLABLE_NAME__", CALLABLE_NAME)
    tracker = tracker.replace("__ENTER_NAME__", ENTER_NAME)
    tracker = tracker.replace("__REFLECT_NAME__", REFLECT_NAME)
    trace = types.ModuleType("_synthetic_trace")
    exec(tracker, trace.__dict__)

    changed = Instrumenter(ids).visit(tree)
    ast.fix_missing_locations(changed)
    namespace = {"__name__": "synthetic"}
    exec(compile(ast.unparse(changed), "synthetic.py", "exec"), namespace)

    def reset(owner):
        trace.EVENTS.clear()
        trace.CURRENT_TEST = owner

    reset("explicit")
    namespace["explicit_cases"]()
    assert not any("reader" in events for events in trace.EVENTS.values()), {
        label: dict(events) for label, events in trace.EVENTS.items()
    }

    reset("omitted")
    namespace["omitted_cases"]()
    assert all(events["reader"] == {"omitted"} for events in trace.EVENTS.values())

    reset("positional-only-keyword")
    namespace["positional_only_cases"]()
    assert trace.EVENTS["positional_only:x"]["reader"] == {
        "positional-only-keyword"
    }

    reset("starred")
    namespace["starred_cases"]()
    assert trace.EVENTS["candidate:x"]["reader"] == {"starred"}
    assert trace.EVENTS["candidate:y"]["reader"] == {"starred"}

    reset("stale-native")
    namespace["stale_native_cases"]()
    assert trace.EVENTS["candidate:x"]["opaque"] == {"stale-native"}
    assert trace.EVENTS["candidate:y"]["reader"] == {"stale-native"}

    reset("constructor")
    namespace["constructor_case"]()
    assert trace.EVENTS["Constructed.__init__:item"]["reader"] == {"constructor"}

    reset("partial-subclass")
    namespace["partial_subclass_case"]()
    assert trace.EVENTS["candidate:x"]["reader"] == {"partial-subclass"}
    assert trace.EVENTS["candidate:y"]["reader"] == {"partial-subclass"}
    print("function-default tracer synthetic regressions passed")


if __name__ == "__main__":
    main()
