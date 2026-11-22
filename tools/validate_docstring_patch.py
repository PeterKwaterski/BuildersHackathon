"""Answer-free exact-image validation for a docstring research patch."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, "/app")

import selector


selection_file = Path(sys.argv[2])
selection_commit = sys.argv[3]
tests_file = Path(sys.argv[4])

for patch_name in sys.argv[1].split(","):
    changes = selector.patch_changes(Path(patch_name))
    assert len(changes) == 1
    change = changes[0]
    relative = change["old"]
    source = selector.patched_source(change, relative)
    assert source is not None
    (Path("/app/sqlglot-pinned") / relative).write_text(source, encoding="utf-8")

tests = json.loads(tests_file.read_text(encoding="utf-8"))["tests"]
test_by_number = {test["number"]: test["id"] for test in tests}
if selection_commit == "ALL":
    numbers = list(test_by_number)
else:
    selection = None
    for line in selection_file.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if row["commit"] == selection_commit:
            selection = row
            break
    assert selection is not None
    numbers = [number for worker in selection["workers"] for number in worker]
ids = [test_by_number[number] for number in numbers]
raise SystemExit(
    subprocess.call(
        [sys.executable, "-m", "pytest", "-q", *ids],
        cwd="/app/sqlglot-pinned",
    )
)
