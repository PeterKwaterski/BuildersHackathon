#!/usr/bin/env python3
"""Run representative accepted contracts through the complete official test."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ORIGINAL = """        if self.max_nodes > -1:
            self._node_count += 1
            if self._node_count > self.max_nodes:
                self.raise_error(f\"Maximum number of AST nodes ({self.max_nodes}) exceeded\")"""


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tree", type=Path, default=Path("/opt/sqlglot"))
    return parser.parse_args()


def main() -> None:
    args = arguments()
    source = (args.tree / "sqlglot/parser.py").read_text()
    cases = {
        "inclusive-limit": ORIGINAL.replace(
            "if self._node_count > self.max_nodes:",
            "if self._node_count >= self.max_nodes:",
        ),
        "increment-two": ORIGINAL.replace("self._node_count += 1", "self._node_count += 2"),
        "guard-zero": ORIGINAL.replace("if self.max_nodes > -1:", "if self.max_nodes >= 0:"),
        "message-extension": ORIGINAL.replace(
            " exceeded\")",
            " exceeded; Maximum number of AST nodes ({self.max_nodes})\")",
        ),
    }
    for name, block in cases.items():
        with tempfile.TemporaryDirectory(prefix=f"max-nodes-{name}-") as temporary:
            tree = Path(temporary) / "sqlglot"
            shutil.copytree(args.tree, tree, copy_function=os.symlink)
            parser_path = tree / "sqlglot/parser.py"
            parser_path.unlink()
            changed = source.replace(ORIGINAL, block)
            if changed == source:
                raise SystemExit(f"{name}: source mutation did not apply")
            parser_path.write_text(changed)
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(tree)
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-q",
                    "tests/test_parser.py::TestParser::test_max_nodes",
                ],
                cwd=tree,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=120,
                check=False,
                text=True,
            )
            if completed.returncode != 0:
                raise SystemExit(f"{name}: official test failed\n{completed.stdout[-4000:]}")
            print(f"{name}: official test passed")


if __name__ == "__main__":
    main()
