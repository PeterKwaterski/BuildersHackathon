"""List public patch-only candidates for the directive-comment proof."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
import selector


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    for patch in sorted(args.root.glob("*/commits/*.patch")):
        changes = selector.patch_changes(patch)
        if len(changes) != 1:
            continue
        change = changes[0]
        path = change.get("old")
        if (
            isinstance(path, str)
            and selector.comment_only_addition(change)
            and any(selector.COMMENT_DIRECTIVE.search(line) for line in change["added"])
            and selector.inert_comment_addition(change, path)
        ):
            print(f"{patch.parent.parent.name}\t{patch.stem}\t{path}")


if __name__ == "__main__":
    main()
