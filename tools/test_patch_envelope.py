import gzip
import json
import tempfile
import unittest
from pathlib import Path
import sys
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent))
import selector


PATH = "sqlglot/fake.py"


def existing_patch(
    *, path=PATH, header=(), index_before=True, old_marker=None, hunk=None
):
    old_marker = old_marker or f"--- a/{path}"
    hunk = hunk or (
        "@@ -1,1 +1,1 @@",
        "-VALUE = 1",
        "+VALUE = 2",
    )
    markers = [old_marker, f"+++ b/{path}"]
    index = "index 1111111..2222222 100644"
    lines = [f"diff --git a/{path} b/{path}", *header]
    lines.extend(([index, *markers] if index_before else [*markers, index]))
    lines.extend(hunk)
    return ("\n".join(lines) + "\n").encode()


def new_patch():
    path = "tests/test_fresh_envelope.py"
    return (
        f"diff --git a/{path} b/{path}\n"
        "new file mode 100644\n"
        "index 0000000..2222222\n"
        "--- /dev/null\n"
        f"+++ b/{path}\n"
        "@@ -0,0 +1,1 @@\n"
        "+VALUE = 1\n"
    ).encode()


def delete_patch():
    path = "tests/fixtures/fresh.sql"
    return (
        f"diff --git a/{path} b/{path}\n"
        "deleted file mode 100644\n"
        "index 0000000..2222222\n"
        f"--- a/{path}\n"
        "+++ /dev/null\n"
        "@@ -1,1 +0,0 @@\n"
        "-SELECT 1;\n"
    ).encode()


def rename_patch():
    old = "sqlglot/old_name.py"
    new = "sqlglot/new_name.py"
    return (
        f"diff --git a/{old} b/{new}\n"
        "similarity index 100%\n"
        f"rename from {old}\n"
        f"rename to {new}\n"
    ).encode()


class CanonicalPatchEnvelopeTests(unittest.TestCase):
    def changes(self, raw):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "change.patch"
            path.write_bytes(raw)
            return selector.patch_changes(path)

    def assert_rejected(self, raw):
        changes = self.changes(raw)
        self.assertFalse(selector.canonical_text_changes(changes))
        self.assertEqual(
            selector.selected_indices(
                Path("unused.patch"), {"t": []}, {0, 1}, parsed_changes=changes
            ),
            {0, 1},
        )

    def test_accepts_canonical_existing_and_new_text_diffs(self):
        self.assertTrue(selector.canonical_text_changes(self.changes(existing_patch())))
        self.assertTrue(selector.canonical_text_changes(self.changes(new_patch())))
        self.assertTrue(selector.canonical_text_changes(self.changes(delete_patch())))
        self.assertTrue(selector.canonical_text_changes(self.changes(rename_patch())))

    def test_rejects_noncanonical_delete_and_rename_envelopes(self):
        for raw in (
            delete_patch().replace(b"deleted file mode 100644", b"deleted file mode 100755"),
            delete_patch().replace(b"+++ /dev/null", b"+++ b/tests/fixtures/fresh.sql"),
            delete_patch().replace(b"@@ -1,1 +0,0 @@", b"@@ -1,1 +1,0 @@"),
            delete_patch().replace(
                b"@@ -1,1 +0,0 @@\n-SELECT 1;",
                b"@@ -1,1 +1,1 @@\n-SELECT 1;\n+SELECT 2;",
            ),
            delete_patch().replace(
                b"@@ -1,1 +0,0 @@\n-SELECT 1;",
                b"@@ -1,2 +1,1 @@\n-SELECT 1;\n SELECT 2;",
            ),
            rename_patch().replace(b"similarity index 100%", b"similarity index 99%"),
            rename_patch().replace(b"rename to sqlglot/new_name.py", b"rename to sqlglot/other.py"),
            rename_patch() + b"NONSENSE\n",
        ):
            with self.subTest(raw=raw[:100]):
                self.assert_rejected(raw)

    def test_rejects_raw_and_metadata_envelope_variants(self):
        for raw in (
            existing_patch().replace(b"\n", b"\r\n"),
            existing_patch()[:-1],
            existing_patch(header=("old mode 100755", "new mode 100644")),
            existing_patch(header=("index 3333333..4444444 100644",)),
            existing_patch(header=("NONSENSE METADATA",)),
            b"\n" + existing_patch(),
            b"preamble\n" + existing_patch(),
            existing_patch(index_before=False),
            existing_patch(old_marker=f"--- a/{PATH}\t1970-01-01"),
            existing_patch(
                hunk=("@@ -1,99 +1,1 @@", "-VALUE = 1", "+VALUE = 2")
            ),
            existing_patch(
                hunk=("@@ -1,1 +2,1 @@", "-VALUE = 1", "+VALUE = 2")
            ),
        ):
            with self.subTest(raw=raw[:80]):
                self.assert_rejected(raw)

    def test_rejects_unknown_blank_and_binary_headers(self):
        self.assert_rejected(existing_patch(header=("",)))
        self.assert_rejected(existing_patch(header=("GIT binary patch",)))

    def test_invalid_utf8_fails_only_this_patch_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.patch"
            path.write_bytes(b"diff --git a/x b/x\n\xff\n")
            self.assertEqual(
                selector.selected_indices(path, {"t": []}, {3, 4}),
                {3, 4},
            )

    def test_query_shortcut_requires_common_canonical_envelope(self):
        query_path = "sqlglot/expressions/query.py"
        valid = self.changes(existing_patch(path=query_path))
        with (
            mock.patch.object(selector, "pinned_sources", return_value={query_path: "VALUE = 1\n"}),
            mock.patch.object(
                selector.query_modifier_research, "readers", return_value={1}
            ) as readers,
        ):
            self.assertEqual(
                selector.selected_indices(
                    Path("unused.patch"),
                    {"t": []},
                    {0, 1, 2},
                    parsed_changes=valid,
                    query_modifier_model={},
                ),
                {1},
            )
            self.assertEqual(readers.call_count, 1)
        for raw in (
            existing_patch(path=query_path).replace(b"\n", b"\r\n"),
            existing_patch(
                path=query_path,
                header=("old mode 100755", "new mode 100644"),
            ),
            existing_patch(
                path=query_path,
                header=("index 3333333..4444444 100644",),
            ),
        ):
            changes = self.changes(raw)
            with mock.patch.object(
                selector.query_modifier_research,
                "readers",
                side_effect=AssertionError("shortcut reached"),
            ):
                self.assertEqual(
                    selector.selected_indices(
                        Path("unused.patch"),
                        {"t": []},
                        {0, 1, 2},
                        parsed_changes=changes,
                        query_modifier_model={},
                    ),
                    {0, 1, 2},
                )

    def test_rename_never_enters_single_file_semantic_shortcuts(self):
        changes = self.changes(rename_patch())
        root = Path(__file__).resolve().parents[1]
        with gzip.open(root / "selector_model.json.gz", "rt") as stream:
            model = json.load(stream)
        model["h"] = set(model.get("h", ()))
        all_indices = set(range(len(model["t"])))
        with (
            mock.patch.object(
                selector.query_modifier_research,
                "readers",
                side_effect=AssertionError("query shortcut reached"),
            ),
            mock.patch.object(
                selector.registry_key_research,
                "readers",
                side_effect=AssertionError("registry shortcut reached"),
            ),
            mock.patch.object(
                selector,
                "match_none_static",
                side_effect=AssertionError("none shortcut reached"),
            ),
        ):
            self.assertEqual(
                selector.selected_indices(
                    Path("unused.patch"),
                    model,
                    all_indices,
                    parsed_changes=changes,
                    query_modifier_model={},
                    registry_key_model={"d": {}},
                    none_static_profile={},
                ),
                all_indices,
            )


if __name__ == "__main__":
    unittest.main()
