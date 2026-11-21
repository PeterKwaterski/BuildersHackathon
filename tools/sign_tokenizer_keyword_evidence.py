#!/usr/bin/env python3
"""Sign a reviewed tokenizer evidence index with the external private key."""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import tempfile
from pathlib import Path

from tokenizer_keyword_signature import canonical, review_statement


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = arguments()
    repository = Path(__file__).resolve().parents[1]
    private_key = args.private_key.expanduser().resolve()
    if private_key.is_relative_to(repository) or not private_key.is_file():
        raise SystemExit("private review key must be an existing external file")
    if private_key.stat().st_mode & 0o077:
        raise SystemExit("private review key permissions must be owner-only")
    public_key = Path(__file__).with_name("tokenizer_keyword_review_public.pem")
    derived = subprocess.check_output(
        ["/usr/bin/openssl", "pkey", "-in", str(private_key), "-pubout"]
    )
    if derived != public_key.read_bytes():
        raise SystemExit("private review key does not match the pinned public key")
    index_raw = args.index.read_bytes()
    index = json.loads(index_raw)
    statement = review_statement(index_raw, index)
    with tempfile.TemporaryDirectory(prefix="br-keyword-signature-") as temporary:
        root = Path(temporary)
        statement_path = root / "statement.json"
        signature_path = root / "signature.bin"
        statement_path.write_bytes(canonical(statement))
        subprocess.run(
            [
                "/usr/bin/openssl", "pkeyutl", "-sign", "-inkey",
                str(private_key), "-rawin", "-in", str(statement_path),
                "-out", str(signature_path),
            ],
            check=True,
            env={
                "PATH": "/usr/bin:/bin",
                "HOME": str(private_key.parent),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            },
        )
        signature = signature_path.read_bytes()
    if len(signature) != 64:
        raise SystemExit("unexpected Ed25519 signature length")
    document = {
        "schema": 1,
        "algorithm": "Ed25519",
        "statement": statement,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    args.output.write_bytes(canonical(document))
    print(statement["index_sha256"])


if __name__ == "__main__":
    main()
