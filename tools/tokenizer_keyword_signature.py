"""Canonical detached Ed25519 review statements for tokenizer evidence."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path


DOMAIN = "builders-blast-radius/tokenizer-keyword-evidence/v1"
PUBLIC_KEY_SHA256 = "f0f956bbebd967a450e025fb1c18a52562ac123554024770d84e28a2d125b4c4"


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def review_statement(index_raw: bytes, index: dict) -> dict:
    pins = index.get("pins") if isinstance(index, dict) else None
    argv = index.get("collection_argv") if isinstance(index, dict) else None
    if not isinstance(pins, dict) or not isinstance(argv, dict):
        raise SystemExit("cannot form review statement from malformed index")
    return {
        "schema": 1,
        "domain": DOMAIN,
        "purpose": index.get("purpose"),
        "index_sha256": hashlib.sha256(index_raw).hexdigest(),
        "image_id": pins.get("image_id"),
        "python_environment_sha256": pins.get("python_environment_sha256"),
        "collection_argv_sha256": hashlib.sha256(canonical(argv)).hexdigest(),
        "public_key_sha256": PUBLIC_KEY_SHA256,
    }


def verify_signature(index_path: Path, signature_path: Path, public_key: Path) -> dict:
    if public_key.resolve() != Path(__file__).with_name(
        "tokenizer_keyword_review_public.pem"
    ).resolve():
        raise SystemExit("review public key path is not the pinned repository path")
    if hashlib.sha256(public_key.read_bytes()).hexdigest() != PUBLIC_KEY_SHA256:
        raise SystemExit("review public key digest mismatch")
    index_raw = index_path.read_bytes()
    index = json.loads(index_raw)
    document = json.loads(signature_path.read_text())
    expected_statement = review_statement(index_raw, index)
    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "algorithm", "statement", "signature"}
        or document.get("schema") != 1
        or document.get("algorithm") != "Ed25519"
        or document.get("statement") != expected_statement
        or type(document.get("signature")) is not str
    ):
        raise SystemExit("malformed or mismatched review signature document")
    try:
        signature = base64.b64decode(document["signature"], validate=True)
    except Exception as error:
        raise SystemExit("invalid review signature encoding") from error
    if len(signature) != 64 or base64.b64encode(signature).decode() != document["signature"]:
        raise SystemExit("noncanonical Ed25519 signature")
    with tempfile.TemporaryDirectory(prefix="br-keyword-signature-verify-") as temporary:
        root = Path(temporary)
        statement_path = root / "statement.json"
        signature_raw = root / "signature.bin"
        statement_path.write_bytes(canonical(expected_statement))
        signature_raw.write_bytes(signature)
        result = subprocess.run(
            [
                "/usr/bin/openssl", "pkeyutl", "-verify", "-pubin",
                "-inkey", str(public_key), "-rawin", "-in", str(statement_path),
                "-sigfile", str(signature_raw),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    if result.returncode != 0:
        raise SystemExit("Ed25519 review signature verification failed")
    return index
