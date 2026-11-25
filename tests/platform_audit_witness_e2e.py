"""Run the durable audit witness with its own process, state, and signer."""

import base64
import hashlib
import json
import os
import secrets
import ssl
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

WRITER_ENV = "WITNESS_TEST_WRITER"
READER_ENV = "WITNESS_TEST_READER"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def event_digest(record):
    prefix = f"kgateway.audit.v1\0{record['tenant']}\0{record['sequence']}\0{record['previous']}\0".encode()
    return hashlib.sha256(prefix + canonical(record["event"])).hexdigest()


class Witness:
    def __init__(self, scratch, port, ca, cert, tls_key, fetch, process):
        self.port = port
        self.fetch = fetch
        self.process = process
        self.base = f"https://127.0.0.1:{port}"
        self.tls = ssl.create_default_context(cafile=str(ca))
        self.writer = secrets.token_urlsafe(32)
        self.reader = secrets.token_urlsafe(32)
        self.directory = scratch / "audit-witness"
        self.directory.mkdir(mode=0o700)
        key = Ed25519PrivateKey.generate()
        self.verifier = key.public_key()
        private = self.directory / "witness.key"
        private.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        private.chmod(0o600)
        public = self.directory / "witness.pem"
        public.write_bytes(
            self.verifier.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        self.config = self.directory / "witness.json"
        self.config.write_text(
            json.dumps(
                {
                    "bind": "127.0.0.1",
                    "port": port,
                    "state_file": "witness.sqlite",
                    "append_token_env": WRITER_ENV,
                    "audit_token_env": READER_ENV,
                    "tls": {"cert": str(cert), "key": str(tls_key)},
                    "signing_key_file": private.name,
                }
            )
        )
        self.settings = {
            "endpoint": self.base + "/v1/anchors",
            "token_env": WRITER_ENV,
            "ca_file": str(ca),
            "verification_key": str(public),
            "interval_seconds": 1,
        }

    def start(self, log):
        script = Path(__file__).resolve().parents[1] / "control-plane/witness.py"
        return self.process(
            sys.executable,
            [str(script), "--config", str(self.config)],
            self.directory / log,
            {**os.environ, WRITER_ENV: self.writer, READER_ENV: self.reader},
        )

    def call(self, path, token=None, **kwargs):
        return self.fetch(self.base + path, token, context=self.tls, **kwargs)

    def evidence(self, check_conflict=False):
        path = "/v1/anchors/tenant-test"
        assert self.call(path, self.writer)[0] == 401
        status, raw = self.call(path, self.reader)
        assert status == 200, (status, raw)
        page = json.loads(raw)
        rows, read = page["anchors"], page["read_receipt"]
        self.verifier.verify(
            base64.b64decode(read.pop("signature"), validate=True), canonical(read)
        )
        assert read["returned"] == len(rows) and read["tenant"] == "tenant-test", read
        assert rows
        for row in rows:
            record, receipt = row["record"], dict(row["receipt"])
            self.verifier.verify(
                base64.b64decode(receipt.pop("signature"), validate=True),
                canonical(receipt),
            )
            assert record["digest"] == event_digest(record) == receipt["digest"]
            assert record["tenant"] == receipt["tenant"] == "tenant-test"
        if check_conflict:
            original = rows[0]["record"]
            changed = original | {"event": original["event"] | {"actor": "changed"}}
            changed["digest"] = event_digest(changed)
            headers = {"Content-Type": "application/json"}
            assert (
                self.call(
                    "/v1/anchors", self.writer, data=canonical(changed), headers=headers
                )[0]
                == 409
            )
            status, raw = self.call(
                "/v1/anchors", self.writer, data=canonical(original), headers=headers
            )
            assert status == 200 and json.loads(raw) == rows[0]["receipt"], (
                status,
                raw,
            )
        return rows
