"""Run the independent audit witness and its read-only recovery endpoint."""

import argparse
import base64
import hmac
import ipaddress
import json
import os
import socket
import sqlite3
import ssl
from contextlib import closing
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from audit_anchor import TENANT, canonical, receipt_body, validate
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from recovery_protocol import (
    CHALLENGE,
    CHECKPOINT_PATH,
    CLAIM_PATH,
    STATUS,
    heads_digest,
    validate_checkpoint,
    validate_claim,
)


class AnchorConflict(ValueError):
    pass


class Archive:
    def __init__(self, state_file, key):
        self.state_file = state_file
        self.key = key
        fd = os.open(state_file, os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        if state_file.stat().st_mode & 0o077:
            raise ValueError("audit witness state must be restricted to its owner")
        with closing(self.connect()) as db:
            db.execute("PRAGMA journal_mode = WAL")
            db.execute("""CREATE TABLE IF NOT EXISTS anchors (
                tenant TEXT NOT NULL, sequence INTEGER NOT NULL, digest TEXT NOT NULL,
                previous TEXT NOT NULL, record BLOB NOT NULL, receipt BLOB NOT NULL,
                PRIMARY KEY (tenant, sequence)
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS audit_reads (
                id INTEGER PRIMARY KEY, tenant TEXT NOT NULL, cursor INTEGER NOT NULL,
                read_at TEXT NOT NULL, returned INTEGER NOT NULL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS recovery_checkpoints (
                revision INTEGER PRIMARY KEY, archive_sha256 TEXT UNIQUE NOT NULL,
                record BLOB NOT NULL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS recovery_claims (
                revision INTEGER PRIMARY KEY, destination TEXT NOT NULL, record BLOB NOT NULL
            )""")

    def connect(self):
        db = sqlite3.connect(self.state_file, timeout=2, isolation_level=None)
        db.execute("PRAGMA synchronous = FULL")
        return db

    def append(self, record):
        validate(record)
        tenant, sequence = record["tenant"], record["sequence"]
        body = canonical(record)
        with closing(self.connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT record, receipt FROM anchors WHERE tenant = ? AND sequence = ?",
                (tenant, sequence),
            ).fetchone()
            if row is not None:
                if row[0] != body:
                    raise AnchorConflict("different record at an anchored sequence")
                return json.loads(row[1])
            adjacent = {
                seq: (digest, previous)
                for seq, digest, previous in db.execute(
                    "SELECT sequence, digest, previous FROM anchors WHERE tenant = ? AND sequence IN (?, ?)",
                    (tenant, sequence - 1, min(sequence + 1, 2**63 - 1)),
                )
            }
            if (
                sequence - 1 in adjacent
                and adjacent[sequence - 1][0] != record["previous"]
            ) or (
                sequence + 1 in adjacent
                and adjacent[sequence + 1][1] != record["digest"]
            ):
                raise AnchorConflict("record conflicts with an adjacent audit anchor")
            proof = receipt_body(record)
            proof["signature"] = base64.b64encode(
                self.key.sign(canonical(proof))
            ).decode("ascii")
            db.execute(
                "INSERT INTO anchors VALUES (?, ?, ?, ?, ?, ?)",
                (
                    tenant,
                    sequence,
                    record["digest"],
                    record["previous"],
                    body,
                    canonical(proof),
                ),
            )
            db.commit()
        return proof

    def read(self, tenant, after):
        with closing(self.connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                "SELECT record, receipt FROM anchors WHERE tenant = ? AND sequence > ? ORDER BY sequence LIMIT 64",
                (tenant, after),
            )
            anchors = [
                {"record": json.loads(record), "receipt": json.loads(receipt)}
                for record, receipt in rows
            ]
            now = datetime.now(UTC).isoformat()
            cursor = db.execute(
                "INSERT INTO audit_reads (tenant, cursor, read_at, returned) VALUES (?, ?, ?, ?)",
                (tenant, after, now, len(anchors)),
            )
            receipt = {
                "schema": "kgateway.audit-anchor-read.v1",
                "id": cursor.lastrowid,
                "tenant": tenant,
                "after": after,
                "at": now,
                "returned": len(anchors),
            }
            receipt["signature"] = base64.b64encode(
                self.key.sign(canonical(receipt))
            ).decode("ascii")
            db.commit()
        return {"anchors": anchors, "read_receipt": receipt}

    @staticmethod
    def checkpoint_heads(db):
        return heads_digest(
            db.execute(
                "SELECT tenant, MAX(sequence), digest FROM anchors GROUP BY tenant ORDER BY tenant"
            )
        )

    @staticmethod
    def latest_checkpoint(db):
        row = db.execute(
            "SELECT record FROM recovery_checkpoints ORDER BY revision DESC LIMIT 1"
        ).fetchone()
        return json.loads(row[0]) if row is not None else None

    def sign(self, record):
        return {
            **record,
            "signature": base64.b64encode(self.key.sign(canonical(record))).decode(
                "ascii"
            ),
        }

    def seal_checkpoint(self, draft):
        validate_checkpoint(draft)
        with closing(self.connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            if self.checkpoint_heads(db) != draft["audit_heads_sha256"]:
                raise AnchorConflict(
                    "checkpoint does not match the current audit heads"
                )
            latest = self.latest_checkpoint(db)
            saved = db.execute(
                "SELECT record FROM recovery_checkpoints WHERE archive_sha256 = ?",
                (draft["archive_sha256"],),
            ).fetchone()
            if saved is not None:
                record = json.loads(saved[0])
                if record != latest or any(
                    record[key] != value for key, value in draft.items()
                ):
                    raise AnchorConflict(
                        "checkpoint archive has already been superseded or recorded with different metadata"
                    )
            else:
                revision = latest["revision"] + 1 if latest is not None else 1
                record = {
                    **draft,
                    "revision": revision,
                    "at": datetime.now(UTC).isoformat(),
                }
                db.execute(
                    "INSERT INTO recovery_checkpoints VALUES (?, ?, ?)",
                    (revision, draft["archive_sha256"], canonical(record)),
                )
            db.commit()
        return self.sign(record)

    def recovery_status(self, challenge):
        with closing(self.connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            checkpoint = self.latest_checkpoint(db)
            if checkpoint is None:
                raise AnchorConflict("no recovery checkpoint is available")
            now = datetime.now(UTC).isoformat()
            status = {
                "schema": STATUS,
                "challenge": challenge,
                "checkpoint": checkpoint,
                "audit_heads_sha256": self.checkpoint_heads(db),
                "at": now,
            }
            db.execute(
                "INSERT INTO audit_reads (tenant, cursor, read_at, returned) VALUES (?, ?, ?, 1)",
                ("@recovery", checkpoint["revision"], now),
            )
            db.commit()
        return self.sign(status)

    def claim_checkpoint(self, draft):
        validate_claim(draft)
        with closing(self.connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            checkpoint = self.latest_checkpoint(db)
            if (
                checkpoint is None
                or checkpoint["archive_sha256"] != draft["archive_sha256"]
                or checkpoint["audit_heads_sha256"] != self.checkpoint_heads(db)
            ):
                raise AnchorConflict("recovery checkpoint is stale")
            revision = checkpoint["revision"]
            current = db.execute(
                "SELECT destination, record FROM recovery_claims WHERE revision = ?",
                (revision,),
            ).fetchone()
            if current is not None:
                if current[0] != draft["destination"]:
                    raise AnchorConflict(
                        "checkpoint already belongs to another recovery destination"
                    )
                record = json.loads(current[1])
            else:
                record = {
                    **draft,
                    "revision": revision,
                    "at": datetime.now(UTC).isoformat(),
                }
                db.execute(
                    "INSERT INTO recovery_claims VALUES (?, ?, ?)",
                    (revision, draft["destination"], canonical(record)),
                )
            db.commit()
        return self.sign(record)


class API(BaseHTTPRequestHandler):
    def setup(self):
        self.request.settimeout(3)
        super().setup()

    def authorized(self, token):
        values = self.headers.get_all("Authorization") or []
        return len(values) == 1 and hmac.compare_digest(
            values[0].encode(), ("Bearer " + token).encode()
        )

    def do_POST(self):
        if self.path not in {"/v1/anchors", CHECKPOINT_PATH, CLAIM_PATH}:
            self.reply(404, {"error": "unknown route"})
            return
        if not self.authorized(self.server.writer):
            self.reply(401, {"error": "witness writer credential required"})
            return
        try:
            lengths = self.headers.get_all("Content-Length") or []
            if (
                len(lengths) != 1
                or self.headers.get("Transfer-Encoding")
                or not 0 < int(lengths[0]) <= 65536
            ):
                raise ValueError("invalid anchor request length")
            record = json.loads(self.rfile.read(int(lengths[0])))
            if not isinstance(record, dict):
                raise TypeError("invalid audit anchor")
            archive = self.server.archive
            if self.path == CHECKPOINT_PATH:
                self.reply(200, archive.seal_checkpoint(record))
            elif self.path == CLAIM_PATH:
                self.reply(200, archive.claim_checkpoint(record))
            else:
                self.reply(200, archive.append(record))
        except AnchorConflict:
            self.reply(409, {"error": "record conflicts with durable evidence"})
        except (TypeError, ValueError):
            self.reply(400, {"error": "invalid audit anchor"})
        except sqlite3.Error:
            self.reply(503, {"error": "witness state is unavailable"})

    def do_GET(self):
        url = urlsplit(self.path)
        if self.path == "/healthz":
            self.reply(200, {"ok": True})
            return
        if url.path != CHECKPOINT_PATH and not url.path.startswith("/v1/anchors/"):
            self.reply(404, {"error": "unknown route"})
            return
        if not self.authorized(self.server.reader):
            self.reply(401, {"error": "witness reader credential required"})
            return
        try:
            query = parse_qs(url.query, strict_parsing=True, max_num_fields=1)
            if url.path == CHECKPOINT_PATH:
                (challenge,) = query.get("challenge", [])
                if not CHALLENGE.fullmatch(challenge):
                    raise ValueError("invalid recovery challenge")
                self.reply(200, self.server.archive.recovery_status(challenge))
                return
            tenant = url.path.removeprefix("/v1/anchors/")
            after = int(query.get("after", ["0"])[0])
            if (
                not TENANT.fullmatch(tenant)
                or query.keys() - {"after"}
                or not 0 <= after < 2**63
            ):
                raise ValueError("invalid anchor query")
            self.reply(200, self.server.archive.read(tenant, after))
        except AnchorConflict:
            self.reply(409, {"error": "recovery checkpoint unavailable"})
        except ValueError:
            self.reply(400, {"error": "invalid anchor query"})
        except sqlite3.Error:
            self.reply(503, {"error": "witness state is unavailable"})

    def reply(self, status, value):
        body = canonical(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_request(self, *_args):
        pass


class Server(ThreadingHTTPServer):
    def __init__(self, bind, port, tls):
        self.tls = tls
        if bind.version == 6:
            self.address_family = socket.AF_INET6
        super().__init__((str(bind), port), API)

    def get_request(self):
        connection, address = super().get_request()
        return self.tls.wrap_socket(
            connection, server_side=True, do_handshake_on_connect=False
        ), address


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    path = parser.parse_args().config.resolve(strict=True)
    config = json.loads(path.read_bytes())
    directory = path.parent
    reader, writer = (
        os.environ[config[name]] for name in ("audit_token_env", "append_token_env")
    )
    if reader == writer or any(
        len(token) < 32 or not token.isascii() or not token.isprintable()
        for token in (reader, writer)
    ):
        raise ValueError("the witness requires separate read and append credentials")
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(
        directory / config["tls"]["cert"], directory / config["tls"]["key"]
    )
    key = load_pem_private_key(
        (directory / config["signing_key_file"]).read_bytes(), None
    )
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("audit witness signing key must be Ed25519")
    with Server(ipaddress.ip_address(config["bind"]), config["port"], tls) as server:
        server.reader, server.writer = reader, writer
        server.archive = Archive(directory / config["state_file"], key)
        server.serve_forever()


if __name__ == "__main__":
    main()
