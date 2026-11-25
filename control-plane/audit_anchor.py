"""Anchor tenant audit entries at an independently operated HTTPS witness."""

import base64
import hashlib
import json
import logging
import re
import sqlite3
import ssl
from http.client import HTTPException
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

ANCHOR_SCHEMA = "kgateway.audit-anchor.v1"
RECEIPT_SCHEMA = "kgateway.audit-anchor-receipt.v1"
TENANT = re.compile(r"[A-Za-z0-9._:-]{1,128}")
DIGEST = re.compile(r"[0-9a-f]{64}")
LOGGER = logging.getLogger(__name__)


class AnchorUnavailable(Exception):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def validate(record):
    if (
        set(record) != {"schema", "tenant", "sequence", "previous", "digest", "event"}
        or record["schema"] != ANCHOR_SCHEMA
    ):
        raise ValueError("invalid audit anchor fields")
    tenant, sequence, previous, digest, event = (
        record[key] for key in ("tenant", "sequence", "previous", "digest", "event")
    )
    if (
        not TENANT.fullmatch(tenant)
        or type(sequence) is not int
        or not 0 < sequence < 2**63
        or not DIGEST.fullmatch(digest)
        or not DIGEST.fullmatch(previous)
        or not isinstance(event, dict)
    ):
        raise ValueError("invalid audit anchor context")
    if event.get("schema") != "kgateway.audit.v1" or (
        sequence == 1 and previous != "0" * 64
    ):
        raise ValueError("invalid audit anchor event")
    prefix = f"kgateway.audit.v1\0{tenant}\0{sequence}\0{previous}\0".encode()
    if hashlib.sha256(prefix + canonical(event)).hexdigest() != digest:
        raise ValueError("audit anchor digest mismatch")


def receipt_body(record):
    return {
        "schema": RECEIPT_SCHEMA,
        **{key: record[key] for key in ("tenant", "sequence", "digest")},
    }


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


class AnchorClient:
    def __init__(self, spec, directory, token):
        endpoint = urlsplit(spec["endpoint"])
        if (
            endpoint.scheme != "https"
            or not endpoint.hostname
            or endpoint.username is not None
            or endpoint.path != "/v1/anchors"
            or endpoint.query
            or endpoint.fragment
        ):
            raise ValueError("audit witness must use an explicit HTTPS anchor endpoint")
        self.endpoint = endpoint.geturl()
        self.token = token
        self.public_key = load_pem_public_key(
            (directory / spec["verification_key"]).read_bytes()
        )
        if not isinstance(self.public_key, Ed25519PublicKey):
            raise TypeError("audit witness verification key must be Ed25519")
        context = ssl.create_default_context(cafile=str(directory / spec["ca_file"]))
        self.client = build_opener(
            ProxyHandler({}), HTTPSHandler(context=context), NoRedirect()
        )
        self.interval = spec.get("interval_seconds", 60)
        if type(self.interval) is not int or not 1 <= self.interval <= 3600:
            raise ValueError(
                "audit head anchor interval must be between 1 and 3600 seconds"
            )

    def run(self, state, stop):
        while not stop.wait(self.interval):
            try:
                self.sync_heads(state, stop)
            except (AnchorUnavailable, sqlite3.Error) as error:
                LOGGER.warning(
                    "Audit head anchoring deferred: %s", type(error).__name__
                )

    def sync_heads(self, state, stop):
        with state.connect() as db:
            rows = db.execute(
                "SELECT a.tenant, a.sequence, a.previous, a.digest, a.event "
                "FROM tenant_audit_heads h JOIN tenant_audit a ON a.tenant = h.tenant AND a.sequence = h.sequence "
                "WHERE h.sequence > h.witnessed ORDER BY h.witnessed, h.tenant LIMIT 32"
            ).fetchall()
        for tenant, sequence, previous, digest, event in rows:
            if stop.is_set():
                return
            self.confirmed_delivery(tenant, sequence, previous, digest, event)
            with state.connect(write=True) as db:
                self.mark_head(db, tenant, sequence)

    def confirm(self, state, tenant, receipt):
        with state.connect() as db:
            row = db.execute(
                "SELECT previous, digest, event FROM tenant_audit WHERE tenant = ? AND sequence = ?",
                (tenant, receipt["sequence"]),
            ).fetchone()
        if row is None or row[1] != receipt["digest"]:
            raise AnchorUnavailable("audit witness admission record is unavailable")
        proof = self.confirmed_delivery(tenant, receipt["sequence"], *row)
        with state.connect(write=True) as db:
            db.execute(
                "INSERT OR IGNORE INTO audit_witness_receipts VALUES (?, ?, ?, ?)",
                (
                    receipt["request_id"],
                    tenant,
                    receipt["sequence"],
                    canonical(proof).decode(),
                ),
            )
            self.mark_head(db, tenant, receipt["sequence"])

    def mark_head(self, db, tenant, sequence):
        db.execute(
            "UPDATE tenant_audit_heads SET witnessed = MAX(witnessed, ?) WHERE tenant = ?",
            (sequence, tenant),
        )

    def confirmed_delivery(self, tenant, sequence, previous, digest, raw_event):
        record = {
            "schema": ANCHOR_SCHEMA,
            "tenant": tenant,
            "sequence": sequence,
            "previous": previous,
            "digest": digest,
            "event": json.loads(raw_event),
        }
        try:
            return self.deliver(record)
        except (
            URLError,
            OSError,
            HTTPException,
            TypeError,
            ValueError,
            InvalidSignature,
        ) as error:
            raise AnchorUnavailable(
                "independent audit witness did not confirm the record"
            ) from error

    def deliver(self, record):
        request = Request(
            self.endpoint,
            data=canonical(record),
            headers={
                "Authorization": "Bearer " + self.token,
                "Content-Type": "application/json",
            },
        )
        with self.client.open(request, timeout=0.9) as response:
            data = response.read(4097)
            if response.status != 200 or len(data) > 4096:
                raise ValueError("invalid audit witness response")
        payload = json.loads(data)
        if not isinstance(payload, dict):
            raise TypeError("invalid audit witness receipt")
        proof = payload.pop("signature", None)
        if payload != receipt_body(record) or not isinstance(proof, str):
            raise ValueError("audit witness signed a different record")
        signature = base64.b64decode(proof, validate=True)
        if len(signature) != 64:
            raise ValueError("invalid audit witness signature encoding")
        self.public_key.verify(signature, canonical(payload))
        return {**payload, "signature": proof}
