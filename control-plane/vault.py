"""Versioned third-party credential bindings over externally sealed ciphertext."""

import base64
import binascii
import re
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

SCOPE_FIELDS = ("tenant", "org", "project", "env", "provider")
REFERENCE = re.compile(r"urn:plat:vault:secret:[A-Za-z0-9._:-]{1,128}")
IDENTIFIER = re.compile(r"[A-Za-z0-9._:-]{1,128}")
KEY_ID = re.compile(r"[A-Za-z0-9._:/-]{1,512}")
SCOPE = "tenant = ? AND org = ? AND project = ? AND env = ? AND provider = ?"
SCHEMA = "kgateway.vault-receipt.v1"

DDL = """
CREATE TABLE IF NOT EXISTS vault_providers (
    tenant TEXT NOT NULL, org TEXT NOT NULL, project TEXT NOT NULL, env TEXT NOT NULL,
    provider TEXT NOT NULL, aggregate_version INTEGER NOT NULL CHECK (aggregate_version >= 1),
    version INTEGER NOT NULL CHECK (version >= 1),
    PRIMARY KEY (tenant, org, project, env, provider)
);
CREATE TABLE IF NOT EXISTS vault_versions (
    tenant TEXT NOT NULL, org TEXT NOT NULL, project TEXT NOT NULL, env TEXT NOT NULL,
    provider TEXT NOT NULL, version INTEGER NOT NULL CHECK (version >= 1),
    audience TEXT NOT NULL, secret_ref TEXT NOT NULL, ciphertext TEXT, key_id TEXT NOT NULL,
    expires_at TEXT NOT NULL, state TEXT NOT NULL CHECK (state IN ('sealed','active','revoked')),
    CHECK ((state = 'revoked' AND ciphertext IS NULL) OR (state != 'revoked' AND ciphertext IS NOT NULL)),
    PRIMARY KEY (tenant, org, project, env, provider, version)
);
CREATE UNIQUE INDEX IF NOT EXISTS vault_single_active_provider
    ON vault_versions (tenant, org, project, env, provider) WHERE state = 'active';
CREATE TABLE IF NOT EXISTS vault_admissions (
    request_id TEXT PRIMARY KEY, subject TEXT NOT NULL, audience TEXT NOT NULL,
    tenant TEXT NOT NULL, org TEXT NOT NULL, project TEXT NOT NULL, env TEXT NOT NULL,
    provider TEXT NOT NULL, secret_ref TEXT NOT NULL, version INTEGER NOT NULL, expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS vault_admissions_expiry ON vault_admissions (expires_at);
"""


class BindingConflict(ValueError):
    pass


def valid_id(value):
    return isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None


def valid_ref(value):
    return isinstance(value, str) and REFERENCE.fullmatch(value) is not None


def as_scope(entry):
    values = tuple(entry[name] for name in SCOPE_FIELDS)
    if not all(valid_id(value) for value in values):
        raise ValueError("invalid vault scope")
    return values


def active_binding(db, scope, audience, now):
    row = db.execute(
        f"SELECT secret_ref, version FROM vault_versions WHERE {SCOPE} "
        "AND audience = ? AND state = 'active' AND expires_at > ?",
        (*scope, audience, now.isoformat()),
    ).fetchone()
    if row is None:
        raise BindingConflict("vault binding is unavailable")
    return {"secret_ref": row[0], "version": row[1]}


def reserve_binding(db, request_id, subject, scope, audience, binding, now):
    db.execute("DELETE FROM vault_admissions WHERE expires_at <= ?", (now.isoformat(),))
    db.execute(
        "INSERT INTO vault_admissions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            request_id,
            subject,
            audience,
            *scope,
            binding["secret_ref"],
            binding["version"],
            (now + timedelta(minutes=4)).isoformat(),
        ),
    )


def redeem(state, audience, entry, append_audit, require_witness):
    if set(entry) != {"request_id", "secret_ref", "version"} or not valid_ref(
        entry["secret_ref"]
    ):
        raise ValueError("invalid vault redemption fields")
    request = UUID(entry["request_id"])
    version = entry["version"]
    if (
        not request.int
        or str(request) != entry["request_id"]
        or type(version) is not int
        or not 1 <= version < 2**53
    ):
        raise ValueError("invalid vault redemption context")
    now = datetime.now(UTC).isoformat()
    with state.connect(write=True) as db:
        result = db.execute(
            "SELECT a.tenant, v.ciphertext, v.key_id FROM vault_admissions a "
            "JOIN vault_versions v ON (v.tenant, v.org, v.project, v.env, v.provider, v.version) = "
            "(a.tenant, a.org, a.project, a.env, a.provider, a.version) "
            "JOIN credentials c ON c.subject = a.subject "
            "WHERE a.request_id = ? AND a.audience = ? AND a.secret_ref = ? AND a.version = ? "
            "AND v.audience = a.audience AND v.secret_ref = a.secret_ref AND v.state = 'active' "
            "AND a.expires_at > ? AND v.expires_at > ? AND c.expires_at > ? "
            "AND (? = 0 OR EXISTS (SELECT 1 FROM audit_witness_receipts w WHERE w.request_id = a.request_id)) "
            "AND NOT EXISTS (SELECT 1 FROM revocations r WHERE r.subject = a.subject)",
            (
                str(request),
                audience,
                entry["secret_ref"],
                version,
                now,
                now,
                now,
                require_witness,
            ),
        ).fetchone()
        if result is None:
            raise BindingConflict("vault redemption is unavailable")
        tenant, ciphertext, key_id = result
        append_audit(
            db, tenant, {"action": "vault.redeemed", "actor": audience, **entry}
        )
    return {
        "schema": "kgateway.vault-envelope.v1",
        "ciphertext": ciphertext,
        "key_id": key_id,
    }


def validate_update(action, entry, now):
    required = set(SCOPE_FIELDS) | {"secret_ref", "expected_aggregate_version"}
    if action == "materialize":
        required.update({"audience", "ciphertext", "key_id", "expires_at"})
    else:
        required.add("version")
    if set(entry) != required or not valid_ref(entry["secret_ref"]):
        raise ValueError("invalid vault version fields")
    expected = entry["expected_aggregate_version"]
    if type(expected) is not int or not 0 <= expected < 2**53 - 1:
        raise ValueError("invalid vault aggregate version")
    if action != "materialize":
        version = entry["version"]
        if type(version) is not int or not 1 <= version <= expected:
            raise ValueError("invalid vault version")
        return None
    if not valid_id(entry["audience"]) or not KEY_ID.fullmatch(entry["key_id"]):
        raise ValueError("invalid vault service identifier")
    payload = entry["ciphertext"]
    if not isinstance(payload, str) or not 24 <= len(payload) <= 65536:
        raise ValueError("invalid sealed payload size")
    try:
        sealed = base64.b64decode(payload, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("invalid sealed payload") from None
    if len(sealed) < 16 or base64.b64encode(sealed).decode("ascii") != payload:
        raise ValueError("invalid sealed payload encoding")
    expiry = datetime.fromisoformat(entry["expires_at"])
    if expiry.tzinfo is None or expiry <= now:
        raise ValueError("sealed payload expiry must be in the future")
    return expiry.astimezone(UTC).isoformat()


def update(state, action, entry, append_audit):
    now = datetime.now(UTC)
    expiry = validate_update(action, entry, now)
    scope = as_scope(entry)
    reference = entry["secret_ref"]
    expected = entry["expected_aggregate_version"]
    with state.connect(write=True) as db:
        head = db.execute(
            f"SELECT aggregate_version, version FROM vault_providers WHERE {SCOPE}",
            scope,
        ).fetchone()
        aggregate, current_version = head or (0, 0)
        if aggregate != expected:
            raise BindingConflict("vault aggregate version changed")
        if action == "materialize":
            version = current_version + 1
            db.execute(
                "INSERT INTO vault_versions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'sealed')",
                (
                    *scope,
                    version,
                    entry["audience"],
                    reference,
                    entry["ciphertext"],
                    entry["key_id"],
                    expiry,
                ),
            )
            current_version = version
            status = "sealed"
        else:
            version = entry["version"]
            status = transition(
                db, scope, reference, version, action, now, append_audit
            )
        db.execute(
            "INSERT INTO vault_providers VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (tenant, org, project, env, provider) DO UPDATE "
            "SET aggregate_version = excluded.aggregate_version, version = excluded.version",
            (*scope, aggregate + 1, current_version),
        )
        receipt = {
            "schema": SCHEMA,
            "receipt_id": str(uuid4()),
            "scope": dict(zip(SCOPE_FIELDS, scope)),
            "secret_ref": reference,
            "version": version,
            "aggregate_version": aggregate + 1,
            "status": status,
            "at": now.isoformat(),
        }
        audit = append_audit(
            db,
            scope[0],
            {"action": "vault." + action, "actor": "vault-operator", **receipt},
        )
    return {**receipt, "audit": audit}


def transition(db, scope, reference, version, action, now, append_audit):
    row = db.execute(
        f"SELECT state, expires_at FROM vault_versions WHERE {SCOPE} AND version = ? AND secret_ref = ?",
        (*scope, version, reference),
    ).fetchone()
    if row is None or row[0] == "revoked":
        raise BindingConflict("vault version is unavailable")
    if action == "revoke":
        revoke(db, scope, version)
        return "revoked"
    if row[0] != "sealed" or row[1] <= now.isoformat():
        raise BindingConflict("vault version cannot be applied")
    previous = db.execute(
        f"SELECT secret_ref, version FROM vault_versions WHERE {SCOPE} AND state = 'active'",
        scope,
    ).fetchone()
    latest = db.execute(
        f"SELECT MAX(version) FROM vault_versions WHERE {SCOPE} AND state != 'sealed'",
        scope,
    ).fetchone()[0]
    if latest is not None and version <= latest:
        raise BindingConflict("vault rotation must advance the version")
    if previous is not None:
        revoke(db, scope, previous[1])
        append_audit(
            db,
            scope[0],
            {
                "action": "vault.rotation-revoke",
                "actor": "vault-operator",
                "scope": dict(zip(SCOPE_FIELDS, scope)),
                "secret_ref": previous[0],
                "version": previous[1],
                "status": "revoked",
                "at": now.isoformat(),
            },
        )
    db.execute(
        f"UPDATE vault_versions SET state = 'active' WHERE {SCOPE} AND version = ?",
        (*scope, version),
    )
    return "active"


def revoke(db, scope, version):
    db.execute(
        f"UPDATE vault_versions SET state = 'revoked', ciphertext = NULL WHERE {SCOPE} AND version = ?",
        (*scope, version),
    )
