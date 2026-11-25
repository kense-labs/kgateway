"""Durable identity, replica allowance, and delivery state."""

import fcntl
import json
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import sqlite_journal
import vault
from audit import append as append_audit
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


def timestamp():
    return datetime.now(UTC)


def fenced_file(state_file):
    return Path(str(state_file) + ".fenced")


def restore_file(state_file):
    return Path(str(state_file) + ".restore")


@contextmanager
def primary_lock(path):
    path = Path(path).resolve()
    fd = os.open(str(path) + ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError(
                "control-plane state already has an active writer"
            ) from None
        yield path
    finally:
        os.close(fd)


class Conflict(ValueError):
    pass


LEASE_PREPARE_SECONDS = 30


class State:
    def __init__(self, path, window_seconds):
        self.path = Path(path).absolute()
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        if self.path.stat().st_mode & 0o077:
            raise ValueError("control-plane state must be restricted to its owner")
        with self.connect(initialize=True) as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY, value INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS credentials (
                    subject TEXT PRIMARY KEY, prefix TEXT NOT NULL UNIQUE,
                    entry TEXT NOT NULL, expires_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS revocations (
                    id INTEGER PRIMARY KEY, subject TEXT NOT NULL UNIQUE,
                    generation INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS revocation_delivery (
                    replica TEXT PRIMARY KEY, sequence INTEGER NOT NULL,
                    through INTEGER NOT NULL, pending TEXT, pending_through INTEGER
                );
                CREATE TABLE IF NOT EXISTS budget_windows (
                    tenant TEXT NOT NULL, operation TEXT NOT NULL, window INTEGER NOT NULL,
                    hard_limit INTEGER NOT NULL, granted INTEGER NOT NULL,
                    PRIMARY KEY (tenant, operation, window)
                );
                CREATE TABLE IF NOT EXISTS leases (
                    tenant TEXT NOT NULL, operation TEXT NOT NULL, window INTEGER NOT NULL,
                    replica TEXT NOT NULL, id TEXT NOT NULL UNIQUE, requests INTEGER NOT NULL,
                    PRIMARY KEY (tenant, operation, window, replica)
                );
                CREATE TABLE IF NOT EXISTS prepared_leases (id TEXT PRIMARY KEY);
                CREATE TABLE IF NOT EXISTS scoped_budget_windows (
                    tenant TEXT NOT NULL, operation TEXT NOT NULL, window INTEGER NOT NULL,
                    project TEXT NOT NULL, env TEXT NOT NULL,
                    hard_limit INTEGER NOT NULL, granted INTEGER NOT NULL,
                    PRIMARY KEY (tenant, operation, window, project, env)
                );
                CREATE TABLE IF NOT EXISTS scoped_leases (
                    tenant TEXT NOT NULL, operation TEXT NOT NULL, window INTEGER NOT NULL,
                    project TEXT NOT NULL, env TEXT NOT NULL, replica TEXT NOT NULL,
                    id TEXT NOT NULL UNIQUE, requests INTEGER NOT NULL,
                    PRIMARY KEY (tenant, operation, window, project, env, replica)
                );
                CREATE TABLE IF NOT EXISTS usage_events (
                    id TEXT PRIMARY KEY, kind TEXT NOT NULL, parent TEXT,
                    replica TEXT NOT NULL, payload BLOB NOT NULL, digest TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS usage_one_terminal
                    ON usage_events (parent) WHERE parent IS NOT NULL;
                CREATE TABLE IF NOT EXISTS usage_positions (
                    replica TEXT NOT NULL, epoch TEXT NOT NULL, seq INTEGER NOT NULL,
                    event_id TEXT NOT NULL,
                    PRIMARY KEY (replica, epoch, seq)
                );
                CREATE TABLE IF NOT EXISTS usage_tips (
                    replica TEXT PRIMARY KEY, epoch TEXT NOT NULL, seq INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS usage_receipts (
                    replica TEXT NOT NULL, id TEXT NOT NULL, digest TEXT NOT NULL,
                    receipt TEXT NOT NULL, PRIMARY KEY (replica, id)
                );
                CREATE TABLE IF NOT EXISTS maas_usage_events (
                    request_id TEXT PRIMARY KEY, reservation_id TEXT NOT NULL UNIQUE,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS maas_batch_reports (
                    report_id TEXT PRIMARY KEY, payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS maas_batches (
                    batch_id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE,
                    revision INTEGER NOT NULL, status TEXT NOT NULL,
                    completed INTEGER NOT NULL, failed INTEGER NOT NULL, total INTEGER NOT NULL,
                    reserved_requests INTEGER NOT NULL, attempts INTEGER, unused_requests INTEGER
                );
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY, action TEXT NOT NULL,
                    subject TEXT NOT NULL, at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tenant_audit (
                    tenant TEXT NOT NULL, sequence INTEGER NOT NULL, previous TEXT NOT NULL,
                    digest TEXT NOT NULL, event TEXT NOT NULL, PRIMARY KEY (tenant, sequence)
                );
                CREATE TABLE IF NOT EXISTS tenant_audit_heads (
                    tenant TEXT PRIMARY KEY, sequence INTEGER NOT NULL, witnessed INTEGER NOT NULL DEFAULT 0
                );
                INSERT INTO tenant_audit_heads (tenant, sequence)
                    SELECT tenant, MAX(sequence) FROM tenant_audit GROUP BY tenant
                    ON CONFLICT (tenant) DO UPDATE SET sequence = excluded.sequence;
                CREATE TABLE IF NOT EXISTS audit_admissions (
                    id TEXT PRIMARY KEY, request TEXT NOT NULL, receipt TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_witness_receipts (
                    request_id TEXT PRIMARY KEY, tenant TEXT NOT NULL, sequence INTEGER NOT NULL,
                    receipt TEXT NOT NULL, UNIQUE (tenant, sequence)
                );
                CREATE TABLE IF NOT EXISTS delegation_grants (
                    id TEXT PRIMARY KEY, parent TEXT NOT NULL, operation TEXT NOT NULL,
                    action TEXT NOT NULL, urn TEXT NOT NULL, claims TEXT NOT NULL,
                    used_request TEXT UNIQUE,
                    UNIQUE (parent, operation, action, urn)
                );
                """
            )
            db.executescript(vault.DDL)
        with self.connect(write=True) as db:
            db.execute(
                "INSERT OR IGNORE INTO settings VALUES ('budget_window_seconds', ?)",
                (window_seconds,),
            )
            if db.execute(
                "SELECT value FROM settings WHERE key = 'budget_window_seconds'"
            ).fetchone() != (window_seconds,):
                raise Conflict("budget window must be preserved on state reopen")

    @contextmanager
    def connect(self, write=False, initialize=False):
        db = sqlite3.connect(self.path, isolation_level=None, timeout=5)
        try:
            db.execute("PRAGMA synchronous = FULL")
            if initialize:
                sqlite_journal.configure(db)
            else:
                db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield db
            if db.in_transaction:
                db.commit()
        except BaseException:
            if db.in_transaction:
                db.rollback()
            raise
        finally:
            db.close()

    def create_key(self, identity, grants, expires_at):
        subject = str(uuid4())
        prefix = "kense_" + secrets.token_hex(12)
        token = prefix + "." + secrets.token_urlsafe(32)
        verifier = Argon2id(
            salt=secrets.token_bytes(16),
            length=32,
            iterations=2,
            lanes=1,
            memory_cost=19456,
        ).derive_phc_encoded(token.encode())
        entry = {
            **identity,
            "subject": subject,
            "generation": 1,
            "verifier_hash": verifier,
            "expires_at": expires_at,
            "grants": grants,
        }
        with self.connect(write=True) as db:
            db.execute(
                "INSERT INTO credentials VALUES (?, ?, ?, ?)",
                (subject, prefix, json.dumps(entry), expires_at),
            )
            self.audit(db, identity["tenant"], "key.created", subject)
        return {"subject": subject, "key": token, "expires_at": expires_at}

    def revoke_key(self, subject):
        with self.connect(write=True) as db:
            row = db.execute(
                "SELECT entry FROM credentials WHERE subject = ?", (subject,)
            ).fetchone()
            if row is None:
                return False
            credential = json.loads(row[0])
            change = db.execute(
                "INSERT OR IGNORE INTO revocations (subject, generation) VALUES (?, ?)",
                (subject, credential["generation"]),
            )
            if change.rowcount:
                self.audit(db, credential["tenant"], "key.revoked", subject)
        return True

    @staticmethod
    def audit(db, tenant, action, subject):
        db.execute(
            "INSERT INTO audit (action, subject, at) VALUES (?, ?, ?)",
            (action, subject, timestamp().isoformat()),
        )
        append_audit(
            db, tenant, {"action": action, "actor": "operator", "subject": subject}
        )

    def credentials(self, at):
        with self.connect() as db:
            return {
                prefix: json.loads(entry)
                for prefix, entry in db.execute(
                    """
                    SELECT c.prefix, c.entry FROM credentials c
                    WHERE c.expires_at > ?
                      AND NOT EXISTS (SELECT 1 FROM revocations r WHERE r.subject = c.subject)
                    """,
                    (at.isoformat(),),
                )
            }

    def revocation_update(self, replica, remote_sequence, at):
        with self.connect(write=True) as db:
            db.execute(
                "INSERT OR IGNORE INTO revocation_delivery VALUES (?, 0, 0, NULL, NULL)",
                (replica,),
            )
            sequence, through, pending, pending_through = db.execute(
                "SELECT sequence, through, pending, pending_through "
                "FROM revocation_delivery WHERE replica = ?",
                (replica,),
            ).fetchone()
            if remote_sequence == sequence + 1 and pending is not None:
                sequence, through, pending = remote_sequence, pending_through, None
            elif remote_sequence != sequence:
                raise Conflict(
                    "replica revocation cursor does not match durable delivery state"
                )
            if pending is not None:
                update = json.loads(pending)
                if datetime.fromisoformat(update["valid_until"]) > at + timedelta(
                    seconds=5
                ):
                    return update
            rows = db.execute(
                "SELECT id, subject, generation FROM revocations "
                "WHERE id > ? ORDER BY id LIMIT 1025",
                (through,),
            ).fetchall()
            changes = rows[:1024]
            update = {
                "schema": "kgateway.platform-revocations.v1",
                "gateway_id": replica,
                "sequence": sequence + 1,
                "issued_at": at.isoformat(),
                "valid_until": (at + timedelta(seconds=75)).isoformat(),
                "more": len(rows) > len(changes),
                "changes": [
                    {"subject": subject, "through_generation": generation}
                    for _, subject, generation in changes
                ],
            }
            db.execute(
                "UPDATE revocation_delivery SET sequence = ?, through = ?, "
                "pending = ?, pending_through = ? WHERE replica = ?",
                (
                    sequence,
                    through,
                    json.dumps(update),
                    changes[-1][0] if changes else through,
                    replica,
                ),
            )
            return update

    def leases(self, replica, budgets, now, window_seconds):
        window = int(now.timestamp()) // window_seconds * window_seconds
        with self.connect(write=True) as db:
            result = self._window_leases(db, replica, budgets, window, window_seconds)
            if window + window_seconds - now.timestamp() <= LEASE_PREPARE_SECONDS:
                result.extend(
                    self._window_leases(
                        db,
                        replica,
                        budgets,
                        window + window_seconds,
                        window_seconds,
                        prepare=True,
                    )
                )
        return result

    @staticmethod
    def _window_leases(db, replica, budgets, window, window_seconds, prepare=False):
        starts = datetime.fromtimestamp(window, UTC).isoformat()
        expires = datetime.fromtimestamp(window + window_seconds, UTC).isoformat()
        result = []
        for budget in budgets:
            lease = State._allocate_lease(db, replica, budget, window, prepare)
            if lease is None:
                continue
            identifier, requests, prepared = lease
            entry = {
                "id": identifier,
                "requests": requests,
                "gateway_id": replica,
                "tenant": budget["tenant"],
                "operation": budget["operation"],
                "expires_at": expires,
            }
            for field in ("project", "env"):
                if field in budget:
                    entry[field] = budget[field]
            if prepared:
                entry["starts_at"] = starts
            result.append(entry)
        return result

    @staticmethod
    def _allocate_lease(db, replica, budget, window, prepare):
        scoped = "project" in budget
        scope = {
            "tenant": budget["tenant"],
            "operation": budget["operation"],
            "window": window,
        }
        if scoped:
            scope.update(project=budget["project"], env=budget.get("env", ""))
        windows = "scoped_budget_windows" if scoped else "budget_windows"
        leases = "scoped_leases" if scoped else "leases"
        columns = ", ".join(scope)
        parameters = ", ".join("?" for _ in scope)
        where = " AND ".join(f"{field} = ?" for field in scope)
        identity = tuple(scope.values())
        cap = budget["requests"]
        db.execute(
            f"INSERT OR IGNORE INTO {windows} ({columns}, hard_limit, granted) VALUES ({parameters}, ?, 0)",
            (*identity, cap),
        )
        hard_limit, granted = db.execute(
            f"SELECT hard_limit, granted FROM {windows} WHERE {where}", identity
        ).fetchone()
        active_from_window = (
            "1"
            if scoped
            else "EXISTS (SELECT 1 FROM prepared_leases WHERE prepared_leases.id = leases.id)"
        )
        lease = db.execute(
            f"SELECT id, requests, {active_from_window} FROM {leases} WHERE {where} AND replica = ?",
            (*identity, replica),
        ).fetchone()
        if lease is not None:
            return lease
        # Keep committed reservations. A cap change affects the first unallocated window.
        requests = (
            0
            if hard_limit != cap and granted
            else min(budget["replicas"].get(replica, 0), cap - granted)
        )
        if requests == 0 and not scoped:
            return None
        # Publish a zero allowance for a scoped replica with no share so its requests
        # still have to pass the project/environment guard.
        identifier = str(uuid4())
        db.execute(
            f"INSERT INTO {leases} ({columns}, replica, id, requests) VALUES ({parameters}, ?, ?, ?)",
            (*identity, replica, identifier, requests),
        )
        if prepare and not scoped:
            db.execute("INSERT INTO prepared_leases VALUES (?)", (identifier,))
        if requests:
            db.execute(
                f"UPDATE {windows} SET hard_limit = ?, granted = granted + ? WHERE {where}",
                (cap, requests, *identity),
            )
        return identifier, requests, scoped or prepare
