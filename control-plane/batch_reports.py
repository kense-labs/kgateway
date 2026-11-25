"""Reconcile kstack batch checkpoints against gateway reservations."""

import json
import re
from datetime import datetime
from uuid import UUID, uuid5

from audit import append as append_audit
from state import Conflict

from usage import BATCH_CREATE, BATCH_URN, canonical_uuid

SCHEMA = "kgateway.maas-batch-report.v1"
RECEIPT = "kgateway.maas-batch-report-receipt.v1"
ACTIVE = ("validating", "in_progress", "cancelling", "finalizing")
TERMINAL = {"completed", "failed", "expired", "cancelled"}
FIELDS = {
    "schema",
    "report_id",
    "batch_id",
    "revision",
    "observed_at",
    "request_id",
    "reservation_id",
    "trace_id",
    "tenant",
    "project",
    "env",
    "status",
    "total",
    "completed",
    "failed",
}


def validate(event):
    status = event["status"]
    terminal = status in TERMINAL
    if (
        set(event) != FIELDS | ({"attempts"} if terminal else set())
        or event["schema"] != SCHEMA
        or (not terminal and status not in ACTIVE)
        or not re.fullmatch(r"batch_[0-9a-f]{24}", event["batch_id"])
        or not re.fullmatch(r"[0-9a-f]{32}", event["trace_id"])
    ):
        raise ValueError("invalid batch checkpoint fields")
    revision = event["revision"]
    if type(revision) is not int or not 1 <= revision < 2**53:
        raise ValueError("invalid batch checkpoint revision")
    parent = canonical_uuid(event["request_id"])
    canonical_uuid(event["reservation_id"])
    if str(uuid5(UUID(parent), f"batch-status:{revision}")) != event["report_id"]:
        raise ValueError("invalid batch checkpoint identity")
    if datetime.fromisoformat(event["observed_at"]).utcoffset() is None:
        raise ValueError("missing batch checkpoint timezone")
    counts = [event[field] for field in ("total", "completed", "failed")]
    if any(type(count) is not int or not 0 <= count <= 50_000 for count in counts):
        raise ValueError("invalid batch checkpoint counts")
    total, completed, failed = counts
    if not total or completed + failed > total:
        raise ValueError("batch checkpoint counts exceed the file size")
    if terminal and (
        type(event["attempts"]) is not int
        or not completed <= event["attempts"] <= total
    ):
        raise ValueError("invalid terminal batch attempts")


def ingest_report(state, event):
    validate(event)
    receipt = {"schema": RECEIPT, "report_id": event["report_id"]}
    wire = json.dumps(event, sort_keys=True, separators=(",", ":"))
    with state.connect(write=True) as db:
        replay = db.execute(
            "SELECT payload FROM maas_batch_reports WHERE report_id = ?",
            (event["report_id"],),
        ).fetchone()
        if replay:
            if replay[0] != wire:
                raise Conflict("batch checkpoint identity was reused")
            return receipt
        parent = db.execute(
            "SELECT payload FROM usage_events WHERE id = ? AND kind = 'request-started'",
            (event["request_id"],),
        ).fetchone()
        if not parent:
            raise Conflict("batch checkpoint is waiting for gateway admission")
        start = json.loads(parent[0])
        if (
            start["operation"] != BATCH_CREATE
            or start["urn"] != BATCH_URN
            or any(
                start[field] != event[field]
                for field in ("reservation_id", "trace_id", "tenant", "project", "env")
            )
            or event["total"] > start["reserved_requests"]
        ):
            raise Conflict("batch checkpoint exceeds its gateway reservation")
        previous = db.execute(
            "SELECT batch_id, request_id, revision, status, completed, failed, total FROM maas_batches "
            "WHERE batch_id = ? OR request_id = ?",
            (event["batch_id"], event["request_id"]),
        ).fetchone()
        if previous and (
            previous[:2] != (event["batch_id"], event["request_id"])
            or previous[2] >= event["revision"]
            or previous[3] in TERMINAL
            or previous[4] > event["completed"]
            or previous[5] > event["failed"]
            or previous[6] != event["total"]
            or (
                event["status"] in ACTIVE
                and ACTIVE.index(previous[3]) > ACTIVE.index(event["status"])
            )
        ):
            raise Conflict("batch checkpoint went backwards")
        attempts = event.get("attempts")
        unused = start["reserved_requests"] - attempts if attempts is not None else None
        db.execute(
            "INSERT INTO maas_batch_reports VALUES (?, ?)", (event["report_id"], wire)
        )
        db.execute(
            """INSERT INTO maas_batches VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (batch_id) DO UPDATE SET revision = excluded.revision,
            status = excluded.status, completed = excluded.completed, failed = excluded.failed,
            attempts = excluded.attempts, unused_requests = excluded.unused_requests""",
            (
                event["batch_id"],
                event["request_id"],
                event["revision"],
                event["status"],
                event["completed"],
                event["failed"],
                event["total"],
                start["reserved_requests"],
                attempts,
                unused,
            ),
        )
        audit = {**event, "action": "maas.batch-checkpoint", "actor": "kstack"}
        if unused is not None:
            audit["unused_requests"] = unused
        append_audit(db, event["tenant"], audit)
    return receipt
