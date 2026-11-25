"""Validate, persist, and acknowledge an ordered replica usage batch."""

import base64
import hashlib
import json
import re
from datetime import datetime
from uuid import UUID, uuid5

from audit import append as append_audit
from budget_window import matches_leases
from state import Conflict

BATCH_SCHEMAS = {
    "kgateway.usage-batch.v1": "kgateway.usage-batch-receipt.v1",
    "a3s.gateway.usage-batch.v1": "a3s.gateway.usage-batch-receipt.v1",
}
EVENT_SCHEMA = "kgateway.platform-usage.v1"
MAAS_SCHEMA = "kgateway.maas-usage.v1"
BATCH_CREATE = "maas.batches.create"
BATCH_URN = "urn:plat:maas:batches"
MODEL_URN = "urn:plat:maas:model:"


def canonical_uuid(value):
    result = UUID(value)
    if result.int == 0 or str(result) != value:
        raise ValueError("expected a canonical non-nil UUID")
    return value


def cursor(value):
    if set(value) != {"boot_epoch", "sequence"}:
        raise ValueError("invalid usage cursor fields")
    epoch, sequence = canonical_uuid(value["boot_epoch"]), value["sequence"]
    if type(sequence) is not int or not 0 < sequence < 2**63:
        raise ValueError("invalid usage sequence")
    return epoch, sequence


def continues(previous, current):
    if previous is not None and current[0] == previous[0]:
        return current[1] == previous[1] + 1
    return current[1] == 1


def ingest(state, replica, batch):
    required = {"schema", "gateway_id", "batch_id", "records"}
    if (
        not required <= batch.keys()
        or batch.keys() - required - {"after"}
        or batch["schema"] not in BATCH_SCHEMAS
        or batch["gateway_id"] != replica
    ):
        raise ValueError("invalid usage batch")
    batch_id = canonical_uuid(batch["batch_id"])
    records = batch["records"]
    if not isinstance(records, list) or not 0 < len(records) <= 1024:
        raise ValueError("invalid usage batch size")
    after = cursor(batch["after"]) if batch.get("after") is not None else None
    digest = hashlib.sha256(json.dumps(batch, sort_keys=True).encode()).hexdigest()
    receipt = {
        "schema": BATCH_SCHEMAS[batch["schema"]],
        "gateway_id": replica,
        "batch_id": batch_id,
        "acknowledged_through": records[-1]["cursor"],
    }
    with state.connect(write=True) as db:
        replay = db.execute(
            "SELECT digest, receipt FROM usage_receipts WHERE replica = ? AND id = ?",
            (replica, batch_id),
        ).fetchone()
        if replay is not None:
            if replay[0] != digest:
                raise Conflict("usage batch identity was reused")
            return json.loads(replay[1])
        if after is not None and position_at(db, replica, after) is None:
            raise Conflict("usage batch follows an unknown cursor")
        tip = db.execute(
            "SELECT epoch, seq FROM usage_tips WHERE replica = ?", (replica,)
        ).fetchone()
        previous = after
        for record in records:
            current = cursor(record["cursor"])
            if not continues(previous, current):
                raise Conflict("usage batch is discontinuous")
            existing = position_at(db, replica, current)
            event_id = canonical_uuid(record["event_id"])
            if existing is None:
                if previous != tip or not continues(tip, current):
                    raise Conflict("usage event cannot advance the durable cursor")
            elif existing[0] != event_id:
                raise Conflict("usage cursor points to a different event")
            store_event(db, replica, event_id, record)
            if existing is None:
                if (
                    current[1] == 1
                    and db.execute(
                        "SELECT 1 FROM usage_positions WHERE replica = ? AND epoch = ?",
                        (replica, current[0]),
                    ).fetchone()
                    is not None
                ):
                    raise Conflict("usage epoch has already ended")
                db.execute(
                    "INSERT INTO usage_positions VALUES (?, ?, ?, ?)",
                    (replica, *current, event_id),
                )
                tip = current
            previous = current
        db.execute(
            "INSERT OR REPLACE INTO usage_tips VALUES (?, ?, ?)", (replica, *tip)
        )
        db.execute(
            "INSERT INTO usage_receipts VALUES (?, ?, ?, ?)",
            (replica, batch_id, digest, json.dumps(receipt)),
        )
    return receipt


def position_at(db, replica, position):
    return db.execute(
        "SELECT event_id FROM usage_positions WHERE replica = ? AND epoch = ? AND seq = ?",
        (replica, *position),
    ).fetchone()


def ingest_maas(state, event):
    context_keys = {
        "request_id",
        "reservation_id",
        "trace_id",
        "tenant",
        "project",
        "env",
        "operation",
        "urn",
    }
    if (
        set(event) - {"batch_line"}
        != context_keys | {"schema", "status", "outcome", "tokens"}
        or event["schema"] != MAAS_SCHEMA
    ):
        raise ValueError("invalid MaaS usage event fields")
    request = canonical_uuid(event["request_id"])
    reservation = canonical_uuid(event["reservation_id"])
    model_operations = {
        "maas.chat.create",
        "maas.completions.create",
        "maas.embeddings.create",
    }
    if event["operation"] not in model_operations or not event["urn"].startswith(
        MODEL_URN
    ):
        raise ValueError("MaaS usage requires a registered model operation")
    parent = event.get("batch_line")
    parent_request = request
    if "batch_line" in event:
        if not isinstance(parent, dict) or set(parent) != {
            "request_id",
            "reservation_id",
            "line",
        }:
            raise ValueError("invalid MaaS batch line context")
        parent_request = canonical_uuid(parent["request_id"])
        parent_reservation = canonical_uuid(parent["reservation_id"])
        line = parent["line"]
        if (
            type(line) is not int
            or not 1 <= line <= 50000
            or str(uuid5(UUID(parent_request), str(line))) != request
            or str(uuid5(UUID(parent_reservation), str(line))) != reservation
        ):
            raise ValueError("invalid derived batch line identity")
    status = event["status"]
    if type(status) is not int or (status != 0 and not 100 <= status <= 599):
        raise ValueError("invalid MaaS response status")
    if event["outcome"] not in {
        "ok",
        "upstream_error",
        "client_closed",
        "truncated",
        "unknown",
        "not-dispatched",
    }:
        raise ValueError("invalid MaaS usage terminal outcome")
    tokens = event["tokens"]
    if tokens is not None and (
        not isinstance(tokens, dict)
        or not {"prompt", "completion"} <= tokens.keys()
        or tokens.keys() - {"prompt", "completion", "cached"}
        or any(
            type(value) is not int or not 0 <= value < 2**63
            for value in tokens.values()
        )
    ):
        raise ValueError("invalid MaaS token dimensions")
    payload = json.dumps(event, sort_keys=True)
    with state.connect(write=True) as db:
        row = db.execute(
            "SELECT payload FROM usage_events WHERE id = ? AND kind = 'request-started'",
            (parent_request,),
        ).fetchone()
        if row is None:
            raise Conflict("MaaS usage is waiting for gateway start")
        start = json.loads(row[0])
        if parent is None:
            if any(event[key] != start[key] for key in context_keys):
                raise Conflict("MaaS usage context does not match its gateway start")
        elif (
            start["operation"] != BATCH_CREATE
            or start["urn"] != BATCH_URN
            or start["reservation_id"] != parent["reservation_id"]
            or parent["line"] > start["reserved_requests"]
            or event["urn"][len(MODEL_URN) :] not in start["batch_models"]
            or any(
                event[key] != start[key]
                for key in ("trace_id", "tenant", "project", "env")
            )
        ):
            raise Conflict("MaaS usage line does not match its batch reservation")
        existing = db.execute(
            "SELECT payload FROM maas_usage_events WHERE request_id = ? OR reservation_id = ?",
            (request, reservation),
        ).fetchone()
        if existing is None:
            db.execute(
                "INSERT INTO maas_usage_events VALUES (?, ?, ?)",
                (request, reservation, payload),
            )
            append_audit(
                db,
                event["tenant"],
                {
                    "action": "maas.usage",
                    "actor": "kstack",
                    "request_id": request,
                    "reservation_id": reservation,
                    "trace_id": event["trace_id"],
                    "operation": event["operation"],
                    "urn": event["urn"],
                    "outcome": event["outcome"],
                }
                | ({"batch_line": parent} if parent is not None else {}),
            )
        elif existing[0] != payload:
            raise Conflict("MaaS usage event conflicts with an existing terminal")
    return {"schema": "kgateway.maas-usage-receipt.v1", "request_id": request}


def store_event(db, replica, event_id, record):
    if set(record) != {"cursor", "event_id", "payload_base64", "payload_sha256"}:
        raise ValueError("invalid usage record fields")
    payload = base64.b64decode(record["payload_base64"], validate=True)
    digest = hashlib.sha256(payload).hexdigest()
    if digest != record["payload_sha256"]:
        raise ValueError("usage payload digest does not match")
    event = json.loads(payload)
    if event["schema"] != EVENT_SCHEMA or event["event_id"] != event_id:
        raise ValueError("usage event does not match the record")
    existing = db.execute(
        "SELECT replica, digest FROM usage_events WHERE id = ?", (event_id,)
    ).fetchone()
    if existing is not None:
        if existing != (replica, digest):
            raise Conflict("usage event identity was reused")
        return
    common = {
        "schema",
        "kind",
        "event_id",
        "request_id",
        "reservation_id",
        "lease_id",
        "trace_id",
        "tenant",
        "project",
        "env",
        "subject",
        "operation",
        "urn",
        "at",
    }
    if "action" in event:
        if not isinstance(event["action"], str) or not 0 < len(event["action"]) <= 64:
            raise ValueError("invalid protocol action")
        common.add("action")
    if "scope_lease_ids" in event:
        common.add("scope_lease_ids")
    if event["operation"] == BATCH_CREATE:
        reserved = event.get("reserved_requests")
        models = event.get("batch_models")
        if (
            event["urn"] != BATCH_URN
            or type(reserved) is not int
            or not 1 <= reserved <= 50000
            or not isinstance(models, list)
            or not 1 <= len(models) <= 32
            or any(
                not isinstance(model, str)
                or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", model)
                for model in models
            )
            or len(set(models)) != len(models)
        ):
            raise ValueError("invalid batch usage reservation")
        common.update({"reserved_requests", "batch_models"})
    for field in ("request_id", "reservation_id", "lease_id", "subject"):
        canonical_uuid(event[field])
    parent = None
    if event["kind"] == "request-started":
        if event["request_id"] != event_id or set(event) != common:
            raise ValueError("invalid usage start")
        if not matches_leases(db, replica, event, datetime.fromisoformat(event["at"])):
            raise Conflict("usage start does not match an issued lease")
    elif event["kind"] == "request-terminal":
        terminal = {"billing_parent", "status", "outcome", "egress_bytes"}
        parent = canonical_uuid(event["billing_parent"])
        if event["request_id"] != parent or set(event) != common | terminal:
            raise ValueError("invalid terminal usage event")
        if event["outcome"] not in {"succeeded", "failed", "disconnected"}:
            raise ValueError("invalid terminal usage outcome")
        if (
            type(event["egress_bytes"]) is not int
            or not 0 <= event["egress_bytes"] < 2**63
        ):
            raise ValueError("invalid usage byte count")
        previous = db.execute(
            "SELECT payload FROM usage_events WHERE id = ? AND replica = ? AND kind = 'request-started'",
            (parent, replica),
        ).fetchone()
        if previous is None:
            raise Conflict("usage terminal has no start")
        start = json.loads(previous[0])
        if set(start) != common or any(
            event[key] != start[key] for key in common - {"at", "kind", "event_id"}
        ):
            raise Conflict("usage terminal changed its start context")
        if db.execute(
            "SELECT 1 FROM usage_events WHERE parent = ?", (parent,)
        ).fetchone():
            raise Conflict("usage request already has a terminal event")
    else:
        raise ValueError("invalid usage event kind")
    db.execute(
        "INSERT INTO usage_events VALUES (?, ?, ?, ?, ?, ?)",
        (event_id, event["kind"], parent, replica, payload, digest),
    )
    append_audit(
        db,
        event["tenant"],
        {
            "action": event["kind"],
            "actor": replica,
            "subject": event["subject"],
            "request_id": event["request_id"],
            "reservation_id": event["reservation_id"],
            "trace_id": event["trace_id"],
            "operation": event["operation"],
            "urn": event["urn"],
            "at": event["at"],
        },
    )
