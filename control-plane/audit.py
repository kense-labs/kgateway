"""An append-only audit chain scoped to each tenant."""

import hashlib
import json
import re
from datetime import UTC, datetime
from uuid import UUID

import vault
from budget_window import matches_leases

SCHEMA = "kgateway.audit.v1"
EMPTY_HEAD = "0" * 64


def append(db, tenant, event):
    tip = db.execute(
        "SELECT sequence, digest FROM tenant_audit WHERE tenant = ? ORDER BY sequence DESC LIMIT 1",
        (tenant,),
    ).fetchone()
    previous_sequence, previous_digest = tip if tip else (0, EMPTY_HEAD)
    sequence = previous_sequence + 1
    payload = {
        **event,
        "schema": SCHEMA,
        "at": event.get("at") or datetime.now(UTC).isoformat(),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    prefix = f"{SCHEMA}\0{tenant}\0{sequence}\0{previous_digest}\0".encode()
    digest = hashlib.sha256(prefix + canonical.encode()).hexdigest()
    db.execute(
        "INSERT INTO tenant_audit (tenant, sequence, previous, digest, event) VALUES (?, ?, ?, ?, ?)",
        (tenant, sequence, previous_digest, digest, canonical),
    )
    db.execute(
        "INSERT INTO tenant_audit_heads (tenant, sequence) VALUES (?, ?) "
        "ON CONFLICT (tenant) DO UPDATE SET sequence = excluded.sequence",
        (tenant, sequence),
    )
    return {"sequence": sequence, "digest": digest}


def read_page(state, tenant, after, limit):
    with state.connect(write=True) as db:
        receipt = append(
            db, tenant, {"action": "audit.read", "actor": "auditor", "after": after}
        )
        events = [
            {
                "sequence": seq,
                "previous": previous,
                "digest": digest,
                "event": json.loads(event),
            }
            for seq, previous, digest, event in db.execute(
                "SELECT sequence, previous, digest, event FROM tenant_audit "
                "WHERE tenant = ? AND sequence > ? ORDER BY sequence LIMIT ?",
                (tenant, after, limit),
            )
        ]
    return {
        "schema": SCHEMA,
        "tenant": tenant,
        "read_receipt": receipt,
        "events": events,
    }


def matches_admission_target(route, event):
    if route["method"] != event["method"]:
        return False
    query = event.get("query")
    path = route["path"]
    if route["resource"]["kind"] != "maas-asset":
        return query is None and path == event["path"]
    if query is not None:
        if event["operation"] not in {"maas.files.list", "maas.batches.list"}:
            return False
        allowed = {"after", "limit", "order"}
        if event["operation"] == "maas.files.list":
            allowed.add("purpose")
        if not 0 < len(query) <= 256:
            return False
        for field in query.split("&"):
            key, separator, value = field.partition("=")
            if (
                not separator
                or key not in allowed
                or not re.fullmatch(r"[A-Za-z0-9_-]*", value)
            ):
                return False
            allowed.remove(key)
    if "{id}" not in path:
        return path == event["path"]
    prefix, suffix = path.split("{id}", 1)
    id_prefix = (
        "file-" if route["resource"]["urn"] == "urn:plat:maas:files" else "batch_"
    )
    return (
        re.fullmatch(
            re.escape(prefix + id_prefix) + r"[0-9a-f]{24}" + re.escape(suffix),
            event["path"],
        )
        is not None
    )


def confirm_admission(
    state, replica, event, routes, budget_scopes, consume_delegation=None
):
    required = {
        "schema",
        "gateway_id",
        "request_id",
        "reservation_id",
        "lease_id",
        "subject",
        "tenant",
        "project",
        "env",
        "trace_id",
        "method",
        "path",
        "operation",
        "urn",
        "protocol_action",
    }
    if (
        set(event)
        - {
            "query",
            "vault_provider",
            "audience",
            "credential_generation",
            "delegation_ticket",
            "scope_lease_ids",
        }
        != required
        or event["schema"] != "kgateway.audit-admission.v1"
        or event["gateway_id"] != replica
        or not isinstance(event["path"], str)
        or ("query" in event and not isinstance(event["query"], str))
        or not re.fullmatch(r"[0-9a-f]{32}", event["trace_id"])
    ):
        raise ValueError("invalid sensitive admission context")
    for field in ("request_id", "reservation_id", "lease_id", "subject"):
        identifier = UUID(event[field])
        if not identifier.int or str(identifier) != event[field]:
            raise ValueError("invalid sensitive admission identifier")
    operation = event["operation"]
    route = routes.get(operation)
    if (
        not route
        or not route.get("requires_audit_receipt")
        or not matches_admission_target(route, event)
        or route.get("vault_provider") != event.get("vault_provider")
        or ("vault_provider" in event and not vault.valid_id(event["vault_provider"]))
    ):
        raise ValueError("operation is not configured for sensitive admission")
    delegation_route = bool(route.get("delegate_to") or route.get("accept_delegation"))
    delegation_fields = {"audience", "credential_generation"}
    if delegation_route:
        if (
            consume_delegation is None
            or not delegation_fields <= event.keys()
            or event["audience"] != route["audience"]
            or type(event["credential_generation"]) is not int
        ):
            raise ValueError("invalid A2A delegation admission context")
    elif delegation_fields.intersection(event) or "delegation_ticket" in event:
        raise ValueError("operation has no delegation policy")
    request = event["request_id"]
    canonical = json.dumps(event, sort_keys=True, separators=(",", ":"))
    with state.connect(write=True) as db:
        replay = db.execute(
            "SELECT request, receipt FROM audit_admissions WHERE id = ?", (request,)
        ).fetchone()
        if replay is not None and replay[0] != canonical:
            raise ValueError("sensitive request ID was reused")
        provider = route.get("vault_provider")
        if replay is not None and provider is None:
            return json.loads(replay[1])
        now = datetime.now(UTC)
        scope = (event["tenant"], operation, event["project"])
        required_leases = sum(
            (*scope, env) in budget_scopes for env in (None, event["env"])
        )
        if replay is None and not matches_leases(
            db, replica, event, now, required_leases
        ):
            raise ValueError("audit admission does not match an issued lease")
        key = db.execute(
            "SELECT c.entry FROM credentials c WHERE c.subject = ? AND c.expires_at > ? "
            "AND NOT EXISTS (SELECT 1 FROM revocations r WHERE r.subject = c.subject)",
            (event["subject"], now.isoformat()),
        ).fetchone()
        if key is None:
            raise ValueError("audit admission subject is unavailable")
        credential = json.loads(key[0])
        if any(
            event[field] != credential[field] for field in ("tenant", "project", "env")
        ) or event["urn"] not in credential["grants"].get(operation, ()):
            raise ValueError("audit admission exceeds the subject's scope")
        if (
            delegation_route
            and event["credential_generation"] != credential["generation"]
        ):
            raise ValueError("delegation credential generation changed")
        authority = (
            consume_delegation(db, event, credential, route)
            if "delegation_ticket" in event
            else {}
        )
        binding = None
        if provider is not None:
            scope = (
                event["tenant"],
                credential["org"],
                event["project"],
                event["env"],
                provider,
            )
            binding = vault.active_binding(db, scope, route["audience"], now)
            if replay is not None:
                receipt = json.loads(replay[1])
                if receipt.get("vault_binding") != binding:
                    raise vault.BindingConflict(
                        "vault binding has changed since admission"
                    )
                return receipt
            vault.reserve_binding(
                db, request, event["subject"], scope, route["audience"], binding, now
            )
        audit = append(
            db,
            event["tenant"],
            {
                **{name: value for name, value in event.items() if name != "schema"},
                "action": "request.sensitive-admission",
                "actor": replica,
                **authority,
                **({"vault_binding": binding} if binding is not None else {}),
            },
        )
        receipt = {
            "schema": "kgateway.audit-receipt.v1",
            "gateway_id": replica,
            "request_id": request,
            **audit,
        }
        if binding is not None:
            receipt["vault_binding"] = binding
        db.execute(
            "INSERT INTO audit_admissions VALUES (?, ?, ?)",
            (request, canonical, json.dumps(receipt)),
        )
    return receipt
