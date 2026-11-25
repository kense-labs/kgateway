"""Issue and consume single-use, scope-reducing A2A delegation grants."""

import base64
import json
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from audit import append as append_audit
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from state import Conflict

ISSUER = "urn:plat:identity:delegation"
KEY_ID = "delegation-1"
TOKEN_TYPE = "kgateway-delegation"
MAX_DEPTH = 4
MAX_TARGETS = 16
PARENT_LIFETIME = timedelta(minutes=4)


def guarded(route):
    resource = route["resource"]
    return (
        route["method"] == "POST"
        and route.get("requires_audit_receipt") is True
        and resource["kind"] == "rpc"
        and resource["policy"]["protocol"] == "a2a"
    )


def target_key(target):
    return target["operation"], target["action"], target["urn"]


def verify_targets(routes, clients):
    for route in routes.values():
        targets = route.get("delegate_to", [])
        incoming = route.get("accept_delegation", False)
        if (
            type(incoming) is not bool
            or not isinstance(targets, list)
            or len(targets) > MAX_TARGETS
        ):
            raise ValueError("invalid delegation route configuration")
        if (targets or incoming) and (
            not guarded(route) or route["audience"] not in clients
        ):
            raise ValueError("delegation requires an audited, configured A2A workload")
        seen = set()
        for target in targets:
            if set(target) != {"operation", "action", "urn"}:
                raise ValueError("invalid delegation capability")
            operation, action, urn = target_key(target)
            destination = routes.get(operation)
            if (
                not destination
                or destination.get("accept_delegation") is not True
                or not guarded(destination)
                or destination["audience"] == route["audience"]
                or destination["resource"]["policy"]["methods"].get(action) != urn
                or (operation, action, urn) in seen
            ):
                raise ValueError(
                    "delegation capability does not name a distinct audited A2A operation"
                )
            seen.add((operation, action, urn))


def encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=")


class Exchange:
    def __init__(self, signing_file, operations):
        self.key = load_pem_private_key(signing_file.read_bytes(), None)
        if not isinstance(self.key, Ed25519PrivateKey):
            raise TypeError("delegation signing key must be Ed25519")
        self.routes = operations

    def sign(self, claims):
        header = {"alg": "EdDSA", "typ": TOKEN_TYPE, "kid": KEY_ID}
        segments = b".".join(
            encode(json.dumps(item, separators=(",", ":"), sort_keys=True).encode())
            for item in (header, claims)
        )
        return b".".join((segments, encode(self.key.sign(segments)))).decode("ascii")

    def exchange(self, state, actor, request, require_witness):
        if set(request) != {"parent_request_id", "target"} or set(
            request["target"]
        ) != {"operation", "action", "urn"}:
            raise ValueError("invalid delegation exchange context")
        target = request["target"]
        operation, action, urn = target_key(target)
        parent_id = canonical_uuid(request["parent_request_id"])
        now = datetime.now(UTC)
        with state.connect(write=True) as db:
            row = db.execute(
                "SELECT request, receipt FROM audit_admissions WHERE id = ?",
                (parent_id,),
            ).fetchone()
            if row is None:
                raise Conflict("delegation parent is unavailable")
            parent, receipt = map(json.loads, row)
            source = self.routes.get(parent["operation"])
            if (
                not source
                or not source.get("delegate_to")
                or parent.get("audience") != actor
                or source["audience"] != actor
            ):
                raise Conflict("delegation parent does not authorize this workload")
            sequence = receipt["sequence"]
            if (
                require_witness
                and not db.execute(
                    "SELECT 1 FROM audit_witness_receipts WHERE request_id = ?",
                    (parent_id,),
                ).fetchone()
            ):
                raise Conflict(
                    "delegation parent has no independent audit acknowledgement"
                )
            (event,) = db.execute(
                "SELECT event FROM tenant_audit WHERE tenant = ? AND sequence = ?",
                (parent["tenant"], sequence),
            ).fetchone()
            acknowledged_at = datetime.fromisoformat(json.loads(event)["at"])
            if not acknowledged_at <= now < acknowledged_at + PARENT_LIFETIME:
                raise Conflict("delegation parent has expired")
            identity = live_credential(db, parent["subject"], now)
            if any(
                parent[field] != identity[field]
                for field in ("tenant", "project", "env")
            ):
                raise Conflict("delegation parent identity changed")
            if parent.get("credential_generation") != identity["generation"]:
                raise Conflict("delegation parent credential generation changed")
            grants = identity["grants"]
            if parent["urn"] not in grants.get(parent["operation"], ()):
                raise Conflict("delegation parent has lost its authorization")
            limits = tuple(target_key(item) for item in source["delegate_to"])
            chain = []
            chain_deadline = acknowledged_at + PARENT_LIFETIME
            if parent_ticket := parent.get("delegation_ticket"):
                prior = issued(db, parent_ticket)
                remaining = set(map(target_key, prior["remaining"]))
                limits = tuple(item for item in limits if item in remaining)
                chain = prior["chain"]
                chain_deadline = min(
                    chain_deadline, datetime.fromtimestamp(prior["chain_deadline"], UTC)
                )
                if prior["generation"] != identity["generation"]:
                    raise Conflict("delegated identity generation changed")
            if target_key(target) not in limits or urn not in grants.get(operation, ()):
                raise Conflict("delegation exceeds the parent's remaining authority")
            destination = self.routes[operation]
            actors = [*chain, actor]
            if (
                len(actors) > MAX_DEPTH
                or len(set(actors)) != len(actors)
                or destination["audience"] in actors
            ):
                raise Conflict("delegation chain cannot revisit an audience")
            previous = db.execute(
                "SELECT claims, used_request FROM delegation_grants WHERE parent = ? AND operation = ? AND action = ? AND urn = ?",
                (parent_id, operation, action, urn),
            ).fetchone()
            if previous is not None:
                claims = json.loads(previous[0])
                if (
                    previous[1] is not None
                    or claims["exp"] <= int(now.timestamp())
                    or claims["generation"] != identity["generation"]
                ):
                    raise Conflict("the delegation grant is no longer available")
                return self.reply(claims)
            chain_deadline = min(
                chain_deadline, datetime.fromisoformat(identity["expires_at"])
            )
            expiry = min(now + timedelta(minutes=2), chain_deadline)
            claims = {
                "v": 1,
                "iss": ISSUER,
                "iat": int(now.timestamp()),
                "exp": int(expiry.timestamp()),
                "chain_deadline": int(chain_deadline.timestamp()),
                "jti": str(uuid4()),
                "parent_request_id": parent_id,
                "aud": destination["audience"],
                "sub": parent["subject"],
                "generation": identity["generation"],
                "tenant": identity["tenant"],
                "project": identity["project"],
                "env": identity["env"],
                "org": identity["org"],
                "trace_id": parent["trace_id"],
                "method": destination["method"],
                "path": destination["path"],
                **target,
                "chain": actors,
                "remaining": [
                    dict(zip(("operation", "action", "urn"), item))
                    for item in limits
                    if item != target_key(target) and item[2] in grants.get(item[0], ())
                ],
            }
            if claims["exp"] <= claims["iat"]:
                raise Conflict("delegation has no remaining lifetime")
            db.execute(
                "INSERT INTO delegation_grants VALUES (?, ?, ?, ?, ?, ?, NULL)",
                (
                    claims["jti"],
                    parent_id,
                    operation,
                    action,
                    urn,
                    json.dumps(claims, sort_keys=True),
                ),
            )
            append_audit(
                db,
                parent["tenant"],
                {
                    "action": "a2a.delegation-issued",
                    "actor": actor,
                    "subject": parent["subject"],
                    "parent_request_id": parent_id,
                    "ticket_id": claims["jti"],
                    "audience": claims["aud"],
                    "operation": operation,
                    "protocol_action": action,
                    "urn": urn,
                    "delegation_chain": actors,
                },
            )
        return self.reply(claims)

    def reply(self, claims):
        return {
            "schema": "kgateway.delegation.v1",
            "access_token": "kdel." + self.sign(claims),
            "token_type": "Bearer",
            "expires_at": claims["exp"],
        }


def canonical_uuid(value):
    parsed = UUID(value)
    if not parsed.int or str(parsed) != value:
        raise ValueError("invalid delegation identifier")
    return value


def live_credential(db, subject, now):
    row = db.execute(
        "SELECT entry FROM credentials WHERE subject = ? AND expires_at > ? "
        "AND NOT EXISTS (SELECT 1 FROM revocations WHERE subject = ?)",
        (subject, now.isoformat(), subject),
    ).fetchone()
    if row is None:
        raise Conflict("delegation subject is unavailable")
    return json.loads(row[0])


def issued(db, ticket):
    row = db.execute(
        "SELECT claims FROM delegation_grants WHERE id = ?", (ticket,)
    ).fetchone()
    if row is None:
        raise Conflict("delegation ticket is unavailable")
    return json.loads(row[0])


def consume(db, event, credential, route):
    ticket = canonical_uuid(event["delegation_ticket"])
    claims = issued(db, ticket)
    if not route.get("accept_delegation") or (
        claims["exp"] <= int(datetime.now(UTC).timestamp())
        or claims["sub"] != event["subject"]
        or claims["generation"] != credential["generation"]
        or claims["aud"] != route["audience"]
        or claims["action"] != event["protocol_action"]
        or any(
            event[field] != claims[field]
            for field in (
                "tenant",
                "project",
                "env",
                "trace_id",
                "method",
                "path",
                "operation",
                "urn",
            )
        )
    ):
        raise Conflict("delegation grant does not authorize this admission")
    changed = db.execute(
        "UPDATE delegation_grants SET used_request = ? WHERE id = ? AND used_request IS NULL",
        (event["request_id"], ticket),
    ).rowcount
    if changed != 1:
        raise Conflict("delegation grant has already been consumed")
    return {
        "parent_request_id": claims["parent_request_id"],
        "delegation_chain": claims["chain"],
        "on_behalf_of": claims["sub"],
    }
