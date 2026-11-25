"""Publish exact snapshots and ordered revocations through the Node API."""

import hashlib
import http.client
import ipaddress
import json
import logging
import os
import sqlite3
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import urlencode, urlsplit
from uuid import UUID

from state import Conflict, timestamp

SNAPSHOT_SCHEMA = "kgateway.managed-snapshot.v1"
POLICY_SCHEMA = "kgateway.platform-policy.v1"
LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class Replica:
    id: str
    endpoint: str
    token_env: str
    usage_token_env: str
    acl: str
    signer: dict
    tls: ssl.SSLContext | None

    @classmethod
    def from_config(cls, entry, directory):
        replica = str(UUID(entry["id"]))
        endpoint = entry["node_api"].rstrip("/")
        url = urlsplit(endpoint)
        if (
            not url.hostname
            or url.username
            or url.password
            or url.query
            or url.fragment
        ):
            raise ValueError("invalid replica Node API endpoint")
        context = None
        if url.scheme == "https":
            ca = entry.get("node_ca")
            context = ssl.create_default_context(
                cafile=str(directory / ca) if ca else None
            )
            if "node_client_cert" in entry:
                context.load_cert_chain(
                    directory / entry["node_client_cert"],
                    directory / entry["node_client_key"],
                )
        elif url.scheme != "http" or not ipaddress.ip_address(url.hostname).is_loopback:
            raise ValueError("replica Node API requires TLS outside loopback")
        tokens = (entry["node_token_env"], entry["usage_token_env"])
        if any(not os.environ.get(name) for name in tokens):
            raise ValueError(
                "replica Node API and usage credentials must be configured"
            )
        acl = (directory / entry["snapshot_acl"]).read_text(encoding="utf-8")
        if not acl.strip() or "\0" in acl:
            raise ValueError("invalid replica snapshot ACL")
        return cls(replica, endpoint, *tokens, acl, entry["signer"], context)

    def request(self, path, value=None):
        url = urlsplit(self.endpoint)
        if self.tls is None:
            connection = http.client.HTTPConnection(url.hostname, url.port, timeout=8)
        else:
            connection = http.client.HTTPSConnection(
                url.hostname, url.port, context=self.tls, timeout=8
            )
        try:
            headers = {"Authorization": "Bearer " + os.environ[self.token_env]}
            method, body = "GET", None
            if value is not None:
                method, body = "POST", json.dumps(value).encode()
                headers["Content-Type"] = "application/json"
            connection.request(method, url.path + path, body, headers)
            response = connection.getresponse()
            raw = response.read(65537)
            if response.status != 200 or len(raw) > 65536:
                raise Conflict(f"replica returned HTTP {response.status} for {path}")
            data = json.loads(raw)
            if data.get("gateway_id") != self.id:
                raise Conflict("Node API reported a different replica identity")
            return data
        finally:
            connection.close()


class Publisher:
    def __init__(self, state, replica, registry, releases, budgets, window_seconds):
        self.state = state
        self.replica = replica
        self.registry = registry
        self.releases = releases
        self.budgets = budgets
        self.window_seconds = window_seconds
        self.last_revision = None
        self.last_policy_digest = None

    def run(self, stop):
        while not stop.is_set():
            more = False
            try:
                more = self.publish_revocations()
                if not more:
                    self.publish_policy()
            except (
                OSError,
                ValueError,
                http.client.HTTPException,
                sqlite3.Error,
            ) as error:
                LOGGER.warning(
                    "Replica %s synchronization failed: %s", self.replica.id, error
                )
            stop.wait(0 if more else 5)

    def publish_revocations(self):
        status = self.replica.request("/platform/revocations")
        update = self.state.revocation_update(
            self.replica.id, status["sequence"], timestamp()
        )
        result = self.replica.request("/platform/revocations", update)
        if (
            result["sequence"] != update["sequence"]
            or result["fresh"] == update["more"]
        ):
            raise Conflict("replica did not confirm the exact revocation cursor")
        return update["more"]

    def publish_policy(self):
        now = timestamp()
        status = self.replica.request("/snapshots/status")
        active = status.get("applied")
        last_revision = active["revision"] if active else None
        credentials = self.state.credentials(now)
        # During a registry change keep only the grants still present in the catalogue.
        # Dropping a capability removes its old grant from subsequent snapshots.
        available = self.registry.grants
        for credential in credentials.values():
            credential["grants"] = {
                operation: sorted(set(resources) & available[operation])
                for operation, resources in credential["grants"].items()
                if operation in available and (set(resources) & available[operation])
            }
        release_revision, routes = self.releases.policy_routes()
        policy = {
            "schema": POLICY_SCHEMA,
            "signer": self.replica.signer,
            "credentials": credentials,
            "routes": routes,
            "leases": self.state.leases(
                self.replica.id, self.budgets, now, self.window_seconds
            ),
        }
        fingerprint = hashlib.sha256(
            json.dumps([release_revision, policy], sort_keys=True).encode()
        ).digest()
        if (
            active
            and self.last_revision == last_revision
            and self.last_policy_digest == fingerprint
            and datetime.fromisoformat(active["expires_at"])
            > now + timedelta(seconds=30)
        ):
            exact = urlencode(
                {
                    key: active[key]
                    for key in ("gateway_id", "revision", "snapshot_digest")
                }
            )
            if self.replica.request("/snapshots/status?" + exact)["ready"]:
                return
        expiry = min(
            now + timedelta(seconds=110),
            datetime.fromisoformat(self.replica.signer["authorized_until"]),
        )
        if expiry <= now + timedelta(seconds=30):
            raise Conflict("replica signing authority needs renewal")
        policy["expires_at"] = expiry.isoformat()
        quoted = json.dumps(json.dumps(policy, sort_keys=True, separators=(",", ":")))
        acl = self.replica.acl
        if self.registry.routers:
            acl += "\n" + self.registry.routers
        acl += f"\nplatform_policy {{ json = {quoted} }}\n"
        digest = "sha256:" + hashlib.sha256(acl.encode()).hexdigest()
        revision = (last_revision or 0) + 1
        envelope = {
            "schema": SNAPSHOT_SCHEMA,
            "gateway_id": self.replica.id,
            "revision": revision,
            "expected_revision": last_revision,
            "snapshot_digest": digest,
            "acl": acl,
            "issued_at": now.isoformat(),
            "expires_at": expiry.isoformat(),
        }
        result = self.replica.request("/snapshots/apply", envelope)
        applied = result.get("applied") or {}
        if (
            not result["ready"]
            or applied.get("revision") != revision
            or applied.get("snapshot_digest") != digest
        ):
            raise Conflict("replica did not confirm the exact snapshot")
        self.releases.published(self.replica.id, release_revision, revision, digest)
        self.last_revision = revision
        self.last_policy_digest = fingerprint
