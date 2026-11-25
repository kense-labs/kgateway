# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography==50.0.2"]
# ///
"""Run the Kense gateway control plane."""

import argparse
import hmac
import ipaddress
import json
import logging
import os
import re
import signal
import sqlite3
import ssl
import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import delegation
import maas_releases
import vault
from audit import append as append_audit
from audit import confirm_admission, read_page
from audit_anchor import AnchorClient, AnchorUnavailable
from batch_reports import SCHEMA as BATCH_REPORT_SCHEMA
from batch_reports import ingest_report
from registry import Registry
from replicas import Publisher, Replica
from state import Conflict, State, fenced_file, primary_lock, restore_file, timestamp

from usage import canonical_uuid, ingest, ingest_maas

IDENTIFIER = re.compile(r"[A-Za-z0-9._:-]{1,128}")
MAX_BODY = 8 * 1024 * 1024
LOGGER = logging.getLogger(__name__)
VAULT_ROUTES = {
    f"/v1/api/__local/vault/{action}": action
    for action in ("materialize", "apply", "revoke")
}
VAULT_REDEEM = "/v1/api/__local/vault/redeem"


class ControlPlane:
    def __init__(self, configuration, config):
        directory = configuration.resolve().parent
        self.admin_token = secret(config["admin_token_env"])
        known_tokens = {self.admin_token}
        self.replicas = {}
        self.usage_tokens = {}
        for entry in config["replicas"]:
            replica = Replica.from_config(entry, directory)
            token = secret(replica.usage_token_env)
            node_token = secret(replica.token_env)
            if (
                replica.id in self.replicas
                or token == node_token
                or known_tokens.intersection((token, node_token))
            ):
                raise ValueError("replica IDs and service credentials must be unique")
            known_tokens.update((token, node_token))
            self.replicas[replica.id] = replica
            self.usage_tokens[replica.id] = token
        if not self.replicas:
            raise ValueError("configure at least one gateway replica")
        self.maas_token = (
            secret(config["maas_usage_token_env"])
            if "maas_usage_token_env" in config
            else None
        )
        if self.maas_token in known_tokens:
            raise ValueError("MaaS metering producer must have a separate credential")
        self.audit_token = (
            secret(config["audit_token_env"]) if "audit_token_env" in config else None
        )
        if self.audit_token is not None and self.audit_token in {
            *known_tokens,
            self.maas_token,
        }:
            raise ValueError("auditor must have a separate credential")
        self.vault_token = (
            secret(config["vault_operator_token_env"])
            if "vault_operator_token_env" in config
            else None
        )
        if self.vault_token is not None and self.vault_token in {
            *known_tokens,
            self.maas_token,
            self.audit_token,
        }:
            raise ValueError("vault operator must have a separate credential")
        self.vault_consumers = {}
        known_tokens.update((self.maas_token, self.audit_token, self.vault_token))
        for audience, env in config.get("vault_consumers", {}).items():
            credential = secret(env)
            if (
                self.vault_token is None
                or not vault.valid_id(audience)
                or credential in known_tokens
            ):
                raise ValueError(
                    "Vault consumers require distinct audience credentials and an operator"
                )
            known_tokens.add(credential)
            self.vault_consumers[audience] = credential
        self.audit_witness = None
        if "audit_witness" in config:
            witness = config["audit_witness"]
            token = secret(witness["token_env"])
            if token in known_tokens:
                raise ValueError("audit witness writer must have a separate credential")
            self.audit_witness = AnchorClient(witness, directory, token)
            known_tokens.add(token)
        self.registry = Registry(config["routes"])
        self.routes = self.registry.routes
        self.operations = {route["operation"]: route for route in self.routes.values()}
        self.grants = self.registry.grants
        self.delegation = None
        self.delegation_clients = {}
        if exchange := config.get("delegation"):
            self.delegation = delegation.Exchange(
                directory / exchange["signing_key_file"], self.operations
            )
            for audience, env in exchange["client_token_env"].items():
                token = secret(env)
                if not vault.valid_id(audience) or token in known_tokens:
                    raise ValueError(
                        "delegation workloads require distinct audience credentials"
                    )
                known_tokens.add(token)
                self.delegation_clients[audience] = token
        delegation.verify_targets(self.operations, self.delegation_clients)
        for route in self.routes.values():
            if "vault_provider" in route and (
                self.vault_token is None
                or not vault.valid_id(route["vault_provider"])
                or not route.get("requires_audit_receipt")
                or route["audience"] == "urn:plat:maas:kstack"
                or route["audience"] not in self.vault_consumers
            ):
                raise ValueError(
                    "Vault route requires an audited operation for its credential-consuming service"
                )
        self.budgets = config["budgets"]
        scopes = set()
        for budget in self.budgets:
            tenant = identifier(budget["tenant"])
            operation = budget["operation"]
            project = identifier(budget["project"]) if "project" in budget else None
            env = identifier(budget["env"]) if "env" in budget else None
            scope = (tenant, operation, project, env)
            limits = budget["replicas"]
            if (
                not budget.keys()
                <= {"tenant", "operation", "project", "env", "requests", "replicas"}
                or scope in scopes
                or operation not in self.grants
                or (env is not None and project is None)
                or not limits
                or limits.keys() - self.replicas.keys()
                or any(type(value) is not int or value < 1 for value in limits.values())
                or type(budget["requests"]) is not int
                or not 0 < sum(limits.values()) <= budget["requests"] < 2**63
            ):
                raise ValueError(
                    "budgets require unique registered scopes and replica allowances within the hard cap"
                )
            scopes.add(scope)
        for tenant, operation, project, env in scopes:
            if (
                project is not None
                and (tenant, operation, project if env else None, None) not in scopes
            ):
                raise ValueError(
                    "project and environment budgets require a parent budget"
                )
        self.budget_scopes = scopes
        self.window_seconds = config.get("budget_window_seconds", 3600)
        if (
            type(self.window_seconds) is not int
            or not 60 <= self.window_seconds <= 86400
        ):
            raise ValueError("budget window must be between 60 and 86400 seconds")
        self.state = State(directory / config["state_db"], self.window_seconds)
        self.releases = maas_releases.Releases(self.state, self.registry)
        self.bind = ipaddress.ip_address(config["bind"])
        self.port = config["port"]
        self.tls = None
        if tls := config.get("tls"):
            self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.tls.minimum_version = ssl.TLSVersion.TLSv1_2
            self.tls.load_cert_chain(directory / tls["cert"], directory / tls["key"])
        elif not self.bind.is_loopback:
            raise ValueError("control plane requires TLS outside loopback")

    def publisher(self, replica):
        return Publisher(
            self.state,
            replica,
            self.registry,
            self.releases,
            self.budgets,
            self.window_seconds,
        )

    def create_key(self, entry):
        fields = {"tenant", "project", "env", "org"}
        if set(entry) != fields | {"grants", "ttl_seconds"}:
            raise ValueError(
                "key requires tenant, project, env, org, grants, and ttl_seconds"
            )
        identity = {field: identifier(entry[field]) for field in fields}
        ttl = entry["ttl_seconds"]
        if type(ttl) is not int or not 60 <= ttl <= 90 * 86400:
            raise ValueError("key validity must be between 60 seconds and 90 days")
        grants = entry["grants"]
        if not isinstance(grants, dict) or not grants:
            raise ValueError("key requires registered grants")
        for operation, resources in grants.items():
            if (
                not isinstance(resources, list)
                or not resources
                or not set(resources) <= self.grants.get(operation, set())
            ):
                raise ValueError("key grant exceeds the registered operation scope")
        expiry = (timestamp() + timedelta(seconds=ttl)).isoformat()
        return self.state.create_key(identity, grants, expiry)


def secret(name):
    token = os.environ.get(name, "")
    if not re.fullmatch(r"[!-~]{32,1024}", token):
        raise ValueError(
            f"{name} must hold a printable bearer token of at least 32 bytes"
        )
    return token


def identifier(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError("invalid identity field")
    return value


class API(BaseHTTPRequestHandler):
    server_version = "kgateway-control-plane"

    def setup(self):
        self.request.settimeout(10)
        super().setup()

    def do_GET(self):
        if self.path == "/healthz":
            self.reply(200, {"ok": True})
            return
        url = urlsplit(self.path)
        plane = self.server.plane
        if url.path == maas_releases.PATH:
            if not self.authorized(plane.admin_token):
                self.reply(401, {"error": "operator credential required"})
                return
            try:
                wanted = None
                if url.query:
                    key, _, value = url.query.partition("=")
                    if key != "revision" or not re.fullmatch(
                        r"0|[1-9][0-9]{0,15}", value
                    ):
                        raise ValueError("invalid MaaS release query")
                    wanted = maas_releases.revision(int(value))
                self.reply(200, plane.releases.status(plane.replicas, wanted))
            except (ValueError, sqlite3.Error) as error:
                self.error_response(error)
            return
        if self.path == "/v1/registry/openapi.json":
            if not self.authorized(plane.admin_token):
                self.reply(401, {"error": "operator credential required"})
                return
            try:
                self.reply(200, plane.registry.open_api())
            except (ValueError, TypeError, KeyError) as error:
                self.error_response(error)
            return
        token = plane.audit_token
        if url.path.startswith("/v1/audit/") and token is not None:
            if not self.authorized(token):
                self.reply(401, {"error": "auditor credential required"})
                return
            try:
                tenant = identifier(url.path.removeprefix("/v1/audit/"))
                parameters = parse_qs(
                    url.query,
                    keep_blank_values=True,
                    strict_parsing=True,
                    max_num_fields=2,
                )
                if parameters.keys() - {"after", "limit"} or any(
                    len(value) != 1 for value in parameters.values()
                ):
                    raise ValueError("invalid audit cursor query")
                after = int(parameters.get("after", ["0"])[0])
                limit = int(parameters.get("limit", ["128"])[0])
                if not 0 <= after < 2**63 or not 1 <= limit <= 256:
                    raise ValueError("audit cursor and limit are out of range")
                self.reply(
                    200, read_page(self.server.plane.state, tenant, after, limit)
                )
            except (ValueError, sqlite3.Error) as error:
                self.error_response(error)
            return
        self.reply(404, {"error": "unknown route"})

    def do_POST(self):
        plane = self.server.plane
        try:
            if self.path == "/v1/keys":
                if not self.authorized(plane.admin_token):
                    self.reply(401, {"error": "operator credential required"})
                    return
                self.reply(201, plane.create_key(self.read_json()))
            elif self.path in {maas_releases.PATH, maas_releases.PATH + "/rollback"}:
                if not self.authorized(plane.admin_token):
                    self.reply(401, {"error": "operator credential required"})
                    return
                self.reply(
                    201,
                    plane.releases.commit(
                        self.read_json(), self.path.endswith("/rollback")
                    ),
                )
            elif (
                self.path == "/v1/delegations/exchange" and plane.delegation is not None
            ):
                actor = next(
                    (
                        audience
                        for audience, token in plane.delegation_clients.items()
                        if self.authorized(token)
                    ),
                    None,
                )
                if actor is None:
                    self.reply(
                        401, {"error": "delegation workload credential required"}
                    )
                    return
                self.reply(
                    200,
                    plane.delegation.exchange(
                        plane.state,
                        actor,
                        self.read_json(),
                        plane.audit_witness is not None,
                    ),
                )
            elif self.path in VAULT_ROUTES and plane.vault_token is not None:
                if not self.authorized(plane.vault_token):
                    self.reply(401, {"error": "vault operator credential required"})
                    return
                action = VAULT_ROUTES[self.path]
                result = vault.update(
                    plane.state, action, self.read_json(), append_audit
                )
                self.reply(201 if action == "materialize" else 200, result)
            elif self.path == VAULT_REDEEM and plane.vault_consumers:
                audience = next(
                    (
                        audience
                        for audience, token in plane.vault_consumers.items()
                        if self.authorized(token)
                    ),
                    None,
                )
                if audience is None:
                    self.reply(401, {"error": "vault consumer credential required"})
                    return
                self.reply(
                    200,
                    vault.redeem(
                        plane.state,
                        audience,
                        self.read_json(),
                        append_audit,
                        plane.audit_witness is not None,
                    ),
                )
            elif self.path in {"/v1/usage", "/v1/audit/admissions"}:
                replica = next(
                    (
                        replica
                        for replica, token in plane.usage_tokens.items()
                        if self.authorized(token)
                    ),
                    None,
                )
                if replica is None:
                    self.reply(401, {"error": "producer credential required"})
                    return
                event = self.read_json()
                if self.path == "/v1/audit/admissions":
                    result = confirm_admission(
                        plane.state,
                        replica,
                        event,
                        plane.operations,
                        plane.budget_scopes,
                        delegation.consume if plane.delegation is not None else None,
                    )
                    if plane.audit_witness is not None:
                        plane.audit_witness.confirm(
                            plane.state, event["tenant"], result
                        )
                else:
                    result = ingest(plane.state, replica, event)
                self.reply(200, result)
            elif self.path == "/v1/maas-usage":
                if plane.maas_token is None or not self.authorized(plane.maas_token):
                    self.reply(401, {"error": "MaaS producer credential required"})
                    return
                event = self.read_json()
                receiver = (
                    ingest_report
                    if event.get("schema") == BATCH_REPORT_SCHEMA
                    else ingest_maas
                )
                self.reply(200, receiver(plane.state, event))
            else:
                self.reply(404, {"error": "unknown route"})
        except AnchorUnavailable as error:
            self.reply(503, {"error": str(error)})
        except (
            KeyError,
            TypeError,
            AttributeError,
            ValueError,
            sqlite3.Error,
        ) as error:
            self.error_response(error)

    def do_DELETE(self):
        plane = self.server.plane
        if not self.path.startswith("/v1/keys/"):
            self.reply(404, {"error": "unknown route"})
            return
        if not self.authorized(plane.admin_token):
            self.reply(401, {"error": "operator credential required"})
            return
        try:
            subject = canonical_uuid(self.path.removeprefix("/v1/keys/"))
            if plane.state.revoke_key(subject):
                self.reply(200, {"subject": subject, "revoked": True})
            else:
                self.reply(404, {"error": "unknown subject"})
        except (
            KeyError,
            TypeError,
            AttributeError,
            ValueError,
            sqlite3.Error,
        ) as error:
            self.error_response(error)

    def read_json(self):
        lengths = self.headers.get_all("Content-Length")
        if not lengths or len(lengths) != 1 or self.headers.get("Transfer-Encoding"):
            raise ValueError("request requires exact content length")
        length = int(lengths[0])
        if not 0 < length <= MAX_BODY:
            raise ValueError("request body is outside the accepted size")
        payload = json.loads(self.rfile.read(length))
        if not isinstance(payload, dict):
            raise TypeError("request body must be a JSON object")
        return payload

    def authorized(self, token):
        values = self.headers.get_all("Authorization")
        if not values or len(values) != 1:
            return False
        return hmac.compare_digest(
            values[0].encode("utf-8"), ("Bearer " + token).encode()
        )

    def error_response(self, error):
        if isinstance(error, (Conflict, vault.BindingConflict)):
            self.reply(409, {"error": str(error)})
        elif isinstance(error, sqlite3.Error):
            LOGGER.error(
                "Control-plane state operation failed: %s", type(error).__name__
            )
            self.reply(503, {"error": "durable state is unavailable"})
        else:
            self.reply(400, {"error": "request does not match the API contract"})

    def reply(self, status, value):
        payload = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def log_request(self, code="-", size="-"):
        LOGGER.info("Control-plane %s request returned %s", self.command, code)


class ControlPlaneServer(ThreadingHTTPServer):
    def __init__(self, plane):
        import socket

        self.plane = plane
        if plane.bind.version == 6:
            self.address_family = socket.AF_INET6
        super().__init__((str(plane.bind), plane.port), API)

    def get_request(self):
        connection, address = super().get_request()
        if self.plane.tls is not None:
            connection = self.plane.tls.wrap_socket(
                connection, server_side=True, do_handshake_on_connect=False
            )
        return connection, address


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    path = args.config.resolve(strict=True)
    config = json.loads(path.read_text(encoding="utf-8"))
    with primary_lock(path.parent / config["state_db"]) as locked:
        if fenced_file(locked).exists():
            raise SystemExit("control-plane state was fenced by a recovery checkpoint")
        if restore_file(locked).exists():
            raise SystemExit("control-plane state has an incomplete recovery")
        serve(ControlPlane(path, config))


def serve(plane):
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    with ControlPlaneServer(plane) as server:
        publishers = []
        for replica in plane.replicas.values():
            worker = threading.Thread(
                target=plane.publisher(replica).run, args=(stop,), daemon=True
            )
            worker.start()
            publishers.append(worker)
        if plane.audit_witness is not None:
            witness = threading.Thread(
                target=plane.audit_witness.run, args=(plane.state, stop), daemon=True
            )
            witness.start()
            publishers.append(witness)
        server.timeout = 0.5
        while not stop.is_set():
            server.handle_request()
        for worker in publishers:
            worker.join(timeout=9)


if __name__ == "__main__":
    main()
