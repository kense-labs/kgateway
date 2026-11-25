"""Exercise A2A workload identity and downscoping across a gateway pair."""

import base64
import json
import secrets
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from platform_protocol_sdk import check_a2a

EXCHANGE = "/v1/delegations/exchange"
ACTORS = ("a", "b", "c", "d")
HEADERS = {"Content-Type": "application/json"}


def audience(actor):
    return f"urn:plat:a2a:fixture-{actor}"


def capability(actor, action="SendMessage"):
    return {
        "operation": f"a2a.fixture-{actor}.rpc",
        "action": action,
        "urn": f"{audience(actor)}:{action}",
    }


def routes(task_key):
    graph = {"a": ("b", "c"), "b": ("c", "d"), "c": (), "d": ()}
    return {
        f"a2a-{actor}": {
            "method": "POST",
            "path": f"/agent-{actor}",
            "audience": audience(actor),
            "operation": capability(actor)["operation"],
            "requires_audit_receipt": True,
            "accept_delegation": actor != "a",
            "delegate_to": [capability(target) for target in graph[actor]],
            "resource": {
                "kind": "rpc",
                "policy": {
                    "protocol": "a2a",
                    "task_public_key": task_key,
                    "methods": {
                        action: capability(actor, action)["urn"]
                        for action in ("SendMessage", "SendStreamingMessage")
                    },
                },
            },
        }
        for actor in ACTORS
    }


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@dataclass
class Agents:
    port: int
    key_file: Path
    public_file: Path
    task_key: str
    observed: dict
    credentials: dict

    def token_env(self, actor):
        return "DELEGATION_ACTOR_" + actor.upper()


@contextmanager
def agents(scratch, server_cert, server_key, ca, signer):
    broker = Ed25519PrivateKey.generate()
    broker_key, broker_public = scratch / "delegation.key", scratch / "delegation.pem"
    broker_key.write_bytes(
        broker.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    broker_key.chmod(0o600)
    broker_public.write_bytes(
        broker.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    task_key = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode()
    )
    verifier = serialization.load_pem_private_key(
        signer.read_bytes(), None
    ).public_key()
    observed = {actor: [] for actor in ACTORS}

    class Agent(BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                actor = self.path.removeprefix("/agent-")
                scheme, token = self.headers["Authorization"].split(" ", 1)
                header, payload, signature = token.split(".")
                verifier.verify(decode(signature), f"{header}.{payload}".encode())
                subject = json.loads(decode(payload))
                request = json.loads(
                    self.rfile.read(int(self.headers["Content-Length"]))
                )
                assert scheme == "Bearer" and subject["aud"] == audience(actor)
                assert subject["method"] == "POST" and subject["path"] == self.path
                expected = capability(actor, request["method"])
                assert (
                    subject["operation"] == expected["operation"]
                    and subject["urn"] == expected["urn"]
                )
                assert subject["action"] == request["method"] and subject["exp"] > int(
                    time.time()
                )
                observed[actor].append(subject)
            except (AssertionError, InvalidSignature, KeyError, ValueError):
                self.send_error(400, "unexpected A2A invocation")
                return
            data = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": request["id"],
                    "result": {"message": {"role": "ROLE_AGENT", "messageId": "fixture-response", "parts": [{"text": "ok"}]}},
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Agent) as server:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(str(server_cert), str(server_key))
        tls.load_verify_locations(cafile=str(ca))
        tls.verify_mode = ssl.CERT_REQUIRED
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield Agents(
                server.server_port,
                broker_key,
                broker_public,
                task_key,
                observed,
                {actor: secrets.token_urlsafe(32) for actor in ACTORS},
            )
        finally:
            server.shutdown()
            thread.join(timeout=5)


def invoke(fetch, base, actor, token, action="SendMessage"):
    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": action,
        "params": {"message": {"role": "ROLE_USER", "parts": [{"text": "hello"}]}},
    }
    return fetch(
        base + f"/agent-{actor}",
        token,
        data=json.dumps(message).encode(),
        headers=HEADERS,
    )


def check(first, second, owner, admin, api, fetch, agents):
    def exchange(actor_token, parent, target):
        return api(
            EXCHANGE,
            actor_token,
            data=json.dumps(
                {
                    "parent_request_id": parent["request_id"],
                    "target": capability(target),
                }
            ).encode(),
            headers=HEADERS,
        )

    check_a2a(first + "/agent-a", owner)
    root = agents.observed["a"][0]
    assert "on_behalf_of" not in root and "delegation_chain" not in root
    assert exchange(admin, root, "b")[0] == 401
    assert exchange(agents.credentials["b"], root, "b")[0] == 409
    assert exchange(agents.credentials["a"], root, "d")[0] == 409
    status, body = exchange(agents.credentials["a"], root, "b")
    assert status == 200, (status, body)
    ticket = json.loads(body)
    assert exchange(agents.credentials["a"], root, "b") == (200, body)
    access = ticket["access_token"]
    assert invoke(fetch, second, "c", access)[0] == 401
    assert invoke(fetch, second, "b", access + "x")[0] == 401
    assert invoke(fetch, second, "b", access, "SendStreamingMessage")[0] == 403
    status, body = invoke(fetch, second, "b", access)
    assert status == 200, (status, body)
    assert invoke(fetch, first, "b", access)[0] == 503
    assert exchange(agents.credentials["a"], root, "b")[0] == 409
    (middle,) = agents.observed["b"]
    assert (
        middle["delegation_chain"] == [audience("a")]
        and middle["on_behalf_of"] == root["sub"]
    )
    assert middle["exp"] <= ticket["expires_at"]
    assert exchange(agents.credentials["b"], middle, "d")[0] == 409
    status, body = exchange(agents.credentials["b"], middle, "c")
    assert status == 200, (status, body)
    leaf_ticket = json.loads(body)["access_token"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        jobs = [
            pool.submit(invoke, fetch, base, "c", leaf_ticket)
            for base in (first, second)
        ]
        outcomes = [job.result() for job in jobs]
    assert sorted(status for status, _ in outcomes) == [200, 503], outcomes
    (leaf,) = agents.observed["c"]
    assert leaf["delegation_chain"] == [audience("a"), audience("b")]
    assert leaf["sub"] == leaf["on_behalf_of"] == root["sub"]
    assert leaf["trace_id"] == middle["trace_id"] == root["trace_id"]
    observations = json.dumps(agents.observed)
    assert all(
        secret not in observations
        for secret in [owner, access, *agents.credentials.values()]
    )
    assert not agents.observed["d"]
    status, body = invoke(fetch, first, "a", owner)
    assert status == 200, (status, body)
    status, body = exchange(agents.credentials["a"], agents.observed["a"][-1], "b")
    assert status == 200, (status, body)
    return json.loads(body)
