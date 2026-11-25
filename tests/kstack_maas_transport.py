# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography==50.0.2", "mcp==1.29.0", "a2a-sdk==1.3.0", "openapi-spec-validator==0.7.2"]
# ///
"""Run the live kgateway-to-kstack transport contract against two built binaries."""

import argparse
import base64
import contextlib
import hashlib
import http.server
import json
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from uuid import uuid4

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from kstack_metal_model import running_metal_model
from kstack_model_fixture import (
    STREAM_CHUNKS,
    STREAM_FIRST_DELTA_MS,
    console_api,
    running_models,
)
from openbao_kms import openbao
from paired_maas_performance import CHAT_PATH, DIRECT_TENANT, Workload
from platform_control_plane_e2e import exercise_control_plane, wait_until
from platform_delegation_e2e import agents as delegated_agents
from platform_protocol_sdk import check_mcp
from platform_registry_sdk import generate_artifacts, registered_routes
from platform_vault_e2e import consumer as vault_consumer


def run(
    gateway_binary,
    kstack_binary,
    scratch,
    fleet_host,
    workload=None,
    rollout=False,
    with_openbao=False,
    recovery=False,
    metal=None,
):
    root = Path(__file__).resolve().parents[1]
    vector = json.loads(
        (root / "contracts/fixtures/signed-service-token-v1.json").read_text()
    )

    def decode(value):
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

    def encode(value):
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

    def port():
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            return listener.getsockname()[1]

    key = serialization.load_der_private_key(
        decode(vector["test_private_key_pkcs8"]), password=None
    )
    public_key = scratch / "signer.pem"
    public_key.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    signing_key = scratch / "signer.key"
    signing_key.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    signing_key.chmod(0o600)
    now = datetime.now(UTC)
    ca_key = Ed25519PrivateKey.generate()
    ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "kgateway integration CA")]
    )

    def certificate_builder(name, issuer, public_key):
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
            )
        )

    ca = (
        certificate_builder(ca_name, ca_name, ca_key.public_key())
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .sign(ca_key, None)
    )
    ca_file = scratch / "test-ca.pem"
    ca_file.write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    def leaf(label, usage):
        leaf_key = Ed25519PrivateKey.generate()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)])
        cert = (
            certificate_builder(name, ca_name, leaf_key.public_key())
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    True, False, False, False, False, False, False, False, False
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
            .add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ip_address("127.0.0.1"))]),
                critical=False,
            )
            .sign(ca_key, None)
        )
        return (
            cert.public_bytes(serialization.Encoding.PEM),
            leaf_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )

    private_cert_pem, private_key_pem = leaf("kstack", ExtendedKeyUsageOID.SERVER_AUTH)
    server_cert = scratch / "kstack.crt"
    server_key = scratch / "kstack.key"
    server_cert.write_bytes(private_cert_pem)
    server_key.write_bytes(private_key_pem)
    client_cert_pem, client_key_pem = leaf("kgateway", ExtendedKeyUsageOID.CLIENT_AUTH)
    client_identity = scratch / "client-identity.pem"
    client_identity.write_bytes(client_cert_pem + client_key_pem)

    kms_context = contextlib.nullcontext(None)
    vault_cert, vault_key = server_cert, server_key
    if with_openbao:
        kms_cert, kms_key = leaf("openbao", ExtendedKeyUsageOID.SERVER_AUTH)
        kms_context = openbao(scratch, kms_cert, kms_key, ca_file, wait_until)
        workload_cert, workload_key = leaf(
            "vault-workload", ExtendedKeyUsageOID.SERVER_AUTH
        )
        vault_cert = scratch / "vault-workload.crt"
        vault_key = scratch / "vault-workload.key"
        vault_cert.write_bytes(workload_cert)
        vault_key.write_bytes(workload_key)
        vault_key.chmod(0o600)

    def token(audience, **overrides):
        claims = json.loads(
            (root / "contracts/fixtures/service-token-v1.json").read_text()
        )
        now = int(time.time())
        claims.update(
            aud=audience,
            iat=now,
            exp=now + 300,
            method="GET",
            path="/v1/models",
            urn="urn:plat:maas:models",
            operation="maas.models.list",
            deployments=[],
        )
        claims.update(overrides)
        data = (
            vector["token"].split(".")[0]
            + "."
            + encode(json.dumps(claims, separators=(",", ":")).encode())
        )
        return data + "." + encode(key.sign(data.encode()))

    ports = set()
    while len(ports) < 5:
        ports.add(port())
    maas_port, console_port, gateway_port, node_port, control_port = sorted(ports)
    usage_token = secrets.token_urlsafe(32)
    kstack_config = scratch / "server.yaml"
    kstack_config.write_text(
        json.dumps(
            {
                "listen": {"console": [f"127.0.0.1:{console_port}"]},
                "auto_check_updates": False,
                "usage_report": False,
                "disable_legacy_gateway": metal is not None,
                "outbound_allow_private_hosts": ["127.0.0.1"],
                "data_dir": str(scratch / "kstack-data"),
                "maas": {
                    "addr": f"127.0.0.1:{maas_port}",
                    "tls_cert_file": str(server_cert),
                    "tls_key_file": str(server_key),
                    "client_ca_file": str(ca_file),
                    "token_issuer": "urn:plat:identity:integration",
                    "token_public_keys": {"test-key": str(public_key)},
                    "usage_endpoint": f"https://127.0.0.1:{control_port}/v1/maas-usage",
                    "usage_token_env": "KSTACK_TEST_MAAS_USAGE_TOKEN",
                    "usage_ca_file": str(ca_file),
                },
            }
        )
    )
    gateway_config = scratch / "gateway.acl"
    gateway_config.write_text(f'''
    entrypoints "edge" {{
        address = "127.0.0.1:{gateway_port}"
    }}
    routers "models" {{
        rule = "Path(`/v1/models`)"
        service = "maas"
        entrypoints = ["edge"]
    }}
    services "maas" {{
        load_balancer {{
            tls_ca_file = "{ca_file}"
            tls_client_identity_file = "{client_identity}"
            servers = [{{ url = "https://127.0.0.1:{maas_port}" }}]
        }}
    }}
    ''')

    @contextlib.contextmanager
    def process(binary, args, log, env=None):
        with log.open("w") as stream:
            child = subprocess.Popen(
                [str(binary), *args], stdout=stream, stderr=subprocess.STDOUT, env=env
            )
            try:
                yield child
            finally:
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()

    def fetch(
        url,
        jwt=None,
        context=None,
        data=None,
        headers=None,
        method=None,
        include_headers=False,
    ):
        request = urllib.request.Request(
            url, data=data, headers=headers or {}, method=method
        )
        if jwt:
            request.add_header("Authorization", "Bearer " + jwt)
        try:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=context),
            )
            with opener.open(request, timeout=10) as response:
                output = response.status, response.read()
                return (*output, response.headers) if include_headers else output
        except urllib.error.HTTPError as error:
            output = error.code, error.read()
            return (*output, error.headers) if include_headers else output

    password = secrets.token_urlsafe(32)
    kstack_env = dict(
        os.environ,
        GPUWORKS_ADMIN_PASSWORD=password,
        KSTACK_TEST_MAAS_USAGE_TOKEN=usage_token,
    )
    console_base = f"http://127.0.0.1:{console_port}"
    maas_base = f"https://127.0.0.1:{maas_port}"
    cert = ssl.create_default_context(cafile=str(ca_file))
    cert.load_cert_chain(str(client_identity))

    def start_kstack(log):
        return process(
            kstack_binary,
            ["serve", "--config", str(kstack_config)],
            scratch / log,
            kstack_env,
        )

    def wait_for_maas(maas):
        deadline = time.monotonic() + 120
        while True:
            try:
                assert fetch(maas_base + "/healthz", context=cert)[0] == 204
                return
            except urllib.error.URLError:
                if maas.poll() is not None or time.monotonic() >= deadline:
                    raise
                time.sleep(0.05)

    remaining_legacy_key = None
    with start_kstack("kstack.log") as maas:
        wait_for_maas(maas)
        if metal:
            assert fetch(console_base + "/v1/models")[0] == 404
        anonymous = ssl.create_default_context(cafile=str(ca_file))
        try:
            fetch(f"https://127.0.0.1:{maas_port}/healthz", context=anonymous)
        except ssl.SSLError as error:
            if error.reason != "TLSV13_ALERT_CERTIFICATE_REQUIRED":
                raise
        else:
            raise AssertionError(
                "maas accepted a client without a verified certificate"
            )
        subprocess.run(
            [str(gateway_binary), "validate", "--config", str(gateway_config)],
            check=True,
        )
        with process(
            gateway_binary, ["--config", str(gateway_config)], scratch / "kgateway.log"
        ) as gateway:
            url = f"http://127.0.0.1:{gateway_port}/v1/models"
            deadline = time.monotonic() + 20
            while True:
                try:
                    status, body = fetch(url, token("urn:plat:maas:kstack"))
                    assert status == 200 and json.loads(body) == {
                        "object": "list",
                        "data": [],
                    }, (status, body)
                    break
                except urllib.error.URLError:
                    if gateway.poll() is not None or time.monotonic() >= deadline:
                        raise
                    time.sleep(0.05)
            for jwt in (None, token("urn:plat:saas:directory")):
                status, body = fetch(url, jwt)
                assert (
                    status == 401
                    and json.loads(body)["error"]["code"] == "INVALID_API_KEY"
                ), (status, body)
        exercise_platform_admission(
            gateway_binary,
            scratch,
            gateway_config,
            gateway_port,
            node_port,
            ca_file,
            server_cert,
            server_key,
            client_identity,
            signing_key,
            key,
            process,
            fetch,
            token,
        )
        if metal:
            model_context = running_metal_model(
                *metal,
                console_port,
                password,
                scratch,
                process,
                fetch,
                engine_port=port(),
            )
        elif fleet_host:
            model_context = running_models(
                fleet_host,
                console_port,
                password,
                scratch,
                process,
                fetch,
                rollout=rollout,
            )
        else:
            model_context = contextlib.nullcontext(([], None))
        with (
            model_context as (models, engine_or_console),
            kms_context as kms,
            vault_consumer(
                vault_cert,
                vault_key,
                ca_file,
                public_key,
                control_port,
                kms=kms,
                scratch=scratch,
                process=process,
                wait_until=wait_until,
            ) as vault,
            delegated_agents(
                scratch, server_cert, server_key, ca_file, signing_key
            ) as agents,
        ):
            benchmark_ingress = None
            benchmark_artifacts = None
            benchmark_engine = None
            model = (
                ("kense-public-fixture", models[0][1])
                if rollout
                else (models[0] if models else None)
            )
            if workload is not None:
                alias, deployment = model
                direct_subject = str(uuid4())

                def direct_credential():
                    claims = {
                        "sub": direct_subject,
                        "tenant": DIRECT_TENANT,
                        "project": "project-test",
                        "env": "env-test",
                        "org": "org-test",
                        "operation": "maas.chat.create",
                        "method": "POST",
                        "path": CHAT_PATH,
                        "urn": "urn:plat:maas:model:" + alias,
                        "request_id": str(uuid4()),
                        "reservation_id": str(uuid4()),
                        "trace_id": secrets.token_hex(16),
                    }
                    return token(
                        "urn:plat:maas:kstack", **claims, deployments=[deployment]
                    ), claims

                benchmark_ingress = (cert, direct_credential)
                benchmark_artifacts = {
                    "kgateway": gateway_binary,
                    "kstack": kstack_binary,
                }
                if metal:
                    benchmark_artifacts["kstack-agent"] = metal[0]
                    benchmark_engine = engine_or_console
                else:
                    benchmark_artifacts["fleet-host"] = fleet_host
                    benchmark_engine = {
                        "kind": "fleet-host fake OpenAI engine",
                        "stream_first_delta_delay_ms": STREAM_FIRST_DELTA_MS,
                        "stream_chunks": STREAM_CHUNKS,
                    }
            cutover = None
            if model is not None and workload is None and not rollout:
                alias, deployment = model
                cutover, remaining_legacy_key = legacy_cohort(
                    console_base, engine_or_console, alias, deployment["id"], fetch
                )
            exercise_control_plane(
                gateway_binary,
                scratch,
                port,
                control_port,
                maas_port,
                ca_file,
                server_cert,
                server_key,
                client_identity,
                signing_key,
                process,
                fetch,
                model,
                usage_token,
                vault,
                agents,
                workload=workload,
                direct_ingress=benchmark_ingress,
                benchmark_artifacts=benchmark_artifacts,
                benchmark_engine=benchmark_engine,
                rollout=(models[1][1], engine_or_console) if rollout else None,
                recovery=recovery,
                on_model_settled=cutover,
            )
            if workload is not None or rollout:
                return
            rollover = scratch / "budget-rollover"
            rollover.mkdir()
            exercise_control_plane(
                gateway_binary,
                rollover,
                port,
                port(),
                maas_port,
                ca_file,
                server_cert,
                server_key,
                client_identity,
                signing_key,
                process,
                fetch,
                None,
                usage_token,
                vault,
                agents,
                budget_rollover=True,
            )
    if remaining_legacy_key is not None:
        config = json.loads(kstack_config.read_text())
        config["disable_legacy_gateway"] = True
        kstack_config.write_text(json.dumps(config))
        with start_kstack("kstack-cutover.log") as maas:
            wait_for_maas(maas)
            _, api = console_api(console_port, password, fetch)
            assert api("/auth/me")["username"] == "admin"
            for path, method in (
                ("/v1", "GET"),
                ("/v1/models", "GET"),
                (CHAT_PATH, "POST"),
                ("/v1/files", "GET"),
                ("/v1/batches", "GET"),
            ):
                status, raw = fetch(
                    console_base + path, remaining_legacy_key, method=method
                )
                assert status == 404, (path, status, raw)
            assert (
                fetch(
                    maas_base + "/v1/models",
                    token("urn:plat:maas:kstack"),
                    context=cert,
                )[0]
                == 200
            )
        print(
            "Verified legacy key cohort cutover and shutdown of the legacy /v1 listener."
        )
    print(
        "Live kgateway to kstack transport and snapshot-managed primary-key admission passed."
    )


def legacy_cohort(base, api, alias, deployment_id, fetch):
    keys = {
        name: api("/apikeys", {"name": name, "deployment_ids": [deployment_id]})["key"]
        for name in ("migration-pilot", "migration-next")
    }
    prefixes = {row["name"]: row["prefix"] for row in api("/apikeys")["items"]}
    payload = json.dumps(
        {"model": alias, "messages": [{"role": "user", "content": "hello"}]}
    ).encode()

    def chat(key):
        return fetch(
            base + CHAT_PATH,
            key,
            data=payload,
            headers={"Content-Type": "application/json"},
        )

    assert fetch(base + "/v1/models")[0] == 401
    for key in keys.values():
        status, raw = chat(key)
        assert status == 200 and json.loads(raw)["usage"]["completion_tokens"] > 0, (
            status,
            raw,
        )

    def cutover():
        api("/apikeys/" + prefixes["migration-pilot"], method="DELETE")
        assert chat(keys["migration-pilot"])[0] == 401
        for path in ("/v1/models", "/v1/files", "/v1/batches"):
            assert fetch(base + path, keys["migration-pilot"])[0] == 401
        assert chat(keys["migration-next"])[0] == 200

    return cutover, keys["migration-next"]


def exercise_platform_admission(
    gateway_binary,
    scratch,
    gateway_config,
    gateway_port,
    node_port,
    ca_file,
    server_cert,
    server_key,
    client_identity,
    signing_key,
    key,
    process,
    fetch,
    legacy_token,
):
    issued = datetime.now(UTC)
    expires = issued + timedelta(minutes=20)
    gateway_id = str(uuid4())
    admin = secrets.token_urlsafe(32)
    primary = "kense_first." + secrets.token_urlsafe(32)
    other = "kense_other." + secrets.token_urlsafe(32)
    observed = []
    rpc_observed = []
    sessions = set()
    upstream_session = "directory-upstream-session"
    mcp_key = scratch / "mcp-session.key"
    mcp_key.write_bytes(secrets.token_bytes(32))
    mcp_key.chmod(0o600)
    failures = []
    directory_urn = "urn:plat:directory:catalog"
    models_urn = "urn:plat:maas:models"
    a2a_signer = Ed25519PrivateKey.generate()
    tasks = {}
    a2a_resources = {
        "SendMessage": "urn:plat:agent:directory:send",
        "GetTask": "urn:plat:agent:directory:tasks",
        "CancelTask": "urn:plat:agent:directory:cancel",
    }
    rpc_targets = {
        "/mcp": (
            "urn:plat:mcp:directory",
            "mcp.directory.rpc",
            "tools/call",
            "urn:plat:mcp:directory:lookup",
        ),
        "/a2a": (
            "urn:plat:agent:directory",
            "a2a.directory.rpc",
            "GetTask",
            "urn:plat:agent:directory:tasks",
        ),
    }

    def signed_claims(header):
        assert header not in (f"Bearer {primary}", f"Bearer {other}")
        scheme, token = header.split(" ")
        protected, payload, signature = token.split(".")
        assert scheme == "Bearer"
        key.public_key().verify(
            decode_segment(signature), f"{protected}.{payload}".encode()
        )
        return json.loads(decode_segment(payload))

    def task_receipt(claims):
        header = {"alg": "EdDSA", "typ": "kgateway-a2a-task"}
        body = {scope: claims[scope] for scope in ("tenant", "project", "env")}
        body.update(
            audience=claims["aud"],
            subject=claims["sub"],
            task="task-from-directory",
            exp=int(time.time()) + 180,
            context="directory-context",
        )
        parts = [
            base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=")
            for value in (header, body)
        ]
        content = b".".join(parts)
        signature = base64.urlsafe_b64encode(a2a_signer.sign(content)).rstrip(b"=")
        return (content + b"." + signature).decode()

    class Directory(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/mcp":
                self.session_action("session/stream", "urn:plat:mcp:directory:stream")
                return
            try:
                claims = signed_claims(self.headers.get("Authorization", ""))
                assert claims["aud"] == "urn:plat:service:directory"
                assert claims["urn"] == directory_urn
                assert claims["operation"] == "directory.read"
                assert claims["method"] == "GET" and claims["path"] == self.path
                assert claims["tenant"] == "tenant-first"
                assert (
                    self.headers["x-kense-subject"] == claims["sub"] == "subject-first"
                )
                assert self.headers["x-kense-org"] == claims["org"] == "org-first"
                assert self.headers["x-kense-plane"] == claims["plane"] == "tenant"
                assert self.headers["x-request-id"] == claims["request_id"]
                assert claims["trace_id"] in self.headers["traceparent"]
                assert self.headers.get("Cookie") is None
                assert self.headers.get("X-Api-Key") is None
                assert self.headers.get("X-Kense-Tenant") is None
                observed.append(claims)
            except (
                AssertionError,
                InvalidSignature,
                KeyError,
                TypeError,
                ValueError,
            ) as error:
                failures.append(type(error).__name__)
                self.send_error(
                    400, "Scoped directory request did not match its contract"
                )
                return
            self.reply(b'{"services":["directory"]}')

        def do_POST(self):
            try:
                claims = signed_claims(self.headers.get("Authorization", ""))
                audience, operation, action, urn = rpc_targets[self.path]
                if self.path == "/mcp" and claims.get("action") == "initialize":
                    action, urn = "initialize", "urn:plat:mcp:directory:initialize"
                elif (
                    self.path == "/mcp"
                    and claims.get("action") == "notifications/initialized"
                ):
                    action, urn = (
                        "notifications/initialized",
                        "urn:plat:mcp:directory:initialized",
                    )
                elif self.path == "/a2a":
                    action = claims["action"]
                    urn = a2a_resources[action]
                assert claims["aud"] == audience and claims["operation"] == operation
                assert claims["action"] == action and claims["urn"] == urn
                assert claims["method"] == "POST" and claims["path"] == self.path
                assert (
                    claims["tenant"] == "tenant-first"
                    and claims["sub"] == "subject-first"
                )
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                assert body["method"] == action
                if action == "initialize":
                    sessions.add(upstream_session)
                    self.reply(
                        json.dumps(
                            {
                                "jsonrpc": "2.0",
                                "id": body["id"],
                                "result": {
                                    "protocolVersion": "2025-11-25",
                                    "capabilities": {"tools": {"listChanged": False}},
                                    "serverInfo": {"name": "directory", "version": "1"},
                                },
                            }
                        ).encode(),
                        session=upstream_session,
                    )
                    return
                if action == "notifications/initialized":
                    assert (
                        self.headers["Mcp-Session-Id"] == upstream_session
                        and "id" not in body
                    )
                    self.reply(b"", status=202)
                    return
                if action == "tools/call":
                    assert body["params"]["name"] == "lookup"
                    reply = {"content": [{"type": "text", "text": "directory lookup"}]}
                elif action == "SendMessage":
                    assert body["params"]["message"]["messageId"] == "directory-message"
                    ticket = task_receipt(claims)
                    tasks["task-from-directory"] = {
                        "id": ticket,
                        "status": {"state": "TASK_STATE_WORKING"},
                    }
                    reply = {"task": tasks["task-from-directory"]}
                else:
                    assert body["params"]["id"] == "task-from-directory"
                    task = tasks[body["params"]["id"]]
                    if action == "CancelTask":
                        task["status"]["state"] = "TASK_STATE_CANCELED"
                    reply = task
                rpc_observed.append(claims)
                self.reply(
                    json.dumps(
                        {"jsonrpc": "2.0", "id": body["id"], "result": reply}
                    ).encode()
                )
            except (
                AssertionError,
                InvalidSignature,
                KeyError,
                TypeError,
                ValueError,
            ) as error:
                failures.append(type(error).__name__)
                self.send_error(400, "Scoped RPC request did not match its contract")

        def do_DELETE(self):
            self.session_action("session/end", "urn:plat:mcp:directory:end")

        def session_action(self, action, urn):
            try:
                claims = signed_claims(self.headers.get("Authorization", ""))
                assert (
                    claims["action"] == action
                    and claims["urn"] == urn
                    and claims["sub"] == "subject-first"
                )
                assert (
                    claims["path"] == self.path == "/mcp"
                    and claims["method"] == self.command
                )
                assert self.headers.get("Mcp-Session-Id") == upstream_session
                if upstream_session not in sessions:
                    self.reply(b'{"error":"session expired"}', status=404)
                elif self.command == "GET":
                    if self.headers.get("Last-Event-ID") == "event-1":
                        self.reply(
                            b'id: event-2\ndata: {"jsonrpc":"2.0","method":"notifications/message"}\n\n',
                            media="text/event-stream",
                        )
                    else:
                        self.reply(b"", status=405)
                else:
                    sessions.remove(upstream_session)
                    self.reply(b"", status=204)
            except (
                AssertionError,
                InvalidSignature,
                KeyError,
                TypeError,
                ValueError,
            ) as error:
                failures.append(type(error).__name__)
                self.send_error(
                    400, "Scoped session request did not match its contract"
                )

        def reply(self, body, status=200, session=None, media="application/json"):
            self.send_response(status)
            self.send_header("Content-Type", media)
            self.send_header("Content-Length", str(len(body)))
            if session:
                self.send_header("Mcp-Session-Id", session)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            pass

    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Directory) as directory:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(str(server_cert), str(server_key))
        tls.load_verify_locations(cafile=str(ca_file))
        tls.verify_mode = ssl.CERT_REQUIRED
        directory.socket = tls.wrap_socket(directory.socket, server_side=True)
        server_thread = threading.Thread(target=directory.serve_forever, daemon=True)
        server_thread.start()
        try:
            public_acl = gateway_config.read_text()
            entry = public_acl[: public_acl.index('    routers "models"')]
            bootstrap = f'''
                mode {{ kind = "cloud-managed" }}
                managed {{
                    gateway_id = "{gateway_id}"
                    state_file = "{scratch / "snapshot.json"}"
                    usage_spool {{ directory = "{scratch / "usage"}" }}
                    platform {{
                        signing_key_file = "{signing_key}"
                        budget_state_file = "{scratch / "budgets.json"}"
                        mcp_session_key_file = "{mcp_key}"
                    }}
                }}
                management {{
                    enabled = true
                    address = "127.0.0.1:{node_port}"
                    auth_token_env = "KGATEWAY_PLATFORM_TEST_ADMIN"
                }}
                {entry}
            '''
            gateway_config.write_text(bootstrap)
            active = (
                bootstrap
                + public_acl[public_acl.index('    services "maas"') :]
                + f'''
                services "directory" {{
                    load_balancer {{
                        tls_ca_file = "{ca_file}"
                        tls_client_identity_file = "{client_identity}"
                        servers = [{{ url = "https://127.0.0.1:{directory.server_port}" }}]
                    }}
                }}
            '''
            )
            session_methods = {"stream": "GET", "end": "DELETE"}

            def credential(name, token, grants):
                return {
                    "subject": f"subject-{name}",
                    "generation": 1,
                    "tenant": f"tenant-{name}",
                    "project": f"project-{name}",
                    "env": "prod",
                    "org": f"org-{name}",
                    "expires_at": expires.isoformat(),
                    "grants": grants,
                    "verifier_hash": Argon2id(
                        salt=secrets.token_bytes(16),
                        length=32,
                        iterations=2,
                        lanes=1,
                        memory_cost=19456,
                    ).derive_phc_encoded(token.encode()),
                }

            def lease(operation, requests, tenant="tenant-first"):
                return {
                    "id": str(uuid4()),
                    "gateway_id": gateway_id,
                    "tenant": tenant,
                    "operation": operation,
                    "expires_at": expires.isoformat(),
                    "requests": requests,
                }

            policy = {
                "schema": "kgateway.platform-policy.v1",
                "expires_at": expires.isoformat(),
                "signer": {
                    "issuer": "urn:plat:identity:integration",
                    "key_id": "test-key",
                    "authorized_until": expires.isoformat(),
                },
                "credentials": {
                    "kense_first": credential(
                        "first",
                        primary,
                        {
                            "directory.read": [directory_urn],
                            "maas.models.list": [models_urn],
                            "mcp.directory.rpc": [
                                "urn:plat:mcp:directory:list",
                                "urn:plat:mcp:directory:initialize",
                                "urn:plat:mcp:directory:initialized",
                                "urn:plat:mcp:directory:call",
                                "urn:plat:mcp:directory:lookup",
                            ],
                            "a2a.directory.rpc": list(a2a_resources.values()),
                            "mcp.directory.stream": ["urn:plat:mcp:directory:stream"],
                            "mcp.directory.end": ["urn:plat:mcp:directory:end"],
                        },
                    ),
                    "kense_other": credential(
                        "other",
                        other,
                        {
                            "maas.models.list": [models_urn],
                            "mcp.directory.stream": ["urn:plat:mcp:directory:stream"],
                            "a2a.directory.rpc": [a2a_resources["GetTask"]],
                        },
                    ),
                },
                "routes": {
                    "models": {
                        "method": "GET",
                        "path": "/v1/models",
                        "audience": "urn:plat:maas:kstack",
                        "operation": "maas.models.list",
                        "resource": {
                            "kind": "model-list",
                            "urn": models_urn,
                            "targets": {},
                        },
                    },
                    "directory": {
                        "method": "GET",
                        "path": "/directory",
                        "audience": "urn:plat:service:directory",
                        "operation": "directory.read",
                        "resource": {"kind": "fixed", "urn": directory_urn},
                    },
                },
                "leases": [
                    lease("directory.read", 2),
                    lease("maas.models.list", 2),
                    lease("maas.models.list", 2, "tenant-other"),
                    lease("mcp.directory.rpc", 3),
                    lease("a2a.directory.rpc", 4),
                    lease("mcp.directory.stream", 6),
                    lease("mcp.directory.end", 3),
                ],
            }
            policies = {
                "/mcp": {
                    "protocol": "mcp",
                    "origins": ["https://tools.example.test"],
                    "methods": {
                        "tools/list": "urn:plat:mcp:directory:list",
                        "initialize": "urn:plat:mcp:directory:initialize",
                        "notifications/initialized": "urn:plat:mcp:directory:initialized",
                        "tools/call": "urn:plat:mcp:directory:call",
                    },
                    "tools": {
                        "lookup": {
                            "urn": "urn:plat:mcp:directory:lookup",
                            "description": "Read a directory entry.",
                            "inputSchema": {"type": "object"},
                        },
                        "update": {
                            "urn": "urn:plat:mcp:directory:update",
                            "description": "Update a directory entry.",
                            "inputSchema": {"type": "object"},
                        },
                    },
                },
                "/a2a": {
                    "protocol": "a2a",
                    "methods": a2a_resources,
                    "task_public_key": a2a_signer.public_key()
                    .public_bytes(
                        serialization.Encoding.PEM,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                    .decode(),
                },
            }
            for path, (audience, operation, _, _) in rpc_targets.items():
                policy["routes"][path[1:]] = {
                    "method": "POST",
                    "path": path,
                    "audience": audience,
                    "operation": operation,
                    "resource": {"kind": "rpc", "policy": policies[path]},
                }
            for action, method in session_methods.items():
                policy["routes"][f"mcp-{action}"] = {
                    "method": method,
                    "path": "/mcp",
                    "audience": "urn:plat:mcp:directory",
                    "operation": f"mcp.directory.{action}",
                    "resource": {
                        "kind": "mcp-session",
                        "urn": f"urn:plat:mcp:directory:{action}",
                    },
                }
            registration = scratch / "protocol-registry.json"
            services = dict.fromkeys(policy["routes"].keys() - {"models"}, "directory")
            registration.write_text(
                json.dumps({"routes": registered_routes(policy["routes"], services)})
            )
            output = scratch / "protocol-registry"
            spec = generate_artifacts(registration, output)
            mcp = spec["paths"]["/mcp"]
            assert set(mcp) == {"post", "get", "delete"}
            assert (
                mcp["post"]["x-kense"]["tools"]["lookup"]["urn"]
                == "urn:plat:mcp:directory:lookup"
            )
            assert (
                spec["paths"]["/a2a"]["post"]["x-kense"]["rpcMethods"] == a2a_resources
            )
            assert spec["paths"]["/directory"]["get"]["x-kense"]["protocol"] == "rest"
            active += "\n" + (output / "routers.acl").read_text()
            with_policy = (
                active
                + f"platform_policy {{ json = {json.dumps(json.dumps(policy))} }}\n"
            )
            node = f"http://127.0.0.1:{node_port}/api/gateway"
            public = f"http://127.0.0.1:{gateway_port}"
            env = dict(os.environ, KGATEWAY_PLATFORM_TEST_ADMIN=admin)

            def publish(revision, configuration):
                envelope = {
                    "schema": "a3s.gateway.managed-snapshot.v1",
                    "gateway_id": gateway_id,
                    "revision": revision,
                    "expected_revision": revision - 1 or None,
                    "snapshot_digest": "sha256:"
                    + hashlib.sha256(configuration.encode()).hexdigest(),
                    "issued_at": issued.isoformat(),
                    "expires_at": expires.isoformat(),
                    "acl": configuration,
                }
                return fetch(
                    node + "/snapshots/apply",
                    admin,
                    data=json.dumps(envelope).encode(),
                    headers={"Content-Type": "application/json"},
                )

            def wait_ready(child):
                deadline = time.monotonic() + 20
                while True:
                    try:
                        assert fetch(node + "/health", admin)[0] == 200
                        return
                    except urllib.error.URLError:
                        if child.poll() is not None or time.monotonic() >= deadline:
                            raise
                        time.sleep(0.05)

            def revocation_update(sequence, changes):
                now = datetime.now(UTC)
                return {
                    "schema": "kgateway.platform-revocations.v1",
                    "gateway_id": gateway_id,
                    "sequence": sequence,
                    "issued_at": now.isoformat(),
                    "valid_until": (now + timedelta(seconds=90)).isoformat(),
                    "changes": changes,
                }

            def update_revocations(update, bearer=admin):
                return fetch(
                    node + "/platform/revocations",
                    bearer,
                    data=json.dumps(update).encode(),
                    headers={"Content-Type": "application/json"},
                )

            with process(
                gateway_binary,
                ["--config", str(gateway_config)],
                scratch / "kgateway-platform.log",
                env,
            ) as gateway:
                wait_ready(gateway)
                assert fetch(public + "/v1/models", primary)[0] == 404
                status, body = publish(1, with_policy)
                assert status == 200 and json.loads(body)["ready"], (status, body)
                assert fetch(public + "/v1/models", primary)[0] == 503
                heartbeat = revocation_update(1, [])
                assert update_revocations(heartbeat, bearer=primary)[0] == 401
                status, body = update_revocations(heartbeat)
                assert status == 200 and json.loads(body)["fresh"], (status, body)
                assert update_revocations(heartbeat)[0] == 200
                assert update_revocations(revocation_update(3, []))[0] == 409
                status, body = fetch(public + "/v1/models", primary)
                assert status == 200 and json.loads(body) == {
                    "object": "list",
                    "data": [],
                }, (status, body)
                status, body = fetch(
                    public + "/directory",
                    primary,
                    headers={
                        "X-Kense-Subject": "forged",
                        "X-Kense-Org": "forged",
                        "X-Kense-Tenant": "forged",
                        "X-Api-Key": primary,
                        "Cookie": "credential=" + primary,
                    },
                )
                assert status == 200 and json.loads(body) == {
                    "services": ["directory"]
                }, (status, body)
                assert fetch(public + "/directory", other)[0] == 403
                assert (
                    fetch(
                        public + "/directory",
                        legacy_token("urn:plat:service:directory"),
                    )[0]
                    == 401
                )
                assert fetch(public + "/v1/models", primary, method="POST")[0] == 404
                session = check_rpc_routes(fetch, public, primary, other)
                assert session != upstream_session
                assert len(rpc_observed) == 5 and not failures
                assert publish(2, active)[0] != 200
                sdk_policy = policy | {
                    "leases": [
                        entry
                        for entry in policy["leases"]
                        if entry["operation"] != "mcp.directory.rpc"
                    ]
                    + [lease("mcp.directory.rpc", 6)]
                }
                sdk_snapshot = (
                    active
                    + f"platform_policy {{ json = {json.dumps(json.dumps(sdk_policy))} }}\n"
                )
                assert publish(2, sdk_snapshot)[0] == 200
                check_mcp_session(
                    fetch, public, primary, other, session, upstream_session
                )
                check_mcp(public + "/mcp", primary, upstream_session)
                assert upstream_session not in sessions and not failures
                assert fetch(public + "/directory", primary)[0] == 200
                assert fetch(public + "/directory", primary)[0] == 429
                assert len(observed) == 2 and not failures
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    health = json.loads(fetch(node + "/health", admin)[1])
                    if health.get("usage_spool", {}).get("retained_records", 0) >= 6:
                        break
                    time.sleep(0.03)
                else:
                    raise AssertionError(
                        "start and terminal usage events did not reach the durable spool"
                    )

            with process(
                gateway_binary,
                ["--config", str(gateway_config)],
                scratch / "kgateway-platform-restart.log",
                env,
            ) as gateway:
                wait_ready(gateway)
                assert fetch(public + "/directory", primary)[0] == 429
                assert fetch(public + "/v1/models", primary)[0] == 200
                assert fetch(public + "/v1/models", primary)[0] == 429
                assert len(observed) == 2
                status, body = update_revocations(
                    revocation_update(
                        2, [{"subject": "subject-first", "through_generation": 1}]
                    )
                )
                assert status == 200 and json.loads(body)["sequence"] == 2, (
                    status,
                    body,
                )
                assert fetch(public + "/directory", primary)[0] == 401
                assert fetch(public + "/v1/models", other)[0] == 200
                expiring = revocation_update(3, [])
                expiring["valid_until"] = (
                    datetime.now(UTC) + timedelta(seconds=1)
                ).isoformat()
                assert update_revocations(expiring)[0] == 200
                wait_until(
                    lambda: (
                        not json.loads(fetch(node + "/platform/revocations", admin)[1])[
                            "fresh"
                        ]
                    ),
                    timeout=4,
                )
                assert fetch(public + "/v1/models", other)[0] == 503
                assert (
                    update_revocations(revocation_update(4, []) | {"more": True})[0]
                    == 200
                )
                assert fetch(public + "/v1/models", other)[0] == 503
                assert update_revocations(revocation_update(5, []))[0] == 200
                assert fetch(public + "/v1/models", other)[0] == 200
                assert fetch(public + "/v1/models", other)[0] == 429
                assert publish(3, with_policy)[0] == 200
                assert fetch(public + "/directory", primary)[0] == 401
                records = []
                for segment in (scratch / "usage").glob("epoch-*.jsonl"):
                    for line in segment.read_text().splitlines()[1:]:
                        raw = base64.b64decode(json.loads(line)["payload_base64"])
                        assert primary.encode() not in raw and other.encode() not in raw
                        records.append(json.loads(raw))
                for claims in observed:
                    events = [
                        event
                        for event in records
                        if event["request_id"] == claims["request_id"]
                    ]
                    assert [event["kind"] for event in events] == [
                        "request-started",
                        "request-terminal",
                    ]
                    assert events[1]["billing_parent"] == events[0]["event_id"]
                    assert events[1]["reservation_id"] == claims["reservation_id"]
                    assert events[1]["egress_bytes"] == len(
                        b'{"services":["directory"]}'
                    )
            with process(
                gateway_binary,
                ["--config", str(gateway_config)],
                scratch / "kgateway-platform-revocation-restart.log",
                env,
            ) as gateway:
                wait_ready(gateway)
                status, body = fetch(node + "/platform/revocations", admin)
                assert status == 200 and json.loads(body)["sequence"] == 5, (
                    status,
                    body,
                )
                assert fetch(public + "/directory", primary)[0] == 401
        finally:
            directory.shutdown()
            server_thread.join(timeout=3)


def decode_segment(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def check_rpc_routes(fetch, public, primary, other):
    def rpc(path, method, params, token=primary, origin=None, include_headers=False):
        headers = {"Content-Type": "application/json"}
        if origin:
            headers["Origin"] = origin
        data = json.dumps(
            {"jsonrpc": "2.0", "id": "r1", "method": method, "params": params}
        ).encode()
        return fetch(
            public + path,
            token,
            data=data,
            headers=headers,
            include_headers=include_headers,
        )

    lookup = {"name": "lookup", "arguments": {"id": "fixture"}}
    status, body = rpc("/mcp", "tools/list", {})
    assert status == 200 and [
        tool["name"] for tool in json.loads(body)["result"]["tools"]
    ] == ["lookup"]
    assert (
        rpc("/mcp", "tools/call", lookup, origin="https://other.example.test")[0] == 403
    )
    assert rpc("/mcp", "tools/call", lookup, token=other)[0] == 403
    assert rpc("/mcp", "tools/call", {"name": "update"})[0] == 403
    assert rpc("/mcp", "tools/call", {"name": None})[0] == 400
    status, body = rpc(
        "/mcp", "tools/call", lookup, origin="https://tools.example.test"
    )
    assert (
        status == 200
        and json.loads(body)["result"]["content"][0]["text"] == "directory lookup"
    )
    status, body, headers = rpc(
        "/mcp",
        "initialize",
        {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"},
        },
        include_headers=True,
    )
    assert (
        status == 200 and json.loads(body)["result"]["protocolVersion"] == "2025-11-25"
    )
    assert rpc("/mcp", "tools/call", lookup)[0] == 429
    assert rpc("/a2a", "GetTask", {"id": "task-from-directory"})[0] == 403
    message = {
        "messageId": "directory-message",
        "role": "ROLE_USER",
        "parts": [{"text": "Read the directory."}],
    }
    status, body = rpc("/a2a", "SendMessage", {"message": message})
    assert status == 200, (status, body)
    started = json.loads(body)["result"]["task"]
    assert started["status"]["state"] == "TASK_STATE_WORKING"
    task = {"id": started["id"]}
    assert rpc("/a2a", "SubscribeToTask", task)[0] == 403
    assert rpc("/a2a", "GetTask", task, token=other)[0] == 403
    status, body = rpc("/a2a", "GetTask", task)
    assert status == 200 and json.loads(body)["result"]["id"] == task["id"]
    status, body = rpc("/a2a", "CancelTask", task)
    assert (
        status == 200
        and json.loads(body)["result"]["status"]["state"] == "TASK_STATE_CANCELED"
    )
    status, body = rpc("/a2a", "GetTask", task)
    assert (
        status == 200
        and json.loads(body)["result"]["status"]["state"] == "TASK_STATE_CANCELED"
    )
    return headers["Mcp-Session-Id"]


def check_mcp_session(fetch, public, primary, other, session, raw_session):
    url = public + "/mcp"
    headers = {
        "Accept": "text/event-stream",
        "Mcp-Protocol-Version": "2025-11-25",
        "Mcp-Session-Id": session,
        "Last-Event-ID": "event-1",
    }
    assert session
    assert fetch(url, other, headers=headers)[0] == 403
    assert (
        fetch(url, primary, headers=headers | {"Mcp-Session-Id": raw_session})[0] == 403
    )
    status, body = fetch(url, primary, headers=headers)
    assert status == 200 and b"id: event-2\n" in body, (status, body)
    assert (
        fetch(url, primary, headers={"Mcp-Session-Id": session}, method="DELETE")[0]
        == 204
    )
    assert fetch(url, primary, headers=headers)[0] == 404


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kgateway", required=True, type=Path)
    parser.add_argument("--kstack", required=True, type=Path)
    parser.add_argument("--fleet-host", type=Path)
    parser.add_argument(
        "--metal-agent", type=Path, help="native kstack agent for the performance run"
    )
    parser.add_argument(
        "--metal-model", type=Path, help="GGUF file in a local model directory"
    )
    parser.add_argument(
        "--metal-image", help="darwin/arm64 llama.cpp host environment image"
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--performance-output", type=Path)
    mode.add_argument("--release-rollout", action="store_true")
    parser.add_argument(
        "--recovery",
        action="store_true",
        help="exercise a witnessed control-plane handoff during --release-rollout",
    )
    mode.add_argument(
        "--openbao",
        action="store_true",
        help="run Vault acceptance with isolated OpenBao Transit via Docker",
    )
    parser.add_argument(
        "--performance-requests",
        type=int,
        default=64,
        help="measured requests per ingress, protocol and round",
    )
    parser.add_argument("--performance-concurrency", type=int, default=8)
    args = parser.parse_args()
    if args.release_rollout and args.fleet_host is None:
        parser.error("--release-rollout requires --fleet-host")
    if args.recovery and not args.release_rollout:
        parser.error("--recovery requires --release-rollout")
    metal = None
    if any((args.metal_agent, args.metal_model, args.metal_image)):
        if (
            not all(
                (
                    args.metal_agent,
                    args.metal_model,
                    args.metal_image,
                    args.performance_output,
                )
            )
            or args.fleet_host
        ):
            parser.error(
                "Metal testing requires --metal-agent, --metal-model, --metal-image and --performance-output without --fleet-host"
            )
        if (os.uname().sysname, os.uname().machine) != ("Darwin", "arm64"):
            parser.error("Metal testing requires an Apple Silicon macOS host")
        metal = (
            args.metal_agent.resolve(strict=True),
            args.metal_model.resolve(strict=True),
            args.metal_image,
        )
    workload = None
    if args.performance_output is not None:
        if args.fleet_host is None and metal is None:
            parser.error(
                "--performance-output requires --fleet-host or the Metal arguments"
            )
        if not 1 <= args.performance_concurrency <= args.performance_requests:
            parser.error(
                "performance concurrency must be between 1 and the request count"
            )
        workload = Workload(
            args.performance_output.resolve(),
            args.performance_requests,
            args.performance_concurrency,
            minimum_prompt_tokens=int(metal is not None),
        )
    scratch = Path(tempfile.mkdtemp(prefix="kgateway-kstack-transport-"))
    try:
        run(
            args.kgateway.resolve(strict=True),
            args.kstack.resolve(strict=True),
            scratch,
            args.fleet_host.resolve(strict=True) if args.fleet_host else None,
            workload,
            args.release_rollout,
            args.openbao,
            args.recovery,
            metal,
        )
    except Exception as error:
        error.add_note(f"Process logs and configuration are in {scratch}")
        raise
    else:
        shutil.rmtree(scratch)


if __name__ == "__main__":
    main()
