"""Exercise Vault bindings with a private mTLS credential-consuming service."""

import base64
import hashlib
import json
import os
import secrets
import ssl
import sys
import threading
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import UUID

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from openbao_kms import KEY_ID as TRANSIT_KEY_ID
from openbao_kms import KmsFixture, Transit, json_post

PATH = "/vault-probe"
PROVIDER = "provider-test"
OPERATION = "connector.vault-probe.call"
URN = "urn:plat:service:vault-egress:call"
AUDIENCE = "urn:plat:service:vault-egress"
VAULT_API = "/v1/api/__local/vault/"
OTHER_AUDIENCE = "urn:plat:service:other-egress"
ISSUER = "urn:plat:identity:integration"
LOCAL_KEY_ID = "kms/test/key-1"
SCOPE = {
    "tenant": "tenant-test",
    "org": "org-test",
    "project": "project-test",
    "env": "env-test",
    "provider": PROVIDER,
}
Seal = Callable[[bytes, dict, str], bytes]


@dataclass
class Consumer:
    port: int
    credential: str
    other_credential: str
    key_id: str
    seal: Seal
    records: list | Path
    kms: KmsFixture | None = None

    @property
    def observed(self):
        if isinstance(self.records, Path):
            return [json.loads(line) for line in self.records.read_text().splitlines()]
        return self.records


@contextmanager
def listener(
    server_cert,
    server_key,
    ca,
    signer,
    control_port,
    credential,
    key_id,
    decrypt,
    record,
):
    verifier = load_pem_public_key(signer.read_bytes())
    control_tls = ssl.create_default_context(cafile=str(ca))

    def decode(value):
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

    class Egress(BaseHTTPRequestHandler):
        def do_GET(self):
            try:
                (authorization,) = self.headers.get_all("Authorization") or []
                scheme, token = authorization.split(" ", 1)
                header, payload, signature = token.split(".")
                assert json.loads(decode(header)) == {
                    "alg": "EdDSA",
                    "typ": "JWT",
                    "kid": "test-key",
                }
                verifier.verify(decode(signature), f"{header}.{payload}".encode())
                identity = json.loads(decode(payload))
                assert (
                    scheme == "Bearer"
                    and identity["aud"] == AUDIENCE
                    and identity["iss"] == ISSUER
                )
                assert identity["v"] == 1 and identity["plane"] == "tenant"
                assert (
                    identity["iat"] <= datetime.now(UTC).timestamp() < identity["exp"]
                )
                assert identity["operation"] == OPERATION and identity["urn"] == URN
                assert (
                    identity["method"] == "GET"
                    and identity["path"] == self.path == PATH
                )
                assert all(
                    identity[key] == value
                    for key, value in SCOPE.items()
                    if key != "provider"
                )
                binding = identity["vault_binding"]
                assert (
                    set(binding) == {"secret_ref", "version"}
                    and UUID(identity["request_id"]).int
                )
            except (AssertionError, InvalidSignature, KeyError, TypeError, ValueError):
                self.send_error(400, "invalid scoped invocation")
                return
            try:
                status, envelope = json_post(
                    f"https://127.0.0.1:{control_port}",
                    VAULT_API + "redeem",
                    control_tls,
                    {"request_id": identity["request_id"], **binding},
                    credential,
                )
                if (
                    status != 200
                    or not isinstance(envelope, dict)
                    or envelope.keys() != {"schema", "ciphertext", "key_id"}
                    or envelope.get("schema") != "kgateway.vault-envelope.v1"
                    or envelope.get("key_id") != key_id
                ):
                    raise ValueError("credential envelope unavailable")
                scope = {key: identity[key] for key in SCOPE if key != "provider"} | {
                    "provider": PROVIDER
                }
                sealed = base64.b64decode(envelope["ciphertext"], validate=True)
                plaintext = decrypt(sealed, scope, binding["secret_ref"])
            except (InvalidTag, ValueError, KeyError, OSError):
                self.send_error(503, "credential unavailable")
                return
            record((identity, hashlib.sha256(plaintext).hexdigest()))
            response = json.dumps(binding).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, *_):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Egress) as server:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(str(server_cert), str(server_key))
        tls.load_verify_locations(cafile=str(ca))
        tls.verify_mode = ssl.CERT_REQUIRED
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        yield server


@contextmanager
def consumer(
    server_cert,
    server_key,
    ca,
    signer,
    control_port,
    *,
    kms,
    scratch,
    process,
    wait_until,
):
    credential = secrets.token_urlsafe(32)
    other = secrets.token_urlsafe(32)
    if kms is not None:
        directory = scratch / "vault-workload"
        directory.mkdir(mode=0o700)
        ready = directory / "ready"
        records = directory / "observations.jsonl"
        records.touch(mode=0o600)
        config = directory / "fixture.json"
        config.write_text(
            json.dumps(
                {
                    "cert": str(server_cert),
                    "key": str(server_key),
                    "ca": str(ca),
                    "signer": str(signer),
                    "control_port": control_port,
                    "kms": kms.transit.endpoint,
                    "ready": str(ready),
                    "records": str(records),
                }
            )
        )
        workload_env = {
            "KENSE_VAULT_CONSUMER_TOKEN": credential,
            "KENSE_OPENBAO_DECRYPT_TOKEN": kms.decrypt_token,
            "PYTHONUNBUFFERED": "1",
        }
        if "LD_LIBRARY_PATH" in os.environ:
            workload_env["LD_LIBRARY_PATH"] = os.environ["LD_LIBRARY_PATH"]
        with process(
            sys.executable,
            [str(Path(__file__).resolve()), str(config)],
            directory / "service.log",
            workload_env,
        ) as child:

            def ready_port():
                assert child.poll() is None, (
                    "Vault workload exited before becoming ready"
                )
                return (
                    int(ready.read_text())
                    if ready.exists() and ready.stat().st_size
                    else None
                )

            port = wait_until(ready_port)
            yield Consumer(
                port,
                credential,
                other,
                TRANSIT_KEY_ID,
                partial(kms.transit.encrypt, kms.encrypt_token),
                records,
                kms,
            )
        return

    cipher = AESGCM(AESGCM.generate_key(bit_length=256))

    def seal(value, _scope, _reference):
        nonce = os.urandom(12)
        return nonce + cipher.encrypt(nonce, value, None)

    def decrypt(sealed, _scope, _reference):
        return cipher.decrypt(sealed[:12], sealed[12:], None)

    observed = []
    with listener(
        server_cert,
        server_key,
        ca,
        signer,
        control_port,
        credential,
        LOCAL_KEY_ID,
        decrypt,
        observed.append,
    ) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield Consumer(
                server.server_port, credential, other, LOCAL_KEY_ID, seal, observed
            )
        finally:
            server.shutdown()
            thread.join(timeout=5)


def run_workload(config_path):
    config = json.loads(Path(config_path).read_text())
    transit = Transit(config["kms"], config["ca"])
    decrypt = partial(transit.decrypt, os.environ["KENSE_OPENBAO_DECRYPT_TOKEN"])

    def record(value):
        with Path(config["records"]).open("a") as stream:
            stream.write(json.dumps(value) + "\n")

    with listener(
        config["cert"],
        config["key"],
        config["ca"],
        Path(config["signer"]),
        config["control_port"],
        os.environ["KENSE_VAULT_CONSUMER_TOKEN"],
        TRANSIT_KEY_ID,
        decrypt,
        record,
    ) as server:
        Path(config["ready"]).write_text(str(server.server_port))
        server.serve_forever()


def check_vault(
    first, second, owner, other_org, vault_operator, admin, api, fetch, consumer
):
    scope = SCOPE
    reference = "urn:plat:vault:secret:provider-test"
    plaintext = b"upstream-credential-" + os.urandom(16).hex().encode()
    first_sealed = consumer.seal(plaintext, scope, reference)
    ciphertext = base64.b64encode(first_sealed).decode()

    def call(action, expected, *, token=vault_operator, **extra):
        return api(
            VAULT_API + action,
            token,
            data=json.dumps(
                {
                    **scope,
                    "secret_ref": reference,
                    "expected_aggregate_version": expected,
                    **extra,
                }
            ).encode(),
            headers={"Content-Type": "application/json"},
        )

    envelope = {
        "audience": AUDIENCE,
        "ciphertext": ciphertext,
        "key_id": consumer.key_id,
        "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    }
    assert call("materialize", 0, token=admin, **envelope)[0] == 401
    assert call("materialize", 0, plaintext=plaintext.hex(), **envelope)[0] == 400
    status, body = call("materialize", 0, **envelope)
    assert status == 201 and json.loads(body)["status"] == "sealed", (status, body)
    assert ciphertext.encode() not in body and b"key_id" not in body
    assert fetch(first + PATH, owner)[0] == 503
    assert call("apply", 0, version=1)[0] == 400
    status, body = call("apply", 1, version=1)
    assert status == 200 and json.loads(body)["status"] == "active", (status, body)
    assert fetch(first + PATH, other_org)[0] == 503
    status, body = fetch(second + PATH, owner)
    assert status == 200 and json.loads(body) == {
        "secret_ref": reference,
        "version": 1,
    }, (status, body)

    def redeem(identity, token):
        return api(
            VAULT_API + "redeem",
            token,
            data=json.dumps(
                {
                    "request_id": identity["request_id"],
                    **identity["vault_binding"],
                }
            ).encode(),
            headers={"Content-Type": "application/json"},
        )

    first_identity, _ = consumer.observed[0]
    assert redeem(first_identity, admin)[0] == 401
    assert redeem(first_identity, consumer.other_credential)[0] == 409
    expected_versions = [1]
    expected_plaintext = [plaintext]
    if consumer.kms is not None:
        kms = consumer.kms
        assert first_sealed.startswith(b"vault:v1:")
        kms.check_workload_policy(first_sealed, scope, reference)
        with kms.unavailable():
            status, body = fetch(first + PATH, owner)
            assert status == 503 and b"credential unavailable" in body, status
            assert len(consumer.observed) == 1
        status, body = fetch(first + PATH, owner)
        assert status == 200 and json.loads(body) == {
            "secret_ref": reference,
            "version": 1,
        }
        expected_versions.append(1)
        expected_plaintext.append(plaintext)
        kms.rotate()
        opened = kms.transit.decrypt(kms.decrypt_token, first_sealed, scope, reference)
        assert opened == plaintext, "existing envelope unreadable after KMS rotation"
    assert call("materialize", 1, **envelope)[0] == 409
    rotated_plaintext = b"rotated-credential-" + os.urandom(16).hex().encode()
    rotated_sealed = consumer.seal(rotated_plaintext, scope, reference)
    rotated_ciphertext = base64.b64encode(rotated_sealed).decode()
    if consumer.kms is not None:
        assert rotated_sealed.startswith(b"vault:v2:")
    assert (
        call("materialize", 2, **(envelope | {"ciphertext": rotated_ciphertext}))[0]
        == 201
    )
    assert call("apply", 3, version=2)[0] == 200
    assert redeem(first_identity, consumer.credential)[0] == 409
    assert call("apply", 4, version=1)[0] == 409
    if consumer.kms is not None:
        consumer.kms.retire_first_version()
        try:
            kms.transit.decrypt(kms.decrypt_token, first_sealed, scope, reference)
        except ValueError as error:
            assert "HTTP 400" in str(error), str(error)
        else:
            raise AssertionError("retired OpenBao key version decrypted")
    status, body = fetch(first + PATH, owner)
    assert status == 200 and json.loads(body) == {
        "secret_ref": reference,
        "version": 2,
    }, (status, body)
    assert call("revoke", 4, version=2)[0] == 200
    assert fetch(second + PATH, owner)[0] == 503
    assert redeem(consumer.observed[-1][0], consumer.credential)[0] == 409
    assert [
        identity["vault_binding"]["version"] for identity, _ in consumer.observed
    ] == [*expected_versions, 2], consumer.observed
    assert [digest for _, digest in consumer.observed] == [
        hashlib.sha256(value).hexdigest()
        for value in (*expected_plaintext, rotated_plaintext)
    ]
    forwarded = json.dumps(consumer.observed).encode()
    secrets_in_plaintext = [
        encoded
        for value in (plaintext, rotated_plaintext)
        for encoded in (value.decode(), base64.b64encode(value).decode())
    ]
    if consumer.kms is not None:
        secrets_in_plaintext.extend(consumer.kms.secret_values())
    protected = [
        ciphertext,
        rotated_ciphertext,
        *secrets_in_plaintext,
        consumer.key_id,
        owner,
    ]
    assert all(value.encode() not in forwarded for value in protected), (
        "workload recorded protected material"
    )
    return protected, secrets_in_plaintext


if __name__ == "__main__":
    run_workload(sys.argv[1])
