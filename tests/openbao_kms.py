"""An isolated OpenBao Transit service for the paired Vault acceptance test."""

import base64
import json
import os
import ssl
import subprocess
from contextlib import contextmanager
from urllib.error import HTTPError, URLError
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)
from uuid import uuid4

IMAGE = "ghcr.io/openbao/openbao:2.7.3@sha256:ba4b133eb9586630024e71a617e66f37f29cc3534cdd46a6233e098ceded8dc9"
KEY = "kgateway-egress"
KEY_ID = f"openbao/transit/keys/{KEY}"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def json_post(
    endpoint,
    path,
    tls,
    body,
    token=None,
    *,
    token_header="Authorization",
    method="POST",
):
    data = json.dumps(body).encode()
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers[token_header] = (
            "Bearer " + token if token_header == "Authorization" else token
        )
    req = Request(endpoint + path, data=data, headers=headers, method=method)
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=tls), NoRedirect())
    try:
        with opener.open(req, timeout=4) as response:
            value = response.read(131073)
            if len(value) > 131072:
                raise ValueError("private service response exceeds expected size")
            return response.status, json.loads(value) if value else {}
    except HTTPError as error:
        with error:
            return error.code, {}
    except URLError:
        return 503, {}


def derivation_context(scope, reference):
    data = json.dumps(
        {**scope, "secret_ref": reference}, sort_keys=True, separators=(",", ":")
    )
    return base64.b64encode(data.encode()).decode()


class Transit:
    def __init__(self, endpoint, ca):
        self.endpoint = endpoint
        self.ca = ca
        self.tls = ssl.create_default_context(cafile=str(ca))

    def request(self, path, token, value, *, method="POST"):
        return json_post(
            self.endpoint,
            "/v1/" + path,
            self.tls,
            value,
            token,
            token_header="X-Vault-Token",
            method=method,
        )

    def require(self, path, token, value, *, method="POST"):
        status, body = self.request(path, token, value, method=method)
        if status not in {200, 204}:
            raise ValueError(f"OpenBao returned HTTP {status} for {path}")
        return body

    def encrypt(self, token, value, scope, reference):
        body = self.require(
            f"transit/encrypt/{KEY}",
            token,
            {
                "plaintext": base64.b64encode(value).decode(),
                "context": derivation_context(scope, reference),
            },
        )
        return body["data"]["ciphertext"].encode("ascii")

    def decrypt(self, token, value, scope, reference):
        body = self.require(
            f"transit/decrypt/{KEY}",
            token,
            {
                "ciphertext": value.decode("ascii"),
                "context": derivation_context(scope, reference),
            },
        )
        return base64.b64decode(body["data"]["plaintext"], validate=True)


class KmsFixture:
    def __init__(self, transit):
        self.transit = transit
        init = transit.require(
            "sys/init", None, {"secret_shares": 1, "secret_threshold": 1}, method="PUT"
        )
        self.root = init["root_token"]
        self.share = init["keys_base64"][0]
        self.unseal()
        transit.require("sys/mounts/transit", self.root, {"type": "transit"})
        for name in (KEY, "another-workload"):
            transit.require(
                f"transit/keys/{name}",
                self.root,
                {"type": "aes256-gcm96", "derived": True},
            )
        self.encrypt_token = self.scoped_token("sealer", f"transit/encrypt/{KEY}")
        self.decrypt_token = self.scoped_token("workload", f"transit/decrypt/{KEY}")
        self.rotation_token = self.scoped_token(
            "rotation", f"transit/keys/{KEY}/rotate", f"transit/keys/{KEY}/config"
        )

    def scoped_token(self, name, *paths):
        policy = "\n".join(
            f'path "{path}" {{ capabilities = ["update"] }}' for path in paths
        )
        self.transit.require(
            f"sys/policies/acl/{name}", self.root, {"policy": policy}, method="PUT"
        )
        body = self.transit.require(
            "auth/token/create",
            self.root,
            {
                "policies": [name],
                "no_default_policy": True,
                "ttl": "20m",
                "renewable": False,
            },
        )
        return body["auth"]["client_token"]

    def unseal(self):
        body = self.transit.require(
            "sys/unseal", None, {"key": self.share}, method="PUT"
        )
        assert body["sealed"] is False

    @contextmanager
    def unavailable(self):
        self.transit.require("sys/seal", self.root, {}, method="PUT")
        try:
            yield
        finally:
            self.unseal()

    def rotate(self):
        self.transit.require(f"transit/keys/{KEY}/rotate", self.rotation_token, {})

    def retire_first_version(self):
        self.transit.require(
            f"transit/keys/{KEY}/config",
            self.rotation_token,
            {"min_decryption_version": 2},
        )

    def check_workload_policy(self, value, scope, reference):
        sealed = {
            "ciphertext": value.decode("ascii"),
            "context": derivation_context(scope, reference),
        }
        assert (
            self.transit.request(f"transit/decrypt/{KEY}", self.encrypt_token, sealed)[
                0
            ]
            == 403
        )
        assert (
            self.transit.request(
                f"transit/encrypt/{KEY}",
                self.decrypt_token,
                {"plaintext": "dGVzdA==", "context": sealed["context"]},
            )[0]
            == 403
        )
        assert (
            self.transit.request(
                "transit/decrypt/another-workload", self.decrypt_token, sealed
            )[0]
            == 403
        )
        assert (
            self.transit.request(f"transit/keys/{KEY}/rotate", self.decrypt_token, {})[
                0
            ]
            == 403
        )
        forged = derivation_context({**scope, "tenant": "wrong-tenant"}, reference)
        assert (
            self.transit.request(
                f"transit/decrypt/{KEY}",
                self.decrypt_token,
                {**sealed, "context": forged},
            )[0]
            == 400
        )

    def secret_values(self):
        return (
            self.root,
            self.share,
            self.encrypt_token,
            self.decrypt_token,
            self.rotation_token,
        )


@contextmanager
def openbao(scratch, cert, key, ca, wait_until):
    config = scratch / "openbao"
    config.mkdir(mode=0o700)
    (config / "tls.crt").write_bytes(cert)
    key_path = config / "tls.key"
    key_path.write_bytes(key)
    key_path.chmod(0o600)
    (config / "service.hcl").write_text("""
disable_mlock = true
storage "inmem" {}
listener "tcp" {
  address = "0.0.0.0:8200"
  tls_cert_file = "/fixture/tls.crt"
  tls_key_file = "/fixture/tls.key"
  tls_min_version = "tls12"
}
""")
    name = "kgateway-openbao-" + uuid4().hex
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--detach",
            "--name",
            name,
            "--publish",
            "127.0.0.1::8200",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--mount",
            f"type=bind,src={config},dst=/fixture,readonly",
            "--entrypoint",
            "/usr/bin/bao",
            IMAGE,
            "server",
            "-config=/fixture/service.hcl",
        ],
        check=True,
        capture_output=True,
    )
    try:
        address = subprocess.check_output(
            ["docker", "port", name, "8200/tcp"], text=True
        ).strip()
        assert address.startswith("127.0.0.1:") and address.rsplit(":", 1)[1].isdigit()
        transit = Transit("https://" + address, ca)
        wait_until(
            lambda: transit.request("sys/init", None, {}, method="GET")[0] == 200
        )
        yield KmsFixture(transit)
    finally:
        with (scratch / "openbao.log").open("wb") as log:
            subprocess.run(
                ["docker", "logs", name],
                stdout=log,
                stderr=subprocess.STDOUT,
                check=False,
            )
        subprocess.run(
            ["docker", "stop", "-t", "3", name], check=False, capture_output=True
        )
