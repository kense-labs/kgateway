"""Live control-plane, two gateway replicas, and private kstack MaaS check."""

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlencode
from uuid import uuid4

import platform_delegation_e2e as delegation_case
import platform_vault_e2e as vault_case
from paired_maas_performance import DIRECT_TENANT, Ingress, measure
from paired_maas_performance import TENANT as BENCHMARK_TENANT
from platform_audit_witness_e2e import WRITER_ENV, Witness
from platform_recovery_e2e import replace_control_plane
from platform_registry_sdk import (
    build_probes,
    check_probes,
    generate_artifacts,
    registered_routes,
)
from platform_release_e2e import (
    PILOT_TENANT,
    RELEASE_API,
    ROLLOUT_BATCH_LINES,
    STABLE_TENANT,
    exercise_release_rollout,
)

OPERATION = "maas.models.list"
RESOURCE = "urn:plat:maas:models"
CHAT = "maas.chat.create"
COMPLETIONS = "maas.completions.create"
EMBEDDINGS = "maas.embeddings.create"
FILE_URN = "urn:plat:maas:files"
BATCH_URN = "urn:plat:maas:batches"
QUOTA_TENANT = "tenant-quota"
FILE_ROUTES = {
    "list": ("GET", "/v1/files"),
    "create": ("POST", "/v1/files"),
    "get": ("GET", "/v1/files/{id}"),
    "content": ("GET", "/v1/files/{id}/content"),
    "delete": ("DELETE", "/v1/files/{id}"),
}
BATCH_ROUTES = {
    "list": ("GET", "/v1/batches"),
    "create": ("POST", "/v1/batches"),
    "get": ("GET", "/v1/batches/{id}"),
    "cancel": ("POST", "/v1/batches/{id}/cancel"),
}


def wait_until(check, timeout=25):
    deadline = time.monotonic() + timeout
    while True:
        try:
            if result := check():
                return result
        except (URLError, sqlite3.OperationalError):
            if time.monotonic() >= deadline:
                raise
        if time.monotonic() >= deadline:
            raise AssertionError("condition did not become true before its deadline")
        time.sleep(0.1)


def exercise_control_plane(
    gateway,
    scratch,
    bind_port,
    control_port,
    maas_port,
    ca,
    server_cert,
    server_key,
    client_identity,
    signer,
    process,
    fetch,
    model,
    usage_token,
    vault,
    agents,
    *,
    budget_rollover=False,
    workload=None,
    direct_ingress=None,
    benchmark_artifacts=None,
    benchmark_engine=None,
    rollout=None,
    recovery=False,
    on_model_settled=None,
):
    directory = scratch / "control-plane"
    directory.mkdir()
    control_base = f"https://127.0.0.1:{control_port}"
    control_tls = ssl.create_default_context(cafile=str(ca))

    def api(path, token=None, **kwargs):
        return fetch(control_base + path, token, context=control_tls, **kwargs)

    admin = secrets.token_urlsafe(32)
    auditor = secrets.token_urlsafe(32)
    vault_token = secrets.token_urlsafe(32)
    witness = Witness(scratch, bind_port(), ca, server_cert, server_key, fetch, process)
    env = {
        **os.environ,
        "CONTROL_TEST_ADMIN": admin,
        "CONTROL_TEST_AUDITOR": auditor,
        "CONTROL_TEST_MAAS_USAGE": usage_token,
        "CONTROL_TEST_VAULT": vault_token,
        "CONTROL_TEST_VAULT_CONSUMER": vault.credential,
        "CONTROL_TEST_VAULT_OTHER_CONSUMER": vault.other_credential,
        WRITER_ENV: witness.writer,
        **{
            agents.token_env(actor): token
            for actor, token in agents.credentials.items()
        },
    }
    routes = {
        "models": {
            "method": "GET",
            "path": "/v1/models",
            "audience": "urn:plat:maas:kstack",
            "operation": OPERATION,
            "resource": {"kind": "model-list", "urn": RESOURCE, "targets": {}},
        },
        "vault-probe": {
            "method": "GET",
            "path": vault_case.PATH,
            "audience": vault_case.AUDIENCE,
            "operation": vault_case.OPERATION,
            "requires_audit_receipt": True,
            "vault_provider": vault_case.PROVIDER,
            "resource": {"kind": "fixed", "urn": vault_case.URN},
        },
    }
    vault_grants = {vault_case.OPERATION: [vault_case.URN]}
    delegation_routes = delegation_case.routes(agents.task_key)
    routes.update(delegation_routes)
    delegation_grants = {
        route["operation"]: list(route["resource"]["policy"]["methods"].values())
        for route in delegation_routes.values()
    }
    services = {
        "vault-probe": "vault-egress",
        **dict.fromkeys(delegation_routes, "delegated-agents"),
    }
    grants = {OPERATION: [RESOURCE]}
    file_grants = {}
    for action, (method, path) in FILE_ROUTES.items():
        operation = f"maas.files.{action}"
        routes[f"files-{action}"] = {
            "method": method,
            "path": path,
            "audience": "urn:plat:maas:kstack",
            "operation": operation,
            "requires_audit_receipt": action == "delete",
            "resource": {"kind": "maas-asset", "urn": FILE_URN},
        }
        file_grants[operation] = [FILE_URN]
    batch_grants = {}
    if model is not None:
        alias, version = model
        model_urn = "urn:plat:maas:model:" + alias
        targets = {alias: [{"deployment": version, "weight": 1}]}
        routes["models"]["resource"]["targets"] = targets
        routes["chat"] = {
            "method": "POST",
            "path": "/v1/chat/completions",
            "audience": "urn:plat:maas:kstack",
            "operation": CHAT,
            "requires_audit_receipt": True,
            "resource": {"kind": "model", "targets": targets},
        }
        grants[OPERATION].append(model_urn)
        grants[CHAT] = [model_urn]
        for name, operation in (
            ("completions", COMPLETIONS),
            ("embeddings", EMBEDDINGS),
        ):
            routes[name] = {
                "method": "POST",
                "path": f"/v1/{name}",
                "audience": "urn:plat:maas:kstack",
                "operation": operation,
                "resource": {"kind": "model", "targets": targets},
            }
            grants[operation] = [model_urn]
        for action, (method, path) in BATCH_ROUTES.items():
            operation = f"maas.batches.{action}"
            resource = {"kind": "maas-asset", "urn": BATCH_URN}
            batch_grants[operation] = [BATCH_URN]
            if action == "create":
                resource.update(
                    batch_max_requests=ROLLOUT_BATCH_LINES if rollout else 2,
                    targets=targets,
                )
                batch_grants[operation].append(model_urn)
            routes[f"batches-{action}"] = {
                "method": method,
                "path": path,
                "audience": "urn:plat:maas:kstack",
                "operation": operation,
                "requires_audit_receipt": action in {"create", "cancel"},
                "resource": resource,
            }
    asset_grants = file_grants | batch_grants
    sdk_grants = {
        operation: urns
        for operation, urns in (grants | asset_grants).items()
        if operation in {OPERATION, CHAT, "maas.files.create", "maas.files.get"}
    }
    replicas = {}
    for index in range(2):
        replica, http, node = str(uuid4()), bind_port(), bind_port()
        name = f"replica-{index}"
        directory.joinpath(name).mkdir()
        state = directory / name
        node_env, usage_env = (
            f"NODE_TEST_CREDENTIAL_{index}",
            f"USAGE_TEST_CREDENTIAL_{index}",
        )
        env[node_env] = secrets.token_urlsafe(32)
        env[usage_env] = secrets.token_urlsafe(32)
        node_api = f"http://127.0.0.1:{node}/api/gateway"
        bootstrap = f"""
        mode {{ kind = "cloud-managed" }}
        managed {{
            gateway_id = "{replica}"
            state_file = "{state / "snapshot.json"}"
            usage_spool {{
                directory = "{state / "usage"}"
                cloud_ingest_endpoint = "{control_base}/v1/usage"
                cloud_ingest_token_env = "{usage_env}"
                cloud_ingest_server_ca_file = "{ca}"
            }}
            platform {{
                signing_key_file = "{signer}"
                budget_state_file = "{state / "budget.json"}"
                audit_receipt_endpoint = "{control_base}/v1/audit/admissions"
                delegation_verification_key_file = "{agents.public_file}"
            }}
        }}
        management {{
            enabled = true
            address = "127.0.0.1:{node}"
            auth_token_env = "{node_env}"
        }}
        entrypoints "edge" {{ address = "127.0.0.1:{http}" }}
        """
        benchmark_port = None
        if workload is not None:
            benchmark_port = bind_port()
            bootstrap += f'''
            entrypoints "benchmark" {{
                address = "127.0.0.1:{benchmark_port}"
                tls {{
                    cert_file = "{server_cert}"
                    key_file = "{server_key}"
                }}
            }}
            '''
        (state / "bootstrap.acl").write_text(bootstrap)
        (state / "snapshot.acl").write_text(
            bootstrap
            + f"""
            services "maas" {{
                load_balancer {{
                    tls_ca_file = "{ca}"
                    tls_client_identity_file = "{client_identity}"
                    servers = [{{ url = "https://127.0.0.1:{maas_port}" }}]
                }}
            }}
            services "vault-egress" {{
                load_balancer {{
                    tls_ca_file = "{ca}"
                    tls_client_identity_file = "{client_identity}"
                    servers = [{{ url = "https://127.0.0.1:{vault.port}" }}]
                }}
            }}
            services "delegated-agents" {{
                load_balancer {{
                    tls_ca_file = "{ca}"
                    tls_client_identity_file = "{client_identity}"
                    servers = [{{ url = "https://127.0.0.1:{agents.port}" }}]
                }}
            }}
            """
        )
        replicas[replica] = {
            "id": replica,
            "node_api": node_api,
            "node_token_env": node_env,
            "usage_token_env": usage_env,
            "snapshot_acl": f"{name}/snapshot.acl",
            "signer": {
                "issuer": "urn:plat:identity:integration",
                "key_id": "test-key",
                "authorized_until": (
                    datetime.now(UTC) + timedelta(hours=1)
                ).isoformat(),
            },
            "test_base": f"http://127.0.0.1:{http}",
            "test_state": state,
            "test_benchmark_port": benchmark_port,
        }
    state_db = directory / "state.sqlite"
    config_path = directory / "control.json"
    now = int(time.time())
    budget_window = (
        60
        if budget_rollover
        else max((21_600, 86_399, 86_400), key=lambda seconds: seconds - now % seconds)
    )
    budgets = [
        {
            "tenant": tenant,
            "operation": operation,
            "requests": 2 * allowance,
            "replicas": dict.fromkeys(replicas, allowance),
        }
        for tenant, operations, count in [
            ("tenant-test", grants, 128 if rollout else 2),
            ("tenant-test", asset_grants, 64 if rollout else 8),
            ("tenant-isolated", asset_grants, 8),
            (STABLE_TENANT, grants | asset_grants if rollout else {}, 64),
            ("tenant-test", vault_grants, 8),
            ("tenant-test", delegation_grants, 8),
            ("tenant-sdk", sdk_grants if not budget_rollover else {}, 4),
        ]
        for operation in operations
        for allowance in [64 if operation == "maas.batches.get" else count]
    ]
    registry = registered_routes(routes, services)
    if workload is not None:
        registry["chat"]["routing"]["entrypoints"].append("benchmark")
        allowance = workload.allowance_per_replica
        _, direct_replica = replicas
        budgets.append(
            {
                "tenant": DIRECT_TENANT,
                "operation": CHAT,
                "requests": allowance,
                "replicas": {direct_replica: allowance},
            }
        )
        budgets.append(
            {
                "tenant": BENCHMARK_TENANT,
                "operation": CHAT,
                "requests": 2 * allowance,
                "replicas": dict.fromkeys(replicas, allowance),
            }
        )
    elif budget_rollover:
        tenant_budget = next(
            budget for budget in budgets if budget["operation"] == OPERATION
        )
        project_budget = tenant_budget | {"project": "project-test"}
        budgets.extend((project_budget, project_budget | {"env": "env-test"}))
    elif rollout is None:
        budgets.extend(scoped_budgets(replicas, model is not None))
    config_path.write_text(
        json.dumps(
            {
                "bind": "127.0.0.1",
                "port": int(control_base.rsplit(":", 1)[1]),
                "state_db": state_db.name,
                "admin_token_env": "CONTROL_TEST_ADMIN",
                "budget_window_seconds": budget_window,
                "audit_token_env": "CONTROL_TEST_AUDITOR",
                "audit_witness": witness.settings,
                "delegation": {
                    "signing_key_file": str(agents.key_file),
                    "client_token_env": {
                        delegation_case.audience(actor): agents.token_env(actor)
                        for actor in agents.credentials
                    },
                },
                "maas_usage_token_env": "CONTROL_TEST_MAAS_USAGE",
                "vault_operator_token_env": "CONTROL_TEST_VAULT",
                "vault_consumers": {
                    vault_case.AUDIENCE: "CONTROL_TEST_VAULT_CONSUMER",
                    vault_case.OTHER_AUDIENCE: "CONTROL_TEST_VAULT_OTHER_CONSUMER",
                },
                "tls": {"cert": str(server_cert), "key": str(server_key)},
                "replicas": [
                    {
                        key: value
                        for key, value in replica.items()
                        if not key.startswith("test_")
                    }
                    for replica in replicas.values()
                ],
                "routes": registry,
                "budgets": budgets,
            }
        )
    )
    sdk = directory / "registry-artifacts"
    if not budget_rollover and workload is None and rollout is None:
        spec = generate_artifacts(config_path, sdk)
        detail = spec["paths"]["/v1/files/{id}"]["get"]
        assert detail["operationId"] == "maas.files.get"
        assert detail["parameters"][0]["schema"]["pattern"] == "^file-[0-9a-f]{24}$"
        assert detail["x-kense"]["resourceUrns"] == [FILE_URN]
        if model is not None:
            chat = spec["paths"]["/v1/chat/completions"]["post"]
            assert set(chat["responses"]["200"]["content"]) == {
                "application/json",
                "text/event-stream",
            }
            assert chat["x-kense"]["meteringUnits"] == [
                "requests",
                "egress_bytes",
                "prompt_tokens",
                "completion_tokens",
            ]
            assert chat["x-kense"]["audit"] == "receipt"
        build_probes(sdk, model is not None)
    control = Path(__file__).resolve().parents[1] / "control-plane/main.py"

    def control_process(name, config=config_path):
        return process(
            sys.executable,
            [str(control), "--config", str(config)],
            directory / name,
            env,
        )

    def gateway_process(replica, name):
        state = replica["test_state"]
        return process(
            gateway, ["--config", str(state / "bootstrap.acl")], state / name, env
        )

    def node_status(replica, path="/snapshots/status"):
        status, raw = fetch(replica["node_api"] + path, env[replica["node_token_env"]])
        assert status == 200, (status, raw)
        return json.loads(raw)

    def events_count():
        with sqlite3.connect(state_db) as db:
            return dict(
                db.execute("SELECT kind, COUNT(*) FROM usage_events GROUP BY kind")
            )

    def models(replica, key):
        return fetch(replica["test_base"] + "/v1/models", key)

    def replica_ready(replica):
        active = node_status(replica).get("applied")
        if not active:
            return False
        identity = urlencode(
            {key: active[key] for key in ("gateway_id", "revision", "snapshot_digest")}
        )
        return node_status(replica, "/snapshots/status?" + identity)["ready"]

    def next_window_leases(boundary):
        with sqlite3.connect(state_db) as db:
            leases = dict(
                db.execute(
                    "SELECT replica, leases.id FROM leases JOIN prepared_leases "
                    "ON prepared_leases.id = leases.id WHERE window = ? "
                    "AND tenant = 'tenant-test' AND operation = ?",
                    (boundary, OPERATION),
                )
            )
        if leases.keys() != replicas.keys():
            return None
        for replica in replicas.values():
            snapshot = json.loads((replica["test_state"] / "snapshot.json").read_text())
            if leases[replica["id"]] not in snapshot["snapshot"][
                "acl"
            ] or not replica_ready(replica):
                return None
        return leases

    with (
        witness.start("witness.log") as anchor,
        control_process("control.log") as controller,
        ExitStack() as processes,
    ):
        wait_until(lambda: witness.call("/healthz")[0] == 200)
        wait_until(lambda: api("/healthz")[0] == 200)
        raw_key_request = json.dumps(
            {
                "tenant": "tenant-test",
                "project": "project-test",
                "env": "env-test",
                "org": "org-test",
                "grants": grants | asset_grants | vault_grants | delegation_grants,
                "ttl_seconds": 600 if rollout else 300,
            }
        ).encode()
        content_type = {"Content-Type": "application/json"}
        status, _ = api("/v1/keys", data=raw_key_request, headers=content_type)
        assert status == 401
        status, encoded = api(
            "/v1/keys", admin, data=raw_key_request, headers=content_type
        )
        assert status == 201, (status, encoded)
        created = json.loads(encoded)
        primary = created["key"]

        def create_key(**overrides):
            request = json.loads(raw_key_request) | overrides
            status, raw = api(
                "/v1/keys",
                admin,
                data=json.dumps(request).encode(),
                headers=content_type,
            )
            assert status == 201, (status, raw)
            return json.loads(raw)["key"]

        if workload is not None:
            key = create_key(
                tenant=BENCHMARK_TENANT, ttl_seconds=1800, grants={CHAT: grants[CHAT]}
            )
            for replica in replicas.values():
                processes.enter_context(gateway_process(replica, "gateway.log"))
            first, direct = replicas.values()
            for replica in replicas.values():
                wait_until(lambda replica=replica: replica_ready(replica))
            direct_tls, make_credential = direct_ingress
            prepare_direct = benchmark_reservations(
                state_db, direct, env[direct["usage_token_env"]], api, make_credential
            )
            results = measure(
                workload,
                model[0],
                {
                    "kstack-direct": Ingress(maas_port, direct_tls, prepare_direct),
                    "kgateway": Ingress(
                        first["test_benchmark_port"],
                        control_tls,
                        lambda count: [key] * count,
                    ),
                },
                benchmark_artifacts,
                benchmark_engine,
            )
            expected = {
                tenant: sum(
                    arms[name]["succeeded"]
                    + arms[name]["warmup_attempts"]
                    - arms[name]["warmup_errors"]
                    for arms in results.values()
                )
                for tenant, name in (
                    (DIRECT_TENANT, "kstack-direct"),
                    (BENCHMARK_TENANT, "kgateway"),
                )
            }

            def settled():
                with sqlite3.connect(state_db) as db:
                    received = dict(
                        db.execute(
                            "SELECT json_extract(payload, '$.tenant'), COUNT(*) FROM maas_usage_events "
                            "WHERE json_extract(payload, '$.outcome') = 'ok' "
                            "AND json_extract(payload, '$.tokens.prompt') >= ? "
                            "AND json_extract(payload, '$.tokens.completion') > 0 GROUP BY 1",
                            (workload.minimum_prompt_tokens,),
                        )
                    )
                return all(
                    received.get(tenant, 0) >= count
                    for tenant, count in expected.items()
                )

            wait_until(settled, timeout=90)
            print("MaaS usage settled for both benchmark ingresses.")
            return

        if rollout is not None:
            candidate, monitor = rollout
            active = create_key()
            stable_key = create_key(tenant=STABLE_TENANT, grants=grants | asset_grants)
            for replica in replicas.values():
                processes.enter_context(gateway_process(replica, "gateway.log"))
            for replica in replicas.values():
                wait_until(lambda replica=replica: replica_ready(replica))

            assert api(RELEASE_API)[0] == 401
            status, raw = api(RELEASE_API, admin)
            assert status == 200 and json.loads(raw)["revision"] == 0, (status, raw)
            release = 0
            initial_targets = [{"deployment": model[1], "weight": 1}]

            def applied_revisions():
                return {
                    replica["id"]: node_status(replica)["applied"]["revision"]
                    for replica in replicas.values()
                }

            def await_publications(previous, targets):
                def exact():
                    assert controller.poll() is None
                    status, raw = api(RELEASE_API, admin)
                    assert status == 200, (status, raw)
                    saved = json.loads(raw)
                    assert saved["revision"] == release, saved
                    assert all(
                        entry[alias] == initial_targets
                        for entry in saved["targets"].values()
                    ), saved
                    scoped = (
                        {
                            name: {PILOT_TENANT: {alias: targets}}
                            for name in saved["targets"]
                        }
                        if targets is not None
                        else {}
                    )
                    assert saved["tenant_targets"] == scoped, saved
                    for replica_id, replica in replicas.items():
                        receipt = saved["replicas"].get(replica_id)
                        if (
                            receipt is None
                            or receipt["release_revision"] != release
                            or receipt["revision"] <= previous[replica_id]
                        ):
                            return False
                        identity = urlencode(
                            {
                                "gateway_id": replica_id,
                                "revision": receipt["revision"],
                                "snapshot_digest": receipt["snapshot_digest"],
                            }
                        )
                        if not node_status(replica, "/snapshots/status?" + identity)[
                            "ready"
                        ]:
                            return False
                    return True

                wait_until(exact)

            def release_post(path, entry, token=admin):
                return api(
                    path,
                    token,
                    data=json.dumps(entry).encode(),
                    headers={"Content-Type": "application/json"},
                )

            def publish(new_targets, phase):
                nonlocal release
                previous = applied_revisions()
                payload = {
                    "expected_revision": release,
                    "alias": alias,
                    "tenant": PILOT_TENANT,
                }
                path = RELEASE_API
                if phase == "rollback":
                    path += "/rollback"
                    payload["rollback_revision"] = 0
                else:
                    payload["targets"] = new_targets
                if phase == "weighted":
                    assert release_post(path, payload, active)[0] == 401
                    assert release_post(path, payload | {"tenant": ""})[0] == 400
                    assert (
                        release_post(path, payload | {"alias": "unregistered"})[0]
                        == 400
                    )
                    assert (
                        release_post(path, payload | {"targets": new_targets * 2})[0]
                        == 400
                    )
                    with ThreadPoolExecutor(max_workers=2) as workers:
                        replies = list(
                            workers.map(lambda _: release_post(path, payload), range(2))
                        )
                    assert sorted(code for code, _ in replies) == [201, 409], replies
                    status, raw = next(reply for reply in replies if reply[0] == 201)
                else:
                    status, raw = release_post(path, payload)
                assert status == 201, (status, raw)
                result = json.loads(raw)
                assert (
                    result["revision"] == release + 1
                    and result["change"]["previous_revision"] == release
                    and result["change"]["tenant"] == PILOT_TENANT
                )
                release = result["revision"]
                if phase == "rollback":
                    assert result["change"]["source_revision"] == 0
                    status, raw = api(RELEASE_API + "?revision=1", admin)
                    assert status == 200 and json.loads(raw)["change"]["alias"] == alias
                    assert json.loads(raw)["tenant_targets"]
                await_publications(previous, new_targets)

            def restart(configured_targets):
                nonlocal controller, state_db
                previous = applied_revisions()
                if recovery:

                    def standalone_models():
                        for replica in replicas.values():
                            assert models(replica, active)[0] == 200
                            assert models(replica, primary)[0] == 401

                    def check_sensitive_offline():
                        for replica in replicas.values():
                            status, body = fetch(
                                replica["test_base"] + "/v1/chat/completions",
                                active,
                                data=json.dumps(
                                    {
                                        "model": alias,
                                        "messages": [
                                            {"role": "user", "content": "offline probe"}
                                        ],
                                    }
                                ).encode(),
                                headers=content_type,
                            )
                            assert status == 503, (status, body)

                    controller, state_db = replace_control_plane(
                        scratch=directory,
                        source_config=config_path,
                        source_db=state_db,
                        controller=controller,
                        witness=witness,
                        env=env,
                        replicas=list(replicas.values()),
                        standalone_models=standalone_models,
                        check_sensitive_offline=check_sensitive_offline,
                        start=lambda configuration: processes.enter_context(
                            control_process("control-recovered.log", configuration)
                        ),
                        wait_until=wait_until,
                        ready=lambda: api("/healthz")[0] == 200,
                    )
                else:
                    controller.terminate()
                    controller.wait(timeout=20)
                    config = json.loads(config_path.read_text())
                    for route in config["routes"].values():
                        if alias in route["resource"].get("targets", {}):
                            route["resource"]["targets"][alias] = configured_targets
                    config_path.write_text(json.dumps(config))
                    controller = processes.enter_context(
                        control_process("control-reopened.log")
                    )
                    wait_until(lambda: api("/healthz")[0] == 200)
                await_publications(previous, None)
                for replica in replicas.values():
                    assert models(replica, primary)[0] == 401
                with sqlite3.connect(state_db) as db:
                    changes = list(
                        db.execute(
                            "SELECT action, subject FROM audit WHERE action LIKE 'maas.release.%' ORDER BY id"
                        )
                    )
                    assert changes == [
                        ("maas.release.publish", "1"),
                        ("maas.release.publish", "2"),
                        ("maas.release.publish", "3"),
                        ("maas.release.rollback", "4"),
                    ], changes
                    tenant_changes = [
                        (tenant, event["action"], str(event["revision"]))
                        for tenant, raw in db.execute(
                            "SELECT tenant, event FROM tenant_audit ORDER BY sequence"
                        )
                        if (event := json.loads(raw))["action"].startswith(
                            "maas.release."
                        )
                    ]
                    assert tenant_changes == [
                        (PILOT_TENANT, action, number) for action, number in changes
                    ], tenant_changes
                return state_db

            def revoke():
                status, raw = api(
                    "/v1/keys/" + created["subject"], admin, method="DELETE"
                )
                assert status == 200 and json.loads(raw)["revoked"], (status, raw)
                for replica in replicas.values():
                    wait_until(
                        lambda replica=replica: models(replica, primary)[0] == 401
                    )

            exercise_release_rollout(
                replicas=list(replicas.values()),
                alias=alias,
                stable=model[1],
                candidate=candidate,
                old_key=primary,
                active_key=active,
                stable_key=stable_key,
                publish=publish,
                restart=restart,
                revoke=revoke,
                monitor=monitor,
                fetch=fetch,
                wait_until=wait_until,
                upload_batch_file=upload_batch_file,
            )
            return

        same_tenant = create_key(tenant="tenant-test", grants=asset_grants)
        other_tenant = create_key(tenant="tenant-isolated", grants=asset_grants)
        other_org = create_key(org="org-isolated", grants=vault_grants)
        quota_keys = (
            {
                name: create_key(
                    tenant=QUOTA_TENANT, project=project, env=env, grants=grants
                )
                for name, project, env in (
                    ("production", "project-a", "prod"),
                    ("production-peer", "project-a", "prod"),
                    ("test", "project-a", "test"),
                    ("private", "project-a", "private"),
                    ("sibling", "project-b", "prod"),
                )
            }
            if not budget_rollover
            else {}
        )
        if not budget_rollover:
            sdk_key = create_key(tenant="tenant-sdk", grants=sdk_grants)
            assert api("/v1/registry/openapi.json", sdk_key)[0] == 401
            status, raw = api("/v1/registry/openapi.json", admin)
            assert status == 200 and json.loads(raw) == spec
        for replica in replicas.values():
            processes.enter_context(gateway_process(replica, "gateway.log"))
        for replica in replicas.values():
            wait_until(lambda replica=replica: replica_ready(replica))
        if budget_rollover:
            boundary = (int(time.time()) // budget_window + 1) * budget_window
            if boundary - time.time() < 18:
                time.sleep(max(0, boundary - time.time()) + 0.1)
                boundary += budget_window
        for replica in replicas.values():
            status, raw = models(replica, primary)
            listing = json.loads(raw)
            assert status == 200 and listing["object"] == "list", (status, raw)
            assert [entry["id"] for entry in listing["data"]] == (
                [alias] if model else []
            )
        with ThreadPoolExecutor(max_workers=6) as pool:
            pending = [
                pool.submit(models, replica, primary)
                for replica in replicas.values()
                for _ in range(3)
            ]
            assert sorted(job.result()[0] for job in pending) == [
                200,
                200,
                429,
                429,
                429,
                429,
            ]
        if budget_rollover:
            wait_until(lambda: events_count().get("request-terminal") == 4)
            prepared = wait_until(lambda: next_window_leases(boundary), timeout=40)
            revisions = {
                name: node_status(replica)["applied"]["revision"]
                for name, replica in replicas.items()
            }
            controller.terminate()
            controller.wait(timeout=10)
            assert time.time() < boundary - 1, (
                "controller stopped after the test window"
            )
            for replica in replicas.values():
                assert models(replica, primary)[0] == 429
            time.sleep(max(0, boundary - time.time()) + 0.1)
            with ThreadPoolExecutor(max_workers=6) as pool:
                calls = [
                    pool.submit(models, replica, primary)
                    for replica in replicas.values()
                    for _ in range(3)
                ]
                assert sorted(call.result()[0] for call in calls) == [
                    200,
                    200,
                    200,
                    200,
                    429,
                    429,
                ]
            config = json.loads(config_path.read_text())
            for budget in config["budgets"]:
                if (
                    budget["tenant"] == "tenant-test"
                    and budget["operation"] == OPERATION
                ):
                    budget.update(requests=2, replicas=dict.fromkeys(replicas, 1))
            config_path.write_text(json.dumps(config))
            processes.enter_context(control_process("control-restart.log"))
            wait_until(lambda: api("/healthz")[0] == 200)
            wait_until(
                lambda: all(
                    node_status(replica)["applied"]["revision"] > revisions[name]
                    for name, replica in replicas.items()
                )
            )
            wait_until(
                lambda: events_count() == {"request-started": 8, "request-terminal": 8}
            )
            with sqlite3.connect(state_db) as db:
                received = [
                    json.loads(row[0])
                    for row in db.execute(
                        "SELECT payload FROM usage_events WHERE kind = 'request-started'"
                    )
                ]
                for replica, lease in prepared.items():
                    scoped = [
                        row[0]
                        for row in db.execute(
                            "SELECT id FROM scoped_leases WHERE window = ? AND replica = ? "
                            "AND tenant = 'tenant-test' AND operation = ? ORDER BY env",
                            (boundary, replica, OPERATION),
                        )
                    ]
                    assert len(scoped) == 2
                    assert [
                        event["scope_lease_ids"]
                        for event in received
                        if event["lease_id"] == lease
                    ] == [scoped, scoped]
                assert db.execute(
                    "SELECT window, granted FROM budget_windows WHERE tenant = 'tenant-test' "
                    "AND operation = ? AND window IN (?, ?) ORDER BY window",
                    (OPERATION, boundary - budget_window, boundary),
                ).fetchall() == [(boundary - budget_window, 4), (boundary, 4)]
            for replica in replicas.values():
                assert models(replica, primary)[0] == 429
            print(
                "Two replicas preserved their hard limits through budget rollover with the control plane offline."
            )
            return
        first = next(iter(replicas.values()))
        snapshot = json.loads((first["test_state"] / "snapshot.json").read_text())
        assert (sdk / "routers.acl").read_text() in snapshot["snapshot"]["acl"]
        if model is not None:
            check_model_requests(first["test_base"], primary, alias, fetch)
            check_additional_inference(first["test_base"], primary, alias, fetch)
        requests = 8 if model else 4
        expected_events = dict.fromkeys(
            ("request-started", "request-terminal"), requests
        )
        wait_until(lambda: events_count() == expected_events)
        if model is not None:

            def model_events():
                with sqlite3.connect(state_db) as db:
                    events = [
                        json.loads(row[0])
                        for row in db.execute(
                            "SELECT m.payload FROM maas_usage_events m "
                            "JOIN usage_events e ON m.request_id = e.id"
                        )
                    ]
                    return events if len(events) >= 4 else None

            measured = wait_until(model_events)
            assert len(measured) == 4
            operations = [item["operation"] for item in measured]
            assert sorted(operations) == sorted([CHAT, CHAT, COMPLETIONS, EMBEDDINGS])
            assert all(
                item["outcome"] == "ok"
                and (
                    item["tokens"]["prompt"] > 0 and item["tokens"]["completion"] == 0
                    if item["operation"] == EMBEDDINGS
                    else item["tokens"]["completion"] > 0
                )
                for item in measured
            ), measured
            entry = json.dumps(measured[0]).encode()
            assert (
                api(
                    "/v1/maas-usage",
                    admin,
                    data=entry,
                    headers=content_type,
                )[0]
                == 401
            )
            status, receipt = api(
                "/v1/maas-usage",
                usage_token,
                data=entry,
                headers=content_type,
            )
            assert (
                status == 200
                and json.loads(receipt)["request_id"] == measured[0]["request_id"]
            )
            assert len(model_events()) == 4
            if on_model_settled is not None:
                on_model_settled()
        with sqlite3.connect(state_db) as db:
            data = db.execute(
                "SELECT p.epoch, p.seq, e.id, e.payload, e.digest FROM usage_positions p "
                "JOIN usage_events e ON p.event_id = e.id "
                "WHERE p.replica = ? ORDER BY p.seq",
                (first["id"],),
            ).fetchall()
            assert db.execute("SELECT SUM(granted) FROM budget_windows").fetchone() == (
                sum(
                    budget["requests"] for budget in budgets if "project" not in budget
                ),
            )
            assert primary.encode() not in state_db.read_bytes()
        batch = {
            "schema": "kgateway.usage-batch.v1",
            "gateway_id": first["id"],
            "batch_id": str(uuid4()),
            "records": [
                {
                    "cursor": {"boot_epoch": epoch, "sequence": sequence},
                    "event_id": event_id,
                    "payload_base64": base64.b64encode(payload).decode(),
                    "payload_sha256": digest,
                }
                for epoch, sequence, event_id, payload, digest in data
            ],
        }
        request = json.dumps(batch).encode()
        token = env[first["usage_token_env"]]
        for _ in range(2):
            status, raw = api("/v1/usage", token, data=request, headers=content_type)
            assert (
                status == 200
                and json.loads(raw)["acknowledged_through"]
                == batch["records"][-1]["cursor"]
            ), (status, raw)
        assert events_count() == expected_events
        second = list(replicas.values())[1]
        file_id = check_files(
            first["test_base"],
            second["test_base"],
            primary,
            same_tenant,
            other_tenant,
            fetch,
        )
        with sqlite3.connect(state_db) as db:
            admissions = [
                json.loads(row[0])
                for row in db.execute("SELECT request FROM audit_admissions")
            ]
            assert any(
                event["operation"] == "maas.files.delete"
                and event["path"] == "/v1/files/" + file_id
                for event in admissions
            ), admissions
        if model is not None:
            with sqlite3.connect(state_db) as db:
                assert db.execute(
                    "SELECT COUNT(*) FROM audit_admissions"
                ).fetchone() == (3,)
            check_batches(
                first["test_base"],
                second["test_base"],
                primary,
                same_tenant,
                other_tenant,
                alias,
                fetch,
                state_db,
                api,
                usage_token,
            )
        protected, plaintext_values = vault_case.check_vault(
            first["test_base"],
            second["test_base"],
            primary,
            other_org,
            vault_token,
            admin,
            api,
            fetch,
            vault,
        )
        with sqlite3.connect(state_db) as db:
            rows = db.execute(
                "SELECT version, state, ciphertext FROM vault_versions ORDER BY version"
            ).fetchall()
            assert rows == [(1, "revoked", None), (2, "revoked", None)], rows
            evidence = json.dumps(
                db.execute("SELECT event FROM tenant_audit").fetchall()
            )
            assert all(secret not in evidence for secret in protected), (
                "audit contains protected material"
            )
        for path in [
            *directory.glob("*.log"),
            *directory.glob("replica-*/*.log"),
            state_db,
            state_db.with_suffix(".sqlite-wal"),
        ]:
            if path.is_file():
                data = path.read_bytes()
                assert all(
                    secret.encode() not in data for secret in plaintext_values
                ), f"plaintext entered {path.name}"
        if vault.kms is not None:
            print(
                "OpenBao Transit verified TLS, workload ACLs, context binding, sealed-service recovery, rotation and old-key retirement."
            )
        revoked_ticket = delegation_case.check(
            first["test_base"], second["test_base"], primary, admin, api, fetch, agents
        )
        anchors = witness.evidence(check_conflict=True)
        assert any(
            row["record"]["event"].get("delegation_chain")
            == [delegation_case.audience("a"), delegation_case.audience("b")]
            for row in anchors
        ), anchors
        assert any(row["record"]["event"].get("vault_binding") for row in anchors), (
            anchors
        )
        wait_until(
            lambda: any(
                row["record"]["event"]["action"] != "request.sensitive-admission"
                for row in witness.evidence()
            )
        )
        file_id, _ = upload_batch_file(
            first["test_base"], primary, "witness-model", 1, fetch
        )
        file_url = second["test_base"] + "/v1/files/" + file_id
        anchor.terminate()
        anchor.wait(timeout=10)
        assert fetch(file_url, primary, method="DELETE")[0] == 503
        assert fetch(file_url, primary)[0] == 200
        processes.enter_context(witness.start("witness-restart.log"))
        wait_until(lambda: witness.call("/healthz")[0] == 200)
        restored = witness.evidence()
        assert all(row in restored for row in anchors)
        assert fetch(file_url, primary, method="DELETE")[0] == 200
        recovered = witness.evidence()
        assert len(recovered) > len(anchors) and all(
            row in recovered for row in anchors
        )
        check_scope_limits(
            models,
            replicas,
            quota_keys,
            state_db,
            api,
            env,
            fetch,
            model,
        )
        sdk_file, _ = upload_batch_file(
            first["test_base"], sdk_key, "sdk-model", 1, fetch
        )
        check_probes(
            sdk,
            first["test_base"],
            sdk_key,
            sdk_file,
            alias if model is not None else None,
        )
        if model is not None:
            controller.terminate()
            controller.wait(timeout=10)
            retained = witness.evidence()
            assert all(row in retained for row in recovered)
            assert replica_ready(second)
            journal = scratch / "kstack-data/maas-usage.sqlite"
            with sqlite3.connect(journal) as db:
                before = db.execute("SELECT COUNT(*) FROM maas_usage").fetchone()
            status, detail = fetch(
                second["test_base"] + "/v1/chat/completions",
                primary,
                data=json.dumps(
                    {"model": alias, "messages": [{"role": "user", "content": "probe"}]}
                ).encode(),
                headers=content_type,
            )
            assert status == 503, (status, detail)
            with sqlite3.connect(journal) as db:
                assert (
                    db.execute("SELECT COUNT(*) FROM maas_usage").fetchone() == before
                )

    with (
        control_process("control-restart.log"),
        gateway_process(first, "gateway-restart.log"),
    ):
        wait_until(lambda: api("/healthz")[0] == 200)
        wait_until(lambda: replica_ready(first))
        assert models(first, primary)[0] == 429
        assert models(first, quota_keys["sibling"])[0] == 429
        if model is not None:
            status, _ = fetch(
                first["test_base"] + "/v1/chat/completions",
                quota_keys["production-peer"],
                data=json.dumps(
                    {
                        "model": alias,
                        "messages": [{"role": "user", "content": "restart"}],
                    }
                ).encode(),
                headers=content_type,
            )
            assert status == 429
        status, raw = api("/v1/keys/" + created["subject"], admin, method="DELETE")
        assert status == 200 and json.loads(raw)["revoked"], (status, raw)
        wait_until(lambda: models(first, primary)[0] == 401)
        assert revoked_ticket["expires_at"] > time.time()
        assert (
            delegation_case.invoke(
                fetch, first["test_base"], "b", revoked_ticket["access_token"]
            )[0]
            == 401
        )
        assert len(agents.observed["b"]) == 1
        audit_path = "/v1/audit/tenant-test?limit=256"
        assert api(audit_path, admin)[0] == 401
        status, page = api(audit_path, auditor)
        assert status == 200, (status, page)
        verify_audit_page(json.loads(page), primary)
        if model is not None:
            assert "request.sensitive-admission" in {
                row["event"]["action"] for row in json.loads(page)["events"]
            }
        with sqlite3.connect(state_db) as db:
            assert [
                row[0]
                for row in db.execute(
                    "SELECT action FROM audit WHERE subject = ? ORDER BY id",
                    (created["subject"],),
                )
            ] == ["key.created", "key.revoked"]
    print(
        "Control plane, two replica allowances, exact usage receipts, Files and Batch settlement, Vault bindings, A2A delegation, and independent audit recovery passed."
    )


def benchmark_reservations(state_db, replica, token, api, issue):
    """Reserve start records for direct requests before measuring their ingress."""
    epoch = str(uuid4())
    position = None

    def prepare(count):
        nonlocal position
        now = datetime.now(UTC)
        with sqlite3.connect(state_db) as db:
            (lease,) = db.execute(
                "SELECT id FROM leases WHERE replica = ? AND tenant = ? AND operation = ? "
                "AND window <= ? ORDER BY window DESC LIMIT 1",
                (replica["id"], DIRECT_TENANT, CHAT, int(now.timestamp())),
            ).fetchone()
        credentials = []
        for batch_start in range(0, count, 128):
            records = []
            sequence = position["sequence"] if position else 0
            for offset in range(min(128, count - batch_start)):
                credential, claims = issue()
                credentials.append(credential)
                request_id = claims["request_id"]
                event = {
                    field: claims[field]
                    for field in (
                        "tenant",
                        "project",
                        "env",
                        "reservation_id",
                        "trace_id",
                        "operation",
                        "urn",
                    )
                }
                event.update(
                    schema="kgateway.platform-usage.v1",
                    kind="request-started",
                    event_id=request_id,
                    request_id=request_id,
                    lease_id=lease,
                    subject=claims["sub"],
                    at=now.isoformat(),
                )
                payload = json.dumps(event, separators=(",", ":")).encode()
                records.append(
                    {
                        "cursor": {
                            "boot_epoch": epoch,
                            "sequence": sequence + offset + 1,
                        },
                        "event_id": request_id,
                        "payload_base64": base64.b64encode(payload).decode(),
                        "payload_sha256": hashlib.sha256(payload).hexdigest(),
                    }
                )
            batch = {
                "schema": "kgateway.usage-batch.v1",
                "gateway_id": replica["id"],
                "batch_id": str(uuid4()),
                "after": position,
                "records": records,
            }
            status, response = api(
                "/v1/usage",
                token,
                data=json.dumps(batch).encode(),
                headers={"Content-Type": "application/json"},
            )
            assert status == 200, (status, response)
            position = records[-1]["cursor"]
            assert json.loads(response)["acknowledged_through"] == position
        return credentials

    return prepare


def scoped_budgets(replicas, has_model):
    limits = [
        (OPERATION, None, None, (3, 3)),
        (OPERATION, "project-a", None, (2, 2)),
        (OPERATION, "project-a", "prod", (1, 1)),
        (OPERATION, "project-a", "test", (2, 2)),
        (OPERATION, "project-a", "private", (1, 0)),
        (OPERATION, "project-b", None, (3, 3)),
        (OPERATION, "project-b", "prod", (3, 3)),
    ]
    if has_model:
        limits.extend(
            (
                (CHAT, None, None, (2, 2)),
                (CHAT, "project-a", None, (2, 2)),
                (CHAT, "project-a", "prod", (1, 1)),
                (CHAT, "project-a", "test", (1, 1)),
            )
        )
    budgets = []
    for operation, project, env, allowances in limits:
        budget = {
            "tenant": QUOTA_TENANT,
            "operation": operation,
            "requests": sum(allowances),
            "replicas": {
                replica: amount
                for replica, amount in zip(replicas, allowances)
                if amount
            },
        }
        if project:
            budget["project"] = project
        if env:
            budget["env"] = env
        budgets.append(budget)
    return budgets


def check_scope_limits(models, replicas, keys, state_db, api, env, fetch, model):
    first, second = replicas.values()
    assert models(second, keys["private"])[0] == 429

    def burst(first_key, second_key):
        with ThreadPoolExecutor(max_workers=4) as pool:
            calls = [
                [
                    pool.submit(models, replica, keys[key])
                    for key in (first_key, second_key)
                ]
                for replica in replicas.values()
            ]
            assert [sorted(call.result()[0] for call in pair) for pair in calls] == [
                [200, 429],
                [200, 429],
            ]

    burst("production", "production-peer")
    burst("test", "test")
    burst("sibling", "sibling")

    headers = {"Content-Type": "application/json"}
    if model is not None:
        data = json.dumps(
            {"model": model[0], "messages": [{"role": "user", "content": "quota"}]}
        )
        url = first["test_base"] + "/v1/chat/completions"
        assert (
            fetch(url, keys["production"], data=data.encode(), headers=headers)[0]
            == 200
        )
        assert (
            fetch(url, keys["production-peer"], data=data.encode(), headers=headers)[0]
            == 429
        )

    def scoped_usage():
        with sqlite3.connect(state_db) as db:
            records = [
                json.loads(row[0])
                for row in db.execute("SELECT payload FROM usage_events")
            ]
        return [event for event in records if event["tenant"] == QUOTA_TENANT]

    requests = 7 if model is not None else 6
    usage = wait_until(
        lambda: records if len(records := scoped_usage()) == 2 * requests else None
    )
    starts = {
        event["request_id"]: event
        for event in usage
        if event["kind"] == "request-started"
    }
    assert len(starts) == requests and all(
        len(event["scope_lease_ids"]) == 2 for event in starts.values()
    )
    for event in usage:
        assert (
            event["scope_lease_ids"] == starts[event["request_id"]]["scope_lease_ids"]
        )
    if model is not None:
        with sqlite3.connect(state_db) as db:
            requests = [
                json.loads(row[0])
                for row in db.execute("SELECT request FROM audit_admissions")
            ]
            (admission,) = [
                event for event in requests if event["tenant"] == QUOTA_TENANT
            ]
            (other_env_lease,) = db.execute(
                "SELECT id FROM scoped_leases WHERE tenant = ? AND operation = ? AND project = ? "
                "AND env = 'test' AND replica = ? ORDER BY window DESC LIMIT 1",
                (QUOTA_TENANT, CHAT, admission["project"], first["id"]),
            ).fetchone()
        charged = starts[admission["request_id"]]["scope_lease_ids"]
        assert admission["scope_lease_ids"] == charged
        producer = env[first["usage_token_env"]]
        for scoped_ids in (None, charged[:1], [charged[0], other_env_lease]):
            forged = {
                **admission,
                "request_id": str(uuid4()),
                "reservation_id": str(uuid4()),
            }
            if scoped_ids is None:
                del forged["scope_lease_ids"]
            else:
                forged["scope_lease_ids"] = scoped_ids
            status, raw = api(
                "/v1/audit/admissions",
                producer,
                data=json.dumps(forged).encode(),
                headers=headers,
            )
            assert status == 400, (status, raw)
    print(
        "Tenant, project, and environment budgets enforced atomically on both replicas."
    )


def upload_batch_file(base, owner, model, lines, fetch):
    content = b"".join(
        json.dumps(
            {
                "custom_id": f"req-{index + 1}",
                "method": "POST",
                "url": "/v1/chat/completions",
                "body": {
                    "model": model,
                    "messages": [{"role": "user", "content": "hello"}],
                },
            }
        ).encode()
        + b"\n"
        for index in range(lines)
    )
    boundary = "test-batch-" + secrets.token_hex(8)
    body = (
        (
            f'--{boundary}\r\nContent-Disposition: form-data; name="purpose"\r\n\r\nbatch\r\n'
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="input.jsonl"\r\n'
            "Content-Type: application/jsonl\r\n\r\n"
        ).encode()
        + content
        + f"\r\n--{boundary}--\r\n".encode()
    )
    status, payload = fetch(
        base + "/v1/files",
        owner,
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    assert status == 200, (status, payload)
    return json.loads(payload)["id"], content


def check_files(first, second, owner, same_tenant, other_tenant, fetch):
    file_id, content = upload_batch_file(first, owner, "batch-model", 1, fetch)
    path = "/v1/files"
    detail = path + "/" + file_id
    status, payload = fetch(second + detail, owner)
    assert status == 200 and json.loads(payload)["id"] == file_id, (status, payload)
    assert fetch(second + detail + "/content", owner) == (200, content)
    status, payload = fetch(second + path + "?purpose=batch&limit=1", owner)
    assert status == 200 and [row["id"] for row in json.loads(payload)["data"]] == [
        file_id
    ], (status, payload)
    status, payload = fetch(second + path + "?after=" + file_id, owner)
    assert status == 200 and json.loads(payload)["data"] == [], (status, payload)
    assert fetch(second + path + "?limit=1&limit=2", owner)[0] == 404
    assert fetch(second + detail.replace("file-", "file%2d"), owner)[0] == 404
    for key in (same_tenant, other_tenant):
        assert fetch(first + detail, key)[0] == 404
        assert fetch(first + detail + "/content", key)[0] == 404
        status, payload = fetch(first + path + "?after=" + file_id, key)
        assert status == 200 and json.loads(payload)["data"] == [], (status, payload)
    status, payload = fetch(second + detail, owner, method="DELETE")
    assert status == 200 and json.loads(payload)["deleted"], (status, payload)
    assert fetch(second + detail, owner)[0] == 404
    return file_id


def check_batches(
    first,
    second,
    owner,
    same_tenant,
    other_tenant,
    alias,
    fetch,
    state_db,
    api,
    usage_token,
):
    path = "/v1/batches"
    header = {"Content-Type": "application/json"}

    def submit(file_id, base=first):
        return fetch(
            base + path,
            owner,
            data=json.dumps(
                {
                    "input_file_id": file_id,
                    "endpoint": "/v1/chat/completions",
                    "completion_window": "24h",
                }
            ).encode(),
            headers=header,
        )

    file_id, _ = upload_batch_file(second, owner, alias, 2, fetch)
    status, payload = submit(file_id)
    assert status == 200, (status, payload)
    batch_id = json.loads(payload)["id"]
    detail = path + "/" + batch_id

    def completed():
        status, payload = fetch(second + detail, owner)
        assert status == 200, (status, payload)
        row = json.loads(payload)
        assert row["status"] not in {"failed", "expired", "cancelled"}, row
        return row if row["status"] == "completed" else None

    row = wait_until(completed)
    assert row["request_counts"] == {"total": 2, "completed": 2, "failed": 0}, row
    output = "/v1/files/" + row["output_file_id"] + "/content"
    status, payload = fetch(second + output, owner)
    assert status == 200, (status, payload)
    lines = [json.loads(line) for line in payload.splitlines()]
    assert {line["custom_id"] for line in lines} == {"req-1", "req-2"}, lines
    assert all(line["response"]["status_code"] == 200 for line in lines), lines
    for key in (same_tenant, other_tenant):
        status, payload = fetch(second + detail, key)
        assert status == 404, (status, payload)
        assert fetch(second + detail + "/cancel", key, method="POST")[0] == 404
        assert fetch(second + output, key)[0] == 404
        status, payload = fetch(second + path + "?limit=1", key)
        assert status == 200 and json.loads(payload)["data"] == [], (status, payload)
    assert fetch(second + detail + "/cancel", owner, method="POST")[0] == 409
    foreign, _ = upload_batch_file(second, same_tenant, alias, 1, fetch)
    oversized, _ = upload_batch_file(second, owner, alias, 3, fetch)
    forbidden, _ = upload_batch_file(second, owner, "not-in-the-grant", 1, fetch)
    for input_id, status_code, code in (
        (foreign, 400, "file_not_found"),
        (oversized, 400, "batch_request_limit"),
        (forbidden, 403, "batch_model_scope_denied"),
    ):
        status, payload = submit(input_id)
        assert status == status_code and json.loads(payload)["error"]["code"] == code, (
            status,
            payload,
        )
    assert submit(file_id)[0] == 429  # Four reservations consume eight units.

    def measured_lines():
        with sqlite3.connect(state_db) as db:
            rows = [
                json.loads(payload)
                for (payload,) in db.execute("SELECT payload FROM maas_usage_events")
            ]
            events = [row for row in rows if "batch_line" in row]
            if len(events) < 2:
                return None
            parent = events[0]["batch_line"]["request_id"]
            (start,) = db.execute(
                "SELECT payload FROM usage_events WHERE id = ?", (parent,)
            ).fetchone()
        return events, json.loads(start)

    events, start = wait_until(measured_lines)
    assert start["reserved_requests"] == 2 and start["batch_models"] == [alias], start
    assert {event["batch_line"]["line"] for event in events} == {1, 2}, events
    assert all(
        event["batch_line"]["reservation_id"] == start["reservation_id"]
        and event["tokens"]["completion"] > 0
        for event in events
    ), events

    status, payload = submit(file_id, second)
    assert status == 200, (status, payload)
    cancelling = path + "/" + json.loads(payload)["id"]
    status, payload = fetch(first + cancelling + "/cancel", owner, method="POST")
    assert status == 200 and json.loads(payload)["status"] == "cancelling", (
        status,
        payload,
    )

    def cancelled():
        status, payload = fetch(second + cancelling, owner)
        assert status == 200, (status, payload)
        return json.loads(payload)["status"] == "cancelled"

    wait_until(cancelled)

    def settlement(batch, status):
        with sqlite3.connect(state_db) as db:
            return db.execute(
                "SELECT reserved_requests, attempts, unused_requests FROM maas_batches WHERE batch_id = ? AND status = ?",
                (batch, status),
            ).fetchone()

    assert wait_until(lambda: settlement(batch_id, "completed")) == (2, 2, 0)
    reserved, attempts, unused = wait_until(
        lambda: settlement(cancelling.rsplit("/", 1)[-1], "cancelled")
    )
    assert reserved == 2 and 0 <= attempts <= 2 and unused == 2 - attempts

    short_file, _ = upload_batch_file(second, owner, alias, 1, fetch)
    status, payload = submit(short_file, second)
    assert status == 200, (status, payload)
    short_batch = json.loads(payload)["id"]
    assert wait_until(lambda: settlement(short_batch, "completed")) == (2, 1, 1)

    with sqlite3.connect(state_db) as db:
        (event,) = db.execute(
            "SELECT payload FROM maas_batch_reports WHERE json_extract(payload, '$.batch_id') = ? "
            "AND json_extract(payload, '$.status') = 'completed'",
            (short_batch,),
        ).fetchone()
    report = json.loads(event)
    status, body = api(
        "/v1/maas-usage", usage_token, data=event.encode(), headers=header
    )
    assert status == 200 and json.loads(body)["report_id"] == report["report_id"], (
        status,
        body,
    )
    report["observed_at"] = datetime.now(UTC).isoformat()
    assert (
        api(
            "/v1/maas-usage",
            usage_token,
            data=json.dumps(report).encode(),
            headers=header,
        )[0]
        == 409
    )


def check_model_requests(base, primary, alias, fetch):
    url = base + "/v1/chat/completions"

    def chat(stream=False, model=alias):
        request = {
            "model": model,
            "messages": [{"role": "user", "content": "Return a greeting."}],
            "stream": stream,
        }
        if stream:
            request["stream_options"] = {"include_usage": True}
        return fetch(
            url,
            primary,
            data=json.dumps(request).encode(),
            headers={"Content-Type": "application/json"},
        )

    status, json_body = chat()
    assert status == 200, (status, json_body)
    response = json.loads(json_body)
    assert response["model"] == alias and response["choices"][0]["message"]["content"]
    assert response["usage"]["completion_tokens"] > 0
    status, sse = chat(stream=True)
    assert status == 200, (status, sse)
    frames = [
        line.removeprefix(b"data: ")
        for line in sse.splitlines()
        if line.startswith(b"data: ")
    ]
    assert frames[-1] == b"[DONE]"
    chunks = [json.loads(frame) for frame in frames[:-1]]
    assert all(chunk["model"] == alias for chunk in chunks)
    assert any(
        chunk["usage"]["completion_tokens"] > 0
        for chunk in chunks
        if chunk.get("usage")
    )
    assert chat(model="ungranted-alias")[0] == 403
    assert chat()[0] == 429
    print("The same primary key listed the model and completed chat over JSON and SSE.")


def check_additional_inference(base, primary, alias, fetch):
    def call(name, **inputs):
        status, body = fetch(
            base + "/v1/" + name,
            primary,
            data=json.dumps({"model": alias, **inputs}).encode(),
            headers={"Content-Type": "application/json"},
        )
        assert status == 200, (name, status, body)
        return json.loads(body)

    completion = call("completions", prompt="hello", max_tokens=8)
    assert completion["object"] == "text_completion"
    assert completion["choices"][0]["text"]
    embedding = call("embeddings", input="hello")
    assert embedding["data"][0]["embedding"] == [0.125, -0.25, 0.5]
    assert embedding["usage"]["prompt_tokens"] > 0


def verify_audit_page(page, primary):
    assert page["schema"] == "kgateway.audit.v1" and page["tenant"] == "tenant-test"
    previous = "0" * 64
    actions = set()
    for sequence, row in enumerate(page["events"], 1):
        assert row["sequence"] == sequence and row["previous"] == previous
        canonical = json.dumps(row["event"], sort_keys=True, separators=(",", ":"))
        prelude = f"kgateway.audit.v1\0tenant-test\0{sequence}\0{previous}\0"
        assert (
            row["digest"] == hashlib.sha256((prelude + canonical).encode()).hexdigest()
        )
        assert primary not in canonical
        previous = row["digest"]
        actions.add(row["event"]["action"])
    assert page["read_receipt"] == {"sequence": len(page["events"]), "digest": previous}
    assert {
        "key.created",
        "key.revoked",
        "request-started",
        "request-terminal",
        "audit.read",
    } <= actions
