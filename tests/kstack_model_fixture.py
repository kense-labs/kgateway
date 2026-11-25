"""Enroll a kstack test agent and deploy its OpenAI engine through the console."""

import json
import socket
from contextlib import ExitStack, contextmanager

from platform_control_plane_e2e import wait_until

STREAM_CHUNKS = 4
STREAM_FIRST_DELTA_MS = 900


def console_api(console_port, password, fetch):
    base = f"http://127.0.0.1:{console_port}"
    headers = {"Content-Type": "application/json"}
    status, body = fetch(
        base + "/api/v1/auth/login",
        data=json.dumps({"username": "admin", "password": password}).encode(),
        headers=headers,
    )
    assert status == 200, (status, body)
    token = json.loads(body)["token"]

    def api(path, payload=None, *, method=None):
        status, body = fetch(
            base + "/api/v1" + path,
            token,
            data=json.dumps(payload).encode() if payload is not None else None,
            headers=headers,
            method=method,
        )
        assert status in (200, 201, 204), (status, body)
        return json.loads(body) if body else None

    return base, api


def live_deployment(api, deployment_id):
    detail = api(f"/deployments/{deployment_id}")
    if any(instance["state"] == "running" for instance in detail.get("instances", [])):
        return detail
    return None


@contextmanager
def running_models(
    fleet_host, console_port, password, scratch, process, fetch, *, rollout=False
):
    base, api = console_api(console_port, password, fetch)

    names = (
        ("kense-stable-fixture", "kense-canary-fixture")
        if rollout
        else ("kense-chat-fixture",)
    )
    roster_entries = []
    for name in names:
        node = api("/nodes", {"name": name, "server_url": base})
        roster_entries.append(
            {"name": name, "uuid": node["node"]["uuid"], "token": node["token"]}
        )
    if rollout:
        # Keep both binds open until distinct ports have been assigned.
        with ExitStack() as ports:
            for node in roster_entries:
                listener = ports.enter_context(socket.socket())
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
                node["engine_ports"] = {"start": port, "end": port}
    node_ids = {node["uuid"] for node in roster_entries}
    roster = scratch / "roster.json"
    roster.write_text(json.dumps(roster_entries))
    roster.chmod(0o600)
    ready = scratch / "fleet-ready"
    model_dir = scratch / "fleet-model"
    with process(
        fleet_host,
        [
            "--roster",
            str(roster),
            "--server",
            base,
            "--state-root",
            str(scratch / "agents"),
            "--model-dir",
            str(model_dir),
            "--ready",
            str(ready),
            "--gpus",
            "1",
            "--engine-chunks",
            str(24 if rollout else STREAM_CHUNKS),
            "--engine-ttft",
            "2s" if rollout else f"{STREAM_FIRST_DELTA_MS}ms",
            "--engine-tpot",
            "1s" if rollout else "0s",
            "--log",
            str(scratch / "agent.log"),
        ],
        scratch / "fleet.log",
    ):
        wait_until(ready.exists, timeout=40)
        wait_until(
            lambda: (
                node_ids
                <= {
                    row["uuid"]
                    for row in api("/nodes")["items"]
                    if row["state"] == "online" and row["gpu_count"] > 0
                }
            ),
            timeout=40,
        )

        deployments = []
        for node in roster_entries:
            model = api(
                "/models/local",
                {
                    "node_uuid": node["uuid"],
                    "path": str(model_dir),
                    "source_id": "qwen3-" + node["name"],
                    "name": "qwen3-" + node["name"],
                },
            )
            deployment = api(
                "/deployments",
                {
                    "model_id": model["id"],
                    "node_uuid": node["uuid"],
                    "served_name": node["name"],
                    "quick_params": {"max_model_len": 512},
                },
            )
            deployments.append(deployment["id"])
        result = []
        for node, deployment_id in zip(roster_entries, deployments, strict=True):
            current = wait_until(
                lambda deployment_id=deployment_id: live_deployment(api, deployment_id),
                timeout=120,
            )
            if rollout:
                assert {
                    instance["api_port"]
                    for instance in current["instances"]
                    if instance["state"] == "running"
                } == {node["engine_ports"]["start"]}, current
            result.append(
                (
                    node["name"],
                    {"id": current["id"], "version": current["maas_revision"]},
                )
            )
        yield result, api
