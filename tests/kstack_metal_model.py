"""Deploy real GGUF weights through a native kstack Apple Silicon agent."""

import hashlib
import os
import re
import socket
from contextlib import contextmanager

from kstack_model_fixture import console_api, live_deployment
from platform_control_plane_e2e import wait_until


@contextmanager
def running_metal_model(
    agent, model, image, console_port, password, scratch, process, fetch, *, engine_port
):
    base, api = console_api(console_port, password, fetch)
    alias = "kense-metal-gguf"
    model_id = "kense/metal-gguf-acceptance"
    node = api("/nodes", {"name": alias, "server_url": base})
    node_uuid = node["node"]["uuid"]
    state = scratch / "metal-agent"
    with process(
        agent,
        [
            "run",
            "--server",
            base,
            "--state",
            str(state),
            "--driver",
            "host",
            "--engine-ports",
            f"{engine_port}-{engine_port}",
        ],
        scratch / "metal-agent.log",
        dict(os.environ, GPUWORKS_TOKEN=node["token"]),
    ):
        wait_until(
            lambda: any(
                item["uuid"] == node_uuid
                and item["state"] == "online"
                and item["gpu_count"] > 0
                for item in api("/nodes")["items"]
            ),
            timeout=60,
        )
        local = api(
            "/models/local",
            {
                "node_uuid": node_uuid,
                "path": str(model.parent),
                "source_id": model_id,
                "name": alias,
            },
        )
        api(
            "/inference-templates/import",
            {
                "models": [
                    {
                        "model_id": model_id,
                        "display_title": alias,
                        "context_length": 2048,
                        "specs": [
                            {
                                "name": "metal",
                                "engine": "callable",
                                "image": image,
                                "gpus": {"vendor": "apple"},
                                "weight_bytes": model.stat().st_size,
                                "weights": {
                                    "quantization": "GGUF",
                                    "sources": [{"local": model_id}],
                                },
                                "entrypoint": ["llama-server"],
                                "args": [
                                    "-m",
                                    "${MODEL_PATH}/" + model.name,
                                    "--host",
                                    "${API_HOST}",
                                    "--port",
                                    "${API_PORT}",
                                    "--alias",
                                    alias,
                                    "--jinja",
                                    "--device",
                                    "MTL0",
                                    "-ngl",
                                    "99",
                                    "-c",
                                    "2048",
                                    "-np",
                                    "2",
                                    "-n",
                                    "24",
                                    "-lv",
                                    "5",
                                ],
                                "placement": {
                                    "language": "starlark",
                                    "resolver": "def resolve(gpu):\n    return accept(gpu_memory_mib_per_device=2048)\n",
                                },
                                "api": {
                                    "health_endpoint": "/health",
                                    "operations": [
                                        {
                                            "type": "openai.chat",
                                            "endpoint": "/v1/chat/completions",
                                            "mode": "stream",
                                        }
                                    ],
                                },
                            }
                        ],
                    }
                ]
            },
        )
        template = api("/inference-templates/model/" + model_id)
        deployment = api(
            "/deployments",
            {
                "model_id": local["id"],
                "template_id": template["id"],
                "template_spec_name": "metal",
                "template_spec_source": "user",
                "node_uuid": node_uuid,
                "served_name": alias,
            },
        )
        try:
            current = wait_until(
                lambda: live_deployment(api, deployment["id"]), timeout=180
            )

            def gpu_load():
                for log in (state / "host-state").glob("*.log"):
                    contents = log.read_text(errors="replace")
                    layers = re.findall(
                        r"offloaded (\d+)/(\d+) layers to GPU", contents
                    )
                    devices = re.findall(r"using device MTL0 \(([^)]+)\)", contents)
                    if layers and devices and "ggml_metal" in contents:
                        return devices[-1], *map(int, layers[-1])
                return None

            device, loaded, total = wait_until(gpu_load, timeout=15)
            assert loaded == total and loaded > 0, (loaded, total)
            with model.open("rb") as weights:
                model_sha256 = hashlib.file_digest(weights, "sha256").hexdigest()
            metadata = {
                "kind": "llama.cpp on a native kstack Apple Metal agent",
                "image": image,
                "model_filename": model.name,
                "model_sha256": model_sha256,
                "gpu_device": device,
                "gpu_offloaded_layers": loaded,
            }
            yield (
                [(alias, {"id": current["id"], "version": current["maas_revision"]})],
                metadata,
            )
        finally:
            api(f"/deployments/{deployment['id']}/stop", method="POST")

            def stopped():
                with socket.socket() as listener:
                    listener.settimeout(0.1)
                    return listener.connect_ex(("127.0.0.1", engine_port)) != 0

            wait_until(stopped, timeout=15)
