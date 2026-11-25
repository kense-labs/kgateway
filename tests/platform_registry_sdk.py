"""Exercise registry-generated routing and native HTTP SDKs in the paired test."""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from openapi_spec_validator import validate

ROOT = Path(__file__).resolve().parents[1]

RUST_PROBE = r"""
#[allow(dead_code)]
mod sdk { include!("client.rs"); }

#[tokio::main]
async fn main() -> sdk::Result<()> {
    let base = std::env::var("SDK_BASE")?;
    let token = std::env::var("SDK_TOKEN")?;
    let file = std::env::var("SDK_FILE_ID")?;
    assert_eq!(std::env::var("SDK_DIGEST")?, sdk::API_CONTRACT_SHA256);
    assert!(sdk::Client::new("http://example.test", &token).is_err());
    let client = sdk::Client::new(&base, &token)?;
    assert!(client.request_maas_files_get("file-../invalid").is_err());
    let models: serde_json::Value = client.request_maas_models_list()?.send().await?
        .error_for_status()?.json().await?;
    assert_eq!(models["object"], "list");
    let stored: serde_json::Value = client.request_maas_files_get(&file)?.send().await?
        .error_for_status()?.json().await?;
    assert_eq!(stored["id"], file);
    // @CHAT@
    Ok(())
}
"""

RUST_CHAT = r"""
    let stream = client.request_maas_chat_create()?
        .header("Content-Type", "application/json")
        .body(std::env::var("SDK_CHAT")?)
        .send().await?.error_for_status()?;
    assert!(stream.headers()["content-type"].to_str()?.starts_with("text/event-stream"));
    assert!(stream.text().await?.contains("data: [DONE]"));
"""

GO_PROBE = r"""
package main

import (
    "context"
    "encoding/json"
    "io"
    "log"
    "net/http"
    "os"
    // @CHAT_IMPORT@
    "time"

    "example.test/registry-probe/kgateway"
)

func main() {
    ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
    defer cancel()
    token, file := os.Getenv("SDK_TOKEN"), os.Getenv("SDK_FILE_ID")
    if kgateway.APIContractSHA256 != os.Getenv("SDK_DIGEST") { log.Fatal("contract digest differs") }
    if _, err := kgateway.NewClient("http://example.test", token, nil); err == nil { log.Fatal("accepted insecure origin") }
    client, err := kgateway.NewClient(os.Getenv("SDK_BASE"), token, nil)
    if err != nil { log.Fatal(err) }
    if _, err := client.RequestMaasFilesGet(ctx, "file-../invalid", nil); err == nil { log.Fatal("accepted invalid file ID") }
    body := func(request *http.Request, err error) []byte {
        if err != nil { log.Fatal(err) }
        response, err := client.Do(request)
        if err != nil { log.Fatal(err) }
        defer response.Body.Close()
        if response.StatusCode != http.StatusOK { log.Fatal(request.URL.Path, ": ", response.StatusCode) }
        data, err := io.ReadAll(io.LimitReader(response.Body, 1 << 20))
        if err != nil { log.Fatal(err) }
        return data
    }
    models := map[string]any{}
    err = json.Unmarshal(body(client.RequestMaasModelsList(ctx, nil)), &models)
    if err != nil || models["object"] != "list" { log.Fatal("invalid model list") }
    stored := map[string]any{}
    err = json.Unmarshal(body(client.RequestMaasFilesGet(ctx, file, nil)), &stored)
    if err != nil || stored["id"] != file { log.Fatal("invalid file detail") }
    // @CHAT@
    log.Print("Generated Go client passed.")
}
"""

GO_CHAT = r"""
    request, err := client.RequestMaasChatCreate(ctx, strings.NewReader(os.Getenv("SDK_CHAT")))
    if err != nil { log.Fatal(err) }
    request.Header.Set("Content-Type", "application/json")
    response := body(request, nil)
    if !strings.Contains(string(response), "data: [DONE]") { log.Fatal("missing streaming completion") }
"""


def registered_routes(routes, services):
    registrations = {}
    for name, route in routes.items():
        kind = route["resource"]["kind"]
        protocol = {
            "fixed": "rest",
            "model": "openai",
            "model-list": "openai",
            "maas-asset": "openai",
            "mcp-session": "mcp",
        }.get(kind)
        if kind == "rpc":
            protocol = route["resource"]["policy"]["protocol"]
        units = ["requests", "egress_bytes"]
        if route["operation"] in {
            "maas.chat.create",
            "maas.completions.create",
            "maas.embeddings.create",
            "maas.batches.create",
        }:
            units.extend(("prompt_tokens", "completion_tokens"))
        contract = {
            "protocol": protocol,
            "metering_units": units,
            "quota_dimensions": ["tenant", "project", "env"],
            "slo": {"availability": 0.999, "p99_ms": 1000},
        }
        if protocol == "mcp" and route["method"] == "DELETE":
            contract["responses"] = {"204": {"description": "MCP session ended"}}
        elif protocol == "mcp" and route["method"] == "GET":
            contract["responses"] = {
                "200": {
                    "description": "MCP event stream",
                    "content": {"text/event-stream": {"schema": {"type": "string"}}},
                }
            }
        elif route["operation"] == "maas.chat.create" or protocol == "mcp":
            contract["responses"] = {
                "200": {
                    "description": "JSON or an event stream",
                    "content": {
                        "application/json": {"schema": {}},
                        "text/event-stream": {"schema": {"type": "string"}},
                    },
                }
            }
        registrations[name] = route | {
            "routing": {"service": services.get(name, "maas"), "entrypoints": ["edge"]},
            "contract": contract,
        }
    return registrations


def generate_artifacts(config, directory):
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "control-plane/registry.py"),
            "--config",
            str(config),
            "--output",
            str(directory),
        ],
        check=True,
    )
    manifest = json.loads((directory / "manifest.json").read_text())
    for name, expected in manifest["sha256"].items():
        assert hashlib.sha256((directory / name).read_bytes()).hexdigest() == expected
    spec = json.loads((directory / "openapi.json").read_text())
    validate(spec)
    return spec


def build_probes(directory, with_chat):
    artifacts = subprocess.check_output(
        ["cargo", "build", "--locked", "--bin", "kgateway", "--message-format=json"],
        cwd=ROOT,
        text=True,
    )
    dependencies = {}
    for line in artifacts.splitlines():
        message = json.loads(line)
        if message["reason"] == "compiler-artifact" and message["target"]["name"] in {
            "reqwest",
            "tokio",
            "serde_json",
        }:
            name = message["target"]["name"]
            dependencies[name] = next(
                Path(file) for file in message["filenames"] if file.endswith(".rlib")
            )
    (directory / "probe.rs").write_text(
        RUST_PROBE.replace("// @CHAT@", RUST_CHAT if with_chat else "")
    )
    rust = [
        "rustc",
        "--edition=2021",
        "--crate-name",
        "registry_probe",
        str(directory / "probe.rs"),
        "-o",
        str(directory / "rust-probe"),
    ]
    for parent in sorted({path.parent for path in dependencies.values()}):
        rust.extend(("-L", f"dependency={parent}"))
    for name, path in dependencies.items():
        rust.extend(("--extern", f"{name}={path}"))
    subprocess.run(rust, check=True)

    package = directory / "kgateway"
    package.mkdir()
    (package / "client.go").write_bytes((directory / "client.go").read_bytes())
    go = directory / "cmd"
    go.mkdir()
    (go / "main.go").write_text(
        GO_PROBE.replace("// @CHAT_IMPORT@", '"strings"' if with_chat else "").replace(
            "// @CHAT@", GO_CHAT if with_chat else ""
        )
    )
    (directory / "go.mod").write_text("module example.test/registry-probe\n\ngo 1.20\n")
    subprocess.run(
        ["go", "build", "-o", str(directory / "go-probe"), "./cmd"],
        cwd=directory,
        check=True,
    )


def check_probes(directory, base, token, file_id, model):
    env = {
        **os.environ,
        "SDK_BASE": base,
        "SDK_TOKEN": token,
        "SDK_FILE_ID": file_id,
        "SDK_DIGEST": hashlib.sha256(
            (directory / "openapi.json").read_bytes()
        ).hexdigest(),
    }
    if model:
        env["SDK_CHAT"] = json.dumps(
            {
                "model": model,
                "stream": True,
                "messages": [{"role": "user", "content": "SDK"}],
            }
        )
    for language in ("rust", "go"):
        subprocess.run(
            [str(directory / f"{language}-probe")], env=env, check=True, timeout=30
        )
    print("Registry-generated Rust and Go SDKs called the live kgateway routes.")
