# kgateway

`kgateway` is the public traffic entry point for Kense OS. The Rust data plane supports HTTP, gRPC, WebSocket, SSE, TCP, and UDP. It validates and applies managed snapshots atomically. In standalone mode it serves routes from local ACL configuration.

## Install on Linux

Releases provide GNU libc and musl archives for Linux AMD64 and ARM64. The `kgateway` and `kgateway-control` OCI images support both architectures. [Linux installer](https://kense-labs.github.io/kgateway/install.sh) · [GitHub Releases](https://github.com/kense-labs/kgateway/releases)

## Build and run

```sh
cargo build --locked --bin kgateway
./target/debug/kgateway --version
./target/debug/kgateway validate --config gateway.acl
./target/debug/kgateway --config gateway.acl
```

A local ACL needs an entrypoint, a router, and a service. This example binds the gateway to loopback and forwards requests to a locally running upstream on port 9000.

```acl
entrypoints "web" { address = "127.0.0.1:8080" }
routers "local" {
  rule = "PathPrefix(`/`)"
  service = "local"
  entrypoints = ["web"]
}
services "local" {
  load_balancer {
    servers = [{ url = "http://127.0.0.1:9000" }]
  }
}
```

## Kense MaaS

`kgateway` validates Kense Keys against managed policy and issues a short-lived credential for the selected service. `kstack` runs models and selects a replica within the deployment named in that credential. It verifies the credential and the gateway's mTLS identity on its private listener.

The control plane creates and revokes Keys, publishes replica snapshots and allowances, and receives idempotent gateway and MaaS usage events. The paired deployment runs all three services independently. [Paired deployment](deploy/kstack/README.md) · [Implementation plan](IMPLEMENTATION_PLAN.md) · [Service-token contract](contracts/service-token-v1.schema.json)

## Testing

```sh
cargo fmt --all -- --check
cargo test --locked --lib --bins --tests
```

Build both services and the kstack test agent to exercise chat, text completions, embeddings, Files and Batches with a local test engine, two gateway replicas, and a control-plane process. The same suite verifies MCP 2025-11-25 and A2A JSON-RPC through the pinned Python SDKs.

```sh
(cd ../kstack && go build -o ../kgateway/target/debug/kstack ./cmd/gpuworks)
(cd ../kstack && go build -o ../kgateway/target/debug/fleet-host ./test/l2/cmd/fleet-host)
uv run tests/kstack_maas_transport.py \
  --kgateway target/debug/kgateway \
  --kstack target/debug/kstack \
  --fleet-host target/debug/fleet-host
```

The paired suite covers legacy key cutover and shutdown of the old `/v1` entry. A native Apple Silicon run also verifies inference and token settlement with actual weights. [Client migration](deploy/kstack/README.md#migrate-existing-kstack-clients) · [Real model test](benchmarks/README.md#apple-silicon-with-actual-model-weights)

See [LICENSE](LICENSE) for the MIT license.
