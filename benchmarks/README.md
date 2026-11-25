# Performance

The repository publishes complementary performance datasets.

- Criterion measurements for route matching, middleware execution, and ACL
  parsing without socket or upstream work.
- A same-host kgateway and NGINX matrix covering every traffic type
  implemented by the Gateway data plane.
- A paired MaaS baseline comparing kgateway with the private kstack listener.

## Criterion

Criterion covers:

- route matching with 10, 100, and 1,000 configured routes;
- request processing through 0, 3, 5, and 10 middleware entries;
- parsing complete ACL configurations with 3, 30, and 300 services.

Each benchmark uses 100 samples, a two-second warm-up, and a five-second
measurement window. Exported JSON includes the median, 95% confidence interval,
commit, CPU, memory, kernel, and Rust compiler. These measurements exclude
sockets, TLS, upstream work, response bodies, and clients.

## Capacity / soak harness

Core data-plane soak (HTTP JSON + finite SSE) is owned by
`scripts/soak-gateway.py` with the contract in
`release.json`. Smoke results write
`benchmarks/soak/results/smoke-*.json` with
`envelope_status: "smoke-only"`. Same-host comparison matrices below are
regression evidence; they are not capacity envelopes.

## Paired MaaS baseline

Run the load against a single kstack deployment served by the `fleet-host` test engine. The two paths use the same JSON bodies and the same warm engine. The direct path uses the private mTLS listener with preissued service tokens and usage starts. The public path enters kgateway over TLS with a Kense Key, durable quota and metering, and the independent audit witness enabled. Both paths deliver their MaaS token usage to the control plane.

```sh
uv run tests/kstack_maas_transport.py \
  --kgateway target/debug/kgateway \
  --kstack /path/to/kstack \
  --fleet-host /path/to/fleet-host \
  --performance-output /tmp/paired-maas-performance.json
```

The default workload runs two rounds of 64 measured requests per protocol and path, with eight TLS workers and one warmup per worker per trial. It alternates path order and measures the first SSE content delta and the `[DONE]` event. The report records per-request samples, throughput, P99, error and stream interruption rates, host load, and exact SHA-256 hashes of the artifacts. The paired workflow archives the report with the tested revisions. The local ARM64 sample uses debug kgateway and records a shared host under concurrent compilation. Production capacity validation uses the target deployment and real model hardware. [Local result](soak/results/paired-maas-arm64-local.json) · [Paired workload](../tests/paired_maas_performance.py) · [Paired workflow](../.github/workflows/paired-maas.yml)

### Apple Silicon with actual model weights

Build the native agent and run the same comparison against a model deployed by kstack's `host` runtime. Store the downloaded GGUF in its own directory and pass the file path. The test checks that llama.cpp placed all model layers on Metal, records the weight hash and image reference, and waits for the control plane to receive positive prompt and completion token totals for both paths. The kstack legacy `/v1` listener is closed during the run. [Qwen2.5 GGUF weights](https://huggingface.co/bartowski/Qwen2.5-0.5B-Instruct-GGUF/blob/21ef23001f314d0895bd8439b08157c2d4cd9bb7/Qwen2.5-0.5B-Instruct-Q4_K_M.gguf)

The Apple M5 run completed all 128 measured requests with zero stream interruptions at two workers. The report includes the device, the 25 offloaded layers, and per-request samples. [Apple Metal result](soak/results/paired-maas-apple-metal-local.json)

```sh
(cd ../kstack && go build -o ../kgateway/target/debug/kstack-agent ./cmd/gpuworks-agent)
uv run tests/kstack_maas_transport.py \
  --kgateway target/debug/kgateway \
  --kstack /path/to/kstack \
  --metal-agent target/debug/kstack-agent \
  --metal-model /path/to/weights/Qwen2.5-0.5B-Instruct-Q4_K_M.gguf \
  --metal-image registry-1.docker.io/gpuworks/gpuworks-runner@sha256:0d045bdc834340ec2b2f127d8e4e9b3496d8629f205f46fedce7341cffeea332 \
  --performance-requests 16 --performance-concurrency 2 \
  --performance-output /tmp/paired-maas-metal.json
```

## Same-host protocol matrix

The matrix runs kgateway and NGINX on one Ubuntu 24.04 GitHub-hosted runner.
Both products use the same certificate and the same local upstream for each
profile. Observability and access logs are disabled. Product order alternates
on every trial to reduce fixed order bias.

| Profile | Workload | Concurrency | Reported operation |
| --- | --- | ---: | --- |
| HTTP/1.1 | GET, keep-alive, 42-byte JSON | 64 connections | completed request |
| HTTPS · HTTP/1.1 | GET, downstream TLS termination | 64 connections | completed request |
| HTTPS · HTTP/2 | GET over multiplexed TLS | 4 × 16 streams | completed request |
| gRPC unary | Empty message, HTTP/2 TLS to proxy, h2c upstream | 4 × 16 streams | completed RPC |
| SSE | Finite three-event HTTP/1.1 response | 64 connections | completed stream |
| WebSocket | Persistent 32-byte binary echo | 64 connections | echoed message |
| TCP | Persistent 32-byte echo | 64 connections | round trip |
| UDP | 32-byte datagram echo | 64 connected sockets | round trip |
| OpenAI JSON | Chat Completions body validation and forwarding | 64 connections | completed request |
| OpenAI stream | Bounded JSON validation and finite SSE relay | 64 connections | completed stream |

Each row uses three 10-second measured trials after a two-second warm-up. The
exporter records every trial and reports the median of requests, streams,
messages, or round trips per second plus average, P50, P90, and P99 end-to-end
latency. Values within three percent are marked within threshold; other
positions state which measured throughput is higher or which latency is lower.

At the duration boundary, the HTTP generator stops creating work and drains
in-flight HTTP/1.1 requests. HTTP/2 and gRPC retain four client connections for
the trial. The short-lived NGINX fixture raises `keepalive_requests` from its
default of 1,000 to 1,000,000 so connection rotation does not interrupt active
multiplexed streams. This changes connection lifetime for the fixture; it does
not disable response or transport error accounting.

HTTP-family traffic uses the checksum-pinned `oha` 1.15.0 release. The
repository-owned `protocol_benchmark_load` example measures WebSocket, TCP,
and UDP so these protocols are not represented as HTTP requests.

### Capability alignment

HTTP, HTTPS, HTTP/2, gRPC, SSE, WebSocket, TCP, and UDP use comparable
forwarding capabilities in both products. The two OpenAI profiles deliberately
measure a different question: kgateway recognizes and validates the OpenAI
request shape before using its bounded response relay, while NGINX performs
transport-only forwarding. Those rows quantify the cost of enabled kgateway
features and are not an equivalent policy-capability comparison.

The result remains a synthetic same-host measurement on shared infrastructure.
It is useful for within-run product ratios and regressions on comparable runner
hardware, not as a universal ranking or a production capacity forecast.

## Reproduce

Run the in-process baselines:

```bash
cargo bench --locked --bench routing
cargo bench --locked --bench middleware_pipeline
cargo bench --locked --bench acl_parse
```

On Ubuntu, install NGINX with its stream module, OpenSSL, and `oha` 1.15.0,
then build the shipped release profile and benchmark fixtures:

```bash
cargo build --locked --release \
  --bin kgateway \
  --example protocol_benchmark_upstream \
  --example protocol_benchmark_load
bash scripts/run-proxy-comparison.sh
```

Environment variables can adjust the local run:

| Variable | Default |
| --- | ---: |
| `PROXY_BENCH_TRIALS` | `3` |
| `PROXY_BENCH_DURATION_SECONDS` | `10` |
| `PROXY_BENCH_WARMUP_SECONDS` | `2` |
| `PROXY_BENCH_CONNECTIONS` | `64` |
| `PROXY_BENCH_HTTP2_CONNECTIONS` | `4` |
| `PROXY_BENCH_HTTP2_PARALLEL` | `16` |

The machine-readable output is
`website/assets/performance-comparison.json`.
