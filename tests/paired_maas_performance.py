"""Compare a live paired MaaS deployment with its private ingress under the same load."""

import hashlib
import http.client
import json
import math
import os
import platform
import ssl
import statistics
import tempfile
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import Barrier

CHAT_PATH = "/v1/chat/completions"
TENANT = "tenant-benchmark"
DIRECT_TENANT = "tenant-benchmark-direct"
ROUNDS = 2
MAX_RESPONSE_BYTES = 1 << 20


@dataclass(frozen=True)
class Workload:
    output: Path
    requests: int
    concurrency: int
    minimum_prompt_tokens: int = 0

    @property
    def allowance_per_replica(self):
        return 2 * ROUNDS * (self.requests + self.concurrency)


@dataclass(frozen=True)
class Ingress:
    port: int
    tls: ssl.SSLContext
    credentials: Callable[[int], list[str]]


@dataclass
class Observation:
    elapsed_ms: float
    status: int | None
    first_token_ms: float | None
    stream_opened: bool
    stream_interrupted: bool
    error: str | None


class EventStream:
    """Decode the benchmark's OpenAI content deltas and terminal event."""

    def __init__(self):
        self.first_token = None
        self.done = False

    def read(self, response):
        fields = []
        remaining = MAX_RESPONSE_BYTES
        while line := response.readline(remaining + 1):
            remaining -= len(line)
            if remaining < 0:
                raise ValueError("SSE response exceeds the benchmark limit")
            line = line.rstrip(b"\r\n")
            if line:
                name, _, value = line.partition(b":")
                if name == b"data":
                    fields.append(value.removeprefix(b" "))
                continue
            if not fields:
                continue
            payload = b"\n".join(fields)
            fields.clear()
            if self.done:
                raise ValueError("received data after SSE completion")
            if payload == b"[DONE]":
                self.done = True
                continue
            event = json.loads(payload)
            if not isinstance(event, dict) or "error" in event:
                raise ValueError("invalid OpenAI stream event")
            if self.first_token is None and any(
                choice.get("delta", {}).get("content")
                for choice in event.get("choices", [])
            ):
                self.first_token = time.perf_counter()


def request(connection, credential, payload, streaming):
    status = None
    stream = None
    error = None
    started = time.perf_counter()
    try:
        connection.request(
            "POST",
            CHAT_PATH,
            body=payload,
            headers={
                "Authorization": "Bearer " + credential,
                "Content-Type": "application/json",
                "Accept": "text/event-stream" if streaming else "application/json",
            },
        )
        with connection.getresponse() as response:
            status = response.status
            if status != 200:
                response.read(MAX_RESPONSE_BYTES)
                error = "http_status"
            elif streaming:
                if response.headers.get_content_type() != "text/event-stream":
                    raise ValueError("wrong SSE content type")
                stream = EventStream()
                stream.read(response)
                if not stream.done:
                    error = "stream_interrupted"
                elif stream.first_token is None:
                    error = "empty_completion"
            else:
                data = response.read(MAX_RESPONSE_BYTES + 1)
                if len(data) > MAX_RESPONSE_BYTES:
                    raise ValueError("JSON response exceeds the benchmark limit")
                completion = json.loads(data)
                if (
                    not isinstance(completion["choices"][0]["message"]["content"], str)
                    or not completion["choices"][0]["message"]["content"]
                ):
                    error = "empty_completion"
    except (OSError, http.client.HTTPException):
        error = "transport"
    except (ValueError, KeyError, AttributeError, TypeError, IndexError):
        error = "invalid_response"
    interrupted = stream is not None and not stream.done
    if error:
        connection.close()
    return Observation(
        elapsed_ms=(time.perf_counter() - started) * 1000,
        status=status,
        first_token_ms=(stream.first_token - started) * 1000
        if stream and stream.first_token
        else None,
        stream_opened=stream is not None,
        stream_interrupted=interrupted,
        error=error,
    )


def trial(ingress, payload, streaming, workload):
    started = []
    barrier = Barrier(
        workload.concurrency,
        action=lambda: started.append(time.perf_counter()),
        timeout=40,
    )
    # The direct arm signs unique mTLS service credentials before the measured phase.
    credentials = ingress.credentials(workload.requests + workload.concurrency)

    def worker(lane):
        connection = http.client.HTTPSConnection(
            "127.0.0.1", ingress.port, context=ingress.tls, timeout=15
        )
        try:
            warmup = request(connection, credentials[lane], payload, streaming)
            barrier.wait()
            observations = [
                request(connection, credential, payload, streaming)
                for credential in credentials[
                    workload.concurrency + lane :: workload.concurrency
                ]
            ]
            return warmup, observations, time.perf_counter()
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=workload.concurrency) as pool:
        lanes = list(pool.map(worker, range(workload.concurrency)))
    elapsed = max(lane[2] for lane in lanes) - started[0]
    return {
        "elapsed_seconds": elapsed,
        "warmup_attempts": len(lanes),
        "warmup_errors": sum(bool(warmup.error) for warmup, _, _ in lanes),
        "warmup_observations": [warmup for warmup, _, _ in lanes],
        "observations": [measurement for _, lane, _ in lanes for measurement in lane],
    }


def distribution(samples):
    ordered = sorted(samples)
    if not ordered:
        return None
    return {
        "count": len(ordered),
        "median": statistics.median(ordered),
        "p99": ordered[math.ceil(0.99 * len(ordered)) - 1],
    }


def summarize(trials):
    attempts = [
        observation for trial in trials for observation in trial["observations"]
    ]
    elapsed = sum(trial["elapsed_seconds"] for trial in trials)
    succeeded = sum(observation.error is None for observation in attempts)
    opened = sum(observation.stream_opened for observation in attempts)
    interrupted = sum(observation.stream_interrupted for observation in attempts)
    return {
        "attempts": len(attempts),
        "succeeded": succeeded,
        "failed": len(attempts) - succeeded,
        "warmup_errors": sum(trial["warmup_errors"] for trial in trials),
        "warmup_attempts": sum(trial["warmup_attempts"] for trial in trials),
        "error_rate": 1 - succeeded / len(attempts),
        "requests_per_second": len(attempts) / elapsed,
        "completed_per_second": succeeded / elapsed,
        "elapsed_seconds": elapsed,
        "stream_opened": opened,
        "stream_interrupted": interrupted,
        "stream_interruption_rate": interrupted / opened if opened else None,
        "end_to_end_ms": distribution(attempt.elapsed_ms for attempt in attempts),
        "successful_end_to_end_ms": distribution(
            attempt.elapsed_ms for attempt in attempts if not attempt.error
        ),
        "first_token_ms": distribution(
            attempt.first_token_ms
            for attempt in attempts
            if attempt.first_token_ms is not None
        ),
    }


def file_digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def measure(workload, model, ingresses, binaries, engine):
    records = []
    summary = {}
    prompt = "Return a short greeting."
    load_average = getattr(os, "getloadavg", lambda: None)
    initial_load = load_average()
    for mode in ("json", "sse"):
        streaming = mode == "sse"
        payload = json.dumps(
            {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": streaming,
            }
        ).encode()
        results = {name: [] for name in ingresses}
        for round_index in range(ROUNDS):
            order = list(ingresses) if round_index == 0 else list(reversed(ingresses))
            for name in order:
                measurements = trial(ingresses[name], payload, streaming, workload)
                results[name].append(measurements)
                records.append(
                    {
                        "mode": mode,
                        "round": round_index + 1,
                        "ingress": name,
                        **measurements,
                    }
                )
        summary[mode] = {name: summarize(trials) for name, trials in results.items()}

    control_plane = Path(__file__).resolve().parents[1] / "control-plane"
    report = {
        "schema": "kgateway.paired-maas-performance.v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "host": {
            "system": platform.system(),
            "machine": platform.machine(),
            "kernel": platform.release(),
            "logical_cpus": os.cpu_count(),
            "python": platform.python_version(),
            "load_average_start": initial_load,
            "load_average_end": load_average(),
        },
        "binary_sha256": {name: file_digest(path) for name, path in binaries.items()},
        "control_plane_sha256": {
            path.name: file_digest(path) for path in sorted(control_plane.glob("*.py"))
        },
        "engine": engine,
        "workload": {
            "model": model,
            "prompt": prompt,
            "path": CHAT_PATH,
            "requests_per_trial": workload.requests,
            "concurrency": workload.concurrency,
            "warmup_per_trial": workload.concurrency,
            "rounds_per_ingress": ROUNDS,
            "transport": "HTTP/1.1 over TLS, one reusable connection per worker",
            "kgateway": "Kense Key, durable quota and usage, sensitive admission with separate audit witness, then kstack mTLS",
            "kstack-direct": "private mTLS listener with preissued service credentials and matched usage starts",
            "percentile": "nearest-rank P99 over all measured requests; warmup excluded",
        },
        "results": summary,
        "trials": [
            trial
            | {
                "observations": [
                    asdict(measurement) for measurement in trial["observations"]
                ],
                "warmup_observations": [
                    asdict(measurement) for measurement in trial["warmup_observations"]
                ],
            }
            for trial in records
        ],
    }
    workload.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", dir=workload.output.parent, delete=False
    ) as scratch:
        temporary = Path(scratch.name)
        try:
            json.dump(report, scratch, indent=2, allow_nan=False)
            scratch.write("\n")
            scratch.close()
            temporary.replace(workload.output)
        finally:
            temporary.unlink(missing_ok=True)
    for mode, comparisons in summary.items():
        for name, stats in comparisons.items():
            print(
                f"{mode} {name}: {stats['succeeded']}/{stats['attempts']} completed, "
                f"{stats['completed_per_second']:.1f} req/s, P99 {stats['end_to_end_ms']['p99']:.1f} ms"
            )
    if any(
        stats["succeeded"] == 0 for arms in summary.values() for stats in arms.values()
    ):
        raise RuntimeError(
            f"An ingress produced no successful measurements. Recorded at {workload.output}"
        )
    return summary
