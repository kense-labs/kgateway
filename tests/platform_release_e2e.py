"""Check published release weights against the actual kstack deployments."""

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from time import time_ns
from urllib.request import ProxyHandler, Request, build_opener
from uuid import UUID

CHAT_PATH = "/v1/chat/completions"
JSON_HEADERS = {"Content-Type": "application/json"}
ROLLOUT_BATCH_LINES = 32
RELEASE_API = "/v1/releases/maas"
PILOT_TENANT = "tenant-test"
STABLE_TENANT = "tenant-stable"


def exercise_release_rollout(
    *,
    replicas,
    alias,
    stable,
    candidate,
    old_key,
    active_key,
    stable_key,
    publish,
    restart,
    revoke,
    monitor,
    fetch,
    wait_until,
    upload_batch_file,
):
    bases = [replica["test_base"] for replica in replicas]
    model_urn = "urn:plat:maas:model:" + alias

    def target(deployment, weight=1):
        return {"deployment": deployment, "weight": weight}

    def assert_catalogue(key=active_key, aliases=(alias,), supplied_tenant=None):
        for base in bases:
            headers = {"X-Kense-Tenant": supplied_tenant} if supplied_tenant else None
            status, raw = fetch(base + "/v1/models", key, headers=headers)
            assert status == 200, (status, raw)
            assert tuple(entry["id"] for entry in json.loads(raw)["data"]) == aliases

    def payload(stream=False):
        return json.dumps(
            {
                "model": alias,
                "messages": [{"role": "user", "content": "Rollout probe"}],
                "stream": stream,
            }
        ).encode()

    def chat(base, key=active_key, supplied_tenant=None):
        request_headers = dict(JSON_HEADERS)
        if supplied_tenant:
            request_headers["X-Kense-Tenant"] = supplied_tenant
        status, raw, headers = fetch(
            base + CHAT_PATH,
            key,
            data=payload(),
            headers=request_headers,
            include_headers=True,
        )
        assert status == 200 and json.loads(raw)["model"] == alias, (status, raw)
        return str(UUID(headers["X-Request-ID"]))

    def observed(expected):
        expected_ids = set(expected)

        def ready():
            result = {}
            for deployment in (stable, candidate):
                page = monitor(
                    f"/monitor/deployments/{deployment['id']}/requests?view=history&limit=256"
                )
                for record in page["requests"]:
                    if record["id"] in expected_ids:
                        result[record["id"]] = record
            if expected_ids <= result.keys():
                return result
            return None

        records = wait_until(ready, timeout=40)
        assert {
            key: record["deployment_id"] for key, record in records.items()
        } == expected
        return records

    def chat_spend(replica):
        ledger = json.loads((replica["test_state"] / "budget.json").read_text())
        return {
            identifier: item["requests"]
            for identifier, item in ledger["spent"].items()
            if item["lease"]["tenant"] == PILOT_TENANT
            and item["lease"]["operation"] == "maas.chat.create"
        }

    def create_batch(base, file_id, key=active_key):
        return fetch(
            base + "/v1/batches",
            key,
            headers=JSON_HEADERS,
            data=json.dumps(
                {
                    "input_file_id": file_id,
                    "endpoint": CHAT_PATH,
                    "completion_window": "24h",
                }
            ).encode(),
        )

    def batch_records(batch_id, key, target_id, count):
        def completed():
            status, raw = fetch(bases[0] + "/v1/batches/" + batch_id, key)
            assert status == 200, (status, raw)
            row = json.loads(raw)
            assert row["status"] not in {"failed", "expired", "cancelled"}, row
            return row if row["status"] == "completed" else None

        batch = wait_until(completed, timeout=50)
        status, raw = fetch(
            bases[0] + "/v1/files/" + batch["output_file_id"] + "/content", key
        )
        assert status == 200, (status, raw)
        lines = [json.loads(line)["response"] for line in raw.splitlines()]
        assert len(lines) == count and all(
            line["status_code"] == 200 and line["body"]["model"] == alias
            for line in lines
        ), lines
        records = observed({line["request_id"]: target_id for line in lines})
        assert len(records) == count
        return records

    assert_catalogue()
    assert_catalogue(stable_key)
    assert fetch(bases[0] + "/v1/models", old_key)[0] == 200
    stable_request = chat(bases[0])
    observed({stable_request: stable["id"]})
    with ThreadPoolExecutor(max_workers=1) as worker:
        during_publish = worker.submit(chat, bases[0])
        publish([target(stable, 3), target(candidate, 1)], "weighted")
        during_publish_id = during_publish.result()
    assert_catalogue()
    selected = {}
    for _ in range(4):
        with ThreadPoolExecutor(max_workers=8) as workers:
            for identifier in workers.map(chat, bases * 8):
                selected[identifier] = (
                    candidate["id"] if UUID(identifier).int % 4 == 3 else stable["id"]
                )
        if len(selected) >= 32 and len(set(selected.values())) == 2:
            break
    assert set(selected.values()) == {stable["id"], candidate["id"]}
    observed(selected)
    stable_requests = {chat(base, stable_key): stable["id"] for base in bases}
    observed(stable_requests)

    file_id, _ = upload_batch_file(
        bases[1], active_key, alias, ROLLOUT_BATCH_LINES, fetch
    )
    publish([target(candidate | {"version": "sha256:" + "0" * 64})], "stale")
    assert_catalogue(aliases=(), supplied_tenant=STABLE_TENANT)
    assert_catalogue(stable_key, supplied_tenant=PILOT_TENANT)
    status, raw = fetch(
        bases[0] + CHAT_PATH, active_key, data=payload(), headers=JSON_HEADERS
    )
    assert (
        status == 403 and json.loads(raw)["error"]["code"] == "MODEL_ACCESS_DENIED"
    ), (status, raw)
    status, raw = create_batch(bases[0], file_id)
    assert status == 400 and json.loads(raw)["error"]["code"] == "model_not_found", (
        status,
        raw,
    )
    publish([target(candidate)], "candidate")
    with ThreadPoolExecutor(max_workers=2 * len(bases)) as workers:
        calls = [
            (
                workers.submit(chat, base, active_key, STABLE_TENANT),
                workers.submit(chat, base, stable_key, PILOT_TENANT),
            )
            for base in bases
        ]
        candidate_requests = {pilot.result(): candidate["id"] for pilot, _ in calls}
        stable_requests.update({control.result(): stable["id"] for _, control in calls})
    observed(candidate_requests | stable_requests)
    stable_file, _ = upload_batch_file(bases[0], stable_key, alias, 2, fetch)
    status, raw = create_batch(bases[0], stable_file, stable_key)
    assert status == 200, (status, raw)
    stable_batch_id = json.loads(raw)["id"]
    revoke()

    opener = build_opener(ProxyHandler({}))
    request = Request(
        bases[1] + CHAT_PATH,
        headers=JSON_HEADERS
        | {
            "Authorization": "Bearer " + active_key,
            "Accept": "text/event-stream",
        },
        data=payload(stream=True),
    )
    with opener.open(request, timeout=40) as response:
        assert (
            response.status == 200
            and response.headers.get_content_type() == "text/event-stream"
        )
        stream_id = str(UUID(response.headers["X-Request-ID"]))
        prefix = response.readline()
        assert prefix.startswith(b"data: ")
        status, raw = create_batch(bases[1], file_id)
        assert status == 200, (status, raw)
        batch_id = json.loads(raw)["id"]
        spend = [chat_spend(replica) for replica in replicas]
        assert all(len(ledger) == 1 for ledger in spend)
        publish(None, "rollback")
        rollback_ms = time_ns() // 1_000_000
        live = monitor(f"/monitor/deployments/{candidate['id']}/requests?view=live")
        assert any(record["id"] == stream_id for record in live["requests"]), live
        for base in bases:
            assert fetch(base + "/v1/models", old_key)[0] == 401
        assert_catalogue()
        after = {chat(base): stable["id"] for base in bases}
        for replica, previous in zip(replicas, spend, strict=True):
            assert chat_spend(replica) == {
                key: amount + 1 for key, amount in previous.items()
            }
        remaining = prefix + response.read()
        assert b"data: [DONE]" in remaining
        names = [
            frame["model"]
            for line in remaining.splitlines()
            if line.startswith(b"data: ")
            and line != b"data: [DONE]"
            and "model" in (frame := json.loads(line.removeprefix(b"data: ")))
        ]
        assert names and set(names) == {alias}, names
    observed(after | {stream_id: candidate["id"]})

    batch_records(stable_batch_id, stable_key, stable["id"], 2)
    records = batch_records(batch_id, active_key, candidate["id"], ROLLOUT_BATCH_LINES)
    assert any(record["received_ms"] > rollback_ms for record in records.values()), (
        records
    )

    state_db = restart([target(candidate)])
    assert_catalogue()
    after_restart = {chat(base): stable["id"] for base in bases}
    observed(after_restart)
    ids = (
        set(selected)
        | set(after)
        | set(after_restart)
        | set(candidate_requests)
        | {
            stream_id,
            stable_request,
            during_publish_id,
        }
    )

    def settled():
        with sqlite3.connect(state_db) as db:
            measured = {
                request_id: data["tenant"]
                for request_id, raw in db.execute(
                    "SELECT request_id, payload FROM maas_usage_events"
                )
                if (data := json.loads(raw))["urn"] == model_urn
            }
            audited = {
                request_id: json.loads(request)["tenant"]
                for request_id, request in db.execute(
                    "SELECT id, request FROM audit_admissions"
                )
            }
        expected = {
            **dict.fromkeys(ids, PILOT_TENANT),
            **dict.fromkeys(stable_requests, STABLE_TENANT),
        }
        return all(
            measured.get(request_id) == audited.get(request_id) == tenant
            for request_id, tenant in expected.items()
        )

    wait_until(settled, timeout=40)
    print(
        "Paired MaaS rollout verified tenant-scoped discovery, inference, batches, metering and rollback on both replicas."
    )
