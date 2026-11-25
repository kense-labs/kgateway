"""Replace a stopped control plane with its witnessed state on fresh storage."""

import base64
import json
import shutil
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path
from time import monotonic
from uuid import uuid4

from platform_audit_witness_e2e import READER_ENV

ROOT = Path(__file__).resolve().parents[1] / "control-plane"
WITNESS_CHECKPOINTS = "/v1/recovery/checkpoints"
WITNESS_CLAIM = "/v1/recovery/claim"
TABLES = (
    "credentials",
    "revocations",
    "revocation_delivery",
    "leases",
    "scoped_leases",
    "budget_windows",
    "scoped_budget_windows",
    "usage_events",
    "usage_positions",
    "usage_receipts",
    "maas_usage_events",
    "maas_batches",
    "maas_releases",
    "maas_release_tenants",
    "tenant_audit",
    "audit_witness_receipts",
)


def facts(path):
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
        return {table: set(db.execute("SELECT * FROM " + table)) for table in TABLES}


def pending_models(replicas):
    selected = {}
    for replica in replicas:
        for segment in (replica["test_state"] / "usage").glob("epoch-*.jsonl"):
            data = segment.read_bytes()
            lines = data.splitlines()[1:]
            if data and not data.endswith(b"\n"):
                lines = lines[:-1]
            for line in lines:
                payload = base64.b64decode(json.loads(line)["payload_base64"])
                event = json.loads(payload)
                if event["operation"] == "maas.models.list":
                    selected[event["event_id"]] = event
    return selected


def budget_spend(replicas):
    return {
        replica["id"]: json.loads((replica["test_state"] / "budget.json").read_text())[
            "spent"
        ]
        for replica in replicas
    }


def copy_policy(source, target):
    target.mkdir(mode=0o700)
    config = json.loads(source.read_text())
    for replica in config["replicas"]:
        relative = Path(replica["snapshot_acl"])
        assert not relative.is_absolute()
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source.parent / relative, destination)
    copied = target / source.name
    copied.write_text(json.dumps(config))
    return copied, target / config["state_db"]


def replace_control_plane(
    *,
    scratch,
    source_config,
    source_db,
    controller,
    witness,
    env,
    replicas,
    standalone_models,
    check_sensitive_offline,
    start,
    wait_until,
    ready,
):
    backup_site = scratch / "checkpoint-storage"
    backup_site.mkdir(mode=0o700)
    restore_keys = scratch / "restore-credentials"
    restore_keys.mkdir(mode=0o700)
    identity, wrong_identity = (
        restore_keys / name for name in ("recipient.agekey", "wrong.agekey")
    )
    for key in (identity, wrong_identity):
        subprocess.run(
            ["age-keygen", "-o", str(key)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    recipients = restore_keys / "recipients.txt"
    recipients.write_bytes(subprocess.check_output(["age-keygen", "-y", str(identity)]))
    archive = backup_site / "control-plane.age"
    reader_env = {**env, READER_ENV: witness.reader}

    def run(command, config, *arguments, success=True, reader=False):
        run = subprocess.run(
            [
                sys.executable,
                str(ROOT / "recovery.py"),
                command,
                "--config",
                str(config),
                *map(str, arguments),
            ],
            check=False,
            capture_output=True,
            timeout=25,
            text=True,
            env=reader_env if reader else env,
        )
        if success:
            assert run.returncode == 0, run.stderr
            return json.loads(run.stdout)
        assert run.returncode != 0, "unsafe recovery command succeeded"
        return run.stderr

    def checkpoint(*, success=True):
        return run(
            "handoff",
            source_config,
            "--archive",
            archive,
            "--recipients",
            recipients,
            success=success,
        )

    def restore(config, *values, sealed=archive, key=identity, success=True):
        return run(
            "restore",
            config,
            "--archive",
            sealed,
            "--identity",
            key,
            "--witness-reader-env",
            READER_ENV,
            *values,
            success=success,
            reader=True,
        )

    assert "active writer" in checkpoint(success=False)
    assert not archive.exists()
    target_config, target_db = copy_policy(
        source_config, scratch / "replacement-control"
    )
    retry_config, retry_db = copy_policy(source_config, scratch / "rejected-recovery")
    start_time = monotonic()
    controller.terminate()
    assert controller.wait(timeout=20) == 0
    captured = facts(source_db)
    assert len(captured["revocations"]) == 1 and len(captured["maas_releases"]) == 5
    assert captured["maas_usage_events"] and captured["audit_witness_receipts"]
    receipt = checkpoint()
    assert archive.read_bytes().startswith(b"age-encryption.org/v1\n")
    assert checkpoint() == receipt  # Retry after a lost witness acknowledgement.
    failed_source = subprocess.run(
        [sys.executable, str(ROOT / "main.py"), "--config", str(source_config)],
        check=False,
        capture_output=True,
        timeout=6,
        env=env,
    )
    assert failed_source.returncode != 0 and b"state was fenced" in failed_source.stderr
    lost_site = scratch / "unavailable-primary"
    lost_site.mkdir(mode=0o700)
    source_db.replace(lost_site / source_db.name)
    assert not source_db.exists()

    altered = backup_site / "incorrect.age"
    altered.write_bytes(archive.read_bytes() + b"changed")
    assert "latest witnessed checkpoint" in restore(
        retry_config, sealed=altered, success=False
    )
    assert not retry_db.exists()
    assert "no identity matched" in restore(
        retry_config, key=wrong_identity, success=False
    )
    assert not retry_db.exists()
    config = json.loads(retry_config.read_text())
    config["budgets"][0]["requests"] += 1
    retry_config.write_text(json.dumps(config))
    assert "incompatible" in restore(retry_config, success=False)
    assert not retry_db.exists()
    config["budgets"][0]["requests"] -= 1
    retry_config.write_text(json.dumps(config))

    old_pending = pending_models(replicas)
    standalone_models()
    check_sensitive_offline()

    def offline_events():
        entries = {
            key: value
            for key, value in pending_models(replicas).items()
            if key not in old_pending
        }
        return entries if len(entries) == 2 * len(replicas) else None

    events = wait_until(offline_events)
    spent = budget_spend(replicas)
    # The destination persisted its request before the witness reply was lost.
    pending = Path(str(target_db) + ".restore")
    claim = {
        "schema": "kgateway.control-checkpoint-claim.v1",
        "archive_sha256": receipt["archive_sha256"],
        "destination": uuid4().hex,
    }
    pending.write_text(json.dumps(claim))
    pending.chmod(0o600)
    for bearer, expected in ((witness.reader, 401), (witness.writer, 200)):
        status, body = witness.call(
            WITNESS_CLAIM,
            bearer,
            data=json.dumps(claim).encode(),
            headers={"Content-Type": "application/json"},
        )
        assert status == expected, (status, body)
    blocked_target = subprocess.run(
        [sys.executable, str(ROOT / "main.py"), "--config", str(target_config)],
        check=False,
        capture_output=True,
        timeout=6,
        env=env,
    )
    assert (
        blocked_target.returncode != 0
        and b"incomplete recovery" in blocked_target.stderr
    )
    assert not target_db.exists()
    assert restore(target_config) == receipt
    assert not pending.exists()
    assert "independent witness rejected" in restore(retry_config, success=False)
    assert not retry_db.exists() and not Path(str(retry_db) + ".restore").exists()
    assert facts(target_db) == captured

    child = start(target_config)
    wait_until(ready)
    assert budget_spend(replicas) == spent

    def reconciled():
        with closing(sqlite3.connect(target_db)) as db:
            stored = {
                event_id: json.loads(payload)
                for event_id, payload in db.execute(
                    "SELECT id, payload FROM usage_events"
                )
            }
        return all(stored.get(event_id) == event for event_id, event in events.items())

    wait_until(reconciled)

    def witness_advanced():
        challenge = uuid4().hex
        status, raw = witness.call(
            WITNESS_CHECKPOINTS + "?challenge=" + challenge, witness.reader
        )
        assert status == 200, (status, raw)
        seen = json.loads(raw)
        assert seen["checkpoint"] == receipt
        return seen["audit_heads_sha256"] != receipt["audit_heads_sha256"]

    wait_until(witness_advanced)
    assert "stale" in restore(retry_config, success=False)
    assert not retry_db.exists()
    print(
        f"Witnessed control-plane handoff recovered on fresh storage in {monotonic() - start_time:.2f}s with {len(events)} queued usage records reconciled."
    )
    return child, target_db
