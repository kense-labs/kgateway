"""Fence a control-plane writer and hand off an encrypted, witnessed checkpoint."""

import argparse
import base64
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
from contextlib import closing
from pathlib import Path
from threading import Event
from urllib.error import HTTPError, URLError
from urllib.request import Request
from uuid import uuid4

from audit_anchor import AnchorClient, AnchorUnavailable, canonical
from cryptography.exceptions import InvalidSignature
from recovery_protocol import (
    CHECKPOINT,
    CHECKPOINT_PATH,
    CLAIM,
    CLAIM_PATH,
    STATUS,
    heads_digest,
    validate_checkpoint,
    validate_claim,
)
from state import State, fenced_file, primary_lock, restore_file


class WitnessConflict(ValueError):
    pass


def file_digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def policy_digest(config, directory):
    replicas = {
        entry["id"]: {
            "signer": entry["signer"],
            "acl_sha256": file_digest(directory / entry["snapshot_acl"]),
        }
        for entry in config["replicas"]
    }
    policy = {
        "routes": config["routes"],
        "budgets": config["budgets"],
        "window": config.get("budget_window_seconds", 3600),
        "replicas": replicas,
    }
    return hashlib.sha256(canonical(policy)).hexdigest()


def state_heads(db):
    return heads_digest(
        db.execute(
            "SELECT tenant, MAX(sequence), digest FROM tenant_audit GROUP BY tenant ORDER BY tenant"
        )
    )


def readonly(path):
    return sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)


def checkpoint_heads(path):
    with closing(readonly(path)) as db:
        if db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
            raise ValueError("checkpoint SQLite integrity check failed")
        return state_heads(db)


def sync_heads(state, witness):
    while True:
        with state.connect() as db:
            if (
                db.execute(
                    "SELECT 1 FROM tenant_audit_heads WHERE sequence > witnessed LIMIT 1"
                ).fetchone()
                is None
            ):
                return
        witness.sync_heads(state, Event())


def witness_request(witness, *, draft=None, challenge=None, path=CHECKPOINT_PATH):
    url = witness.endpoint.removesuffix("/v1/anchors") + path
    if challenge is not None:
        url += "?challenge=" + challenge
    req = Request(
        url,
        data=canonical(draft) if draft is not None else None,
        headers={
            "Authorization": "Bearer " + witness.token,
            "Content-Type": "application/json",
        },
    )
    try:
        with witness.client.open(req, timeout=5) as response:
            reply = response.read(8193)
            if response.status != 200 or len(reply) > 8192:
                raise ValueError("invalid recovery witness response")
        signed = json.loads(reply)
        signature = base64.b64decode(signed.pop("signature"), validate=True)
        witness.public_key.verify(signature, canonical(signed))
        return signed
    except HTTPError as error:
        if error.code == 409:
            raise WitnessConflict(
                "independent witness rejected the checkpoint or destination"
            ) from error
        raise ValueError(
            f"independent witness returned HTTP {error.code} for recovery"
        ) from error
    except (URLError, InvalidSignature, KeyError, TypeError) as error:
        raise ValueError(
            "independent witness did not verify the recovery checkpoint"
        ) from error


def durable_publish(source, target):
    # The staging file lives on the same filesystem; link refuses replacement.
    with source.open("rb") as stream:
        os.fsync(stream.fileno())
    os.link(source, target)
    sync_directory(target.parent)


def sync_directory(path):
    parent = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def write_marker(path, draft):
    with tempfile.TemporaryDirectory(dir=path.parent) as directory:
        candidate = Path(directory) / "fence"
        candidate.write_bytes(canonical(draft))
        candidate.chmod(0o600)
        durable_publish(candidate, path)


def age_to_file(executable, options, source, destination):
    with open(
        destination, "xb", opener=lambda path, flags: os.open(path, flags, 0o600)
    ) as result:
        subprocess.run(
            [executable, *options, str(source)],
            stdout=result,
            stdin=subprocess.DEVNULL,
            check=True,
        )


def handoff(config_file, archive, recipients, age):
    config_file = config_file.resolve(strict=True)
    config = json.loads(config_file.read_bytes())
    directory = config_file.parent
    witness_spec = config["audit_witness"]
    witness = AnchorClient(
        witness_spec, directory, os.environ[witness_spec["token_env"]]
    )
    with primary_lock(directory / config["state_db"]) as source:
        marker = fenced_file(source)
        if restore_file(source).exists():
            raise ValueError("handoff requires a completed recovery on the source")
        policy_sha = policy_digest(config, directory)
        if marker.exists():
            draft = json.loads(marker.read_bytes())
            validate_checkpoint(draft)
            if (
                file_digest(archive) != draft["archive_sha256"]
                or policy_sha != draft["policy_sha256"]
            ):
                raise ValueError(
                    "fenced source requires its original checkpoint archive and policy"
                )
        else:
            if not source.is_file():
                raise ValueError("control-plane source database does not exist")
            state = State(source, config.get("budget_window_seconds", 3600))
            sync_heads(state, witness)
            with (
                tempfile.TemporaryDirectory(dir=source.parent) as database_tmp,
                tempfile.TemporaryDirectory(dir=archive.parent) as archive_tmp,
            ):
                snapshot = Path(database_tmp) / "checkpoint.sqlite"
                with (
                    closing(readonly(source)) as live,
                    closing(sqlite3.connect(snapshot)) as backup,
                ):
                    live.backup(backup)
                    backup.execute("PRAGMA journal_mode = DELETE")
                snapshot.chmod(0o600)
                head_sha = checkpoint_heads(snapshot)
                sealed = Path(archive_tmp) / "checkpoint.age"
                age_to_file(age, ["-R", str(recipients)], snapshot, sealed)
                draft = {
                    "schema": CHECKPOINT,
                    "archive_sha256": file_digest(sealed),
                    "policy_sha256": policy_sha,
                    "audit_heads_sha256": head_sha,
                }
                durable_publish(sealed, archive)
                # Prevent restarting this writer even if the witness response is lost.
                write_marker(marker, draft)
        receipt = witness_request(witness, draft=draft)
        if any(receipt.get(key) != value for key, value in draft.items()):
            raise ValueError("independent witness confirmed a different checkpoint")
        return receipt


def recover(config_file, archive, identity, witness_reader_env, age):
    config_file = config_file.resolve(strict=True)
    config = json.loads(config_file.read_bytes())
    directory = config_file.parent
    witness = AnchorClient(
        config["audit_witness"], directory, os.environ[witness_reader_env]
    )
    with primary_lock(directory / config["state_db"]) as output:
        marker = restore_file(output)
        if (output.exists() and not marker.exists()) or any(
            path.exists()
            for path in [
                fenced_file(output),
                Path(str(output) + "-wal"),
                Path(str(output) + "-shm"),
            ]
        ):
            raise ValueError("restore requires a fresh control-plane state path")
        challenge = uuid4().hex
        status = witness_request(witness, challenge=challenge)
        checkpoint = status["checkpoint"]
        if (
            status["schema"] != STATUS
            or status["challenge"] != challenge
            or checkpoint["audit_heads_sha256"] != status["audit_heads_sha256"]
            or checkpoint["policy_sha256"] != policy_digest(config, directory)
        ):
            raise ValueError(
                "checkpoint is stale or incompatible with the recovery policy"
            )
        with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
            temporary = Path(temporary)
            # Verify the very same inode that age decrypts even if storage is being updated.
            sealed = temporary / "checkpoint.age"
            with archive.open("rb") as incoming, sealed.open("xb") as staging:
                shutil.copyfileobj(incoming, staging)
            if file_digest(sealed) != checkpoint["archive_sha256"]:
                raise ValueError(
                    "archive does not match the latest witnessed checkpoint"
                )
            recovered = temporary / "checkpoint.sqlite"
            age_to_file(age, ["-d", "-i", str(identity)], sealed, recovered)
            if checkpoint_heads(recovered) != checkpoint["audit_heads_sha256"]:
                raise ValueError(
                    "recovered database does not match the witnessed audit heads"
                )
            if output.exists() and file_digest(output) != file_digest(recovered):
                raise ValueError(
                    "incomplete recovery database differs from the checkpoint"
                )
            claim_destination(config, directory, marker, checkpoint, output.exists())
            if not output.exists():
                durable_publish(recovered, output)
            marker.unlink()
            sync_directory(marker.parent)
        return checkpoint


def claim_destination(config, directory, marker, checkpoint, linked):
    archive_sha = checkpoint["archive_sha256"]
    if marker.exists():
        claim = json.loads(marker.read_bytes())
        validate_claim(claim)
        if claim["archive_sha256"] != archive_sha:
            raise ValueError("incomplete recovery belongs to another checkpoint")
    else:
        claim = {
            "schema": CLAIM,
            "archive_sha256": archive_sha,
            "destination": uuid4().hex,
        }
        write_marker(marker, claim)
    spec = config["audit_witness"]
    witness = AnchorClient(spec, directory, os.environ[spec["token_env"]])
    try:
        receipt = witness_request(witness, draft=claim, path=CLAIM_PATH)
    except WitnessConflict:
        if not linked:
            marker.unlink()
            sync_directory(marker.parent)
        raise
    if receipt.get("revision") != checkpoint["revision"] or any(
        receipt.get(key) != value for key, value in claim.items()
    ):
        raise ValueError(
            "independent witness confirmed a different recovery destination"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--age", default="age")
    commands = parser.add_subparsers(dest="command", required=True)
    seal = commands.add_parser("handoff")
    restore = commands.add_parser("restore")
    for command in (seal, restore):
        command.add_argument("--config", required=True, type=Path)
        command.add_argument("--archive", required=True, type=Path)
    seal.add_argument("--recipients", required=True, type=Path)
    restore.add_argument("--identity", required=True, type=Path)
    restore.add_argument("--witness-reader-env", required=True)
    args = parser.parse_args()
    try:
        result = (
            handoff(args.config, args.archive, args.recipients, args.age)
            if args.command == "handoff"
            else recover(
                args.config,
                args.archive,
                args.identity,
                args.witness_reader_env,
                args.age,
            )
        )
    except (
        OSError,
        KeyError,
        ValueError,
        AnchorUnavailable,
        sqlite3.Error,
        subprocess.CalledProcessError,
    ) as error:
        parser.exit(1, str(error) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
