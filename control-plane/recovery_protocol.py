"""The independent witness contract for control-plane checkpoints."""

import hashlib
import re

from audit_anchor import DIGEST, canonical

CHECKPOINT = "kgateway.control-checkpoint.v1"
STATUS = "kgateway.control-checkpoint-status.v1"
CLAIM = "kgateway.control-checkpoint-claim.v1"
CHECKPOINT_PATH = "/v1/recovery/checkpoints"
CLAIM_PATH = "/v1/recovery/claim"
CHALLENGE = re.compile(r"[0-9a-f]{32}")


def heads_digest(rows):
    return hashlib.sha256(canonical(list(rows))).hexdigest()


def validate_checkpoint(record):
    fields = {"archive_sha256", "policy_sha256", "audit_heads_sha256"}
    if (
        set(record) != fields | {"schema"}
        or record["schema"] != CHECKPOINT
        or any(
            not isinstance(record[key], str) or not DIGEST.fullmatch(record[key])
            for key in fields
        )
    ):
        raise ValueError("invalid control-plane checkpoint")


def validate_claim(record):
    if (
        record.keys() != {"schema", "archive_sha256", "destination"}
        or record["schema"] != CLAIM
        or not isinstance(record["archive_sha256"], str)
        or not DIGEST.fullmatch(record["archive_sha256"])
        or not isinstance(record["destination"], str)
        or not CHALLENGE.fullmatch(record["destination"])
    ):
        raise ValueError("invalid recovery claim")
