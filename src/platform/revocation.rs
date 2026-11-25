use crate::platform_identity::valid_identifier;
use crate::time::{SignedDuration as Duration, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

/// Maximum period for which a replica can admit traffic without a fresh update.
const MAX_FRESHNESS: Duration = Duration::from_mins(2);
const MAX_CLOCK_SKEW: Duration = Duration::from_secs(5);
const MAX_CHANGES: usize = 1024;

pub const REVOCATION_SCHEMA: &str = "kgateway.platform-revocations.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationUpdate {
    pub schema: String,
    pub gateway_id: Uuid,
    pub sequence: u64,
    pub issued_at: Timestamp,
    pub valid_until: Timestamp,
    #[serde(default)]
    pub more: bool,
    pub changes: Vec<Revocation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revocation {
    pub subject: String,
    pub through_generation: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct Revocations {
    last: Option<RevocationUpdate>,
    revoked: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RevocationStatus {
    pub gateway_id: Uuid,
    pub sequence: u64,
    pub valid_until: Option<Timestamp>,
    pub fresh: bool,
}

#[derive(Debug)]
pub(crate) enum RevocationError {
    Invalid,
    Conflict,
    Unavailable,
}

impl Revocations {
    pub(super) fn apply(
        &mut self,
        gateway_id: Uuid,
        update: RevocationUpdate,
    ) -> Result<bool, RevocationError> {
        if update.schema != REVOCATION_SCHEMA
            || update.gateway_id != gateway_id
            || update.sequence == 0
        {
            return Err(RevocationError::Invalid);
        }
        let seq = self.last.as_ref().map_or(0, |last| last.sequence);
        if update.sequence == seq {
            return if self.last.as_ref() == Some(&update) {
                Ok(false)
            } else {
                Err(RevocationError::Conflict)
            };
        }
        if seq.checked_add(1) != Some(update.sequence) {
            return Err(RevocationError::Conflict);
        }
        let now = Timestamp::now();
        if update.valid_until <= now
            || update.valid_until <= update.issued_at
            || update.valid_until - update.issued_at > MAX_FRESHNESS
            || update.issued_at > now + MAX_CLOCK_SKEW
            || self
                .last
                .as_ref()
                .is_some_and(|last| update.issued_at < last.issued_at)
            || update.changes.len() > MAX_CHANGES
        {
            return Err(RevocationError::Invalid);
        }
        let mut subjects = BTreeSet::new();
        for revocation in &update.changes {
            if !valid_identifier(&revocation.subject)
                || revocation.through_generation == 0
                || !subjects.insert(revocation.subject.as_str())
            {
                return Err(RevocationError::Invalid);
            }
        }
        for change in &update.changes {
            let generation = self.revoked.entry(change.subject.clone()).or_default();
            *generation = (*generation).max(change.through_generation);
        }
        self.last = Some(update);
        Ok(true)
    }

    pub(super) fn status(&self, gateway_id: Uuid, now: Timestamp) -> RevocationStatus {
        let valid_until = self.last.as_ref().map(|last| last.valid_until);
        RevocationStatus {
            gateway_id,
            sequence: self.last.as_ref().map_or(0, |last| last.sequence),
            valid_until,
            fresh: self.fresh(now),
        }
    }

    pub(super) fn fresh(&self, now: Timestamp) -> bool {
        self.last
            .as_ref()
            .is_some_and(|last| !last.more && last.valid_until > now)
    }

    pub(super) fn revoked(&self, subject: &str, generation: u64) -> bool {
        self.revoked
            .get(subject)
            .is_some_and(|through| generation <= *through)
    }
}
