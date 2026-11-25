use super::revocation::{RevocationError, RevocationStatus, RevocationUpdate, Revocations};
use chrono::{DateTime, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

const MAX_LEDGER_BYTES: u64 = 16 * 1024 * 1024;

/// One exclusive request allowance issued to a named gateway replica.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    pub id: Uuid,
    pub gateway_id: Uuid,
    pub tenant: String,
    pub operation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub starts_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub requests: u64,
}

impl Lease {
    fn active_at(&self, now: DateTime<Utc>) -> bool {
        self.starts_at.is_none_or(|start| start <= now) && now < self.expires_at
    }

    pub(super) fn scope(&self) -> (&str, &str, Option<&str>, Option<&str>) {
        (
            &self.tenant,
            &self.operation,
            self.project.as_deref(),
            self.env.as_deref(),
        )
    }

    fn level(&self) -> usize {
        usize::from(self.project.is_some()) + usize::from(self.env.is_some())
    }
}

#[derive(Debug)]
pub(super) struct BudgetDebit {
    ids: Vec<Uuid>,
    pub charged_at: DateTime<Utc>,
    starts_at: Option<DateTime<Utc>>,
    expires_at: DateTime<Utc>,
}

impl BudgetDebit {
    pub(super) fn record_leases(&self, event: &mut serde_json::Value) {
        event["lease_id"] = serde_json::json!(self.ids[0]);
        if self.ids.len() > 1 {
            event["scope_lease_ids"] = serde_json::json!(&self.ids[1..]);
        }
    }

    pub(super) fn active_at(&self, now: DateTime<Utc>) -> bool {
        self.starts_at.is_none_or(|start| start <= now) && now < self.expires_at
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    schema: u8,
    gateway_id: Uuid,
    spent: BTreeMap<Uuid, Spent>,
    #[serde(default)]
    revocations: Revocations,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Spent {
    lease: Lease,
    requests: u64,
}

pub(crate) struct BudgetStore {
    path: PathBuf,
    _lock: File,
    ledger: Mutex<Option<Ledger>>,
}

#[derive(Debug)]
pub(super) enum BudgetError {
    Exhausted,
    Revoked,
    Unavailable,
}

impl BudgetStore {
    pub(crate) fn open(path: &Path, gateway_id: Uuid) -> io::Result<Self> {
        let parent = path
            .parent()
            .ok_or_else(|| invalid("budget path has no parent"))?;
        fs::create_dir_all(parent)?;
        let mut lock_path = path.as_os_str().to_owned();
        lock_path.push(".lock");
        let lock_path = PathBuf::from(lock_path);
        regular_file_or_missing(&lock_path)?;
        let lock = private_open_options()
            .create(true)
            .read(true)
            .write(true)
            .open(lock_path)?;
        FileExt::try_lock_exclusive(&lock)?;
        let ledger = if regular_file_or_missing(path)? {
            let file = File::open(path)?;
            let mut bytes = Vec::new();
            file.take(MAX_LEDGER_BYTES + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_LEDGER_BYTES {
                return Err(invalid("budget state exceeds its size limit"));
            }
            let ledger: Ledger = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
            if ledger.schema != 1
                || ledger.gateway_id != gateway_id
                || ledger.spent.iter().any(|(id, spent)| {
                    *id != spent.lease.id
                        || spent.lease.gateway_id != gateway_id
                        || spent.requests > spent.lease.requests
                })
            {
                return Err(invalid(
                    "budget state does not match the replica or lease inventory",
                ));
            }
            ledger
        } else {
            Ledger {
                schema: 1,
                gateway_id,
                spent: BTreeMap::new(),
                revocations: Revocations::default(),
            }
        };
        Ok(Self {
            path: path.to_owned(),
            _lock: lock,
            ledger: Mutex::new(Some(ledger)),
        })
    }

    pub(crate) fn revocation_status(&self) -> Option<RevocationStatus> {
        let guard = self.ledger.lock().ok()?;
        let ledger = guard.as_ref()?;
        Some(ledger.revocations.status(ledger.gateway_id, Utc::now()))
    }

    pub(crate) async fn apply_revocations(
        self: &Arc<Self>,
        update: RevocationUpdate,
    ) -> Result<RevocationStatus, RevocationError> {
        let store = Arc::clone(self);
        tokio::task::spawn_blocking(move || store.apply_revocations_sync(update))
            .await
            .map_err(|_| RevocationError::Unavailable)?
    }

    fn apply_revocations_sync(
        &self,
        update: RevocationUpdate,
    ) -> Result<RevocationStatus, RevocationError> {
        let mut guard = self
            .ledger
            .lock()
            .map_err(|_| RevocationError::Unavailable)?;
        let ledger = guard.as_mut().ok_or(RevocationError::Unavailable)?;
        if ledger.revocations.apply(ledger.gateway_id, update)? {
            if let Err(error) = self.persist(ledger) {
                *guard = None;
                tracing::error!(%error, "Could not persist platform revocations");
                return Err(RevocationError::Unavailable);
            }
        }
        Ok(ledger.revocations.status(ledger.gateway_id, Utc::now()))
    }

    pub(super) fn check_credential(
        &self,
        subject: &str,
        generation: u64,
    ) -> Result<(), BudgetError> {
        let guard = self.ledger.lock().map_err(|_| BudgetError::Unavailable)?;
        let ledger = guard.as_ref().ok_or(BudgetError::Unavailable)?;
        check_revocation(ledger, subject, generation, Utc::now())
    }

    pub(super) async fn debit(
        self: &Arc<Self>,
        leases: Vec<Lease>,
        subject: &str,
        generation: u64,
        cost: u64,
    ) -> Result<BudgetDebit, BudgetError> {
        let store = Arc::clone(self);
        let subject = subject.to_owned();
        tokio::task::spawn_blocking(move || store.debit_sync(leases, &subject, generation, cost))
            .await
            .map_err(|_| BudgetError::Unavailable)?
    }

    fn debit_sync(
        &self,
        leases: Vec<Lease>,
        subject: &str,
        generation: u64,
        cost: u64,
    ) -> Result<BudgetDebit, BudgetError> {
        let mut guard = self.ledger.lock().map_err(|_| BudgetError::Unavailable)?;
        let ledger = guard.as_mut().ok_or(BudgetError::Unavailable)?;
        let now = Utc::now();
        check_revocation(ledger, subject, generation, now)?;
        let active = active_leases(leases, ledger.gateway_id, now)?;
        let mut debit = BudgetDebit {
            ids: Vec::with_capacity(active.len()),
            charged_at: now,
            starts_at: None,
            expires_at: active[0].expires_at,
        };
        let mut updates = Vec::with_capacity(active.len());
        for lease in active {
            if lease.expires_at != debit.expires_at || debit.ids.contains(&lease.id) {
                return Err(BudgetError::Unavailable);
            }
            let previous = ledger.spent.get(&lease.id);
            if previous.is_some_and(|spent| spent.lease != lease) {
                return Err(BudgetError::Unavailable);
            }
            let requests = previous
                .map_or(0, |spent| spent.requests)
                .checked_add(cost)
                .filter(|total| *total <= lease.requests && cost > 0)
                .ok_or(BudgetError::Exhausted)?;
            debit.ids.push(lease.id);
            debit.starts_at = debit.starts_at.max(lease.starts_at);
            updates.push(Spent { lease, requests });
        }
        for spent in updates {
            ledger.spent.insert(spent.lease.id, spent);
        }
        if let Err(error) = self.persist(ledger) {
            *guard = None;
            tracing::error!(%error, "Could not persist platform budget debit");
            return Err(BudgetError::Unavailable);
        }
        Ok(debit)
    }

    fn persist(&self, ledger: &Ledger) -> io::Result<()> {
        let bytes = serde_json::to_vec(ledger).map_err(io::Error::other)?;
        if bytes.len() as u64 > MAX_LEDGER_BYTES {
            return Err(invalid("budget state exceeds its size limit"));
        }
        let temporary = self
            .path
            .with_file_name(format!(".platform-budget-{}.tmp", Uuid::new_v4()));
        let result = (|| {
            let mut file = private_open_options()
                .create_new(true)
                .write(true)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, &self.path)?;
            #[cfg(unix)]
            File::open(
                self.path
                    .parent()
                    .ok_or_else(|| invalid("budget path has no parent"))?,
            )?
            .sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
}

fn active_leases(
    candidates: Vec<Lease>,
    gateway_id: Uuid,
    now: DateTime<Utc>,
) -> Result<Vec<Lease>, BudgetError> {
    let mut required = [true, false, false];
    let mut levels = [None, None, None];
    for lease in candidates {
        if lease.gateway_id != gateway_id {
            return Err(BudgetError::Unavailable);
        }
        let level = lease.level();
        required[level] = true;
        if lease.active_at(now) && levels[level].replace(lease).is_some() {
            return Err(BudgetError::Unavailable);
        }
    }
    if required
        .into_iter()
        .zip(&levels)
        .any(|(required, lease)| required && lease.is_none())
    {
        return Err(BudgetError::Unavailable);
    }
    Ok(levels.into_iter().flatten().collect())
}

fn check_revocation(
    ledger: &Ledger,
    subject: &str,
    generation: u64,
    now: DateTime<Utc>,
) -> Result<(), BudgetError> {
    if !ledger.revocations.fresh(now) {
        return Err(BudgetError::Unavailable);
    }
    if ledger.revocations.revoked(subject, generation) {
        return Err(BudgetError::Revoked);
    }
    Ok(())
}

fn private_open_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

fn regular_file_or_missing(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => Err(invalid("budget state and lock paths must be regular files")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn exclusive_allowance_survives_restart_and_denies_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("budget.json");
        let mut lease = Lease {
            id: Uuid::new_v4(),
            gateway_id: Uuid::new_v4(),
            tenant: "org".into(),
            operation: "models.list".into(),
            project: None,
            env: None,
            starts_at: None,
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            requests: 1,
        };
        let store = Arc::new(BudgetStore::open(&path, lease.gateway_id).unwrap());
        assert!(BudgetStore::open(&path, lease.gateway_id).is_err());
        let now = Utc::now();
        store
            .apply_revocations(RevocationUpdate {
                schema: super::super::REVOCATION_SCHEMA.to_string(),
                gateway_id: lease.gateway_id,
                sequence: 1,
                issued_at: now,
                valid_until: now + chrono::Duration::minutes(2),
                more: false,
                changes: Vec::new(),
            })
            .await
            .unwrap();
        let future = Lease {
            id: Uuid::new_v4(),
            starts_at: Some(lease.expires_at),
            expires_at: lease.expires_at + chrono::Duration::minutes(5),
            ..lease.clone()
        };
        assert!(!future.active_at(now));
        assert!(future.active_at(lease.expires_at));
        assert!(!lease.active_at(lease.expires_at));
        assert!(!future.active_at(future.expires_at));
        assert!(matches!(
            store.debit(vec![future], "subject", 1, 1).await,
            Err(BudgetError::Unavailable)
        ));
        let both = tokio::join!(
            store.debit(vec![lease.clone()], "subject", 1, 1),
            store.debit(vec![lease.clone()], "subject", 1, 1)
        );
        assert_ne!(both.0.is_ok(), both.1.is_ok());
        drop(store);
        assert!(BudgetStore::open(&path, Uuid::new_v4()).is_err());
        let store = Arc::new(BudgetStore::open(&path, lease.gateway_id).unwrap());
        assert!(matches!(
            store.debit(vec![lease.clone()], "subject", 1, 1).await,
            Err(BudgetError::Exhausted)
        ));
        lease.requests += 1;
        assert!(matches!(
            store.debit(vec![lease.clone()], "subject", 1, 1).await,
            Err(BudgetError::Unavailable)
        ));

        let tenant = Lease {
            id: Uuid::new_v4(),
            requests: 4,
            ..lease
        };
        let project = Lease {
            id: Uuid::new_v4(),
            project: Some("project".into()),
            starts_at: Some(now),
            requests: 3,
            ..tenant.clone()
        };
        let environment = Lease {
            id: Uuid::new_v4(),
            env: Some("env".into()),
            requests: 1,
            ..project.clone()
        };
        let scopes = vec![tenant.clone(), project.clone(), environment.clone()];
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            store.debit(scopes.clone(), "subject", 1, 2).await,
            Err(BudgetError::Exhausted)
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
        let debit = store.debit(scopes, "subject", 1, 1).await.unwrap();
        assert_eq!(debit.ids, vec![tenant.id, project.id, environment.id]);
        assert!(store
            .debit(vec![tenant.clone(), project], "subject", 1, 2)
            .await
            .is_ok());
        assert!(store.debit(vec![tenant], "subject", 1, 1).await.is_ok());
    }
}
