//! Coalesce Argon2 verification for the same Kense Key while bounding distinct work.

use super::Rejection;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::{watch, Semaphore};

static VERIFICATIONS: Semaphore = Semaphore::const_new(4);
type DigestValue = [u8; 32];
type VerificationResult = Result<(), Rejection>;

#[derive(Default)]
pub(super) struct KeyVerifier {
    state: Arc<Mutex<State>>,
}

#[derive(Default)]
struct State {
    verified: HashMap<String, DigestValue>,
    pending: HashMap<DigestValue, watch::Receiver<Option<VerificationResult>>>,
}

impl KeyVerifier {
    pub(super) fn forget(&self, prefix: &str) {
        if let Ok(mut state) = self.state.lock() {
            state.verified.remove(prefix);
        }
    }

    /// Return whether the caller waited for a blocking verification attempt.
    pub(super) async fn verify(
        &self,
        prefix: &str,
        token: &str,
        hash: &str,
    ) -> Result<bool, Rejection> {
        let digest: DigestValue = Sha256::digest(token.as_bytes()).into();
        let mut result = {
            let mut state = self.state.lock().map_err(|_| Rejection::Unavailable)?;
            if state.verified.get(prefix) == Some(&digest) {
                return Ok(false);
            }
            if let Some(pending) = state.pending.get(&digest) {
                pending.clone()
            } else {
                let permit = VERIFICATIONS
                    .try_acquire()
                    .map_err(|_| Rejection::Unavailable)?;
                let (completed, pending) = watch::channel(None);
                state.pending.insert(digest, pending.clone());
                let shared = Arc::clone(&self.state);
                let prefix = prefix.to_owned();
                let token = token.to_owned();
                let hash = hash.to_owned();
                // Finish the shared attempt even if the first HTTP request disconnects.
                tokio::spawn(async move {
                    let _permit = permit;
                    let verified = tokio::task::spawn_blocking(move || {
                        PasswordHash::new(&hash).is_ok_and(|hash| {
                            Argon2::default()
                                .verify_password(token.as_bytes(), &hash)
                                .is_ok()
                        })
                    })
                    .await;
                    let outcome = match (verified, shared.lock()) {
                        (verified, Ok(mut state)) => {
                            state.pending.remove(&digest);
                            match verified {
                                Ok(true) => {
                                    state.verified.insert(prefix, digest);
                                    Ok(())
                                }
                                Ok(false) => Err(Rejection::InvalidKey),
                                Err(_) => Err(Rejection::Unavailable),
                            }
                        }
                        (_, Err(_)) => Err(Rejection::Unavailable),
                    };
                    completed.send_replace(Some(outcome));
                });
                pending
            }
        };
        let outcome = result
            .wait_for(Option::is_some)
            .await
            .map_err(|_| Rejection::Unavailable)?;
        outcome
            .unwrap_or(Err(Rejection::Unavailable))
            .map(|()| true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{password_hash::SaltString, PasswordHasher};

    #[tokio::test]
    async fn cold_burst_shares_verification_of_the_exact_key() {
        let verifier = KeyVerifier::default();
        let token = "key.abcdefghijklmnopqrstuvwxyz123456";
        let hash = Argon2::default()
            .hash_password(
                token.as_bytes(),
                &SaltString::encode_b64(b"verification-salt").unwrap(),
            )
            .unwrap()
            .to_string();
        let burst =
            futures_util::future::join_all((0..12).map(|_| verifier.verify("key", token, &hash)))
                .await;
        assert!(burst.iter().all(Result::is_ok));
        assert!(matches!(
            verifier.verify("key", "key.incorrect-secret", &hash).await,
            Err(Rejection::InvalidKey)
        ));
        assert!(!verifier.verify("key", token, &hash).await.unwrap());
        verifier.forget("key");
        let mut first = Box::pin(verifier.verify("key", token, &hash));
        assert!(futures_util::poll!(&mut first).is_pending());
        drop(first);
        assert!(verifier.verify("key", token, &hash).await.is_ok());
    }
}
