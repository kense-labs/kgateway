//! Scoped service credentials exchanged at the Kense gateway.

use crate::time::Timestamp;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Issuer lifetime bounds for the service-token v1 contract.
pub const MIN_LIFETIME_SECONDS: u64 = 300;
/// Maximum lifetime a downstream service accepts for an exchanged credential.
pub const MAX_LIFETIME_SECONDS: u64 = 900;

/// A deployment's immutable routing identity as exposed by a MaaS service.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentRef {
    pub id: u64,
    pub version: String,
}

/// Work pre-authorized for an asynchronous batch at admission time.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BatchAuthorization {
    pub max_requests: u64,
    pub targets: BTreeMap<String, DeploymentRef>,
}

/// Opaque binding passed only to the target named by the invocation audience.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VaultBinding {
    pub secret_ref: String,
    pub version: u64,
}

impl VaultBinding {
    pub(crate) fn valid(&self) -> bool {
        (1..(1 << 53)).contains(&self.version)
            && self
                .secret_ref
                .strip_prefix("urn:plat:vault:secret:")
                .is_some_and(valid_identifier)
    }
}

/// A single already-authorized downstream invocation.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceInvocation {
    pub aud: String,
    pub sub: String,
    pub tenant: String,
    pub project: String,
    pub env: String,
    pub org: String,
    pub plane: String,
    pub urn: String,
    pub operation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    pub request_id: Uuid,
    pub trace_id: String,
    pub reservation_id: Uuid,
    pub deployments: Vec<DeploymentRef>,
    /// Public model names and their signed deployment IDs for MaaS discovery.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub model_aliases: BTreeMap<String, Vec<u64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch: Option<BatchAuthorization>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_binding: Option<VaultBinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegation_chain: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Serialize)]
struct Claims {
    v: u8,
    iss: String,
    iat: i64,
    exp: i64,
    #[serde(flatten)]
    invocation: ServiceInvocation,
}

/// Errors surfaced without revealing signing material or minted credentials.
#[derive(Debug, thiserror::Error)]
pub enum ServiceTokenError {
    #[error("invalid issuer or service signing key ID")]
    InvalidIssuer,
    #[error("invalid Ed25519 signing key")]
    InvalidKey(#[source] jsonwebtoken::errors::Error),
    #[error("service signing authorization has expired or offers insufficient lifetime")]
    AuthorizationExpired,
    #[error("could not sign the service invocation")]
    SigningFailed(#[source] jsonwebtoken::errors::Error),
}

/// A time-bounded signing authorization loaded from local identity material.
pub struct ServiceTokenSigner {
    issuer: String,
    header: Header,
    key: EncodingKey,
    authorized_until: Timestamp,
}

impl ServiceTokenSigner {
    pub(crate) fn can_issue(&self, now: Timestamp) -> bool {
        self.authorized_until.timestamp() - now.timestamp() >= MIN_LIFETIME_SECONDS as i64
    }

    /// Build a signer for one externally provisioned Ed25519 key.
    pub fn from_ed25519_pem(
        issuer: String,
        key_id: String,
        pem: &[u8],
        authorized_until: Timestamp,
    ) -> Result<Self, ServiceTokenError> {
        Self::new(
            issuer,
            key_id,
            EncodingKey::from_ed_pem(pem).map_err(ServiceTokenError::InvalidKey)?,
            authorized_until,
        )
    }

    fn new(
        issuer: String,
        key_id: String,
        key: EncodingKey,
        authorized_until: Timestamp,
    ) -> Result<Self, ServiceTokenError> {
        if !valid_identifier(&issuer) || !valid_identifier(&key_id) {
            return Err(ServiceTokenError::InvalidIssuer);
        }
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(key_id);
        Ok(Self {
            issuer,
            header,
            key,
            authorized_until,
        })
    }

    /// Issue a credential up to the requested lifetime and the local authorization's expiry.
    pub fn issue(
        &self,
        invocation: ServiceInvocation,
        lifetime_seconds: u64,
        now: Timestamp,
    ) -> Result<String, ServiceTokenError> {
        let iat = now.timestamp();
        let lifetime = lifetime_seconds.min(MAX_LIFETIME_SECONDS) as i64;
        let exp = (iat + lifetime).min(self.authorized_until.timestamp());
        let minimum = if invocation.delegation_chain.is_empty() {
            MIN_LIFETIME_SECONDS as i64
        } else {
            1
        };
        if exp - iat < minimum {
            return Err(ServiceTokenError::AuthorizationExpired);
        }
        jsonwebtoken::encode(
            &self.header,
            &Claims {
                v: 1,
                iss: self.issuer.clone(),
                iat,
                exp,
                invocation,
            },
            &self.key,
        )
        .map_err(ServiceTokenError::SigningFailed)
    }
}

pub(crate) fn valid_identifier(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use jsonwebtoken::{decode, DecodingKey, Validation};

    #[derive(Deserialize)]
    struct TestVector {
        kid: String,
        test_public_key: String,
        test_private_key_pkcs8: String,
        token: String,
    }

    const VECTOR: &str = include_str!("../contracts/fixtures/signed-service-token-v1.json");
    const EXPECTED: &str = include_str!("../contracts/fixtures/service-token-v1.json");

    #[test]
    fn accepts_the_go_signature_and_issues_equivalent_claims() {
        let vector: TestVector = serde_json::from_str(VECTOR).unwrap();
        let expected: Claims = serde_json::from_str(EXPECTED).unwrap();
        let public_key = URL_SAFE_NO_PAD.decode(vector.test_public_key).unwrap();
        let private_key = URL_SAFE_NO_PAD
            .decode(vector.test_private_key_pkcs8)
            .unwrap();
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&[&expected.invocation.aud]);
        validation.set_issuer(&[&expected.iss]);
        validation.validate_exp = false;
        let verifier = DecodingKey::from_ed_der(&public_key);
        let decoded = decode::<Claims>(&vector.token, &verifier, &validation).unwrap();
        assert_eq!(decoded.claims, expected);
        assert_eq!(decoded.header.kid.as_ref(), Some(&vector.kid));

        let issued_at = Timestamp::from_timestamp(expected.iat, 0).unwrap();
        let authorization_expiry = Timestamp::from_timestamp(expected.exp, 0).unwrap();
        let signer = ServiceTokenSigner::new(
            expected.iss.clone(),
            vector.kid,
            EncodingKey::from_ed_der(&private_key),
            authorization_expiry,
        )
        .unwrap();
        let token = signer
            .issue(expected.invocation.clone(), 900, issued_at)
            .unwrap();
        let minted = decode::<Claims>(&token, &verifier, &validation).unwrap();
        assert_eq!(minted.claims, expected);
        assert!(matches!(
            signer.issue(expected.invocation, 900, authorization_expiry),
            Err(ServiceTokenError::AuthorizationExpired)
        ));
    }
}
