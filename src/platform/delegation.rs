use super::{config, Operation, Rejection, Resource, RpcProtocol};
use crate::platform_identity::valid_identifier;
use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

pub(super) const PREFIX: &str = "kdel.";
const ISSUER: &str = "urn:plat:identity:delegation";
const KEY_ID: &str = "delegation-1";
const MAX_HOPS: usize = 4;
const MAX_TARGETS: usize = 16;

/// An exact downstream operation permitted in an A2A delegation graph.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub operation: String,
    pub action: String,
    pub urn: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Ticket {
    v: u8,
    iss: String,
    aud: String,
    iat: i64,
    exp: i64,
    chain_deadline: i64,
    pub jti: Uuid,
    parent_request_id: Uuid,
    pub sub: String,
    pub generation: u64,
    pub tenant: String,
    pub project: String,
    pub env: String,
    pub org: String,
    pub trace_id: String,
    method: String,
    path: String,
    operation: String,
    pub action: String,
    pub urn: String,
    pub chain: Vec<String>,
    remaining: Vec<Target>,
}

impl Ticket {
    pub(super) fn remaining_seconds(&self, now: DateTime<Utc>) -> u64 {
        self.exp.saturating_sub(now.timestamp()).max(0) as u64
    }
}

pub(super) fn validate_graph(policy: &config::PlatformPolicy) -> bool {
    let operations: std::collections::BTreeMap<_, _> = policy
        .routes
        .values()
        .map(|operation| (operation.operation.as_str(), operation))
        .collect();
    policy.routes.values().all(|source| {
        if !source.has_delegation() {
            return true;
        }
        a2a(source)
            && source.delegate_to.len() <= MAX_TARGETS
            && source.delegate_to.iter().collect::<BTreeSet<_>>().len() == source.delegate_to.len()
            && source.delegate_to.iter().all(|target| {
                operations
                    .get(target.operation.as_str())
                    .is_some_and(|destination| {
                        destination.accept_delegation
                            && destination.audience != source.audience
                            && match &destination.resource {
                                Resource::Rpc { policy } => {
                                    policy.methods.get(&target.action) == Some(&target.urn)
                                }
                                _ => false,
                            }
                    })
            })
    })
}

fn a2a(operation: &Operation) -> bool {
    operation.requires_audit_receipt
        && operation.method == "POST"
        && matches!(&operation.resource, Resource::Rpc { policy } if matches!(policy.protocol, RpcProtocol::A2a))
}

pub(super) fn verify(
    token: &str,
    key: &DecodingKey,
    operation: &Operation,
    now: DateTime<Utc>,
) -> Result<Ticket, Rejection> {
    if !operation.accept_delegation || token.len() > 16 * 1024 {
        return Err(Rejection::InvalidKey);
    }
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.leeway = 0;
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[&operation.audience]);
    let data = decode::<Ticket>(token, key, &validation).map_err(|_| Rejection::InvalidKey)?;
    let ticket = data.claims;
    let now = now.timestamp();
    let root_deadline = ticket.iat.saturating_add(240);
    let trace = ticket.trace_id.as_bytes();
    if data.header.typ.as_deref() != Some("kgateway-delegation")
        || data.header.kid.as_deref() != Some(KEY_ID)
        || ticket.v != 1
        || ticket.iss != ISSUER
        || ticket.aud != operation.audience
        || ticket.method != operation.method
        || ticket.path != operation.path
        || ticket.operation != operation.operation
        || ticket.jti.is_nil()
        || ticket.parent_request_id.is_nil()
        || ticket.generation == 0
        || ticket.iat < 0
        || ticket.iat > now + 5
        || ticket.exp <= now
        || ticket.exp <= ticket.iat
        || ticket.exp > ticket.iat.saturating_add(120)
        || ticket.exp > ticket.chain_deadline
        || ticket.chain_deadline > root_deadline
        || trace.len() != 32
        || trace.iter().all(|byte| *byte == b'0')
        || !trace
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        || ticket.chain.is_empty()
        || ticket.chain.len() > MAX_HOPS
        || ticket.chain.iter().collect::<BTreeSet<_>>().len() != ticket.chain.len()
        || !ticket
            .chain
            .iter()
            .all(|actor| valid_identifier(actor) && actor != &operation.audience)
        || ticket.remaining.len() > MAX_TARGETS
        || !config::valid_urn(&ticket.urn)
    {
        return Err(Rejection::InvalidKey);
    }
    Ok(ticket)
}
