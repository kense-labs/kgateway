//! Local admission and service-token exchange for registered platform routes.

mod assets;
mod audit;
mod budget;
mod config;
mod delegation;
pub(crate) mod meter;
mod revocation;
mod rpc;
pub(crate) mod session;
mod task;
mod verification;

pub(crate) use budget::BudgetStore;
pub use budget::Lease;
pub(crate) use config::validate;
pub use config::{
    Credential, ModelTarget, Operation, PlatformBootstrap, PlatformPolicy, Resource, Signer,
    POLICY_SCHEMA,
};
pub use delegation::Target as DelegationTarget;
pub(crate) use revocation::RevocationError;
pub use revocation::{Revocation, RevocationStatus, RevocationUpdate, REVOCATION_SCHEMA};
pub(crate) use rpc::MAX_RPC_BYTES;
pub use rpc::{Policy as RpcPolicy, Protocol as RpcProtocol, Tool as RpcTool};

use crate::platform_identity::{
    BatchAuthorization, DeploymentRef, ServiceInvocation, ServiceTokenSigner, MAX_LIFETIME_SECONDS,
};
use crate::time::Timestamp;
use crate::usage::UsageSpool;
use crate::{GatewayError, Result};
use http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use jsonwebtoken::DecodingKey;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use uuid::Uuid;

pub(crate) struct Admission {
    policy: PlatformPolicy,
    issuer: ServiceTokenSigner,
    budgets: Arc<BudgetStore>,
    mcp_sessions: Option<Arc<session::Codec>>,
    audit: Option<audit::Client>,
    delegation_key: Option<DecodingKey>,
    subjects: BTreeMap<String, String>,
    verifier: verification::KeyVerifier,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Rejection {
    InvalidRequest,
    UnknownOperation,
    InvalidKey,
    ScopeDenied,
    Exhausted,
    Unavailable,
}

impl Rejection {
    pub(crate) fn status(self) -> StatusCode {
        match self {
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::UnknownOperation => StatusCode::NOT_FOUND,
            Self::InvalidKey => StatusCode::UNAUTHORIZED,
            Self::ScopeDenied => StatusCode::FORBIDDEN,
            Self::Exhausted => StatusCode::TOO_MANY_REQUESTS,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    pub(crate) fn detail(self) -> &'static str {
        match self {
            Self::InvalidRequest => "Invalid bounded JSON-RPC request",
            Self::UnknownOperation => "Platform operation is not registered",
            Self::InvalidKey => "Platform key is missing, invalid, or expired",
            Self::ScopeDenied => "Platform scope does not permit this resource",
            Self::Exhausted => "Platform request allowance is exhausted",
            Self::Unavailable => "Platform authorization or metering is unavailable",
        }
    }
}

pub(crate) struct Authenticated<'a> {
    credential: &'a Credential,
    operation: &'a Operation,
    admission: &'a Admission,
    delegation: Option<delegation::Ticket>,
}

pub(crate) enum SelectedResource {
    Model(String),
    Rpc(rpc::Invocation),
}

impl SelectedResource {
    pub(crate) fn take_local_response(&mut self) -> Option<bytes::Bytes> {
        match self {
            Self::Rpc(rpc) => rpc.response.take(),
            Self::Model(_) => None,
        }
    }
}

impl Admission {
    pub(crate) fn new(
        policy: &PlatformPolicy,
        bootstrap: &PlatformBootstrap,
        managed: &crate::config::ManagedConfig,
        budgets: Arc<BudgetStore>,
    ) -> Result<Self> {
        let pem = std::fs::read(&bootstrap.signing_key_file)
            .map_err(|error| GatewayError::Config(format!("Read platform signing key: {error}")))?;
        let issuer = ServiceTokenSigner::from_ed25519_pem(
            policy.signer.issuer.clone(),
            policy.signer.key_id.clone(),
            &pem,
            policy.signer.authorized_until,
        )
        .map_err(|error| GatewayError::Config(error.to_string()))?;
        let mcp_sessions = bootstrap
            .mcp_session_key_file
            .as_ref()
            .map(|path| {
                let bytes = std::fs::read(path).map_err(|error| {
                    GatewayError::Config(format!("Read MCP session key: {error}"))
                })?;
                session::Codec::new(&bytes).map(Arc::new).ok_or_else(|| {
                    GatewayError::Config("MCP session key must contain 32 bytes".into())
                })
            })
            .transpose()?;
        let audit = if policy
            .routes
            .values()
            .any(|operation| operation.requires_audit_receipt)
        {
            let endpoint = bootstrap.audit_receipt_endpoint.clone();
            let transport = managed
                .usage_spool
                .as_ref()
                .map(crate::usage::build_usage_cloud_ingest_transport)
                .transpose()?
                .flatten();
            match (endpoint, managed.gateway_id, transport) {
                (Some(endpoint), Some(gateway_id), Some(transport)) => Some(audit::Client {
                    endpoint,
                    gateway_id,
                    transport,
                }),
                _ => {
                    return Err(GatewayError::Config(
                        "Missing platform audit receipt client settings".to_owned(),
                    ))
                }
            }
        } else {
            None
        };
        let delegation_key = bootstrap
            .delegation_verification_key_file
            .as_ref()
            .map(|file| {
                let key = std::fs::read(file).map_err(|error| {
                    GatewayError::Config(format!("Read delegation verification key: {error}"))
                })?;
                DecodingKey::from_ed_pem(&key)
                    .map_err(|_| GatewayError::Config("Invalid delegation verification key".into()))
            })
            .transpose()?;
        let subjects = if delegation_key.is_some() {
            policy
                .credentials
                .iter()
                .map(|(prefix, key)| (key.subject.clone(), prefix.clone()))
                .collect()
        } else {
            BTreeMap::new()
        };
        let mut policy = policy.clone();
        policy
            .leases
            .sort_unstable_by(|a, b| a.scope().cmp(&b.scope()));
        Ok(Self {
            policy,
            issuer,
            budgets,
            mcp_sessions,
            audit,
            delegation_key,
            subjects,
            verifier: verification::KeyVerifier::default(),
        })
    }

    pub(crate) async fn authenticate(
        &self,
        router: &str,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
    ) -> std::result::Result<Authenticated<'_>, Rejection> {
        let operation = self
            .policy
            .routes
            .get(router)
            .filter(|operation| matches_operation(operation, method, uri))
            .ok_or(Rejection::UnknownOperation)?;
        let now = Timestamp::now();
        if self.policy.expires_at <= now {
            return Err(Rejection::Unavailable);
        }
        let token = primary_key(headers)?;
        if let Some(ticket) = token.strip_prefix(delegation::PREFIX) {
            let key = self.delegation_key.as_ref().ok_or(Rejection::InvalidKey)?;
            let ticket = delegation::verify(ticket, key, operation, now)?;
            let credential = self
                .subjects
                .get(&ticket.sub)
                .and_then(|prefix| self.policy.credentials.get(prefix))
                .filter(|key| {
                    key.expires_at > now
                        && key.generation == ticket.generation
                        && key.tenant == ticket.tenant
                        && key.project == ticket.project
                        && key.env == ticket.env
                        && key.org == ticket.org
                })
                .ok_or(Rejection::InvalidKey)?;
            self.budgets
                .check_credential(&credential.subject, credential.generation)
                .map_err(budget_rejection)?;
            let authenticated = Authenticated {
                credential,
                operation,
                admission: self,
                delegation: Some(ticket),
            };
            if !authenticated.grant()?.contains(
                &authenticated
                    .delegation
                    .as_ref()
                    .ok_or(Rejection::InvalidKey)?
                    .urn,
            ) {
                return Err(Rejection::ScopeDenied);
            }
            return Ok(authenticated);
        }
        let (prefix, suffix) = token.split_once('.').ok_or(Rejection::InvalidKey)?;
        if !(32..=256).contains(&suffix.len())
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(Rejection::InvalidKey);
        }
        let credential = self
            .policy
            .credentials
            .get(prefix)
            .filter(|key| key.expires_at > now)
            .ok_or(Rejection::InvalidKey)?;
        let check_credential = || {
            self.budgets
                .check_credential(&credential.subject, credential.generation)
                .map_err(|error| {
                    if matches!(error, budget::BudgetError::Revoked) {
                        self.verifier.forget(prefix);
                    }
                    budget_rejection(error)
                })
        };
        check_credential()?;
        let waited_for_verification = self
            .verifier
            .verify(prefix, token, &credential.verifier_hash)
            .await?;
        if waited_for_verification {
            let now = Timestamp::now();
            if self.policy.expires_at <= now {
                return Err(Rejection::Unavailable);
            }
            if credential.expires_at <= now {
                return Err(Rejection::InvalidKey);
            }
            check_credential()?;
        }
        let authenticated = Authenticated {
            credential,
            operation,
            admission: self,
            delegation: None,
        };
        let grant = authenticated.grant()?;
        if let Resource::Fixed { urn }
        | Resource::MaasAsset { urn, .. }
        | Resource::ModelList { urn, .. }
        | Resource::McpSession { urn, .. } = &operation.resource
        {
            if !grant.contains(urn) {
                return Err(Rejection::ScopeDenied);
            }
        }
        Ok(authenticated)
    }
}

impl Authenticated<'_> {
    pub(crate) fn mcp_session(
        &self,
        selected: Option<&SelectedResource>,
        headers: &mut HeaderMap,
    ) -> std::result::Result<Option<session::Session>, Rejection> {
        if !self.operation.has_mcp_sessions() {
            return Ok(None);
        }
        let requires_session = match &self.operation.resource {
            Resource::McpSession { origins, .. } => {
                rpc::authorize_origin(headers, origins)?;
                true
            }
            _ => false,
        };
        let initialize =
            matches!(selected, Some(SelectedResource::Rpc(rpc)) if rpc.action == "initialize");
        session::Session::read(
            self.admission.mcp_sessions.clone(),
            self.owner(),
            self.credential.expires_at.timestamp(),
            initialize,
            requires_session,
            headers,
        )
        .map(Some)
    }

    fn owner(&self) -> session::Owner {
        session::Owner {
            subject: self.credential.subject.clone(),
            generation: self.credential.generation,
            tenant: self.credential.tenant.clone(),
            project: self.credential.project.clone(),
            env: self.credential.env.clone(),
            audience: self.operation.audience.clone(),
            path: self.operation.path.clone(),
        }
    }

    pub(crate) fn has_rpc_selector(&self) -> bool {
        matches!(self.operation.resource, Resource::Rpc { .. })
    }

    pub(crate) fn authorize_rpc(
        &self,
        headers: &HeaderMap,
        bytes: &[u8],
    ) -> std::result::Result<(bytes::Bytes, SelectedResource), Rejection> {
        let Resource::Rpc { policy } = &self.operation.resource else {
            return Err(Rejection::ScopeDenied);
        };
        let (body, invocation) = policy.authorize(headers, bytes, self.grant()?, &self.owner())?;
        if self.delegation.as_ref().is_some_and(|ticket| {
            ticket.urn != invocation.urn || ticket.action != invocation.action
        }) {
            return Err(Rejection::ScopeDenied);
        }
        Ok((body, SelectedResource::Rpc(invocation)))
    }

    pub(crate) fn has_model_selector(&self) -> bool {
        matches!(self.operation.resource, Resource::Model { .. })
    }

    fn grant(&self) -> std::result::Result<&BTreeSet<String>, Rejection> {
        self.credential
            .grants
            .get(&self.operation.operation)
            .ok_or(Rejection::ScopeDenied)
    }

    pub(crate) fn authorize_model(&self, model: &str) -> std::result::Result<(), Rejection> {
        if self.grant()?.contains(&config::model_urn(model)) {
            Ok(())
        } else {
            Err(Rejection::ScopeDenied)
        }
    }

    pub(crate) async fn admit(
        self,
        method: &Method,
        uri: &Uri,
        selected: Option<SelectedResource>,
        trace_id: String,
        spool: Option<&UsageSpool>,
    ) -> std::result::Result<(ServiceInvocation, HeaderValue, meter::Meter), Rejection> {
        if !matches_operation(self.operation, method, uri) {
            return Err(Rejection::UnknownOperation);
        }
        let now = Timestamp::now();
        if self.admission.policy.expires_at <= now || !self.admission.issuer.can_issue(now) {
            return Err(Rejection::Unavailable);
        }
        if self.credential.expires_at <= now {
            return Err(Rejection::InvalidKey);
        }
        if self
            .delegation
            .as_ref()
            .is_some_and(|ticket| ticket.remaining_seconds(now) == 0)
        {
            return Err(Rejection::InvalidKey);
        }
        let spool = spool.ok_or(Rejection::Unavailable)?;
        let grant = self.grant()?;
        let request_id = Uuid::new_v4();
        let tenant = self.credential.tenant.as_str();
        let tenant_targets = self.operation.tenant_targets.get(tenant);
        let mut batch = None;
        let mut model_aliases = BTreeMap::new();
        let (urn, deployments, action) = match &self.operation.resource {
            Resource::Fixed { urn } => (urn.clone(), Vec::new(), None),
            Resource::MaasAsset {
                urn,
                batch_max_requests,
                targets,
            } => {
                if let Some(max_requests) = batch_max_requests {
                    let targets: BTreeMap<_, _> =
                        config::resolved_model_targets(targets, tenant_targets)
                            .filter(|(alias, _)| grant.contains(&config::model_urn(alias)))
                            .map(|(alias, targets)| {
                                select_deployment(request_id, targets)
                                    .map(|deployment| (alias.clone(), deployment))
                            })
                            .collect::<std::result::Result<_, _>>()?;
                    if targets.is_empty() {
                        return Err(Rejection::ScopeDenied);
                    }
                    batch = Some(BatchAuthorization {
                        max_requests: *max_requests,
                        targets,
                    });
                }
                (urn.clone(), Vec::new(), None)
            }
            Resource::McpSession { urn, .. } => {
                let action = if *method == Method::GET {
                    "session/stream"
                } else {
                    "session/end"
                };
                (urn.clone(), Vec::new(), Some(action.to_owned()))
            }
            Resource::Rpc { .. } => {
                let Some(SelectedResource::Rpc(rpc)) = selected else {
                    return Err(Rejection::ScopeDenied);
                };
                (rpc.urn, Vec::new(), Some(rpc.action))
            }
            Resource::Model { targets } => {
                let Some(SelectedResource::Model(alias)) = selected else {
                    return Err(Rejection::ScopeDenied);
                };
                let urn = config::model_urn(&alias);
                if !grant.contains(&urn) {
                    return Err(Rejection::ScopeDenied);
                }
                let releases = tenant_targets
                    .and_then(|overrides| overrides.get(&alias))
                    .or_else(|| targets.get(&alias))
                    .ok_or(Rejection::ScopeDenied)?;
                (urn, vec![select_deployment(request_id, releases)?], None)
            }
            Resource::ModelList { urn, targets } => {
                let mut deployments = Vec::new();
                for (alias, releases) in config::resolved_model_targets(targets, tenant_targets) {
                    if grant.contains(&config::model_urn(alias)) {
                        if self.operation.audience == "urn:plat:maas:kstack"
                            && self.operation.operation == "maas.models.list"
                        {
                            model_aliases.insert(
                                alias.clone(),
                                releases.iter().map(|target| target.deployment.id).collect(),
                            );
                        }
                        deployments.extend(releases.iter().map(|target| target.deployment.clone()));
                    }
                }
                (urn.clone(), deployments, None)
            }
        };
        if !grant.contains(&urn) {
            return Err(Rejection::ScopeDenied);
        }
        let operation = self.operation.operation.as_str();
        let project = Some(self.credential.project.as_str());
        let env = Some(self.credential.env.as_str());
        let policies = &self.admission.policy.leases;
        let leases = [
            (tenant, operation, None, None),
            (tenant, operation, project, None),
            (tenant, operation, project, env),
        ]
        .into_iter()
        .flat_map(|scope| {
            let start = policies.partition_point(|lease| lease.scope() < scope);
            policies[start..]
                .iter()
                .take_while(move |lease| lease.scope() == scope)
        })
        .cloned()
        .collect();
        let cost = batch
            .as_ref()
            .map_or(1, |authorization| authorization.max_requests);
        let mut invocation = ServiceInvocation {
            aud: self.operation.audience.clone(),
            sub: self.credential.subject.clone(),
            tenant: self.credential.tenant.clone(),
            project: self.credential.project.clone(),
            env: self.credential.env.clone(),
            org: self.credential.org.clone(),
            plane: "tenant".to_string(),
            urn,
            operation: self.operation.operation.clone(),
            action,
            method: self.operation.method.clone(),
            path: uri.path().to_owned(),
            query: uri.query().map(str::to_owned),
            request_id,
            trace_id: self
                .delegation
                .as_ref()
                .map_or(trace_id, |ticket| ticket.trace_id.clone()),
            reservation_id: Uuid::new_v4(),
            deployments,
            model_aliases,
            batch,
            vault_binding: None,
            delegation_chain: self
                .delegation
                .as_ref()
                .map_or_else(Vec::new, |ticket| ticket.chain.clone()),
            on_behalf_of: self.delegation.as_ref().map(|ticket| ticket.sub.clone()),
        };
        let debit = self
            .admission
            .budgets
            .debit(
                leases,
                &self.credential.subject,
                self.credential.generation,
                cost,
            )
            .await
            .map_err(budget_rejection)?;
        let mut meter = meter::Meter::begin(spool, &invocation, &debit)
            .await
            .map_err(|error| {
                tracing::error!(%error, "Could not reserve platform usage record");
                Rejection::Unavailable
            })?;
        if self.operation.requires_audit_receipt {
            let Some(audit) = &self.admission.audit else {
                meter.reject(StatusCode::SERVICE_UNAVAILABLE);
                return Err(Rejection::Unavailable);
            };
            invocation.vault_binding = match audit
                .confirm(
                    &invocation,
                    &debit,
                    self.operation.vault_provider.as_deref(),
                    self.operation
                        .has_delegation()
                        .then_some(self.credential.generation),
                    self.delegation.as_ref().map(|ticket| ticket.jti),
                )
                .await
            {
                Ok(binding) => binding,
                Err(()) => {
                    meter.reject(StatusCode::SERVICE_UNAVAILABLE);
                    return Err(Rejection::Unavailable);
                }
            };
        }
        let now = Timestamp::now();
        if self.admission.policy.expires_at <= now
            || self.credential.expires_at <= now
            || !debit.active_at(now)
        {
            meter.reject(StatusCode::SERVICE_UNAVAILABLE);
            return Err(Rejection::Unavailable);
        }
        if let Err(error) = self
            .admission
            .budgets
            .check_credential(&self.credential.subject, self.credential.generation)
        {
            let rejection = budget_rejection(error);
            meter.reject(rejection.status());
            return Err(rejection);
        }
        let signed_at = Timestamp::now();
        let lifetime = self
            .delegation
            .as_ref()
            .map_or(MAX_LIFETIME_SECONDS, |ticket| {
                ticket.remaining_seconds(signed_at)
            });
        let authorization = self
            .admission
            .issuer
            .issue(invocation.clone(), lifetime, signed_at)
            .ok()
            .and_then(|token| HeaderValue::from_str(&format!("Bearer {token}")).ok());
        let Some(mut authorization) = authorization else {
            meter.reject(StatusCode::SERVICE_UNAVAILABLE);
            return Err(Rejection::Unavailable);
        };
        authorization.set_sensitive(true);
        Ok((invocation, authorization, meter))
    }
}

fn budget_rejection(error: budget::BudgetError) -> Rejection {
    match error {
        budget::BudgetError::Exhausted => Rejection::Exhausted,
        budget::BudgetError::Revoked => Rejection::InvalidKey,
        budget::BudgetError::Unavailable => Rejection::Unavailable,
    }
}

pub(crate) fn strip_client_identity(headers: &mut HeaderMap) {
    let reserved = headers
        .keys()
        .filter(|name| {
            name.as_str().starts_with("x-kense-")
                || matches!(
                    name.as_str(),
                    "authorization"
                        | "proxy-authorization"
                        | "x-api-key"
                        | "x-request-id"
                        | "x-forwarded-user"
                        | "x-forwarded-subject"
                        | "x-forwarded-org"
                        | "x-forwarded-plane"
                )
        })
        .cloned()
        .collect::<Vec<_>>();
    for name in reserved {
        headers.remove(name);
    }
    headers.remove(header::COOKIE);
}

pub(crate) fn attach_identity(
    headers: &mut HeaderMap,
    invocation: &ServiceInvocation,
    authorization: HeaderValue,
) -> std::result::Result<(), Rejection> {
    strip_client_identity(headers);
    headers.insert(header::AUTHORIZATION, authorization);
    for (name, value) in [
        ("x-kense-subject", invocation.sub.as_str()),
        ("x-kense-plane", invocation.plane.as_str()),
        ("x-kense-org", invocation.org.as_str()),
        ("x-request-id", invocation.request_id.to_string().as_str()),
    ] {
        headers.insert(
            http::HeaderName::from_static(name),
            HeaderValue::from_str(value).map_err(|_| Rejection::Unavailable)?,
        );
    }
    Ok(())
}

fn select_deployment(
    request_id: Uuid,
    targets: &[ModelTarget],
) -> std::result::Result<DeploymentRef, Rejection> {
    let total = targets
        .iter()
        .map(|target| u128::from(target.weight))
        .sum::<u128>();
    let mut slot = request_id
        .as_u128()
        .checked_rem(total)
        .ok_or(Rejection::Unavailable)?;
    for target in targets {
        let weight = u128::from(target.weight);
        if slot < weight {
            return Ok(target.deployment.clone());
        }
        slot -= weight;
    }
    Err(Rejection::Unavailable)
}

fn matches_operation(operation: &Operation, method: &Method, uri: &Uri) -> bool {
    method.as_str() == operation.method
        && if matches!(operation.resource, Resource::MaasAsset { .. }) {
            assets::matches(operation, uri.path(), uri.query())
        } else {
            uri.path() == operation.path && uri.query().is_none()
        }
}

fn primary_key(headers: &HeaderMap) -> std::result::Result<&str, Rejection> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let header = values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(Rejection::InvalidKey)?;
    if values.next().is_some() {
        return Err(Rejection::InvalidKey);
    }
    let (scheme, value) = header.split_once(' ').ok_or(Rejection::InvalidKey)?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return Err(Rejection::InvalidKey);
    }
    Ok(value)
}
