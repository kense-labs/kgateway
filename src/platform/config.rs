use super::budget::Lease;
use crate::config::{GatewayConfig, OperatingMode, Protocol};
use crate::platform_identity::{valid_identifier, DeploymentRef, MIN_LIFETIME_SECONDS};
use crate::time::Timestamp;
use crate::{GatewayError, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::PathBuf,
};

/// Local paths pinned at bootstrap. Snapshots only carry key identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformBootstrap {
    pub signing_key_file: PathBuf,
    pub budget_state_file: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_session_key_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_receipt_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_verification_key_file: Option<PathBuf>,
}

/// Versioned policy delivered atomically with the routes and backends.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformPolicy {
    pub schema: String,
    pub expires_at: Timestamp,
    pub signer: Signer,
    pub credentials: BTreeMap<String, Credential>,
    pub routes: BTreeMap<String, Operation>,
    pub leases: Vec<Lease>,
}

impl fmt::Debug for PlatformPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlatformPolicy")
            .field("schema", &self.schema)
            .field("expires_at", &self.expires_at)
            .field("credential_count", &self.credentials.len())
            .field("routes", &self.routes.keys())
            .finish_non_exhaustive()
    }
}

pub const POLICY_SCHEMA: &str = "kgateway.platform-policy.v1";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signer {
    pub issuer: String,
    pub key_id: String,
    pub authorized_until: Timestamp,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub subject: String,
    pub generation: u64,
    pub verifier_hash: String,
    pub expires_at: Timestamp,
    pub tenant: String,
    pub project: String,
    pub env: String,
    pub org: String,
    /// Operation ID to exact resource URNs.
    pub grants: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub method: String,
    pub path: String,
    pub audience: String,
    pub operation: String,
    pub resource: Resource,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tenant_targets: BTreeMap<String, ModelTargets>,
    #[serde(default)]
    pub requires_audit_receipt: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_provider: Option<String>,
    #[serde(default)]
    pub accept_delegation: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegate_to: Vec<super::DelegationTarget>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Resource {
    Fixed {
        urn: String,
    },
    MaasAsset {
        urn: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        batch_max_requests: Option<u64>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        targets: ModelTargets,
    },
    Model {
        targets: ModelTargets,
    },
    ModelList {
        urn: String,
        targets: ModelTargets,
    },
    Rpc {
        policy: super::RpcPolicy,
    },
    McpSession {
        urn: String,
        #[serde(default)]
        origins: BTreeSet<String>,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelTarget {
    pub deployment: DeploymentRef,
    pub weight: u16,
}

pub type ModelTargets = BTreeMap<String, Vec<ModelTarget>>;
const MAX_TENANT_TARGETS: usize = 64;

pub(super) fn resolved_model_targets<'a>(
    defaults: &'a ModelTargets,
    overrides: Option<&'a ModelTargets>,
) -> impl Iterator<Item = (&'a String, &'a Vec<ModelTarget>)> {
    defaults.iter().map(move |(alias, targets)| {
        let effective = overrides.and_then(|tenants| tenants.get(alias));
        (alias, effective.unwrap_or(targets))
    })
}

pub(crate) fn validate(config: &GatewayConfig) -> Result<()> {
    let Some(bootstrap) = &config.managed.platform else {
        return if config.platform_policy.is_some() {
            Err(config_error("platform_policy requires managed.platform"))
        } else {
            Ok(())
        };
    };
    let gateway_id = config
        .managed
        .gateway_id
        .ok_or_else(|| config_error("managed.platform requires managed.gateway_id"))?;
    if config.mode != OperatingMode::CloudManaged
        || config.managed.state_file.is_none()
        || config.managed.usage_spool.is_none()
        || !config.management.enabled
    {
        return Err(config_error("managed.platform requires cloud-managed mode, a durable snapshot journal, a usage spool, and a Node API listener"));
    }
    let management_is_loopback = config
        .management
        .address
        .parse::<std::net::SocketAddr>()
        .is_ok_and(|address| address.ip().is_loopback());
    if config.management.tls.is_none() && !management_is_loopback {
        return Err(config_error(
            "Platform Node API requires TLS outside loopback",
        ));
    }
    if let Some(endpoint) = config
        .managed
        .usage_spool
        .as_ref()
        .and_then(|spool| spool.cloud_ingest_endpoint.as_deref())
    {
        let uri = reqwest::Url::parse(endpoint)
            .map_err(|_| config_error("Platform usage endpoint must be a valid URL"))?;
        let is_loopback = match uri.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        };
        if uri.scheme() != "https" && !is_loopback {
            return Err(config_error(
                "Platform usage delivery requires HTTPS outside loopback",
            ));
        }
    }
    if let Some(endpoint) = &bootstrap.audit_receipt_endpoint {
        let receipt = reqwest::Url::parse(endpoint)
            .map_err(|_| config_error("Platform audit receipt endpoint must be a valid URL"))?;
        let collector = config
            .managed
            .usage_spool
            .as_ref()
            .filter(|spool| spool.cloud_ingest_token_env.is_some())
            .and_then(|spool| spool.cloud_ingest_endpoint.as_deref())
            .and_then(|endpoint| reqwest::Url::parse(endpoint).ok());
        if receipt.fragment().is_some()
            || receipt.query().is_some()
            || !receipt.username().is_empty()
            || receipt.password().is_some()
            || collector.is_none_or(|collector| collector.origin() != receipt.origin())
        {
            return Err(config_error("Platform audit receipt endpoint must use the configured usage collector origin and replica bearer credential"));
        }
    }
    if [&bootstrap.signing_key_file, &bootstrap.budget_state_file]
        .iter()
        .any(|path| !path.is_absolute() || path.file_name().is_none())
        || bootstrap.signing_key_file == bootstrap.budget_state_file
        || config.managed.state_file.as_ref() == Some(&bootstrap.budget_state_file)
        || bootstrap.mcp_session_key_file.as_ref().is_some_and(|path| {
            !path.is_absolute()
                || path.file_name().is_none()
                || path == &bootstrap.signing_key_file
                || path == &bootstrap.budget_state_file
                || config.managed.state_file.as_ref() == Some(path)
        })
        || bootstrap
            .delegation_verification_key_file
            .as_ref()
            .is_some_and(|path| {
                !path.is_absolute()
                    || path.file_name().is_none()
                    || path == &bootstrap.signing_key_file
                    || path == &bootstrap.budget_state_file
                    || Some(path) == bootstrap.mcp_session_key_file.as_ref()
                    || Some(path) == config.managed.state_file.as_ref()
            })
    {
        return Err(config_error(
            "managed.platform requires distinct absolute signing and budget file paths",
        ));
    }
    let Some(policy) = &config.platform_policy else {
        if config.routers.is_empty() {
            return Ok(());
        }
        return Err(config_error(
            "managed.platform traffic requires platform_policy",
        ));
    };
    if policy.schema != POLICY_SCHEMA
        || config.inference.is_some()
        || config
            .entrypoints
            .values()
            .any(|listener| listener.protocol != Protocol::Http)
        || policy.routes.len() != config.routers.len()
    {
        return Err(config_error(
            "platform_policy requires HTTP entrypoints and a policy for every router",
        ));
    }
    if config.entrypoints.values().any(|listener| {
        listener.tls.is_none()
            && listener
                .address
                .parse::<std::net::SocketAddr>()
                .is_ok_and(|address| !address.ip().is_loopback())
    }) {
        return Err(config_error(
            "Platform ingress requires TLS outside loopback",
        ));
    }
    let mut operations = BTreeMap::new();
    if !super::delegation::validate_graph(policy)
        || (policy.routes.values().any(Operation::has_delegation)
            && bootstrap.delegation_verification_key_file.is_none())
    {
        return Err(config_error(
            "A2A delegation requires an audited graph and a pinned verification key",
        ));
    }
    for (name, operation) in &policy.routes {
        let router = config
            .routers
            .get(name)
            .ok_or_else(|| config_error("platform_policy names an unknown router"))?;
        let service = config
            .services
            .get(&router.service)
            .ok_or_else(|| config_error("platform_policy router requires an upstream service"))?;
        if service.load_balancer.tls_client_identity_file.is_none()
            || service.mirror.is_some()
            || service.failover.is_some()
        {
            return Err(config_error(
                "platform_policy upstreams require mTLS and one service audience",
            ));
        }
        if operation.has_mcp_sessions()
            && bootstrap.mcp_session_key_file.is_some()
            && (service.load_balancer.servers.len() != 1
                || service.scaling.is_some()
                || !service.revisions.is_empty())
        {
            return Err(config_error(
                "MCP sessions require one stable upstream for their endpoint",
            ));
        }
        if matches!(operation.resource, Resource::McpSession { .. })
            && bootstrap.mcp_session_key_file.is_none()
        {
            return Err(config_error(
                "MCP session operations require managed.platform.mcp_session_key_file",
            ));
        }
        if operation.requires_audit_receipt && bootstrap.audit_receipt_endpoint.is_none() {
            return Err(config_error(
                "A sensitive operation requires a configured audit receipt endpoint",
            ));
        }
        if operation.vault_provider.as_ref().is_some_and(|provider| {
            !valid_identifier(provider)
                || !operation.requires_audit_receipt
                || operation.audience == "urn:plat:maas:kstack"
        }) {
            return Err(config_error(
                "Vault provider requires an audited route for a credential-consuming service",
            ));
        }
        if !valid_identifier(&operation.audience)
            || !valid_identifier(&operation.operation)
            || !matches!(
                operation.method.as_str(),
                "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "PATCH" | "OPTIONS"
            )
            || !operation.path.starts_with('/')
            || operation.path.len() > 256
            || operation
                .path
                .parse::<http::uri::PathAndQuery>()
                .ok()
                .is_none_or(|path| path.query().is_some())
        {
            return Err(config_error(
                "platform_policy contains an invalid operation",
            ));
        }
        if operations
            .insert(
                operation.operation.as_str(),
                operation.validate_resources()?,
            )
            .is_some()
        {
            return Err(config_error("platform_policy operation IDs must be unique"));
        }
    }
    let mut identities = BTreeSet::new();
    for (prefix, key) in &policy.credentials {
        if !prefix.starts_with("kense_")
            || prefix.contains('.')
            || !valid_identifier(prefix)
            || key.generation == 0
            || !identities.insert(key.subject.as_str())
            || ![&key.subject, &key.tenant, &key.project, &key.env, &key.org]
                .iter()
                .all(|value| valid_identifier(value))
        {
            return Err(config_error(
                "platform_policy contains an invalid credential identity",
            ));
        }
        crate::config::validate_argon2id_verifier(&key.verifier_hash)?;
        for (operation, resources) in &key.grants {
            if resources.is_empty()
                || operations
                    .get(operation.as_str())
                    .is_none_or(|registered| !resources.is_subset(registered))
            {
                return Err(config_error(
                    "platform_policy grants an unregistered operation or resource",
                ));
            }
        }
    }
    let mut lease_ids = BTreeSet::new();
    let mut lease_scopes = BTreeMap::<_, Vec<_>>::new();
    for lease in &policy.leases {
        if lease.gateway_id != gateway_id
            || lease.id.is_nil()
            || !valid_identifier(&lease.tenant)
            || lease
                .project
                .as_deref()
                .is_some_and(|value| !valid_identifier(value))
            || lease
                .env
                .as_deref()
                .is_some_and(|value| !valid_identifier(value))
            || (lease.project.is_none() && (lease.env.is_some() || lease.requests == 0))
            || (lease.project.is_some() && lease.starts_at.is_none())
            || lease
                .starts_at
                .is_some_and(|start| start >= lease.expires_at)
            || !operations.contains_key(lease.operation.as_str())
            || !lease_ids.insert(lease.id)
        {
            return Err(config_error(
                "platform_policy contains an invalid or duplicate budget lease",
            ));
        }
        lease_scopes.entry(lease.scope()).or_default().push(lease);
    }
    for &(tenant, operation, project, env) in lease_scopes.keys() {
        if env.is_some() && !lease_scopes.contains_key(&(tenant, operation, project, None)) {
            return Err(config_error(
                "platform_policy environment lease requires a project lease",
            ));
        }
    }
    for leases in lease_scopes.values_mut() {
        leases.sort_unstable_by_key(|lease| lease.expires_at);
        if leases.len() > 2
            || leases.windows(2).any(|pair| {
                pair[1]
                    .starts_at
                    .is_none_or(|start| start < pair[0].expires_at)
            })
        {
            return Err(config_error(
                "platform_policy contains overlapping budget leases",
            ));
        }
    }
    Ok(())
}

impl Operation {
    pub(super) fn has_delegation(&self) -> bool {
        self.accept_delegation || !self.delegate_to.is_empty()
    }

    pub(super) fn has_mcp_sessions(&self) -> bool {
        match &self.resource {
            Resource::McpSession { .. } => true,
            Resource::Rpc { policy } => matches!(policy.protocol, super::RpcProtocol::Mcp),
            _ => false,
        }
    }

    fn validate_resources(&self) -> Result<BTreeSet<String>> {
        if !self.tenant_targets.is_empty()
            && (self.audience != "urn:plat:maas:kstack"
                || self.tenant_targets.len() > MAX_TENANT_TARGETS
                || !(matches!(
                    self.resource,
                    Resource::Model { .. } | Resource::ModelList { .. }
                ) || self.operation == super::assets::BATCH_CREATE
                    && matches!(self.resource, Resource::MaasAsset { .. })))
        {
            return Err(config_error(
                "tenant targets require a kstack model or batch-create route",
            ));
        }
        let mut resources = BTreeSet::new();
        let targets = match &self.resource {
            Resource::McpSession { urn, origins } => {
                if !matches!(self.method.as_str(), "GET" | "DELETE")
                    || !valid_urn(urn)
                    || !super::rpc::valid_origins(origins)
                {
                    return Err(config_error(
                        "platform_policy contains an invalid MCP session resource",
                    ));
                }
                return Ok(BTreeSet::from([urn.clone()]));
            }
            Resource::Rpc { policy } => {
                if self.method != "POST"
                    || crate::inference::OpenAiRequestProfile::match_request(
                        &http::Method::POST,
                        &self.path,
                    )
                    .is_some()
                {
                    return Err(config_error(
                        "RPC operations require a dedicated POST endpoint",
                    ));
                }
                return policy.registered_resources().ok_or_else(|| {
                    config_error("platform_policy contains invalid RPC resource rules")
                });
            }
            Resource::Fixed { urn } => {
                if !valid_urn(urn) {
                    return Err(config_error(
                        "platform_policy contains an invalid resource URN",
                    ));
                }
                resources.insert(urn.clone());
                return Ok(resources);
            }
            Resource::MaasAsset {
                urn,
                batch_max_requests,
                targets,
            } => {
                if !super::assets::valid_config(self, urn) {
                    return Err(config_error(
                        "platform_policy contains an invalid MaaS asset route",
                    ));
                }
                resources.insert(urn.clone());
                if self.operation != super::assets::BATCH_CREATE {
                    return if batch_max_requests.is_none() && targets.is_empty() {
                        Ok(resources)
                    } else {
                        Err(config_error(
                            "batch authorization is only valid on batch creation",
                        ))
                    };
                }
                if !batch_max_requests.is_some_and(|cap| (1..=50_000).contains(&cap))
                    || targets.is_empty()
                    || targets.len() > super::assets::MAX_BATCH_TARGETS
                {
                    return Err(config_error(
                        "batch creation requires bounded work and pinned model targets",
                    ));
                }
                targets
            }
            Resource::ModelList { urn, targets } => {
                if self.method != "GET"
                    || self.path != "/v1/models"
                    || urn != "urn:plat:maas:models"
                {
                    return Err(config_error(
                        "model-list operations require the MaaS models endpoint",
                    ));
                }
                resources.insert(urn.clone());
                targets
            }
            Resource::Model { targets } => {
                let profile = crate::inference::OpenAiRequestProfile::match_request(
                    &http::Method::POST,
                    &self.path,
                );
                if self.method != "POST"
                    || !profile
                        .is_some_and(crate::inference::OpenAiRequestProfile::requires_json_body)
                {
                    return Err(config_error(
                        "model operations require an OpenAI JSON endpoint",
                    ));
                }
                targets
            }
        };
        validate_model_targets(targets.iter())?;
        resources.extend(targets.keys().map(|alias| model_urn(alias)));
        for (tenant, overrides) in &self.tenant_targets {
            if !valid_identifier(tenant)
                || overrides.is_empty()
                || overrides.keys().any(|alias| !targets.contains_key(alias))
            {
                return Err(config_error(
                    "tenant targets must override registered model aliases",
                ));
            }
            validate_model_targets(resolved_model_targets(targets, Some(overrides)))?;
        }
        Ok(resources)
    }
}

fn validate_model_targets<'a>(
    targets: impl Iterator<Item = (&'a String, &'a Vec<ModelTarget>)>,
) -> Result<()> {
    let mut deployment_ids = BTreeSet::new();
    for (alias, releases) in targets {
        if !valid_identifier(alias) || releases.is_empty() {
            return Err(config_error(
                "platform_policy contains an invalid model alias",
            ));
        }
        for target in releases {
            let Some(digest) = target.deployment.version.strip_prefix("sha256:") else {
                return Err(config_error(
                    "platform_policy contains an invalid deployment version",
                ));
            };
            if target.deployment.id == 0
                || target.deployment.id >= 1_u64 << 53
                || digest.len() != 64
                || !digest
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                || !deployment_ids.insert(target.deployment.id)
                || target.weight == 0
            {
                return Err(config_error(
                    "platform_policy contains an invalid or duplicate deployment target",
                ));
            }
        }
    }
    if deployment_ids.len() > 64 {
        return Err(config_error(
            "platform_policy exceeds the deployment scope limit",
        ));
    }
    Ok(())
}

pub(super) fn model_urn(alias: &str) -> String {
    format!("urn:plat:maas:model:{alias}")
}

pub(super) fn valid_urn(value: &str) -> bool {
    value.len() > "urn:plat:".len()
        && value.len() <= 256
        && value.starts_with("urn:plat:")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

impl PlatformPolicy {
    pub(crate) fn validate_expiry(
        &self,
        issued_at: Timestamp,
        expires_at: Timestamp,
    ) -> std::result::Result<(), String> {
        if self.expires_at <= issued_at
            || self.expires_at > expires_at
            || self.signer.authorized_until.timestamp() - issued_at.timestamp()
                < MIN_LIFETIME_SECONDS as i64
        {
            return Err(
                "platform_policy validity must fit the snapshot and signing authorization"
                    .to_string(),
            );
        }
        Ok(())
    }
}

fn config_error(reason: &str) -> GatewayError {
    GatewayError::Config(reason.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tenant_targets_keep_the_registered_aliases_and_validate_the_effective_scope() {
        let target = |id| {
            json!([{"deployment": {
            "id": id, "version": format!("sha256:{}", "1".repeat(64))
        }, "weight": 1}])
        };
        let policy = json!({
            "method": "GET", "path": "/v1/models", "operation": "maas.models.list",
            "audience": "urn:plat:maas:kstack",
            "resource": {"kind": "model-list", "urn": "urn:plat:maas:models", "targets": {"a": target(1), "b": target(2)}},
            "tenant_targets": {"pilot": {"a": target(3)}}
        });
        let parse =
            |value| serde_json::from_value::<Operation>(value).expect("policy is valid JSON");
        assert!(parse(policy.clone()).validate_resources().is_ok());

        for tenant_targets in [
            json!({"pilot": {"unknown": target(4)}}),
            json!({"pilot": {"a": target(2)}}),
        ] {
            let mut invalid = policy.clone();
            invalid["tenant_targets"] = tenant_targets;
            assert!(parse(invalid).validate_resources().is_err());
        }
        let mut other_service = policy;
        other_service["audience"] = json!("urn:plat:service:other");
        assert!(parse(other_service).validate_resources().is_err());
    }
}
