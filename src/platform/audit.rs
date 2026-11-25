use super::budget::BudgetDebit;
use crate::platform_identity::{ServiceInvocation, VaultBinding};
use crate::usage::HttpUsageCloudTransport;
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;
use uuid::Uuid;

pub(super) struct Client {
    pub endpoint: String,
    pub gateway_id: Uuid,
    pub transport: HttpUsageCloudTransport,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: String,
    gateway_id: Uuid,
    request_id: Uuid,
    sequence: u64,
    digest: String,
    vault_binding: Option<VaultBinding>,
}

impl Client {
    pub(super) async fn confirm(
        &self,
        invocation: &ServiceInvocation,
        debit: &BudgetDebit,
        vault_provider: Option<&str>,
        delegation_generation: Option<u64>,
        delegation_ticket: Option<Uuid>,
    ) -> Result<Option<VaultBinding>, ()> {
        let mut request = json!({
            "schema": "kgateway.audit-admission.v1",
            "gateway_id": self.gateway_id,
            "request_id": invocation.request_id,
            "reservation_id": invocation.reservation_id,
            "subject": invocation.sub,
            "tenant": invocation.tenant,
            "project": invocation.project,
            "env": invocation.env,
            "trace_id": invocation.trace_id,
            "method": invocation.method,
            "path": invocation.path,
            "operation": invocation.operation,
            "urn": invocation.urn,
            "protocol_action": invocation.action,
        });
        debit.record_leases(&mut request);
        if let Some(query) = &invocation.query {
            request["query"] = json!(query);
        }
        if let Some(provider) = vault_provider {
            request["vault_provider"] = json!(provider);
        }
        if let Some(generation) = delegation_generation {
            request["audience"] = json!(&invocation.aud);
            request["credential_generation"] = json!(generation);
            if let Some(ticket) = delegation_ticket {
                request["delegation_ticket"] = json!(ticket);
            }
        }
        let response = self
            .transport
            .authenticated_post(&self.endpoint)
            .timeout(Duration::from_secs(2))
            .json(&request)
            .send()
            .await;
        let response = response.map_err(|_| ())?;
        if response.status() != http::StatusCode::OK {
            return Err(());
        }
        let mut body = Vec::new();
        let mut chunks = response.bytes_stream();
        while let Some(chunk) = chunks.next().await {
            let chunk = chunk.map_err(|_| ())?;
            if body.len() + chunk.len() > 4096 {
                return Err(());
            }
            body.extend_from_slice(&chunk);
        }
        let receipt: Receipt = serde_json::from_slice(&body).map_err(|_| ())?;
        let valid = receipt.schema == "kgateway.audit-receipt.v1"
            && receipt.gateway_id == self.gateway_id
            && receipt.request_id == invocation.request_id
            && receipt.sequence > 0
            && receipt.digest.len() == 64
            && receipt
                .digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            && match (vault_provider, &receipt.vault_binding) {
                (Some(_), Some(binding)) => binding.valid(),
                (None, None) => true,
                _ => false,
            };
        valid.then_some(receipt.vault_binding).ok_or(())
    }
}
