use super::config::valid_urn;
use super::Rejection;
use crate::platform_identity::valid_identifier;
use bytes::Bytes;
use http::{header, HeaderMap};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const MAX_RPC_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    Mcp,
    A2a,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub protocol: Protocol,
    pub methods: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_public_key: Option<String>,
    #[serde(default)]
    pub tools: BTreeMap<String, Tool>,
    #[serde(default)]
    pub origins: BTreeSet<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub urn: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Map<String, Value>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    jsonrpc: String,
    method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    params: Option<Map<String, Value>>,
}

pub(crate) struct Invocation {
    pub action: String,
    pub urn: String,
    pub response: Option<Bytes>,
}

impl Policy {
    pub(super) fn registered_resources(&self) -> Option<BTreeSet<String>> {
        if self.methods.is_empty()
            || self.methods.len() > 16
            || self.tools.len() > 256
            || !valid_origins(&self.origins)
        {
            return None;
        }
        match self.protocol {
            Protocol::Mcp if self.task_public_key.is_some() => return None,
            Protocol::A2a
                if self
                    .methods
                    .keys()
                    .any(|method| super::task::needs_authority(method)) =>
            {
                let key = self.task_public_key.as_ref()?;
                if key.len() > 4096
                    || jsonwebtoken::DecodingKey::from_ed_pem(key.as_bytes()).is_err()
                {
                    return None;
                }
            }
            _ => {}
        }
        if self
            .methods
            .iter()
            .any(|(method, urn)| !self.protocol.registerable(method) || !valid_urn(urn))
            || self.tools.iter().any(|(name, tool)| {
                !valid_identifier(name)
                    || !valid_urn(&tool.urn)
                    || tool.description.len() > 4096
                    || tool.input_schema.get("type").and_then(Value::as_str) != Some("object")
            })
            || (!self.tools.is_empty()
                && (!matches!(self.protocol, Protocol::Mcp)
                    || !(self.methods.contains_key("tools/call")
                        || self.methods.contains_key("tools/list"))))
            || (self.methods.contains_key("tools/call") && self.tools.is_empty())
        {
            return None;
        }
        Some(
            self.methods
                .values()
                .chain(self.tools.values().map(|tool| &tool.urn))
                .cloned()
                .collect(),
        )
    }

    pub(super) fn authorize(
        &self,
        headers: &HeaderMap,
        body: &[u8],
        grant: &BTreeSet<String>,
        owner: &super::session::Owner,
    ) -> Result<(Bytes, Invocation), Rejection> {
        authorize_origin(headers, &self.origins)?;
        let mut media_types = headers.get_all(header::CONTENT_TYPE).iter();
        let media_type = media_types.next().and_then(|value| value.to_str().ok());
        if media_types.next().is_some()
            || media_type.is_none_or(|value| {
                !value
                    .split(';')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .eq_ignore_ascii_case("application/json")
            })
            || headers
                .get_all(header::CONTENT_ENCODING)
                .iter()
                .any(|encoding| encoding != "identity")
        {
            return Err(Rejection::InvalidRequest);
        }
        let mut request =
            serde_json::from_slice::<Request>(body).map_err(|_| Rejection::InvalidRequest)?;
        if request.jsonrpc != "2.0"
            || request
                .id
                .as_ref()
                .is_some_and(|id| !id.is_string() && !id.is_number())
            || (request.id.is_none() && !request.method.starts_with("notifications/"))
        {
            return Err(Rejection::InvalidRequest);
        }
        let operation = self
            .methods
            .get(&request.method)
            .ok_or(Rejection::ScopeDenied)?;
        let urn = if request.method == "tools/call" {
            let params = request.params.as_ref().ok_or(Rejection::InvalidRequest)?;
            if params
                .get("arguments")
                .is_some_and(|arguments| !arguments.is_object())
            {
                return Err(Rejection::InvalidRequest);
            }
            let tool = params
                .get("name")
                .and_then(Value::as_str)
                .ok_or(Rejection::InvalidRequest)?;
            &self.tools.get(tool).ok_or(Rejection::ScopeDenied)?.urn
        } else {
            operation
        };
        if !grant.contains(operation) || !grant.contains(urn) {
            return Err(Rejection::ScopeDenied);
        }
        if matches!(self.protocol, Protocol::A2a) {
            super::task::authorize(
                &request.method,
                &mut request.params,
                self.task_public_key.as_deref(),
                owner,
            )?;
        }
        let response = if request.method == "tools/list" {
            if request
                .params
                .as_ref()
                .is_some_and(|params| params.contains_key("cursor"))
            {
                return Err(Rejection::InvalidRequest);
            }
            let tools: Vec<_> = self.tools.iter()
                .filter(|(_, tool)| grant.contains(&tool.urn))
                .map(|(name, tool)| json!({
                    "name": name, "description": tool.description, "inputSchema": tool.input_schema,
                }))
                .collect();
            Some(Bytes::from(
                serde_json::to_vec(&json!({
                    "jsonrpc": "2.0", "id": request.id, "result": { "tools": tools },
                }))
                .map_err(|_| Rejection::Unavailable)?,
            ))
        } else {
            None
        };
        let normalized = serde_json::to_vec(&request).map_err(|_| Rejection::InvalidRequest)?;
        Ok((
            Bytes::from(normalized),
            Invocation {
                urn: urn.clone(),
                action: request.method,
                response,
            },
        ))
    }
}

pub(super) fn valid_origins(origins: &BTreeSet<String>) -> bool {
    origins.len() <= 32
        && origins.iter().all(|value| {
            reqwest::Url::parse(value).is_ok_and(|origin| {
                origin.origin().ascii_serialization() == *value && origin.scheme() == "https"
            })
        })
}

pub(super) fn authorize_origin(
    headers: &HeaderMap,
    allowed: &BTreeSet<String>,
) -> Result<(), Rejection> {
    let mut origins = headers.get_all(header::ORIGIN).iter();
    if let Some(origin) = origins.next() {
        if origins.next().is_some()
            || origin
                .to_str()
                .ok()
                .is_none_or(|origin| !allowed.contains(origin))
        {
            return Err(Rejection::ScopeDenied);
        }
    }
    Ok(())
}

impl Protocol {
    fn registerable(self, method: &str) -> bool {
        match self {
            Self::Mcp => matches!(
                method,
                "initialize"
                    | "ping"
                    | "notifications/initialized"
                    | "tools/list"
                    | "tools/call"
                    | "notifications/cancelled"
            ),
            Self::A2a => matches!(
                method,
                "SendMessage"
                    | "SendStreamingMessage"
                    | "GetTask"
                    | "ListTasks"
                    | "CancelTask"
                    | "SubscribeToTask"
                    | "GetExtendedAgentCard"
            ),
        }
    }
}
