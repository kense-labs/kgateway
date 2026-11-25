use super::{session::Owner, Rejection};
use crate::platform_identity::valid_identifier;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::{Map, Value};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    audience: String,
    tenant: String,
    project: String,
    env: String,
    subject: String,
    task: String,
    context: Option<String>,
    #[serde(rename = "exp")]
    _expires_at: i64,
}

pub(super) fn needs_authority(method: &str) -> bool {
    matches!(
        method,
        "GetTask" | "CancelTask" | "SubscribeToTask" | "SendMessage" | "SendStreamingMessage"
    )
}

pub(super) fn authorize(
    method: &str,
    params: &mut Option<Map<String, Value>>,
    public_key: Option<&str>,
    owner: &Owner,
) -> Result<(), Rejection> {
    if !needs_authority(method) {
        return Ok(());
    }
    let key = public_key.ok_or(Rejection::Unavailable)?;
    let params = params.as_mut().ok_or(Rejection::InvalidRequest)?;
    if matches!(method, "SendMessage" | "SendStreamingMessage") {
        let message = params
            .get_mut("message")
            .and_then(Value::as_object_mut)
            .ok_or(Rejection::InvalidRequest)?;
        let Some(task_id) = message.get("taskId") else {
            return if message.contains_key("contextId") {
                Err(Rejection::ScopeDenied)
            } else {
                Ok(())
            };
        };
        let verified = verify(task_id, key, owner)?;
        if let Some(context) = message.get("contextId") {
            if context.as_str() != verified.context.as_deref() {
                return Err(Rejection::ScopeDenied);
            }
        }
        message.insert("taskId".to_owned(), Value::String(verified.task));
    } else {
        let task_id = params.get_mut("id").ok_or(Rejection::InvalidRequest)?;
        *task_id = Value::String(verify(task_id, key, owner)?.task);
    }
    Ok(())
}

fn verify(value: &Value, public_key: &str, owner: &Owner) -> Result<Receipt, Rejection> {
    let token = value.as_str().ok_or(Rejection::InvalidRequest)?;
    if token.len() > 4096 {
        return Err(Rejection::ScopeDenied);
    }
    let key =
        DecodingKey::from_ed_pem(public_key.as_bytes()).map_err(|_| Rejection::Unavailable)?;
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.leeway = 0;
    let token = decode::<Receipt>(token, &key, &validation).map_err(|_| Rejection::ScopeDenied)?;
    let ticket = token.claims;
    if token.header.typ.as_deref() != Some("kgateway-a2a-task")
        || ticket.audience != owner.audience
        || ticket.tenant != owner.tenant
        || ticket.project != owner.project
        || ticket.env != owner.env
        || ticket.subject != owner.subject
        || !valid_identifier(&ticket.task)
        || ticket
            .context
            .as_ref()
            .is_some_and(|id| !valid_identifier(id))
    {
        return Err(Rejection::ScopeDenied);
    }
    Ok(ticket)
}
