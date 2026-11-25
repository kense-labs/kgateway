use super::Rejection;
use crate::response_body::ResponseBody;
use crate::time::Timestamp;
use http::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

const SESSION_ID: HeaderName = HeaderName::from_static("mcp-session-id");
const LAST_EVENT_ID: HeaderName = HeaderName::from_static("last-event-id");
const SESSION_TYPE: &str = "kgateway-mcp-session";
const MAX_LIFETIME: i64 = 900;

pub(super) struct Codec {
    encoder: EncodingKey,
    decoder: DecodingKey,
}

impl Codec {
    pub(super) fn new(key: &[u8]) -> Option<Self> {
        (key.len() == 32).then(|| Self {
            encoder: EncodingKey::from_secret(key),
            decoder: DecodingKey::from_secret(key),
        })
    }

    fn open(&self, signed: &str) -> Option<Receipt> {
        if signed.len() > 4096 {
            return None;
        }
        let mut validation = Validation::new(Algorithm::HS256);
        validation.leeway = 0;
        let session = decode::<Receipt>(signed, &self.decoder, &validation).ok()?;
        (session.header.typ.as_deref() == Some(SESSION_TYPE)).then_some(session.claims)
    }

    fn sign(&self, session: Receipt) -> Option<HeaderValue> {
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some(SESSION_TYPE.to_string());
        let token = encode(&header, &session, &self.encoder).ok()?;
        let mut value = HeaderValue::from_str(&token).ok()?;
        value.set_sensitive(true);
        Some(value)
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct Owner {
    pub subject: String,
    pub generation: u64,
    pub tenant: String,
    pub project: String,
    pub env: String,
    pub audience: String,
    pub path: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    owner: Owner,
    backend: String,
    upstream: String,
    exp: i64,
}

pub(crate) struct Session {
    codec: Option<Arc<Codec>>,
    owner: Owner,
    credential_expiry: i64,
    initialize: bool,
    current: Option<Receipt>,
    backend: Option<String>,
}

pub(crate) fn response(
    session: Option<Session>,
    response: Response<ResponseBody>,
) -> Response<ResponseBody> {
    if let Some(session) = session {
        session.protect_response(response)
    } else {
        response
    }
}

impl Session {
    pub(super) fn read(
        codec: Option<Arc<Codec>>,
        owner: Owner,
        credential_expiry: i64,
        initialize: bool,
        requires_session: bool,
        headers: &mut HeaderMap,
    ) -> Result<Self, Rejection> {
        let has_event_cursor = headers.contains_key(&LAST_EVENT_ID);
        let current = match single_header(headers, &SESSION_ID)? {
            Some(value) if !initialize => {
                let ticket = codec
                    .as_ref()
                    .and_then(|codec| codec.open(value))
                    .filter(|ticket| ticket.owner == owner)
                    .ok_or(Rejection::ScopeDenied)?;
                let mut upstream = HeaderValue::from_str(&ticket.upstream)
                    .map_err(|_| Rejection::InvalidRequest)?;
                upstream.set_sensitive(true);
                headers.insert(&SESSION_ID, upstream);
                Some(ticket)
            }
            Some(_) => return Err(Rejection::InvalidRequest),
            None if has_event_cursor || requires_session => return Err(Rejection::ScopeDenied),
            None => None,
        };
        Ok(Self {
            codec,
            owner,
            credential_expiry,
            initialize,
            current,
            backend: None,
        })
    }

    pub(crate) fn bind_backend(&mut self, address: &str) -> Result<(), Rejection> {
        let fingerprint = format!("{:x}", Sha256::digest(address.as_bytes()));
        if self
            .current
            .as_ref()
            .is_some_and(|ticket| ticket.backend != fingerprint)
        {
            return Err(Rejection::ScopeDenied);
        }
        self.backend = Some(fingerprint);
        Ok(())
    }

    pub(crate) fn protect_response(
        self,
        mut response: Response<ResponseBody>,
    ) -> Response<ResponseBody> {
        if !response.headers().contains_key(&SESSION_ID) {
            return response;
        }
        if !response.status().is_success() {
            response.headers_mut().remove(&SESSION_ID);
            return response;
        }
        let ticket = self.response_ticket(response.headers());
        let Some(ticket) = ticket else {
            let mut failed =
                Response::new(ResponseBody::full("MCP session could not be established"));
            *failed.status_mut() = StatusCode::BAD_GATEWAY;
            return failed;
        };
        response.headers_mut().insert(&SESSION_ID, ticket);
        response
    }

    fn response_ticket(self, headers: &HeaderMap) -> Option<HeaderValue> {
        let id = single_header(headers, &SESSION_ID).ok().flatten()?;
        if id.is_empty() || id.len() > 512 || !id.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        {
            return None;
        }
        let codec = self.codec?;
        let now = Timestamp::now().timestamp();
        let receipt = if self.initialize {
            Receipt {
                owner: self.owner,
                backend: self.backend?,
                upstream: id.to_string(),
                exp: (now + MAX_LIFETIME).min(self.credential_expiry),
            }
        } else {
            self.current.filter(|ticket| ticket.upstream == id)?
        };
        (receipt.exp > now).then(|| codec.sign(receipt)).flatten()
    }
}

fn single_header<'a>(
    headers: &'a HeaderMap,
    name: &HeaderName,
) -> Result<Option<&'a str>, Rejection> {
    let mut values = headers.get_all(name).iter();
    let first = values
        .next()
        .map(|value| value.to_str().map_err(|_| Rejection::InvalidRequest))
        .transpose()?;
    if values.next().is_some() {
        return Err(Rejection::InvalidRequest);
    }
    Ok(first)
}
