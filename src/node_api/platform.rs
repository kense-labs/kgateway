use super::{error_response, json_http_response, NodeApiState, ResponseBody};
use crate::platform::{RevocationError, RevocationUpdate};
use http_body_util::{BodyExt, Limited};
use hyper::{body::Incoming, Method, Request, Response};

const MAX_REVOCATION_BYTES: usize = 256 * 1024;

pub(super) async fn handle_revocations(
    req: Request<Incoming>,
    state: &NodeApiState,
) -> Response<ResponseBody> {
    let Some(store) = &state.platform_budget else {
        return error_response(404, "Platform admission is not configured");
    };
    match *req.method() {
        Method::GET => match store.revocation_status() {
            Some(status) => json_http_response(200, &status),
            None => error_response(503, "Platform admission state is unavailable"),
        },
        Method::POST => {
            let bytes =
                match Limited::new(req.into_body(), MAX_REVOCATION_BYTES)
                    .collect()
                    .await
                {
                    Ok(body) => body.to_bytes(),
                    Err(_) => return error_response(
                        413,
                        "Platform revocation update exceeds the body limit or could not be read",
                    ),
                };
            let update: RevocationUpdate = match serde_json::from_slice(&bytes) {
                Ok(update) => update,
                Err(_) => return error_response(400, "Invalid platform revocation update"),
            };
            match store.apply_revocations(update).await {
                Ok(status) => json_http_response(200, &status),
                Err(RevocationError::Invalid) => {
                    error_response(400, "Invalid or expired platform revocation update")
                }
                Err(RevocationError::Conflict) => {
                    error_response(409, "Platform revocation sequence conflict")
                }
                Err(RevocationError::Unavailable) => {
                    error_response(503, "Platform admission state is unavailable")
                }
            }
        }
        _ => error_response(405, "Unsupported platform revocation method"),
    }
}
