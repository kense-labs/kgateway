use super::budget::BudgetDebit;
use crate::platform_identity::ServiceInvocation;
use crate::response_body::ResponseBody;
use crate::time::Timestamp;
use crate::usage::{UsageReservation, UsageSpool, UsageSpoolError};
use bytes::Bytes;
use http::{Response, StatusCode};
use hyper::body::{Body, Frame, SizeHint};
use serde_json::json;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use uuid::Uuid;

pub(crate) struct Meter {
    started: serde_json::Value,
    terminal_id: Uuid,
    pending: Option<UsageReservation>,
    status: Option<StatusCode>,
    bytes: u64,
}

impl Meter {
    pub(super) fn reject(&mut self, status: StatusCode) {
        self.status = Some(status);
        self.complete();
    }

    pub(super) async fn begin(
        spool: &UsageSpool,
        invocation: &ServiceInvocation,
        debit: &BudgetDebit,
    ) -> Result<Self, UsageSpoolError> {
        let mut started = json!({
            "schema": "kgateway.platform-usage.v1",
            "kind": "request-started",
            "event_id": invocation.request_id,
            "request_id": invocation.request_id,
            "reservation_id": invocation.reservation_id,
            "trace_id": invocation.trace_id,
            "tenant": invocation.tenant,
            "project": invocation.project,
            "env": invocation.env,
            "subject": invocation.sub,
            "operation": invocation.operation,
            "urn": invocation.urn,
            "at": debit.charged_at,
        });
        debit.record_leases(&mut started);
        if let Some(action) = &invocation.action {
            started["action"] = json!(action);
        }
        if let Some(batch) = &invocation.batch {
            started["reserved_requests"] = json!(batch.max_requests);
            started["batch_models"] = json!(batch.targets.keys().collect::<Vec<_>>());
        }
        let payload = encode(&started)?;
        let (_, pending) = spool
            .append_reserving_terminal(invocation.request_id, &payload)
            .await?;
        Ok(Self {
            started,
            terminal_id: Uuid::new_v4(),
            pending: Some(pending),
            status: None,
            bytes: 0,
        })
    }

    fn finish(&mut self, outcome: &str) {
        let Some(reservation) = self.pending.take() else {
            return;
        };
        let record = self
            .started
            .as_object_mut()
            .expect("usage event is an object");
        record.insert("kind".to_string(), json!("request-terminal"));
        record.insert("event_id".to_string(), json!(self.terminal_id));
        record.insert("at".to_string(), json!(Timestamp::now()));
        record.insert("billing_parent".to_string(), record["request_id"].clone());
        record.insert(
            "status".to_string(),
            json!(self.status.map(|status| status.as_u16())),
        );
        record.insert("outcome".to_string(), json!(outcome));
        record.insert("egress_bytes".to_string(), json!(self.bytes));
        match encode(&self.started)
            .and_then(|payload| reservation.commit(self.terminal_id, payload))
        {
            Ok(receipt) => {
                if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                    runtime.spawn(async move {
                        if let Err(error) = receipt.wait().await {
                            tracing::error!(%error, "Could not persist platform usage terminal");
                        }
                    });
                }
            }
            Err(error) => tracing::error!(%error, "Could not enqueue platform usage terminal"),
        }
    }

    fn complete(&mut self) {
        let successful = self
            .status
            .is_some_and(|status| status.is_success() || status.is_redirection());
        self.finish(if successful { "succeeded" } else { "failed" });
    }
}

impl Drop for Meter {
    fn drop(&mut self) {
        self.finish("disconnected");
    }
}

pub(crate) fn track(
    response: Response<ResponseBody>,
    meter: Option<Meter>,
) -> Response<ResponseBody> {
    let Some(mut meter) = meter else {
        return response;
    };
    meter.status = Some(response.status());
    if response.body().is_end_stream() {
        meter.complete();
        return response;
    }
    let (parts, inner) = response.into_parts();
    Response::from_parts(
        parts,
        ResponseBody::boxed(MeteredBody {
            inner: Box::pin(inner),
            meter,
        }),
    )
}

struct MeteredBody {
    inner: Pin<Box<ResponseBody>>,
    meter: Meter,
}

impl Body for MeteredBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        let result = self.inner.as_mut().poll_frame(cx);
        match &result {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    self.meter.bytes = self.meter.bytes.saturating_add(data.len() as u64);
                }
                if self.inner.is_end_stream() {
                    self.meter.complete();
                }
            }
            Poll::Ready(Some(Err(_))) => self.meter.finish("failed"),
            Poll::Ready(None) => self.meter.complete(),
            Poll::Pending => {}
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

fn encode(value: &serde_json::Value) -> Result<Vec<u8>, UsageSpoolError> {
    serde_json::to_vec(value).map_err(|error| UsageSpoolError::Encode {
        reason: error.to_string(),
    })
}
