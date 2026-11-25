use super::config::Operation;

const AUDIENCE: &str = "urn:plat:maas:kstack";
const FILES_URN: &str = "urn:plat:maas:files";
const BATCHES_URN: &str = "urn:plat:maas:batches";
pub(super) const BATCH_CREATE: &str = "maas.batches.create";
pub(super) const MAX_BATCH_TARGETS: usize = 32;

struct Route {
    method: &'static str,
    template: &'static str,
    urn: &'static str,
}

fn route(operation: &str) -> Option<Route> {
    let (method, template, urn) = match operation {
        "maas.files.list" => ("GET", "/v1/files", FILES_URN),
        "maas.files.create" => ("POST", "/v1/files", FILES_URN),
        "maas.files.get" => ("GET", "/v1/files/{id}", FILES_URN),
        "maas.files.content" => ("GET", "/v1/files/{id}/content", FILES_URN),
        "maas.files.delete" => ("DELETE", "/v1/files/{id}", FILES_URN),
        "maas.batches.list" => ("GET", "/v1/batches", BATCHES_URN),
        BATCH_CREATE => ("POST", "/v1/batches", BATCHES_URN),
        "maas.batches.get" => ("GET", "/v1/batches/{id}", BATCHES_URN),
        "maas.batches.cancel" => ("POST", "/v1/batches/{id}/cancel", BATCHES_URN),
        _ => return None,
    };
    Some(Route {
        method,
        template,
        urn,
    })
}

pub(super) fn valid_config(operation: &Operation, urn: &str) -> bool {
    operation.audience == AUDIENCE
        && route(&operation.operation).is_some_and(|route| {
            route.urn == urn && route.method == operation.method && route.template == operation.path
        })
}

pub(super) fn matches(operation: &Operation, path: &str, query: Option<&str>) -> bool {
    let Some(route) = route(&operation.operation) else {
        return false;
    };
    if query.is_some_and(|query| match operation.operation.as_str() {
        "maas.files.list" => !valid_list_query(query, true),
        "maas.batches.list" => !valid_list_query(query, false),
        _ => true,
    }) {
        return false;
    }
    if let Some((prefix, suffix)) = route.template.split_once("{id}") {
        path.strip_prefix(prefix)
            .and_then(|rest| rest.strip_suffix(suffix))
            .and_then(|id| {
                id.strip_prefix(if route.urn == FILES_URN {
                    "file-"
                } else {
                    "batch_"
                })
            })
            .is_some_and(|hex| {
                hex.len() == 24
                    && hex
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            })
    } else {
        path == route.template
    }
}

fn valid_list_query(query: &str, files: bool) -> bool {
    if query.is_empty() || query.len() > 256 {
        return false;
    }
    let mut seen = 0;
    for field in query.split('&') {
        let Some((key, value)) = field.split_once('=') else {
            return false;
        };
        let flag = match key {
            "after" => 1,
            "limit" => 2,
            "order" => 4,
            "purpose" if files => 8,
            _ => return false,
        };
        if seen & flag != 0
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return false;
        }
        seen |= flag;
    }
    true
}
