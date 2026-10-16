//! Scoped forwarding of a fixed, reviewed Genesis Mesh authority API catalog.
use super::{runtime::Principal, ApiError, AppState};
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::OnceLock};

#[derive(Deserialize)]
struct Operation {
    id: String,
    group: String,
    method: String,
    upstream_path: String,
    admin: bool,
    parameters: Vec<String>,
    query: Vec<String>,
    /// `ndjson` for newline-delimited JSON (the evidence export); JSON otherwise.
    #[serde(default)]
    response: Option<String>,
    #[serde(default)]
    max_response_bytes: Option<usize>,
}

/// Default limit on an authority response forwarded to a client.
const MAX_RESPONSE: usize = 2 * 1024 * 1024;

/// Limit on the body of an authority `503` relayed to a client: an error
/// object, never a payload (1.3.1).
const MAX_UNAVAILABLE_RESPONSE: usize = 16 * 1024;

/// Path parameters that carry protocol identifiers rather than the
/// gateway's ASCII resource names. `resource_id` may span segments
/// (`kv:vault/secret`); both may contain non-ASCII text.
const PATH_PARAMETERS: [&str; 1] = ["resource_id"];
const TEXT_PARAMETERS: [&str; 2] = ["resource_id", "vendor_id"];

/// A path segment from protocol text: nonempty, not a dot segment, no
/// control characters, and no `%` or `\` that a server or proxy could decode
/// or normalise into another path.
fn valid_text_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && !segment
            .chars()
            .any(|c| c.is_control() || matches!(c, '%' | '\\' | '/'))
}

fn operations() -> &'static Vec<Operation> {
    static OPS: OnceLock<Vec<Operation>> = OnceLock::new();
    OPS.get_or_init(|| {
        serde_json::from_str(include_str!("../../ui/services.json")).expect("service catalog")
    })
}

pub(super) async fn catalog() -> Json<Value> {
    Json(
        json!({"operations": serde_json::from_str::<Value>(include_str!("../../ui/services.json")).expect("catalog"),
        "route_template": "/v1/networks/{network}/services/{operation}"}),
    )
}

pub(super) async fn execute(
    State(state): State<AppState>,
    (Extension(principal), Extension(facts)): (
        Extension<Principal>,
        Extension<super::runtime::AuditFacts>,
    ),
    Path((network, operation)): Path<(String, String)>,
    Query(query): Query<BTreeMap<String, String>>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let security = state.security.load_full();
    let policy = security.as_ref().ok_or_else(|| {
        ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "authority policy required".into(),
        )
    })?;
    let client = &policy.clients[principal.0.ok_or_else(ApiError::unauthorized)?];
    // Authorize before disclosing whether a network exists or contacting it.
    if !client.networks.contains(&network) {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "network not authorized".into(),
        ));
    }
    let op = operations()
        .iter()
        .find(|o| o.id == operation)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "unknown service operation".into()))?;
    if let Ok(mut context) = facts.0.lock() {
        context.insert("network".into(), json!(network));
        context.insert("operation".into(), json!(op.id));
    }
    if method.as_str() != op.method {
        return Err(ApiError(
            StatusCode::METHOD_NOT_ALLOWED,
            "method does not match service operation".into(),
        ));
    }
    if !client.service_groups.contains(&op.group)
        || (op.admin && (!client.authority_admin || client.demo))
    {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "service operation not authorized".into(),
        ));
    }
    let upstream = policy.networks[&network]
        .authority_url
        .as_ref()
        .ok_or_else(|| {
            ApiError(
                StatusCode::SERVICE_UNAVAILABLE,
                "authority not configured".into(),
            )
        })?;
    let mut url = reqwest::Url::parse(upstream).map_err(|_| ApiError::internal("authority URL"))?;
    if query.len() > 24
        || query
            .iter()
            .any(|(k, v)| v.len() > 2048 || (!op.parameters.contains(k) && !op.query.contains(k)))
    {
        return Err(ApiError::bad_request(
            "unsupported or oversized query parameter",
        ));
    }
    push_upstream_path(&mut url, &op.upstream_path, &query)?;
    for (key, value) in &query {
        if op.query.contains(key) {
            url.query_pairs_mut().append_pair(key, value);
        }
    }
    let mut request = state.authority_http.request(method.clone(), url);
    if method == Method::GET {
        if !body.is_empty() {
            return Err(ApiError::bad_request("GET does not accept a body"));
        }
    } else {
        let parsed: Value = serde_json::from_slice(&body)
            .map_err(|_| ApiError::bad_request("JSON object required"))?;
        if !parsed.is_object() {
            return Err(ApiError::bad_request("JSON object required"));
        }
        request = request
            .header("content-type", "application/json")
            .body(body);
    }
    if op.admin {
        for name in [
            "x-admin-key-id",
            "x-admin-timestamp",
            "x-admin-nonce",
            "x-admin-signature",
        ] {
            let value = headers
                .get(name)
                // The authority refuses longer values, and counts them as failures.
                .filter(|h| !h.is_empty() && h.len() <= 256)
                .ok_or_else(|| {
                    ApiError(
                        StatusCode::UNAUTHORIZED,
                        "operator-signed headers required for this operation".into(),
                    )
                })?;
            request = request.header(name, value);
        }
    }
    // No gateway bearer token, cookie, forwarding header or client URL reaches the authority.
    let mut upstream = request
        .send()
        .await
        .map_err(|_| ApiError(StatusCode::BAD_GATEWAY, "authority unavailable".into()))?;
    let forwarded = upstream_headers(upstream.headers());
    let relayed = async {
        let status = upstream.status();
        let failed = || ApiError(StatusCode::BAD_GATEWAY, "authority request failed".into());
        // An authority 503 keeps its JSON object, so its code reaches the
        // client: SDKs never break the glass on `evidence_store_unavailable`,
        // which a 502 would hide (1.3.1). Other server errors and redirects
        // are the gateway's 502, their bodies unread.
        let unavailable = status == StatusCode::SERVICE_UNAVAILABLE;
        if status.is_redirection() || (status.is_server_error() && !unavailable) {
            return Err(failed());
        }
        let limit = if unavailable {
            MAX_UNAVAILABLE_RESPONSE
        } else {
            op.max_response_bytes.unwrap_or(MAX_RESPONSE)
        };
        let too_large = || {
            if unavailable {
                failed()
            } else {
                ApiError(
                    StatusCode::BAD_GATEWAY,
                    "authority response too large".into(),
                )
            }
        };
        if upstream.content_length().is_some_and(|n| n > limit as u64) {
            return Err(too_large());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = upstream
            .chunk()
            .await
            .map_err(|_| ApiError(StatusCode::BAD_GATEWAY, "authority response failed".into()))?
        {
            if bytes.len() + chunk.len() > limit {
                return Err(too_large());
            }
            bytes.extend_from_slice(&chunk);
        }
        if unavailable {
            return match serde_json::from_slice::<Value>(&bytes) {
                Ok(payload) if payload.is_object() => {
                    tracing::info!(target: "audit", client_id = %client.id, network = %network, operation = %op.id, status = status.as_u16(), "authority operation unavailable");
                    Ok((status, Json(payload)).into_response())
                }
                _ => Err(failed()),
            };
        }
        if status.is_success() && op.response.as_deref() == Some("ndjson") {
            let text = ndjson_text(bytes)?;
            tracing::info!(target: "audit", client_id = %client.id, network = %network, operation = %op.id, status = status.as_u16(), "authority operation completed");
            return Ok((
                status,
                [(axum::http::header::CONTENT_TYPE, "application/x-ndjson")],
                text,
            )
                .into_response());
        }
        let payload: Value = serde_json::from_slice(&bytes).map_err(|_| {
            ApiError(
                StatusCode::BAD_GATEWAY,
                "authority returned invalid JSON".into(),
            )
        })?;
        tracing::info!(target: "audit", client_id = %client.id, network = %network, operation = %op.id, status = status.as_u16(), "authority operation completed");
        Ok((status, Json(payload)).into_response())
    };
    let mut response = relayed.await.unwrap_or_else(IntoResponse::into_response);
    for (name, value) in forwarded {
        response.headers_mut().insert(name, value);
    }
    // A relayed 429 or 503 always says when to retry, as the gateway's own do.
    if matches!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
    ) && !response.headers().contains_key("retry-after")
    {
        response
            .headers_mut()
            .insert("retry-after", axum::http::HeaderValue::from_static("60"));
    }
    Ok(response)
}

/// Replace `url`'s path with the operation's upstream path template, each
/// `{name}` filled from the request's parameters. Every value is validated and
/// pushed as encoded segments, so a value can never add, remove or climb
/// path segments; `resource_id` may span several segments.
fn push_upstream_path(
    url: &mut reqwest::Url,
    template: &str,
    query: &BTreeMap<String, String>,
) -> Result<(), ApiError> {
    let mut segments = url
        .path_segments_mut()
        .map_err(|_| ApiError::internal("authority path"))?;
    segments.clear();
    for segment in template.trim_start_matches('/').split('/') {
        if let Some(name) = segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            let value = query
                .get(name)
                .filter(|s| !s.is_empty() && s.as_str() != "." && s.as_str() != "..")
                .ok_or_else(|| ApiError::bad_request(format!("missing or invalid {name}")))?;
            let parts: Vec<&str> = if PATH_PARAMETERS.contains(&name) {
                value.split('/').collect()
            } else {
                vec![value.as_str()]
            };
            let valid = if name == "node_public_key" {
                crate::crypto::validate_public_key(value).unwrap_or(false)
            } else if TEXT_PARAMETERS.contains(&name) {
                parts.iter().all(|part| valid_text_segment(part))
            } else {
                value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.:@".contains(&b))
            };
            if !valid {
                return Err(ApiError::bad_request("invalid resource identifier"));
            }
            // Each part encoded once as one segment; never interpolate untrusted paths.
            for part in parts {
                segments.push(part);
            }
        } else {
            segments.push(segment);
        }
    }
    Ok(())
}

/// A JSON Lines answer from the authority, passed on as text: valid UTF-8,
/// and every nonblank line a JSON object. The gateway forwards records, not
/// markup.
fn ndjson_text(bytes: Vec<u8>) -> Result<String, ApiError> {
    let text = String::from_utf8(bytes).map_err(|_| {
        ApiError(
            StatusCode::BAD_GATEWAY,
            "authority returned invalid text".into(),
        )
    })?;
    if !text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .all(|line| serde_json::from_str::<Value>(line).is_ok_and(|v| v.is_object()))
    {
        return Err(ApiError(
            StatusCode::BAD_GATEWAY,
            "authority returned invalid JSON Lines".into(),
        ));
    }
    Ok(text)
}

/// What the gateway passes on from the authority's response, when well
/// formed: `Retry-After` in seconds (kept between 1 and 3600) and its request
/// ID as `X-Upstream-Request-ID`, so a client can wait as long as the
/// authority asks and quote the authority's ID when reporting a failure.
fn upstream_headers(
    headers: &reqwest::header::HeaderMap,
) -> Vec<(&'static str, axum::http::HeaderValue)> {
    let mut out = Vec::new();
    let text = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
    };
    if let Some(seconds) = text("retry-after")
        .filter(|v| !v.is_empty() && v.len() <= 5 && v.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|v| v.parse::<u32>().ok())
    {
        out.push((
            "retry-after",
            axum::http::HeaderValue::from(seconds.clamp(1, 3600)),
        ));
    }
    if let Some(id) = text("x-request-id").filter(|v| {
        !v.is_empty()
            && v.len() <= 128
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
    }) {
        if let Ok(value) = axum::http::HeaderValue::from_str(id) {
            out.push(("x-upstream-request-id", value));
        }
    }
    out
}

#[cfg(test)]
mod properties {
    //! Property tests of the request parsers: the path segment validator,
    //! upstream path building and the JSON Lines reader.
    use super::*;
    use proptest::prelude::*;

    /// The segment rule, written out independently of `valid_text_segment`.
    fn segment_rule(segment: &str) -> bool {
        !(segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.contains(['%', '\\', '/'])
            || segment.chars().any(char::is_control))
    }

    fn percent_decoded(segment: &str) -> String {
        let bytes = segment.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                out.push(u8::from_str_radix(&segment[i + 1..i + 3], 16).unwrap());
                i += 3;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        }
        String::from_utf8(out).unwrap()
    }

    /// Any text, weighted towards the characters that matter here.
    fn text() -> impl Strategy<Value = String> {
        prop_oneof![
            prop::collection::vec(any::<char>(), 0..12).prop_map(String::from_iter),
            "[a-z0-9./%:@ \\\\-]{0,10}",
            "(\\.{1,2}|[a-z]{1,3})(/(\\.{0,2}|[a-z]{1,3})){0,3}",
            prop::sample::select(vec![
                "",
                ".",
                "..",
                "/",
                "a/",
                "/a",
                "a//b",
                "kv:vault/secret",
                "zo\u{eb}",
            ])
            .prop_map(str::to_owned),
        ]
    }

    fn build(template: &str, name: &str, value: &str) -> Result<reqwest::Url, ApiError> {
        let mut url = reqwest::Url::parse("https://authority.example:8443/prefix/").unwrap();
        let query = BTreeMap::from([(name.to_owned(), value.to_owned())]);
        push_upstream_path(&mut url, template, &query).map(|()| url)
    }

    fn segments(url: &reqwest::Url) -> Vec<String> {
        url.path_segments().unwrap().map(percent_decoded).collect()
    }

    /// A JSON object as the authority writes one record per line.
    fn record() -> impl Strategy<Value = String> {
        let value = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<i64>().prop_map(Value::from),
            text().prop_map(Value::String),
        ];
        prop::collection::btree_map(text(), value, 0..5).prop_map(|map| {
            serde_json::to_string(&Value::Object(map.into_iter().collect())).unwrap()
        })
    }

    /// A line that is not a JSON object.
    fn not_a_record() -> impl Strategy<Value = String> {
        prop_oneof![
            any::<i64>().prop_map(|n| n.to_string()),
            text().prop_map(|s| serde_json::to_string(&s).unwrap()),
            Just("[]".to_owned()),
            Just("[{}]".to_owned()),
            Just("null".to_owned()),
            Just("true".to_owned()),
            Just("{".to_owned()),
            Just("{\"a\":1}}".to_owned()),
            "[a-z<>]{1,8}",
        ]
    }

    fn lines(records: &[String], crlf: bool, blank: bool, trailing: bool) -> String {
        let newline = if crlf { "\r\n" } else { "\n" };
        let mut text = String::new();
        for (i, record) in records.iter().enumerate() {
            if blank && i % 2 == 1 {
                text.push_str("  ");
                text.push_str(newline);
            }
            text.push_str(record);
            if i + 1 < records.len() || trailing {
                text.push_str(newline);
            }
        }
        text
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn valid_text_segment_follows_its_rule(segment in text()) {
            prop_assert_eq!(valid_text_segment(&segment), segment_rule(&segment));
        }

        /// A resource ID becomes exactly its `/`-separated parts as encoded
        /// segments between the template's own, or is refused; it can never
        /// add a dot segment, change the authority or add a query.
        #[test]
        fn a_resource_id_becomes_its_own_segments_or_is_refused(value in text()) {
            let template = "/evidence/resources/{resource_id}/head";
            let accepted = value != "." && value != ".." && !value.is_empty()
                && value.split('/').all(segment_rule);
            let result = build(template, "resource_id", &value);
            prop_assert_eq!(result.is_ok(), accepted, "{:?}", value);
            match result {
                Ok(url) => {
                    let mut expected = vec!["evidence".to_owned(), "resources".to_owned()];
                    expected.extend(value.split('/').map(str::to_owned));
                    expected.push("head".to_owned());
                    prop_assert_eq!(segments(&url), expected);
                    prop_assert!(url.path_segments().unwrap().all(|s| s != "." && s != ".."));
                    prop_assert_eq!(url.host_str(), Some("authority.example"));
                    prop_assert_eq!(url.port(), Some(8443));
                    prop_assert_eq!(url.query(), None);
                }
                Err(error) => prop_assert_eq!(error.0, StatusCode::BAD_REQUEST),
            }
        }

        /// A text parameter that is not a resource ID is one segment.
        #[test]
        fn a_vendor_id_is_one_segment_or_is_refused(value in text()) {
            let result = build("/evidence/vendors/{vendor_id}/history", "vendor_id", &value);
            prop_assert_eq!(result.is_ok(), segment_rule(&value), "{:?}", value);
            if let Ok(url) = result {
                let expected = ["evidence", "vendors", value.as_str(), "history"].map(str::to_owned);
                prop_assert_eq!(segments(&url), expected.to_vec());
            }
        }

        /// Any other parameter is a plain identifier, kept as one segment.
        #[test]
        fn an_identifier_is_one_plain_segment_or_is_refused(value in text()) {
            let accepted = value != "." && value != ".." && !value.is_empty()
                && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.:@".contains(&b));
            let result = build("/grants/{grant_id}", "grant_id", &value);
            prop_assert_eq!(result.is_ok(), accepted, "{:?}", value);
            if let Ok(url) = result {
                prop_assert_eq!(url.path(), format!("/grants/{value}"));
            }
        }

        /// A template parameter the request does not carry is refused.
        #[test]
        fn a_missing_parameter_is_refused(value in text()) {
            let error = build("/grants/{grant_id}", "other", &value).unwrap_err();
            prop_assert_eq!(error.0, StatusCode::BAD_REQUEST);
        }

        /// JSON Lines of objects pass through unchanged, with LF or CRLF line
        /// ends, blank lines and an optional final newline.
        #[test]
        fn json_lines_of_objects_pass_unchanged(
            records in prop::collection::vec(record(), 0..6),
            crlf in any::<bool>(),
            blank in any::<bool>(),
            trailing in any::<bool>(),
        ) {
            let text = lines(&records, crlf, blank, trailing);
            prop_assert_eq!(ndjson_text(text.clone().into_bytes()).ok(), Some(text));
        }

        /// One line that is not a JSON object refuses the whole answer.
        #[test]
        fn a_line_that_is_not_an_object_is_refused(
            records in prop::collection::vec(record(), 0..6),
            bad in not_a_record(),
            at in any::<prop::sample::Index>(),
            crlf in any::<bool>(),
        ) {
            let mut records = records;
            let position = at.index(records.len() + 1);
            records.insert(position, bad);
            let error = ndjson_text(lines(&records, crlf, false, true).into_bytes()).unwrap_err();
            prop_assert_eq!(error.0, StatusCode::BAD_GATEWAY);
        }

        /// Text that is not UTF-8 is refused.
        #[test]
        fn invalid_utf8_is_refused(
            records in prop::collection::vec(record(), 0..4),
            at in any::<prop::sample::Index>(),
            byte in 0x80u8..=0xff,
        ) {
            let text = lines(&records, false, false, true);
            // Only at a line boundary, so the byte cannot complete a
            // multi-byte character; alone between newlines it is never UTF-8.
            let boundaries: Vec<usize> = std::iter::once(0)
                .chain(text.match_indices('\n').map(|(i, _)| i + 1))
                .collect();
            let position = boundaries[at.index(boundaries.len())];
            let mut bytes = text.into_bytes();
            bytes.splice(position..position, [byte, b'\n']);
            let error = ndjson_text(bytes).unwrap_err();
            prop_assert_eq!(error.0, StatusCode::BAD_GATEWAY);
        }
    }
}
