//! Runtime configuration, parsed once from the environment at startup.

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

/// Every knob the gateway reads from the environment.
#[derive(Clone)]
pub struct Config {
    /// Address to bind. `GATEWAY_ADDR`, default `0.0.0.0:8080`.
    pub addr: SocketAddr,
    /// Bearer token required on every route except `/` and `/health`.
    /// `GATEWAY_TOKEN`; when unset or empty, auth is disabled.
    pub token: Option<String>,
    /// Per-request timeout. `GATEWAY_TIMEOUT_MS`, default 15000.
    pub timeout: Duration,
    /// Max request body size in bytes. `GATEWAY_MAX_BODY_BYTES`, default 1 MiB.
    pub max_body_bytes: usize,
    /// Requests allowed in flight before new ones are shed with 503.
    /// `GATEWAY_MAX_INFLIGHT`, default 512.
    pub max_inflight: usize,
    /// Cap on certificates accepted by `POST /verify/batch`.
    /// `GATEWAY_MAX_BATCH`, default 1024.
    pub max_batch: usize,
    /// Concurrent `/verify/batch` requests before new ones are shed with 503.
    /// `GATEWAY_MAX_BATCH_INFLIGHT`, default 4.
    pub max_batch_inflight: usize,
}

impl Config {
    /// Read the environment. Returns an error string on an unparseable value.
    pub fn from_env() -> Result<Self, String> {
        Ok(Self {
            addr: parse("GATEWAY_ADDR", "0.0.0.0:8080")?,
            token: std::env::var("GATEWAY_TOKEN")
                .ok()
                .filter(|s| !s.is_empty()),
            timeout: Duration::from_millis(parse("GATEWAY_TIMEOUT_MS", "15000")?),
            max_body_bytes: parse("GATEWAY_MAX_BODY_BYTES", "1048576")?,
            max_inflight: parse("GATEWAY_MAX_INFLIGHT", "512")?,
            max_batch: parse("GATEWAY_MAX_BATCH", "1024")?,
            max_batch_inflight: parse("GATEWAY_MAX_BATCH_INFLIGHT", "4")?,
        })
    }
}

/// Redacts `token` so the startup log never carries the secret.
impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("addr", &self.addr)
            .field("token", &self.token.as_ref().map(|_| "<set>"))
            .field("timeout", &self.timeout)
            .field("max_body_bytes", &self.max_body_bytes)
            .field("max_inflight", &self.max_inflight)
            .field("max_batch", &self.max_batch)
            .field("max_batch_inflight", &self.max_batch_inflight)
            .finish()
    }
}

fn parse<T>(key: &str, default: &str) -> Result<T, String>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let raw = std::env::var(key).unwrap_or_else(|_| default.to_string());
    raw.parse()
        .map_err(|e| format!("{key}: cannot parse {raw:?}: {e}"))
}
