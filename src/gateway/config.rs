//! Runtime configuration, parsed once from the environment at startup.

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

/// Every knob the gateway reads from the environment.
#[derive(Clone)]
pub struct Config {
    /// Optional organization token verifier; service scopes stay in operator policy.
    pub oidc: Option<std::sync::Arc<super::oidc::Oidc>>,
    /// Optional shared quota backend, with no local fallback on failure.
    pub distributed_quota: Option<std::sync::Arc<super::quota::DistributedQuota>>,
    /// Optional gateway-owned durable CRL and audit store.
    pub durable: Option<std::sync::Arc<super::durable::DurableState>>,
    /// Explicit local utility mode; production is the default.
    pub development: bool,
    /// Operator policy, required outside development mode.
    pub security: Option<super::security::SecurityPolicy>,
    /// Address to bind. `GATEWAY_ADDR`, default `127.0.0.1:8080`.
    pub addr: SocketAddr,
    /// Bearer token required on every route except `/` and `/health`.
    /// Development mode only; authentication is always required.
    pub token: Option<String>,
    /// Per-request timeout. `GATEWAY_TIMEOUT_MS`, default 15000.
    pub timeout: Duration,
    /// Max request body size in bytes. `GATEWAY_MAX_BODY_BYTES`, default 1 MiB.
    pub max_body_bytes: usize,
    /// Requests allowed in flight before new ones are shed with 503.
    /// `GATEWAY_MAX_INFLIGHT`, default 32.
    pub max_inflight: usize,
    /// Cap on certificates accepted by `POST /verify/batch`.
    /// `GATEWAY_MAX_BATCH`, default 128.
    pub max_batch: usize,
    /// CPU jobs admitted concurrently, independently of HTTP requests.
    pub cpu_workers: usize,
    /// Concurrent batches; reserve CPU capacity for single requests when possible.
    pub max_batch_jobs: usize,
}

impl Config {
    /// Read the environment. Returns an error string on an unparseable value.
    pub fn from_env() -> Result<Self, String> {
        Self::from_env_inner(true)
    }

    /// Explicit first deployment bootstrap; refuses to replace existing state.
    pub fn initialize_state() -> Result<(), String> {
        let mut cfg = Self::from_env_inner(false)?;
        let path = std::env::var("GATEWAY_STATE_FILE").map_err(|_| "set GATEWAY_STATE_FILE")?;
        let policy = cfg
            .security
            .as_mut()
            .ok_or("durable state requires production policy")?;
        super::durable::DurableState::initialize(std::path::Path::new(&path))?;
        super::durable::DurableState::open(std::path::Path::new(&path))?.restore(policy)
    }

    fn from_env_inner(load_state: bool) -> Result<Self, String> {
        let mut security: Option<super::security::SecurityPolicy> =
            std::env::var("GATEWAY_POLICY_FILE")
                .ok()
                .map(|path| {
                    let bytes = std::fs::read(path)
                        .map_err(|_| "cannot read GATEWAY_POLICY_FILE".to_string())?;
                    if bytes.len() > 16 * 1024 * 1024 {
                        return Err("policy file exceeds 16 MiB".into());
                    }
                    serde_json::from_slice(&bytes).map_err(|_| "invalid policy JSON".to_string())
                })
                .transpose()?;
        let durable = if load_state {
            std::env::var("GATEWAY_STATE_FILE")
                .ok()
                .map(|path| {
                    let state = super::durable::DurableState::open(std::path::Path::new(&path))?;
                    state.restore(
                        security
                            .as_mut()
                            .ok_or("durable state requires production policy")?,
                    )?;
                    Ok::<_, String>(std::sync::Arc::new(state))
                })
                .transpose()?
        } else {
            None
        };
        let oidc = std::env::var("GATEWAY_OIDC_FILE")
            .ok()
            .map(|path| {
                super::oidc::Oidc::load(
                    &path,
                    security.as_ref().ok_or("OIDC requires production policy")?,
                )
                .map(std::sync::Arc::new)
            })
            .transpose()?;
        let distributed_quota = std::env::var("GATEWAY_REDIS_URL_FILE")
            .ok()
            .map(|path| {
                super::quota::DistributedQuota::load(
                    &path,
                    std::env::var("GATEWAY_QUOTA_NAMESPACE")
                        .map_err(|_| "set a shared GATEWAY_QUOTA_NAMESPACE")?,
                )
                .map(std::sync::Arc::new)
            })
            .transpose()?;
        let mut cfg = Self {
            oidc,
            distributed_quota,
            durable,
            development: parse("GATEWAY_DEVELOPMENT", "false")?,
            security,
            addr: parse("GATEWAY_ADDR", "127.0.0.1:8080")?,
            token: std::env::var("GATEWAY_TOKEN")
                .ok()
                .filter(|s| !s.is_empty()),
            timeout: Duration::from_millis(parse("GATEWAY_TIMEOUT_MS", "15000")?),
            max_body_bytes: parse("GATEWAY_MAX_BODY_BYTES", "1048576")?,
            max_inflight: parse("GATEWAY_MAX_INFLIGHT", "32")?,
            max_batch: parse("GATEWAY_MAX_BATCH", "128")?,
            cpu_workers: parse("GATEWAY_CPU_WORKERS", "2")?,
            max_batch_jobs: parse("GATEWAY_MAX_BATCH_JOBS", "1")?,
        };
        cfg.prepare()?;
        Ok(cfg)
    }

    /// Validate configuration and populate request-path indexes.
    pub fn prepare(&mut self) -> Result<(), String> {
        self.validate()?;
        if let Some(security) = &mut self.security {
            security.rebuild_indexes();
        }
        Ok(())
    }

    /// Validate programmatic configuration as well as environment input.
    pub fn validate(&self) -> Result<(), String> {
        if self.timeout.is_zero()
            || self.timeout > Duration::from_secs(300)
            || !(1..=16 * 1024 * 1024).contains(&self.max_body_bytes)
            || !(1..=4096).contains(&self.max_inflight)
            || !(1..=4096).contains(&self.max_batch)
            || !(1..=256).contains(&self.cpu_workers)
            || self.max_batch_jobs == 0
            || self.max_batch_jobs > self.cpu_workers
            || (self.cpu_workers > 1 && self.max_batch_jobs == self.cpu_workers)
        {
            return Err("resource limits must be positive and within documented bounds".into());
        }
        if self.development {
            if self.security.is_some() {
                return Err("development mode cannot load production policy".into());
            }
            if self
                .token
                .as_ref()
                .is_none_or(|t| !(32..=1024).contains(&t.len()))
            {
                return Err(
                    "development mode requires GATEWAY_TOKEN with at least 32 bytes".into(),
                );
            }
        } else {
            if self.token.is_some() {
                return Err("production uses policy client credentials, not GATEWAY_TOKEN".into());
            }
            self.security
                .as_ref()
                .ok_or("production requires GATEWAY_POLICY_FILE")?
                .validate()?;
        }
        Ok(())
    }
}

/// Redacts `token` so the startup log never carries the secret.
impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("development", &self.development)
            .field(
                "policy_revision",
                &self.security.as_ref().map(|s| &s.revision),
            )
            .field("addr", &self.addr)
            .field("token", &self.token.as_ref().map(|_| "<set>"))
            .field("timeout", &self.timeout)
            .field("max_body_bytes", &self.max_body_bytes)
            .field("max_inflight", &self.max_inflight)
            .field("max_batch", &self.max_batch)
            .field("cpu_workers", &self.cpu_workers)
            .field("max_batch_jobs", &self.max_batch_jobs)
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
