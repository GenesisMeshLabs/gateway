//! Atomic cross-replica quota admission. Backend failures never fall back to local allowance.
use sha2::{Digest, Sha256};

/// Shared quota failures are explicit and must not cause local fallback.
#[derive(Debug, thiserror::Error)]
#[error("shared quota unavailable")]
pub struct QuotaUnavailable;

/// Redis credentials are loaded from an operator-mounted secret file.
pub struct DistributedQuota {
    client: redis::Client,
    connection: tokio::sync::Mutex<Option<redis::aio::ConnectionManager>>,
    namespace: String,
}
impl DistributedQuota {
    /// Build a lazy connection; readiness/admission checks establish connectivity.
    pub fn load(secret_file: &str, namespace: String) -> Result<Self, String> {
        if namespace.is_empty() || namespace.len() > 128 {
            return Err("quota namespace requires 1..128 characters".into());
        }
        let url =
            std::fs::read_to_string(secret_file).map_err(|_| "cannot read Redis secret file")?;
        let client =
            redis::Client::open(url.trim()).map_err(|_| "invalid Redis connection settings")?;
        Ok(Self {
            client,
            connection: Default::default(),
            namespace,
        })
    }
    /// Bound all backend work to one second and serialize initialization only.
    async fn connection(&self) -> Result<redis::aio::ConnectionManager, ()> {
        let mut guard = self.connection.lock().await;
        if guard.is_none() {
            *guard = Some(self.client.get_connection_manager().await.map_err(|_| ())?);
        }
        Ok(guard.as_ref().ok_or(())?.clone())
    }
    /// Same client and namespace share a sixty-second allowance across
    /// replicas. A refusal says how long until the allowance resets.
    pub async fn admit(
        &self,
        client: &str,
        limit: u32,
    ) -> Result<Result<(), std::time::Duration>, QuotaUnavailable> {
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            let mut connection = self.connection().await?;
            let key = quota_key(&self.namespace, client);
            // Returns ADMITTED, else the allowance's remaining milliseconds. A
            // full allowance that lost its expiry gets the whole window again.
            let script = redis::Script::new("local n=tonumber(redis.call('GET',KEYS[1]) or '0'); if n>=tonumber(ARGV[1]) then local t=redis.call('PTTL',KEYS[1]); if t<0 then redis.call('PEXPIRE',KEYS[1],60000); t=60000 end; return t end; n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('PEXPIRE',KEYS[1],60000) end; return -100");
            let remaining: i64 = script.key(key).arg(limit).invoke_async(&mut connection).await.map_err(|_| ())?;
            Ok::<_, ()>(refusal(remaining))
        }).await.map_err(|_| QuotaUnavailable)?.map_err(|_| QuotaUnavailable)
    }
    /// Health probe for fail-closed readiness.
    pub async fn healthy(&self) -> bool {
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            let mut connection = self.connection().await?;
            let pong: String = redis::cmd("PING")
                .query_async(&mut connection)
                .await
                .map_err(|_| ())?;
            Ok::<_, ()>(pong == "PONG")
        })
        .await
        .is_ok_and(|result| result == Ok(true))
    }
}

/// The script's answer for an admitted request: no `PTTL` is negative but
/// -1 and -2, so it cannot be mistaken for a remaining time.
const ADMITTED: i64 = -100;

/// The script's answer: [`ADMITTED`], or the allowance's remaining
/// milliseconds (anything else waits the whole window).
fn refusal(remaining: i64) -> Result<(), std::time::Duration> {
    match remaining {
        ADMITTED => Ok(()),
        ms if ms >= 0 => Err(std::time::Duration::from_millis(ms.clamp(1, 60_000) as u64)),
        _ => Err(std::time::Duration::from_secs(60)),
    }
}

/// Redis key of one client's allowance in a namespace, as lowercase hex of
/// SHA-256 over `namespace\0client`. Replicas of different versions share these
/// keys during a rolling upgrade, so the format must not change.
fn quota_key(namespace: &str, client: &str) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(format!("{namespace}\0{client}").as_bytes());
    digest
        .iter()
        .fold(String::from("gateway:quota:"), |mut key, byte| {
            let _ = write!(key, "{byte:02x}");
            key
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_refusal_carries_the_remaining_window() {
        use std::time::Duration;
        assert_eq!(refusal(ADMITTED), Ok(()));
        assert_eq!(refusal(12_345), Err(Duration::from_millis(12_345)));
        // PTTL's "no expiry" and "no key" never admit.
        assert_eq!(refusal(-1), Err(Duration::from_secs(60)));
        assert_eq!(refusal(-2), Err(Duration::from_secs(60)));
        assert_eq!(refusal(0), Err(Duration::from_millis(1)));
        assert_eq!(refusal(90_000), Err(Duration::from_secs(60)));
    }
    #[test]
    fn quota_key_format_is_stable_across_versions() {
        assert_eq!(
            quota_key("pilot", "client-a"),
            "gateway:quota:f24a8fd3d18793559a2ce7841fa9d31567a80094c179039c312b0456cbc2c38e"
        );
    }
    #[tokio::test]
    #[ignore = "requires GATEWAY_TEST_REDIS_URL pointing to an isolated test Redis"]
    async fn two_independent_replicas_share_one_atomic_allowance() {
        let url = std::env::var("GATEWAY_TEST_REDIS_URL").expect("test Redis URL");
        let path = std::env::temp_dir().join(format!("gateway-quota-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, url).unwrap();
        let namespace = uuid::Uuid::new_v4().to_string();
        let a = std::sync::Arc::new(
            DistributedQuota::load(path.to_str().unwrap(), namespace.clone()).unwrap(),
        );
        let b =
            std::sync::Arc::new(DistributedQuota::load(path.to_str().unwrap(), namespace).unwrap());
        std::fs::remove_file(path).unwrap();
        assert!(a.healthy().await);
        assert!(b.healthy().await);
        let mut tasks = tokio::task::JoinSet::new();
        for i in 0..40 {
            let replica = if i % 2 == 0 { a.clone() } else { b.clone() };
            tasks.spawn(async move { replica.admit("shared-client", 7).await.unwrap().is_ok() });
        }
        let mut admitted = 0;
        while let Some(result) = tasks.join_next().await {
            if result.unwrap() {
                admitted += 1;
            }
        }
        assert_eq!(admitted, 7);
        assert!(b.admit("another-client", 7).await.unwrap().is_ok());
        let wait = a.admit("shared-client", 7).await.unwrap().unwrap_err();
        assert!(wait > std::time::Duration::ZERO && wait <= std::time::Duration::from_secs(60));
    }
    #[tokio::test]
    async fn unavailable_backend_does_not_issue_local_allowance() {
        let path = std::env::temp_dir().join(format!("gateway-quota-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, "redis://127.0.0.1:1/").unwrap();
        let quota = DistributedQuota::load(path.to_str().unwrap(), "test".into()).unwrap();
        std::fs::remove_file(path).unwrap();
        assert!(quota.admit("client", 100).await.is_err());
        assert!(!quota.healthy().await);
    }
}
