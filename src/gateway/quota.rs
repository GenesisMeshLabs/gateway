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
    /// Same client and namespace share a sixty-second allowance across replicas.
    pub async fn admit(&self, client: &str, limit: u32) -> Result<bool, QuotaUnavailable> {
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            let mut connection = self.connection().await?;
            let key = format!("gateway:quota:{:x}", Sha256::digest(format!("{}\0{client}", self.namespace).as_bytes()));
            let script = redis::Script::new("local n=tonumber(redis.call('GET',KEYS[1]) or '0'); if n>=tonumber(ARGV[1]) then return 0 end; n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('PEXPIRE',KEYS[1],60000) end; return 1");
            let allowed: i32 = script.key(key).arg(limit).invoke_async(&mut connection).await.map_err(|_| ())?;
            Ok::<bool, ()>(allowed == 1)
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

#[cfg(test)]
mod tests {
    use super::*;
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
            tasks.spawn(async move { replica.admit("shared-client", 7).await.unwrap() });
        }
        let mut admitted = 0;
        while let Some(result) = tasks.join_next().await {
            if result.unwrap() {
                admitted += 1;
            }
        }
        assert_eq!(admitted, 7);
        assert!(b.admit("another-client", 7).await.unwrap());
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
