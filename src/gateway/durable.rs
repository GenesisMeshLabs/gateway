//! Gateway-owned CRL checkpoints and durable request audit outbox.
use super::security::{NetworkPolicy, SecurityPolicy};
use crate::models::CertificateRevocationList;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use std::{
    fs::{File, OpenOptions},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};

/// One exclusively owned SQLite store per gateway replica, on persistent storage.
pub struct DurableState {
    connection: Mutex<Connection>,
    _lock: File,
    healthy: AtomicBool,
}

impl DurableState {
    /// Explicitly initialize a new database; normal startup never creates lost state.
    pub fn initialize(path: &Path) -> Result<(), String> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| {
                "state initialization requires a new file in an existing writable directory"
            })?;
        file.sync_all()
            .map_err(|_| "cannot sync initial state file")?;
        let connection = Connection::open(path).map_err(|_| "cannot initialize state database")?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE metadata(version INTEGER NOT NULL); INSERT INTO metadata VALUES(1);
            CREATE TABLE crls(network TEXT NOT NULL, issuer TEXT NOT NULL, body TEXT NOT NULL, PRIMARY KEY(network,issuer));
            CREATE TABLE audit(id TEXT PRIMARY KEY, body TEXT NOT NULL, delivered INTEGER NOT NULL DEFAULT 0);
            CREATE INDEX audit_delivery ON audit(delivered);")
            .map_err(|_| "cannot initialize state schema")?;
        Ok(())
    }

    /// Open existing state and acquire an OS lock, released even after process failure.
    pub fn open(path: &Path) -> Result<Self, String> {
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path.with_extension("lock"))
            .map_err(|_| "cannot open state ownership lock")?;
        fs2::FileExt::try_lock_exclusive(&lock)
            .map_err(|_| "state directory is already owned by another gateway")?;
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
            .map_err(|_| {
                "cannot open existing state database; initialize explicitly, never discard history"
            })?;
        connection
            .busy_timeout(std::time::Duration::from_secs(2))
            .map_err(|_| "cannot configure state timeout")?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA max_page_count=262144;",
            )
            .map_err(|_| "cannot configure durable state")?;
        let version: i64 = connection
            .query_row("SELECT version FROM metadata", [], |r| r.get(0))
            .map_err(|_| "missing or corrupt state schema")?;
        let check: String = connection
            .query_row("PRAGMA quick_check", [], |r| r.get(0))
            .map_err(|_| "state integrity check failed")?;
        if version != 1 || check != "ok" {
            return Err("unsupported or corrupt state database".into());
        }
        Ok(Self {
            connection: Mutex::new(connection),
            _lock: lock,
            healthy: AtomicBool::new(true),
        })
    }

    /// Latched write failures remove readiness until an operator repairs and restarts.
    pub fn healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }

    /// Storage and delivery gauges for operator alerting, without event contents.
    pub fn stats(&self) -> Result<(u64, u64), String> {
        let connection = self.connection.lock().map_err(|_| "state lock poisoned")?;
        let pending = connection
            .query_row("SELECT count(*) FROM audit WHERE delivered=0", [], |r| {
                r.get(0)
            })
            .map_err(|_| "audit count failed")?;
        let bytes = connection
            .query_row(
                "SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()",
                [],
                |r| r.get(0),
            )
            .map_err(|_| "state size failed")?;
        Ok((pending, bytes))
    }

    /// Restore verified state before the listener opens; lower bootstrap state cannot replace it.
    pub fn restore(&self, policy: &mut SecurityPolicy) -> Result<(), String> {
        for (name, network) in &mut policy.networks {
            for additional in network.additional_issuers.values_mut() {
                let mut single = SecurityPolicy {
                    revision: policy.revision.clone(),
                    networks: [(name.clone(), (**additional).clone())].into(),
                    clients: vec![],
                    token_index: Default::default(),
                };
                self.restore(&mut single)?;
                **additional = single.networks.remove(name).expect("checkpoint network");
            }
            let saved: Option<String> = self
                .connection
                .lock()
                .map_err(|_| "state lock poisoned")?
                .query_row(
                    "SELECT body FROM crls WHERE network=?1 AND issuer=?2",
                    params![name, network.crl.issuer],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|_| "cannot read CRL checkpoint")?;
            if let Some(body) = saved {
                let crl: CertificateRevocationList =
                    serde_json::from_str(&body).map_err(|_| "corrupt CRL checkpoint")?;
                let mut recovered = network.clone();
                recovered.crl = crl;
                if !recovered.authentic() || recovered.crl.issuer != network.crl.issuer {
                    return Err("stored CRL no longer authenticates under the configured issuer; explicit rotation migration required".into());
                }
                if network.crl.sequence <= recovered.crl.sequence {
                    if network.crl.sequence == recovered.crl.sequence
                        && network.crl.revoked_certificates != recovered.crl.revoked_certificates
                    {
                        return Err(
                            "bootstrap conflicts with stored CRL at the same sequence".into()
                        );
                    }
                    network.crl = recovered.crl;
                } else {
                    monotonic(&network.crl, &recovered.crl)?;
                }
            }
            network.minimum_crl_sequence = network.minimum_crl_sequence.max(network.crl.sequence);
            self.checkpoint(name, network)?;
        }
        Ok(())
    }

    /// Commit a verified snapshot before it can become visible to requests.
    pub fn checkpoint(&self, name: &str, network: &NetworkPolicy) -> Result<(), String> {
        if !self.healthy() || !network.authentic() {
            return Err("durable checkpoint unavailable or unauthenticated".into());
        }
        let result = (|| {
            let body =
                serde_json::to_string(&network.crl).map_err(|_| "CRL serialization failed")?;
            let mut connection = self.connection.lock().map_err(|_| "state lock poisoned")?;
            let tx = connection
                .transaction()
                .map_err(|_| "cannot begin CRL checkpoint")?;
            let previous: Option<String> = tx
                .query_row(
                    "SELECT body FROM crls WHERE network=?1 AND issuer=?2",
                    params![name, network.crl.issuer],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|_| "cannot read CRL checkpoint")?;
            if let Some(previous) = previous {
                if previous == body {
                    return Ok(());
                }
                let old = serde_json::from_str(&previous).map_err(|_| "corrupt CRL checkpoint")?;
                monotonic(&network.crl, &old)?;
            }
            tx.execute("INSERT INTO crls(network,issuer,body) VALUES(?1,?2,?3) ON CONFLICT(network,issuer) DO UPDATE SET body=excluded.body", params![name, network.crl.issuer, body]).map_err(|_| "CRL write failed")?;
            tx.commit().map_err(|_| "CRL durable commit failed")
        })();
        if result.is_err() {
            self.healthy.store(false, Ordering::Release);
        }
        result.map_err(str::to_owned)
    }

    /// Write an event synchronously; credentials and request bodies must never be passed.
    pub fn audit(&self, id: &str, event: &serde_json::Value) -> Result<(), String> {
        if !self.healthy() {
            return Err("durable state unavailable".into());
        }
        let result = (|| {
            let body = serde_json::to_string(event).map_err(|_| "audit serialization failed")?;
            self.connection
                .lock()
                .map_err(|_| "state lock poisoned")?
                .execute(
                    "INSERT INTO audit(id,body) VALUES(?1,?2)",
                    params![id, body],
                )
                .map_err(|_| "durable audit write failed")?;
            Ok(())
        })();
        if result.is_err() {
            self.healthy.store(false, Ordering::Release);
        }
        result.map_err(str::to_owned)
    }

    /// Read a bounded delivery batch. Event IDs are stable idempotency keys.
    pub fn pending_audit(&self) -> Result<Vec<serde_json::Value>, String> {
        let connection = self.connection.lock().map_err(|_| "state lock poisoned")?;
        let mut query = connection
            .prepare("SELECT id,body FROM audit WHERE delivered=0 ORDER BY rowid LIMIT 100")
            .map_err(|_| "audit read failed")?;
        let rows = query
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|_| "audit read failed")?;
        rows.map(|row| {
            let (id, body) = row.map_err(|_| "audit row read failed")?;
            let event: serde_json::Value =
                serde_json::from_str(&body).map_err(|_| "audit row corrupt")?;
            Ok(serde_json::json!({"id":id,"event":event}))
        })
        .collect()
    }

    /// Acknowledge only IDs the remote durable collector explicitly confirms.
    pub fn acknowledge(&self, ids: &[String]) -> Result<(), String> {
        let mut connection = self.connection.lock().map_err(|_| "state lock poisoned")?;
        let tx = connection
            .transaction()
            .map_err(|_| "audit acknowledgement failed")?;
        for id in ids {
            tx.execute("UPDATE audit SET delivered=1 WHERE id=?1", [id])
                .map_err(|_| "audit acknowledgement failed")?;
        }
        tx.commit()
            .map_err(|_| "audit acknowledgement commit failed".into())
    }
}

fn monotonic(
    new: &CertificateRevocationList,
    old: &CertificateRevocationList,
) -> Result<(), &'static str> {
    if new.issuer != old.issuer
        || new.sequence < old.sequence
        || new.issued_at < old.issued_at
        || (new.sequence == old.sequence && new.revoked_certificates != old.revoked_certificates)
    {
        return Err("CRL checkpoint rollback or conflicting sequence");
    }
    Ok(())
}
