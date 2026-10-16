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

/// The store format, kept in `metadata.version`. A gateway refuses a store
/// of any other format. Migrations below are additive and keep the format,
/// so the previous release can still open a migrated store (a rollback does
/// not need a restore); a migration that breaks older readers must raise it.
const FORMAT: i64 = 1;

/// The format-1 schema as `--init-state` has created it since 0.57.
/// Never change it: later changes are migrations.
const BASE_SCHEMA: &str = "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
    CREATE TABLE metadata(version INTEGER NOT NULL); INSERT INTO metadata VALUES(1);
    CREATE TABLE crls(network TEXT NOT NULL, issuer TEXT NOT NULL, body TEXT NOT NULL, PRIMARY KEY(network,issuer));
    CREATE TABLE audit(id TEXT PRIMARY KEY, body TEXT NOT NULL, delivered INTEGER NOT NULL DEFAULT 0);
    CREATE INDEX audit_delivery ON audit(delivered);";

/// One ordered schema change after the base schema.
struct Migration {
    /// Unique, consecutive from 2 (the base schema is 1).
    version: i64,
    name: &'static str,
    sql: &'static str,
}

/// The migration ladder. Append only: never edit, renumber or remove an
/// entry that has been released. Each one must be additive (new tables,
/// columns with defaults or NULL, indexes) and must never delete rows.
const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 2,
        name: "audit delivery time",
        // When the collector acknowledged a row (Unix seconds). NULL for rows
        // acknowledged before this migration, or by a previous release after a
        // rollback: their retention starts when pruning first sees them.
        sql: "ALTER TABLE audit ADD COLUMN delivered_at INTEGER;
          CREATE INDEX audit_retention ON audit(delivered, delivered_at);",
    },
    Migration {
        version: 3,
        name: "audit record time",
        // When the row was written (Unix seconds), for retention without a
        // collector. NULL for rows written before this migration, or by a
        // previous release after a rollback: their retention starts when pruning
        // first sees them.
        sql: "ALTER TABLE audit ADD COLUMN recorded_at INTEGER;
          CREATE INDEX audit_age ON audit(recorded_at);",
    },
];

/// Audit rows removed per statement, so pruning never holds the store's
/// lock for long.
const PRUNE_CHUNK: i64 = 1000;

/// Apply every migration this store has not recorded, in order, in one
/// transaction: a store is either fully migrated or left as it was.
fn migrate(connection: &mut Connection) -> Result<(), String> {
    let tx = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|_| "cannot begin state migration")?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)",
    )
    .map_err(|_| "cannot record state migrations")?;
    for migration in MIGRATIONS {
        let applied: bool = tx
            .query_row(
                "SELECT count(*) FROM schema_migrations WHERE version=?1",
                [migration.version],
                |r| r.get::<_, i64>(0).map(|n| n > 0),
            )
            .map_err(|_| "cannot read state migrations")?;
        if applied {
            continue;
        }
        tx.execute_batch(migration.sql)
            .map_err(|_| format!("state migration {} failed", migration.version))?;
        tx.execute(
            "INSERT INTO schema_migrations(version,name,applied_at) VALUES(?1,?2,?3)",
            params![
                migration.version,
                migration.name,
                chrono::Utc::now().to_rfc3339()
            ],
        )
        .map_err(|_| "cannot record state migration")?;
    }
    tx.commit()
        .map_err(|_| "state migration commit failed".into())
}

/// Most audit events read, and posted to the collector, at once.
pub const AUDIT_BATCH: usize = 100;

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
        let mut connection =
            Connection::open(path).map_err(|_| "cannot initialize state database")?;
        connection
            .execute_batch(BASE_SCHEMA)
            .map_err(|_| "cannot initialize state schema")?;
        migrate(&mut connection)
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
        let mut connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
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
        if version != FORMAT || check != "ok" {
            return Err("unsupported or corrupt state database".into());
        }
        migrate(&mut connection)?;
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
        // SQLite integers are signed; convert explicitly rather than reading u64.
        let pending: i64 = connection
            .query_row("SELECT count(*) FROM audit WHERE delivered=0", [], |r| {
                r.get(0)
            })
            .map_err(|_| "audit count failed")?;
        let bytes: i64 = connection
            .query_row(
                "SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()",
                [],
                |r| r.get(0),
            )
            .map_err(|_| "state size failed")?;
        let pending = u64::try_from(pending).map_err(|_| "audit count out of range")?;
        let bytes = u64::try_from(bytes).map_err(|_| "state size out of range")?;
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
                    "INSERT INTO audit(id,body,recorded_at) VALUES(?1,?2,?3)",
                    params![id, body, chrono::Utc::now().timestamp()],
                )
                .map_err(|_| "durable audit write failed")?;
            Ok(())
        })();
        if result.is_err() {
            self.healthy.store(false, Ordering::Release);
        }
        result.map_err(str::to_owned)
    }

    /// Read a bounded delivery batch of at most [`AUDIT_BATCH`] events, oldest
    /// first. Event IDs are stable idempotency keys.
    pub fn pending_audit(&self) -> Result<Vec<serde_json::Value>, String> {
        let connection = self.connection.lock().map_err(|_| "state lock poisoned")?;
        let mut query = connection
            .prepare("SELECT id,body FROM audit WHERE delivered=0 ORDER BY rowid LIMIT ?1")
            .map_err(|_| "audit read failed")?;
        let rows = query
            .query_map([AUDIT_BATCH as i64], |row| {
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
    /// The first acknowledgement records when the row was delivered.
    pub fn acknowledge(&self, ids: &[String]) -> Result<(), String> {
        let now = chrono::Utc::now().timestamp();
        let mut connection = self.connection.lock().map_err(|_| "state lock poisoned")?;
        let tx = connection
            .transaction()
            .map_err(|_| "audit acknowledgement failed")?;
        for id in ids {
            tx.execute(
                "UPDATE audit SET delivered=1, delivered_at=COALESCE(delivered_at,?2) WHERE id=?1",
                params![id, now],
            )
            .map_err(|_| "audit acknowledgement failed")?;
        }
        tx.commit()
            .map_err(|_| "audit acknowledgement commit failed".into())
    }

    /// Delete audit rows the collector acknowledged more than `retention`
    /// before `now`, a chunk at a time. Rows not yet delivered are never
    /// deleted, however old. Rows acknowledged without a delivery time (by a
    /// release before 1.7.1) get `now` as theirs first. Returns the rows deleted.
    pub fn prune_delivered(
        &self,
        retention: std::time::Duration,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, String> {
        self.prune(
            retention,
            now,
            "UPDATE audit SET delivered_at=?1 WHERE delivered=1 AND delivered_at IS NULL",
            "DELETE FROM audit WHERE rowid IN (SELECT rowid FROM audit
             WHERE delivered=1 AND delivered_at IS NOT NULL AND delivered_at < ?1 LIMIT ?2)",
        )
    }

    /// Delete every audit row written more than `retention` before `now`,
    /// delivered or not, a chunk at a time. Only for a store without a
    /// collector, where rows can never be delivered and the store is a bounded
    /// local log. Rows written without a time (before 1.7.1) get `now` as
    /// theirs first. Returns the rows deleted.
    pub fn prune_recorded(
        &self,
        retention: std::time::Duration,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, String> {
        self.prune(
            retention,
            now,
            "UPDATE audit SET recorded_at=?1 WHERE recorded_at IS NULL",
            "DELETE FROM audit WHERE rowid IN (SELECT rowid FROM audit
             WHERE recorded_at IS NOT NULL AND recorded_at < ?1 LIMIT ?2)",
        )
    }

    /// Stamp rows without a time with `now`, then delete rows older than the
    /// cutoff in chunks of [`PRUNE_CHUNK`].
    fn prune(
        &self,
        retention: std::time::Duration,
        now: chrono::DateTime<chrono::Utc>,
        stamp: &str,
        delete: &str,
    ) -> Result<u64, String> {
        let now = now.timestamp();
        let retention = i64::try_from(retention.as_secs()).map_err(|_| "retention out of range")?;
        let cutoff = now.saturating_sub(retention);
        self.connection
            .lock()
            .map_err(|_| "state lock poisoned")?
            .execute(stamp, [now])
            .map_err(|_| "audit retention failed")?;
        let mut deleted = 0;
        loop {
            let chunk = self
                .connection
                .lock()
                .map_err(|_| "state lock poisoned")?
                .execute(delete, params![cutoff, PRUNE_CHUNK])
                .map_err(|_| "audit retention failed")?;
            deleted += chunk as u64;
            if (chunk as i64) < PRUNE_CHUNK {
                return Ok(deleted);
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact schema `--init-state` wrote in 1.7.0 and earlier releases.
    const SCHEMA_1_7_0: &str = "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE metadata(version INTEGER NOT NULL); INSERT INTO metadata VALUES(1);
            CREATE TABLE crls(network TEXT NOT NULL, issuer TEXT NOT NULL, body TEXT NOT NULL, PRIMARY KEY(network,issuer));
            CREATE TABLE audit(id TEXT PRIMARY KEY, body TEXT NOT NULL, delivered INTEGER NOT NULL DEFAULT 0);
            CREATE INDEX audit_delivery ON audit(delivered);";

    fn folder() -> std::path::PathBuf {
        let folder = std::env::temp_dir().join(format!("gateway-durable-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&folder).unwrap();
        folder
    }

    /// A store as 1.7.0 left it: CRL checkpoints, undelivered and delivered audit rows.
    fn store_1_7_0(path: &Path) {
        let connection = Connection::open(path).unwrap();
        connection.execute_batch(SCHEMA_1_7_0).unwrap();
        connection
            .execute_batch(
                "INSERT INTO crls VALUES('public-agency','authority','{\"sequence\":5}');
                 INSERT INTO audit(id,body,delivered) VALUES('a:started','{\"phase\":\"started\"}',1);
                 INSERT INTO audit(id,body,delivered) VALUES('a:completed','{\"phase\":\"completed\"}',1);
                 INSERT INTO audit(id,body) VALUES('b:started','{\"phase\":\"started\"}');
                 INSERT INTO audit(id,body) VALUES('b:completed','{\"phase\":\"completed\"}');
                 INSERT INTO audit(id,body) VALUES('c:started','{\"phase\":\"started\"}');",
            )
            .unwrap();
    }

    fn count(path: &Path, sql: &str) -> i64 {
        Connection::open(path)
            .unwrap()
            .query_row(sql, [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn migration_versions_are_unique_consecutive_and_follow_the_base_schema() {
        let mut names = std::collections::BTreeSet::new();
        for (i, migration) in MIGRATIONS.iter().enumerate() {
            assert_eq!(
                migration.version,
                i as i64 + 2,
                "migration {} ({}) is out of order, duplicated or leaves a gap",
                migration.version,
                migration.name
            );
            assert!(
                names.insert(migration.name),
                "duplicate migration name {}",
                migration.name
            );
            let sql = migration.sql.to_ascii_uppercase();
            assert!(
                !sql.contains("DELETE") && !sql.contains("DROP"),
                "migration {} must be additive",
                migration.version
            );
        }
        assert_eq!(
            BASE_SCHEMA.split_whitespace().collect::<Vec<_>>(),
            SCHEMA_1_7_0.split_whitespace().collect::<Vec<_>>(),
            "the base schema is frozen; change the store with a migration"
        );
    }

    #[test]
    fn a_1_7_0_store_is_migrated_in_place_without_losing_audit_or_checkpoints() {
        let folder = folder();
        let path = folder.join("state.db");
        store_1_7_0(&path);
        let store = DurableState::open(&path).unwrap();
        let pending: Vec<_> = store
            .pending_audit()
            .unwrap()
            .iter()
            .map(|e| e["id"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(pending, ["b:started", "b:completed", "c:started"]);
        assert_eq!(store.stats().unwrap().0, 3);
        drop(store);
        assert_eq!(count(&path, "SELECT count(*) FROM audit"), 5);
        assert_eq!(
            count(&path, "SELECT count(*) FROM audit WHERE delivered=1"),
            2
        );
        assert_eq!(count(&path, "SELECT count(*) FROM crls"), 1);
        assert_eq!(
            count(&path, "SELECT version FROM metadata"),
            FORMAT,
            "the previous release must still open a migrated store"
        );
        assert_eq!(
            count(&path, "SELECT count(*) FROM schema_migrations"),
            MIGRATIONS.len() as i64
        );
        // Opening again applies nothing twice.
        drop(DurableState::open(&path).unwrap());
        assert_eq!(
            count(&path, "SELECT count(*) FROM schema_migrations"),
            MIGRATIONS.len() as i64
        );
        assert_eq!(count(&path, "SELECT count(*) FROM audit"), 5);
        std::fs::remove_dir_all(folder).ok();
    }

    fn execute(path: &Path, sql: &str) {
        Connection::open(path).unwrap().execute_batch(sql).unwrap();
    }

    const DAY: std::time::Duration = std::time::Duration::from_secs(86_400);

    #[test]
    fn retention_deletes_only_delivered_rows_past_the_window() {
        let folder = folder();
        let path = folder.join("state.db");
        DurableState::initialize(&path).unwrap();
        let store = DurableState::open(&path).unwrap();
        for id in ["old", "recent", "pending"] {
            store.audit(id, &serde_json::json!({"id": id})).unwrap();
        }
        store.acknowledge(&["old".into(), "recent".into()]).unwrap();
        let now = chrono::Utc::now();
        execute(
            &path,
            &format!(
                "UPDATE audit SET delivered_at={} WHERE id='old';
                 INSERT INTO audit(id,body,delivered) VALUES('acknowledged-by-1.7.0','{{}}',1);
                 UPDATE audit SET body='{{}}' WHERE id='pending';",
                (now - chrono::Duration::days(10)).timestamp()
            ),
        );
        // A pending row is never deleted, however old the clock says it is.
        assert_eq!(store.prune_delivered(7 * DAY, now).unwrap(), 1);
        let ids = |path: &Path| -> Vec<String> {
            let connection = Connection::open(path).unwrap();
            let mut query = connection
                .prepare("SELECT id FROM audit ORDER BY rowid")
                .unwrap();
            query
                .query_map([], |r| r.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        assert_eq!(ids(&path), ["recent", "pending", "acknowledged-by-1.7.0"]);
        assert_eq!(
            count(
                &path,
                "SELECT count(*) FROM audit WHERE delivered_at IS NULL AND delivered=1"
            ),
            0,
            "a row acknowledged without a time starts its retention now"
        );
        assert_eq!(store.prune_delivered(7 * DAY, now).unwrap(), 0);
        let later = now + chrono::Duration::days(8);
        assert_eq!(store.prune_delivered(7 * DAY, later).unwrap(), 2);
        assert_eq!(ids(&path), ["pending"]);
        assert_eq!(store.stats().unwrap().0, 1);
        assert_eq!(
            store.pending_audit().unwrap()[0]["id"],
            "pending",
            "the undelivered row is still delivered"
        );
        std::fs::remove_dir_all(folder).ok();
    }

    #[test]
    fn retention_deletes_a_large_delivered_backlog_in_chunks() {
        let folder = folder();
        let path = folder.join("state.db");
        DurableState::initialize(&path).unwrap();
        let store = DurableState::open(&path).unwrap();
        let rows = 2 * PRUNE_CHUNK + 17;
        execute(
            &path,
            &format!(
                "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<{rows})
                 INSERT INTO audit(id,body,delivered,delivered_at) SELECT 'e'||i,'{{}}',1,0 FROM n;
                 INSERT INTO audit(id,body) VALUES('pending','{{}}');"
            ),
        );
        assert_eq!(
            store.prune_delivered(DAY, chrono::Utc::now()).unwrap(),
            rows as u64
        );
        assert_eq!(count(&path, "SELECT count(*) FROM audit"), 1);
        std::fs::remove_dir_all(folder).ok();
    }

    #[test]
    fn rows_a_1_7_0_store_delivered_are_kept_a_full_window_after_the_upgrade() {
        let folder = folder();
        let path = folder.join("state.db");
        store_1_7_0(&path);
        let store = DurableState::open(&path).unwrap();
        let upgraded = chrono::Utc::now();
        assert_eq!(store.prune_delivered(7 * DAY, upgraded).unwrap(), 0);
        assert_eq!(
            store
                .prune_delivered(7 * DAY, upgraded + chrono::Duration::days(6))
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .prune_delivered(7 * DAY, upgraded + chrono::Duration::days(8))
                .unwrap(),
            2
        );
        assert_eq!(
            count(&path, "SELECT count(*) FROM audit WHERE delivered=0"),
            3
        );
        assert_eq!(count(&path, "SELECT count(*) FROM audit"), 3);
        std::fs::remove_dir_all(folder).ok();
    }

    #[test]
    fn without_a_collector_rows_older_than_the_window_are_deleted_delivered_or_not() {
        let folder = folder();
        let path = folder.join("state.db");
        DurableState::initialize(&path).unwrap();
        let store = DurableState::open(&path).unwrap();
        for id in ["old-pending", "old-delivered", "recent-pending"] {
            store.audit(id, &serde_json::json!({"id": id})).unwrap();
        }
        store.acknowledge(&["old-delivered".into()]).unwrap();
        let now = chrono::Utc::now();
        execute(
            &path,
            &format!(
                "UPDATE audit SET recorded_at={} WHERE id LIKE 'old-%';
                 INSERT INTO audit(id,body) VALUES('written-by-1.7.0','{{}}');",
                (now - chrono::Duration::days(10)).timestamp()
            ),
        );
        assert_eq!(store.prune_recorded(7 * DAY, now).unwrap(), 2);
        assert_eq!(
            count(
                &path,
                "SELECT count(*) FROM audit WHERE recorded_at IS NULL"
            ),
            0,
            "a row written without a time starts its retention now"
        );
        let later = now + chrono::Duration::days(8);
        assert_eq!(store.prune_recorded(7 * DAY, later).unwrap(), 2);
        assert_eq!(count(&path, "SELECT count(*) FROM audit"), 0);
        std::fs::remove_dir_all(folder).ok();
    }

    #[test]
    fn rows_a_1_7_0_store_wrote_are_kept_a_full_window_after_the_upgrade_without_a_collector() {
        let folder = folder();
        let path = folder.join("state.db");
        store_1_7_0(&path);
        let store = DurableState::open(&path).unwrap();
        let upgraded = chrono::Utc::now();
        assert_eq!(store.prune_recorded(7 * DAY, upgraded).unwrap(), 0);
        assert_eq!(
            store
                .prune_recorded(7 * DAY, upgraded + chrono::Duration::days(6))
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .prune_recorded(7 * DAY, upgraded + chrono::Duration::days(8))
                .unwrap(),
            5
        );
        std::fs::remove_dir_all(folder).ok();
    }

    #[test]
    fn a_new_store_has_every_migration() {
        let folder = folder();
        let path = folder.join("state.db");
        DurableState::initialize(&path).unwrap();
        assert_eq!(
            count(&path, "SELECT count(*) FROM schema_migrations"),
            MIGRATIONS.len() as i64
        );
        assert_eq!(count(&path, "SELECT version FROM metadata"), FORMAT);
        std::fs::remove_dir_all(folder).ok();
    }

    #[test]
    fn a_store_of_another_format_is_refused_and_left_unchanged() {
        let folder = folder();
        let path = folder.join("state.db");
        store_1_7_0(&path);
        Connection::open(&path)
            .unwrap()
            .execute("UPDATE metadata SET version=2", [])
            .unwrap();
        assert!(DurableState::open(&path).is_err());
        assert_eq!(
            count(
                &path,
                "SELECT count(*) FROM sqlite_master WHERE name='schema_migrations'"
            ),
            0
        );
        std::fs::remove_dir_all(folder).ok();
    }
}
