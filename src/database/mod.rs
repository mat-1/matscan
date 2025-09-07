pub mod collect_servers;
pub mod migrate_mongo_to_postgres;

use std::{collections::HashSet, net::Ipv4Addr, sync::Arc, time::Duration};

use futures_util::stream::StreamExt;
use lru_cache::LruCache;
use parking_lot::Mutex;
use rustc_hash::FxHashMap;
use sqlx::{PgPool, Row};
use tracing::error;

use crate::database::collect_servers::CollectServersCache;

#[derive(Clone)]
pub struct Database {
    pub pool: PgPool,
    pub shared: Arc<Mutex<DatabaseSharedData>>,
}

pub struct DatabaseSharedData {
    /// This is used to detect duplicate servers.
    ///
    /// `CachedIpHash::count` is set to None if we find a server on this IP with
    /// a different hash.
    pub ip_to_hash_and_ports: LruCache<Ipv4Addr, (CachedIpHash, HashSet<u16>)>,

    /// A map of IP addresses with aliased servers to the only port we're
    /// allowed to ping for them.
    pub aliased_ips_to_allowed_port: FxHashMap<Ipv4Addr, u16>,

    collect_servers_cache: CollectServersCache,
}

pub struct CachedIpHash {
    /// The number of IPs found with the same hash. None if we already found an
    /// IP with a different hash.
    pub count: Option<usize>,
    pub hash: u64,
}

impl Database {
    pub async fn connect(postgres_uri: &str) -> eyre::Result<Self> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(100)
            .connect(postgres_uri)
            .await?;
        sqlx::migrate!().run(&pool).await?;

        let db = Self {
            pool,
            shared: Arc::new(Mutex::new(DatabaseSharedData {
                // arbitrary capacity (2^20)
                ip_to_hash_and_ports: LruCache::new(1_048_576),

                aliased_ips_to_allowed_port: FxHashMap::default(),
                collect_servers_cache: CollectServersCache::default(),
            })),
        };

        db.update_ips_with_aliased_servers().await?;

        let db_clone = db.clone();
        tokio::spawn(async move {
            loop {
                if let Err(e) = db_clone.delete_spam_historical_players().await {
                    error!("got error from delete_spam_historical_players: {e}");
                }
                // every 4 hours
                tokio::time::sleep(Duration::from_secs(60 * 60 * 4)).await;
            }
        });

        Ok(db)
    }

    async fn update_ips_with_aliased_servers(&self) -> eyre::Result<()> {
        let mut aliased_ips_to_allowed_port = FxHashMap::default();
        let rows = sqlx::query("SELECT ip, allowed_port FROM ips_with_aliased_servers")
            .fetch_all(&self.pool)
            .await?;
        for row in rows {
            let ip = Ipv4Addr::from_bits(row.get::<i32, _>(0) as u32);
            let allowed_port = row.get::<i16, _>(1) as u16;
            aliased_ips_to_allowed_port.insert(ip, allowed_port);
        }
        self.shared.lock().aliased_ips_to_allowed_port = aliased_ips_to_allowed_port;

        Ok(())
    }

    pub async fn add_to_ips_with_aliased_servers(
        &self,
        ip: Ipv4Addr,
        allowed_port: u16,
    ) -> eyre::Result<()> {
        self.shared
            .lock()
            .aliased_ips_to_allowed_port
            .insert(ip, allowed_port);

        let mut txn = self.pool.begin().await?;

        sqlx::query("INSERT INTO ips_with_aliased_servers (ip, allowed_port) VALUES ($1, $2)")
            .bind(ip.to_bits() as i32)
            .bind(allowed_port as i16)
            .execute(&mut *txn)
            .await?;
        // delete all servers with this ip that aren't on the allowed port
        let delete_res = sqlx::query("DELETE FROM servers WHERE ip = $1 AND port != $2")
            .bind(ip.to_bits() as i32)
            .bind(allowed_port as i16)
            .execute(&mut *txn)
            .await?;
        let deleted_count = delete_res.rows_affected();

        txn.commit().await?;

        eprintln!("Deleted {deleted_count} bad servers");

        Ok(())
    }

    /// Only keep recent historical players from servers that have too many of
    /// them.
    ///
    /// This exists because some servers randomize the player list in their SLP
    /// response, and we don't want those to fill up our database unnecessarily.
    pub async fn delete_spam_historical_players(&self) -> eyre::Result<()> {
        const ALLOWED_PLAYER_LIMIT: i64 = 1000;
        const KEEP_PLAYER_COUNT: i64 = 500;

        const _: () = assert!(ALLOWED_PLAYER_LIMIT > KEEP_PLAYER_COUNT);

        let mut rows = sqlx::query(
            "
            SELECT DISTINCT ip, player_count FROM (
                SELECT
                    ip,
                    (SELECT count(*) as player_count FROM server_players WHERE server_players.server_ip = servers.ip)
                FROM servers
            ) WHERE player_count > $1;
            ",
        )
        .bind(ALLOWED_PLAYER_LIMIT)
        .fetch(&self.pool);

        while let Some(Ok(row)) = rows.next().await {
            let ip = row.get::<i32, _>(0);
            let player_count = row.get::<i64, _>(1);

            let delete_count = player_count - KEEP_PLAYER_COUNT;

            sqlx::query(
                "
                DELETE FROM ONLY server_players WHERE ctid IN (
                    SELECT ctid
                    FROM server_players
                    WHERE server_ip = $1 ORDER BY last_seen LIMIT $2
                )
                ",
            )
            .bind(ip)
            .bind(delete_count)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }
}

/// Removes null bytes so we don't get errors in Postgres :(
pub fn sanitize_text_for_postgres(s: &str) -> String {
    s.replace('\0', "")
}
