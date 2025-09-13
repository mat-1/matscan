use std::{
    net::{Ipv4Addr, SocketAddrV4},
    time::Instant,
};

use chrono::TimeDelta;
use futures_util::TryStreamExt;
use rustc_hash::FxHashMap;
use sqlx::Row;
use tracing::info;

use crate::database::{Database, PgU16, PgU32};

#[derive(Default)]
pub struct CollectServersCache {
    servers_30_days: CacheItem,
    servers_365_days: CacheItem,
    servers_new: CacheItem,
}
#[derive(Default)]
pub struct CacheItem {
    servers: Box<[SocketAddrV4]>,
    last_updated: Option<Instant>,
}

impl CacheItem {
    pub fn get_servers(&self) -> Option<&[SocketAddrV4]> {
        let cache_duration = TimeDelta::hours(24);

        // first time
        let last_updated = self.last_updated?;
        // cache expired
        if last_updated.elapsed().as_secs_f64() > cache_duration.as_seconds_f64() {
            return None;
        }

        Some(&self.servers)
    }
    pub fn set_servers(&mut self, new_servers: Box<[SocketAddrV4]>) {
        self.servers = new_servers;
        self.last_updated = Some(Instant::now());
    }
}

pub enum UpdateResult {
    Inserted,
    UpdatedAndRevived,
    Updated,
}

#[derive(Debug)]
pub enum CollectServersFilter {
    /// Was alive in the past 30 days
    Active30d,
    /// Was alive in the past 365 days
    Active365d,
    // Found in the past 7 days
    New,
}

impl Database {
    pub async fn collect_all_servers(
        &self,
        filter: CollectServersFilter,
    ) -> eyre::Result<Box<[SocketAddrV4]>> {
        info!("Collecting servers with filter {filter:?}");

        let query = match filter {
            CollectServersFilter::Active30d => {
                if let Some(cached) = self
                    .shared
                    .lock()
                    .collect_servers_cache
                    .servers_30_days
                    .get_servers()
                {
                    return Ok(cached.into());
                }

                sqlx::query(
                    "SELECT ip, port FROM servers WHERE last_pinged > NOW() - INTERVAL '30 days'",
                )
            }
            CollectServersFilter::New => {
                if let Some(cached) = self
                    .shared
                    .lock()
                    .collect_servers_cache
                    .servers_new
                    .get_servers()
                {
                    return Ok(cached.into());
                }

                // inserted in the past 7 days
                sqlx::query(
                    "SELECT ip, port FROM servers WHERE first_pinged > NOW() - INTERVAL '7 days'",
                )
            }
            CollectServersFilter::Active365d => {
                if let Some(cached) = self
                    .shared
                    .lock()
                    .collect_servers_cache
                    .servers_365_days
                    .get_servers()
                {
                    return Ok(cached.into());
                }

                sqlx::query(
                    "SELECT ip, port FROM servers WHERE last_pinged > NOW() - INTERVAL '365 days'",
                )
            }
        };

        let mut rows = query.fetch(&self.pool);

        let mut servers = Vec::new();
        while let Some(row) = rows.try_next().await? {
            let ip = Ipv4Addr::from_bits(row.get::<PgU32, _>(0).0);
            let port = row.get::<PgU16, _>(1).0;

            servers.push(SocketAddrV4::new(ip, port));

            if servers.len() % 10000 == 0 {
                info!("Collected {} servers", servers.len());
            }
        }
        let servers = servers.into_boxed_slice();
        info!("Finished collecting {} servers", servers.len());

        let servers_cloned = servers.clone();
        match filter {
            CollectServersFilter::Active30d => {
                self.shared
                    .lock()
                    .collect_servers_cache
                    .servers_30_days
                    .set_servers(servers_cloned);
            }
            CollectServersFilter::New => {
                self.shared
                    .lock()
                    .collect_servers_cache
                    .servers_30_days
                    .set_servers(servers_cloned);
            }
            CollectServersFilter::Active365d => {
                self.shared
                    .lock()
                    .collect_servers_cache
                    .servers_30_days
                    .set_servers(servers_cloned);
            }
        };

        Ok(servers)
    }
}

#[derive(Default, Debug, Hash, PartialEq)]
pub struct ServerGroup {
    pub ips: Vec<Ipv4Addr>,
    pub ports: Vec<u16>,
}

pub fn to_subnet_16_ranges(known_servers: &[SocketAddrV4]) -> FxHashMap<(u8, u8), ServerGroup> {
    let mut ranges: FxHashMap<(u8, u8), ServerGroup> = FxHashMap::default();
    for target in known_servers {
        let [a, b, _, _] = target.ip().octets();
        let entry = ranges.entry((a, b)).or_default();
        entry.ips.push(*target.ip());
        entry.ports.push(target.port());
    }

    // sort by port
    for range in ranges.values_mut() {
        // combine the ips and ports, sort by port, then split them again
        let mut combined = range
            .ips
            .clone()
            .into_iter()
            .zip(range.ports.clone())
            .collect::<Vec<_>>();
        combined.sort_by_key(|(_, port)| *port);
        range.ips = combined.iter().map(|(ip, _)| *ip).collect();
        range.ports = combined.iter().map(|(_, port)| *port).collect();
    }
    ranges
}
pub fn to_subnet_24_ranges(known_servers: &[SocketAddrV4]) -> FxHashMap<(u8, u8, u8), ServerGroup> {
    let mut ranges: FxHashMap<(u8, u8, u8), ServerGroup> = FxHashMap::default();
    for target in known_servers {
        let [a, b, c, _] = target.ip().octets();
        let entry = ranges.entry((a, b, c)).or_default();
        entry.ips.push(*target.ip());
        entry.ports.push(target.port());
    }

    // sort by port
    for range in ranges.values_mut() {
        // combine the ips and ports, sort by port, then split them again
        let mut combined = range
            .ips
            .clone()
            .into_iter()
            .zip(range.ports.clone())
            .collect::<Vec<_>>();
        combined.sort_by_key(|(_, port)| *port);
        range.ips = combined.iter().map(|(ip, _)| *ip).collect();
        range.ports = combined.iter().map(|(_, port)| *port).collect();
    }
    ranges
}
