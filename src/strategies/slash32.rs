use std::{collections::HashSet, net::Ipv4Addr};

use tracing::info;

use crate::{
    database::{Database, collect_servers::CollectServersFilter},
    scanner::targets::ScanRange,
};

/// Scan every port on every address with at least one server.
pub async fn get_ranges(database: &Database) -> eyre::Result<Vec<ScanRange>> {
    let known_servers = database
        .collect_all_servers(CollectServersFilter::Active365d)
        .await?;

    let known_ips = known_servers
        .iter()
        .map(|target| target.ip())
        .collect::<HashSet<_>>();
    info!("Total unique ips: {}", known_ips.len());

    let mut target_ranges = Vec::new();

    // also scan /0 at the same time to avoid overwhelming our targets
    target_ranges.push(ScanRange::single_port(
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
        25565,
    ));

    for &address in known_ips {
        target_ranges.push(ScanRange {
            ip_start: address,
            ip_end: address,
            port_start: 1024,
            port_end: 65535,
        });
    }

    Ok(target_ranges)
}
