use crate::{
    database::{CollectServersFilter, Database},
    scanner::targets::ScanRange,
};
use std::collections::HashSet;

/// Scan every port on every address with at least one server.
pub async fn get_ranges(database: &Database) -> anyhow::Result<Vec<ScanRange>> {
    println!("collecting servers");
    let known_servers =
        crate::database::collect_all_servers(database, CollectServersFilter::Active365d).await?;
    println!("finished collecting {} servers", known_servers.len());

    let known_ips = known_servers
        .iter()
        .map(|target| target.ip())
        .collect::<HashSet<_>>();

    println!("total unique ips: {}", known_ips.len());

    let mut target_ranges = Vec::new();

    for &address in known_ips {
        target_ranges.push(ScanRange {
            addr_start: address,
            addr_end: address,
            port_start: 1024,
            port_end: 65535,
        });
    }

    Ok(target_ranges)
}
