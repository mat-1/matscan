use std::net::Ipv4Addr;

use crate::{
    database::{
        Database,
        collect_servers::{CollectServersFilter, to_subnet_16_ranges},
    },
    scanner::targets::ScanRange,
};

pub async fn get_ranges(database: &Database) -> eyre::Result<Vec<ScanRange>> {
    let known_servers = database
        .collect_all_servers(CollectServersFilter::Active365d)
        .await?;
    let ranges = to_subnet_16_ranges(&known_servers);

    if ranges.is_empty() {
        return Ok(vec![]);
    }

    let mut target_ranges = Vec::new();
    for (range_prefix, group) in ranges {
        if group.ips.len() < 32 {
            continue;
        }

        target_ranges.push(ScanRange {
            ip_start: Ipv4Addr::new(range_prefix.0, range_prefix.1, 0, 0),
            ip_end: Ipv4Addr::new(range_prefix.0, range_prefix.1, 255, 255),
            port_start: 25565,
            port_end: 25565,
        });
    }

    Ok(target_ranges)
}
