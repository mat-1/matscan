use std::{collections::HashMap, net::Ipv4Addr};

use crate::{
    database::{CollectServersFilter, Database},
    scanner::targets::ScanRange,
};

use super::slash24::{to_ranges, ServerGroup};

pub async fn get_ranges(database: &Database) -> anyhow::Result<Vec<ScanRange>> {
    let known_servers =
        crate::database::collect_all_servers(database, CollectServersFilter::New).await?;

    let known_ranges: HashMap<(u8, u8, u8), ServerGroup> = to_ranges(&known_servers);

    // get top port
    let mut port_counts: HashMap<u16, i32> = HashMap::new();
    for server in &known_servers {
        *port_counts.entry(server.port()).or_insert(0) += 1;
    }
    let mut port_counts: Vec<_> = port_counts.into_iter().collect();
    port_counts.sort_by_key(|(_, count)| *count);
    port_counts.reverse();
    let top_port: u16 = port_counts
        .into_iter()
        .map(|(port, _)| port)
        .next()
        .unwrap_or(25565);

    let mut ranges = Vec::new();
    for ((a, b, c), _) in known_ranges {
        ranges.push(ScanRange::single_port(
            Ipv4Addr::new(a, b, c, 0),
            Ipv4Addr::new(a, b, c, 255),
            top_port,
        ));
    }

    Ok(ranges)
}
