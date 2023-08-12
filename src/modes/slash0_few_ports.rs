use std::{collections::HashMap, net::Ipv4Addr};

use crate::{
    database::{CollectServersFilter, Database},
    scanner::targets::ScanRange,
};

/// Scan world on one port.
///
/// Returns a Vec for consistency with the other modes, even though it will
/// only ever contain one element.
pub async fn get_ranges(database: &Database) -> anyhow::Result<Vec<ScanRange>> {
    let known_servers =
        crate::database::collect_all_servers(database, CollectServersFilter::Active30d).await?;

    // get top 10 ports
    let mut port_counts = HashMap::new();
    for server in &known_servers {
        *port_counts.entry(server.port()).or_insert(0) += 1;
    }
    let mut port_counts: Vec<_> = port_counts.into_iter().collect();
    port_counts.sort_by_key(|(_, count)| *count);
    port_counts.reverse();
    let top_ports: Vec<_> = port_counts
        .into_iter()
        .map(|(port, _)| port)
        .take(10)
        .collect();

    let mut ranges = Vec::new();
    for port in top_ports {
        ranges.push(ScanRange::single_port(
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
            port,
        ));
    }

    Ok(ranges)
}
