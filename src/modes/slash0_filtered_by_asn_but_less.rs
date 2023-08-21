use std::collections::{HashMap, HashSet};

use crate::{
    asns,
    database::{CollectServersFilter, Database},
    scanner::targets::ScanRange,
};

pub async fn get_ranges(database: &Database) -> anyhow::Result<Vec<ScanRange>> {
    let known_servers =
        crate::database::collect_all_servers(database, CollectServersFilter::Active365d).await?;

    let asns = asns::get().await?;

    let mut asns_with_servers = HashMap::new();

    // get the asns with minecraft servers and then only scan those ranges
    for server in &known_servers {
        let asn = asns.get_asn(*server.ip());
        if let Some(asn) = asn {
            *asns_with_servers.entry(asn).or_insert(0) += 1;
        }
    }

    // only keep asns with at least 10 servers
    let asns_with_servers: HashSet<_> = asns_with_servers
        .into_iter()
        .filter(|(_, count)| *count >= 10)
        .map(|(asn, _)| asn)
        .collect();

    // get top port
    let mut port_counts = HashMap::new();
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
    for asn in asns_with_servers {
        let asn_ranges = asns.get_ranges_for_asn(asn);
        for range in asn_ranges {
            ranges.push(ScanRange::single_port(range.start, range.end, top_port));
        }
    }

    Ok(ranges)
}
