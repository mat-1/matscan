use std::{collections::HashMap, net::Ipv4Addr};

use rand::{seq::IteratorRandom, thread_rng};

use crate::{
    database::{CollectServersFilter, Database},
    modes::slash24::{get_related_score, to_ranges, ServerGroup},
    scanner::targets::ScanRange,
};

/// Scan ports that are likely to have servers on random ranges.
pub async fn get_ranges(database: &Database) -> anyhow::Result<Vec<ScanRange>> {
    println!("collecting servers");
    let known_servers =
        crate::database::collect_all_servers(database, CollectServersFilter::Active30d).await?;
    println!("finished collecting {} servers", known_servers.len());

    let ranges: HashMap<(u8, u8, u8), ServerGroup> = to_ranges(&known_servers);
    println!("converted into {} ranges", ranges.len());

    if ranges.is_empty() {
        return Ok(vec![]);
    }

    let mut rng = thread_rng();
    let mut target_ranges = Vec::new();

    for _ in 0..8192 {
        // randomly pick from ranges
        let range_prefix = ranges.keys().choose(&mut rng).unwrap();

        let range_a = &ranges[range_prefix];

        let mut top_ports = HashMap::<u16, u32>::new();

        // find ranges that are similar to this range and add their ports to top_ports
        for range in ranges.values() {
            let relatedness = get_related_score(range_a, range);
            if relatedness > 0.1 {
                let mut ports_deduped = range.ports.clone();
                ports_deduped.dedup();

                for port in ports_deduped {
                    *top_ports.entry(port).or_default() += 1;
                }
            }
        }

        let top_ports = top_ports
            .into_iter()
            .take(8)
            .map(|(port, _)| port)
            .collect::<Vec<_>>();

        for port in top_ports {
            target_ranges.push(ScanRange::single_port(
                Ipv4Addr::new(range_prefix.0, range_prefix.1, range_prefix.2, 0),
                Ipv4Addr::new(range_prefix.0, range_prefix.1, range_prefix.2, 255),
                port,
            ));
        }
    }

    Ok(target_ranges)
}
