use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
};

use rand::{distributions::WeightedIndex, prelude::Distribution, seq::IteratorRandom, thread_rng};

use crate::{
    database::{CollectServersFilter, Database},
    modes::slash24::{get_related_score, to_ranges, ServerGroup},
    scanner::targets::ScanRange,
};

/// Scan ranges where servers tend to appear and disappear frequently (like Ngrok ranges).
pub async fn get_ranges(database: &Database) -> anyhow::Result<Vec<ScanRange>> {
    println!("collecting servers");
    let known_servers =
        crate::database::collect_all_servers(database, CollectServersFilter::New).await?;
    println!("finished collecting {} servers", known_servers.len());

    let ranges: HashMap<(u8, u8, u8), ServerGroup> = to_ranges(&known_servers);
    println!("converted into {} ranges", ranges.len());

    let mut rng = thread_rng();
    let mut target_ranges = Vec::new();

    for _ in 0..1024 {
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

        let top_ports = top_ports.into_iter().collect::<Vec<_>>();

        let known_unique_ports = top_ports.len();

        // const MAX_SCANNING_PORTS: usize = 1024;
        const MAX_SCANNING_PORTS: usize = 64;

        let chosen_ports: Vec<u16> = if top_ports.len() < MAX_SCANNING_PORTS {
            top_ports.iter().map(|(port, _)| *port).collect()
        } else {
            let scanning_num_ports = usize::min(MAX_SCANNING_PORTS, known_unique_ports);

            // top_ports.sort_by_key(|(_, count)| (*count as f32 * 10000f32) as u32);
            let dist = WeightedIndex::new(
                top_ports
                    .iter()
                    .map(|(_, count)| *count)
                    .collect::<Vec<u32>>(),
            )
            .unwrap();
            let mut chosen_ports = HashSet::new();
            while chosen_ports.len() < scanning_num_ports {
                chosen_ports.insert(top_ports[dist.sample(&mut rng)].0);
            }
            chosen_ports.into_iter().collect()
        };

        for port in chosen_ports {
            target_ranges.push(ScanRange::single_port(
                Ipv4Addr::new(range_prefix.0, range_prefix.1, range_prefix.2, 0),
                Ipv4Addr::new(range_prefix.0, range_prefix.1, range_prefix.2, 255),
                port,
            ));
        }
    }

    Ok(target_ranges)
}
