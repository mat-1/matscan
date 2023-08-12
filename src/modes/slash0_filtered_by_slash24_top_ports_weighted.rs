use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
};

use rand::Rng;

use crate::{
    database::{CollectServersFilter, Database},
    scanner::targets::ScanRange,
};

use super::slash24::{to_ranges, ServerGroup};

pub async fn get_ranges(database: &Database) -> anyhow::Result<Vec<ScanRange>> {
    let known_servers =
        crate::database::collect_all_servers(database, CollectServersFilter::Active365d).await?;

    let known_ranges: HashMap<(u8, u8, u8), ServerGroup> = to_ranges(&known_servers);

    let mut port_counts: [u32; 65536] = [0; 65536];
    let mut server_count = 0;
    for server in &known_servers {
        if server.port() == 25565 {
            // ignore default port since we already scan for that in slash0
            continue;
        }
        port_counts[server.port() as usize] += 1;
        server_count += 1;
    }

    let port_counts = port_counts.into_iter().enumerate().collect::<Vec<_>>();

    let mut ports_to_scan = HashSet::<u16>::new();

    // weighted random by picking a random number up to server_count and then
    // iterating through the ports until we reach that number
    for _ in 0..128 {
        let mut rng = rand::thread_rng();
        let mut random: u32 = rng.gen_range(0..server_count);
        for &(port, port_count) in port_counts.iter() {
            if random < port_count {
                // this is the port we want to scan
                ports_to_scan.insert(port as u16);
                break;
            } else {
                random -= port_count;
            }
        }
    }

    // pick 8192 random known_ranges
    let mut chosen_known_ranges = HashSet::<(u8, u8, u8)>::new();
    if known_ranges.len() > 8192 {
        let mut rng = rand::thread_rng();
        while chosen_known_ranges.len() < 8192 {
            let random = rng.gen_range(0..known_ranges.len());
            let chosen = known_ranges.keys().nth(random).unwrap();
            chosen_known_ranges.insert(*chosen);
        }
    } else {
        for key in known_ranges.keys() {
            chosen_known_ranges.insert(*key);
        }
    }

    let mut ranges = Vec::new();
    for (a, b, c) in chosen_known_ranges {
        for &port in &ports_to_scan {
            ranges.push(ScanRange::single_port(
                Ipv4Addr::new(a, b, c, 0),
                Ipv4Addr::new(a, b, c, 255),
                port,
            ));
        }
    }

    Ok(ranges)
}
