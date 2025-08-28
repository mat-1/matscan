use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddrV4},
};

use crate::{
    database::{CollectServersFilter, Database},
    scanner::targets::ScanRange,
};

pub async fn get_ranges(database: &Database) -> anyhow::Result<Vec<ScanRange>> {
    println!("collecting servers");
    let known_servers =
        crate::database::collect_all_servers(database, CollectServersFilter::Active365d).await?;
    println!("finished collecting {} servers", known_servers.len());

    let ranges: HashMap<(u8, u8), ServerGroup> = to_ranges(&known_servers);
    println!("converted into {} ranges", ranges.len());

    if ranges.is_empty() {
        return Ok(vec![]);
    }

    let mut target_ranges = Vec::new();

    for (range_prefix, group) in ranges {
        if group.ips.len() < 32 {
            continue;
        }
        target_ranges.push(ScanRange {
            addr_start: Ipv4Addr::new(range_prefix.0, range_prefix.1, 0, 0),
            addr_end: Ipv4Addr::new(range_prefix.0, range_prefix.1, 255, 255),
            port_start: 25565,
            port_end: 25565,
        });
    }

    Ok(target_ranges)
}

#[derive(Default, Debug, Hash, PartialEq)]
pub struct ServerGroup {
    pub ips: Vec<Ipv4Addr>,
    pub ports: Vec<u16>,
}

pub fn to_ranges(known_servers: &Vec<SocketAddrV4>) -> HashMap<(u8, u8), ServerGroup> {
    let mut ranges: HashMap<(u8, u8), ServerGroup> = HashMap::new();
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
