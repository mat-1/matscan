use std::{
    cmp::Ordering,
    collections::HashMap,
    net::{Ipv4Addr, SocketAddrV4},
};

use crate::{
    database::{CollectServersFilter, Database},
    scanner::targets::ScanRange,
};

/// Scan ports that are likely to have servers on random ranges.
pub async fn get_ranges(database: &Database) -> anyhow::Result<Vec<ScanRange>> {
    println!("collecting servers");
    let known_servers =
        crate::database::collect_all_servers(database, CollectServersFilter::Active365d).await?;
    println!("finished collecting {} servers", known_servers.len());

    let ranges: HashMap<(u8, u8, u8), ServerGroup> = to_ranges(&known_servers);
    println!("converted into {} ranges", ranges.len());

    if ranges.is_empty() {
        return Ok(vec![]);
    }

    let mut target_ranges = Vec::new();

    for (range_prefix, _group) in ranges {
        target_ranges.push(ScanRange {
            addr_start: Ipv4Addr::new(range_prefix.0, range_prefix.1, range_prefix.2, 0),
            addr_end: Ipv4Addr::new(range_prefix.0, range_prefix.1, range_prefix.2, 255),
            port_start: 25560,
            port_end: 25570,
        });
    }

    Ok(target_ranges)
}

#[derive(Default, Debug, Hash, PartialEq)]
pub struct ServerGroup {
    pub ips: Vec<Ipv4Addr>,
    pub ports: Vec<u16>,
}

pub fn to_ranges(known_servers: &Vec<SocketAddrV4>) -> HashMap<(u8, u8, u8), ServerGroup> {
    let mut ranges: HashMap<(u8, u8, u8), ServerGroup> = HashMap::new();
    for target in known_servers {
        let [a, b, c, _] = target.ip().octets();
        let entry = ranges.entry((a, b, c)).or_default();
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

pub fn get_related_score(a_range: &ServerGroup, b_range: &ServerGroup) -> f64 {
    // basically levenstein distance
    let mut distance: u32 = 0;
    let mut a_iter = a_range.ports.iter();
    let mut b_iter = b_range.ports.iter();
    let mut a = a_iter.next();
    let mut b = b_iter.next();
    while a.is_some() && b.is_some() {
        match a.cmp(&b) {
            Ordering::Equal => {
                a = a_iter.next();
                b = b_iter.next();
            }
            Ordering::Less => {
                distance += 1;
                a = a_iter.next();
            }
            Ordering::Greater => {
                distance += 1;
                b = b_iter.next();
            }
        }
    }
    while a.is_some() {
        distance += 1;
        a = a_iter.next();
    }
    while b.is_some() {
        distance += 1;
        b = b_iter.next();
    }
    let max_distance = a_range.ports.len() + b_range.ports.len();
    1.0 - (distance as f64 / max_distance as f64)
}
