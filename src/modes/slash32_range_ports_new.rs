use std::{collections::HashMap, net::Ipv4Addr};

use crate::{
    database::{CollectServersFilter, Database},
    scanner::targets::ScanRange,
};

pub async fn get_ranges(database: &Database) -> anyhow::Result<Vec<ScanRange>> {
    let known_servers =
        crate::database::collect_all_servers(database, CollectServersFilter::New).await?;

    let mut open_ports: HashMap<Ipv4Addr, Vec<u16>> = HashMap::new();
    for server in known_servers {
        open_ports
            .entry(*server.ip())
            .or_default()
            .push(server.port());
    }
    println!("got open ports");

    let mut ranges = Vec::new();
    for (addr, ports) in open_ports {
        if ports.len() < 3 {
            // not enough servers here, don't care
            continue;
        }
        // get the highest and lowest ports in the group
        let mut lowest_port = u16::MAX;
        let mut highest_port = u16::MIN;
        for &port in &ports {
            if port < lowest_port {
                lowest_port = port;
            }
            if port > highest_port {
                highest_port = port;
            }
        }
        let mut modulo = None;
        if ports.len() > 10 {
            // check if they're all modulo something
            for mod_candidate in [1000, 100, 10] {
                let mut all_mod = true;
                for port in &ports {
                    if port % mod_candidate != 0 {
                        all_mod = false;
                        break;
                    }
                }
                if all_mod {
                    modulo = Some(mod_candidate);
                    break;
                }
            }
        }

        if let Some(modulo) = modulo {
            let mut port = lowest_port;
            while port <= highest_port {
                ranges.push(ScanRange::single(addr, port));
                port += modulo;
            }
        } else {
            ranges.push(ScanRange::single_address(addr, lowest_port, highest_port));
        }
    }
    println!("got ranges");

    Ok(ranges)
}
