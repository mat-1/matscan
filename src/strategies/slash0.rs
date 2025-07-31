use std::net::Ipv4Addr;

use crate::{database::Database, scanner::targets::ScanRange};

/// Scan world on one port.
///
/// Returns a Vec for consistency with the other strategies, even though it will
/// only ever contain one element.
pub async fn get_ranges(_database: &mut Database) -> anyhow::Result<Vec<ScanRange>> {
    let top_port = 25565;

    let ranges = vec![ScanRange::single_port(
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
        top_port,
    )];

    Ok(ranges)
}
