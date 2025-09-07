use std::net::SocketAddrV4;

use crate::database::Database;

pub async fn get_addrs_and_protocol_versions(
    _database: &Database,
) -> eyre::Result<Vec<(SocketAddrV4, i32)>> {
    unimplemented!("active fingerprinting was removed from matscan")
}
