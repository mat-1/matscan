use std::{collections::HashMap, io::Write, net::SocketAddrV4};

use super::{ParseResponseError, Protocol, Response};

pub struct MinecraftFingerprinting {
    protocol_versions: HashMap<SocketAddrV4, i32>,
}

impl MinecraftFingerprinting {
    pub fn new(protocol_versions: HashMap<SocketAddrV4, i32>) -> Self {
        Self { protocol_versions }
    }
}

impl Protocol for MinecraftFingerprinting {
    fn payload(&self, address: SocketAddrV4) -> Vec<u8> {
        let Some(&protocol_version) = self.protocol_versions.get(&address) else {
            return vec![];
        };
        build_fingerprint_request(&address.ip().to_string(), address.port(), protocol_version)
    }

    fn parse_response(&self, response: Response) -> Result<Vec<u8>, ParseResponseError> {
        Ok(match response {
            Response::Data(r) => r.to_owned(),
            Response::Rst => return Err(ParseResponseError::Invalid),
        })
    }
}

/// Create a request that will cause servers to respond with an error (which we can then use to identify the server software).
pub fn build_fingerprint_request(hostname: &str, port: u16, protocol_version: i32) -> Vec<u8> {
    // buffer for the 1st packet's data part
    let mut buffer = vec![
        // 0 for handshake packet
        0x00,
    ];

    write_varint(&mut buffer, protocol_version); // protocol version

    // Some server implementations require hostname and port to be properly set (Notchian does not)
    write_varint(&mut buffer, hostname.len() as i32); // length of hostname as VarInt
    buffer.extend_from_slice(hostname.as_bytes());
    buffer.extend_from_slice(&[
        (port >> 8) as u8,
        (port & 0b1111_1111) as u8, // server port as unsigned short
        0x02,                       // next state: 2
    ]);
    // buffer for the 1st and 2nd packet
    let mut full_buffer = vec![];
    write_varint(&mut full_buffer, buffer.len() as i32); // length of 1st packet id + data as VarInt
    full_buffer.append(&mut buffer);
    full_buffer.extend_from_slice(&[
        4,    // length of following data
        0x00, // packet id
        0x00, // username length
        0x00, // no uuid
        0x00, // extra data (to cause error)
    ]);

    full_buffer
}

fn write_varint(writer: &mut Vec<u8>, mut value: i32) {
    let mut buffer = [0];
    if value == 0 {
        writer.write_all(&buffer).unwrap();
    }
    while value != 0 {
        buffer[0] = (value & 0b0111_1111) as u8;
        value = (value >> 7) & (i32::max_value() >> 6);
        if value != 0 {
            buffer[0] |= 0b1000_0000;
        }
        writer.write_all(&buffer).unwrap();
    }
}
