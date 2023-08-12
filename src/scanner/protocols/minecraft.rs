use std::{
    io::{Cursor, Read, Write},
    net::SocketAddrV4,
};

use super::{ParseResponseError, Protocol, Response};

#[derive(Clone)]
pub struct Minecraft {
    minecraft_request: Vec<u8>,
}

impl Minecraft {
    pub fn new(hostname: &str, port: u16, protocol_version: i32) -> Self {
        let minecraft_request = build_latest_request(hostname, port, protocol_version);
        Self { minecraft_request }
    }
}

impl Protocol for Minecraft {
    fn payload(&self, _address: SocketAddrV4) -> Vec<u8> {
        self.minecraft_request.clone()
    }

    fn parse_response(&self, response: Response) -> Result<Vec<u8>, ParseResponseError> {
        let response = match response {
            Response::Data(r) => r,
            Response::Rst => return Err(ParseResponseError::Invalid),
        };

        // ignore the packet length
        let mut stream = Cursor::new(response);
        read_varint(&mut stream).ok_or(ParseResponseError::Invalid)?;
        let packet_id = read_varint(&mut stream).ok_or(ParseResponseError::Invalid)?;
        let response_length = read_varint(&mut stream).ok_or(ParseResponseError::Invalid)?;
        if packet_id != 0x00 || response_length < 0 {
            return Err(ParseResponseError::Invalid);
        }
        // read until end
        let position = stream.position() as usize;
        let status_buffer = &stream.into_inner()[position..];
        if status_buffer.len() < response_length as usize {
            return Err(ParseResponseError::Incomplete {
                expected_length: response_length as u32,
            });
        }

        let status_string = String::from_utf8_lossy(status_buffer).to_string();

        // make sure it starts with {
        if !status_string.starts_with('{') {
            return Err(ParseResponseError::Invalid);
        }

        Ok(status_string.into_bytes())
    }
}

/// https://github.com/kiwiyou/craftping/blob/master/src/lib.rs#L73
pub fn build_latest_request(hostname: &str, port: u16, protocol_version: i32) -> Vec<u8> {
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
        0x01,                       // next state: 1 (status) as VarInt
    ]);
    // buffer for the 1st and 2nd packet
    let mut full_buffer = vec![];
    write_varint(&mut full_buffer, buffer.len() as i32); // length of 1st packet id + data as VarInt
    full_buffer.append(&mut buffer);
    full_buffer.extend_from_slice(&[
        1,    // length of 2nd packet id + data as VarInt
        0x00, // 2nd packet id: 0 for request as VarInt
    ]);

    eprintln!("full_buffer: {full_buffer:?}");

    // let mut f = std::fs::File::create("request.bin").unwrap();
    // f.write_all(&full_buffer).unwrap();

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

fn read_varint(reader: &mut (dyn Read + Unpin + Send)) -> Option<i32> {
    let mut buffer = [0];
    let mut ans = 0;
    for i in 0..5 {
        reader.read_exact(&mut buffer).ok()?;
        ans |= ((buffer[0] & 0b0111_1111) as i32) << (7 * i);
        if buffer[0] & 0b1000_0000 == 0 {
            return Some(ans);
        }
    }
    Some(ans)
}
