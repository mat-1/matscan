mod minecraft;
mod minecraft_fingerprinting;

use std::net::SocketAddrV4;

pub use minecraft::Minecraft;
pub use minecraft_fingerprinting::MinecraftFingerprinting;

#[derive(Debug)]
pub enum ParseResponseError {
    Invalid,
    Incomplete { expected_length: u32 },
}

pub enum Response {
    Data(Vec<u8>),
    Rst,
    Fin,
}

pub trait Protocol: Send + Sync {
    fn payload(&self, address: SocketAddrV4) -> Vec<u8>;
    fn parse_response(&self, response: Response) -> Result<Vec<u8>, ParseResponseError>;
}
