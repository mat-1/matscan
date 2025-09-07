use crate::processing::minecraft::PingResponse;

const BANNED_DESCRIPTIONS: &[&str] = &[
    "Craftserve.pl - wydajny hosting Minecraft!",
    "Pay for the server on https://craftserve.com to be able to log in.",
    "Craftserve: Error finding route. Please contact support.",
    "Nie znaleziono serwera o podanym adresie, zakup go na https://craftserve.com",
    //
    "Ochrona DDoS: Przekroczono limit polaczen.",
    "¨ |  ",
    "Start the server at FalixNodes.net/start",
    "This server is offline Powered by FalixNodes.net",
    "Serwer jest aktualnie wy",
    "Blad pobierania statusu. Polacz sie bezposrednio!",
    "Error connecting to server#",
    // play.devlencio.net requested exclusion because Velocity logs errors
    // on ping, and by MOTD due to a dynamic IP.
    "The hub for all Devlencio servers",
    // mc.playersworld.ru requested exclusion
    "Players World — равноправие",
];
const BANNED_VERSIONS: &[&str] = &["COSMIC GUARD", "TCPShield.com", "â  Error", "⚠ Error"];

pub fn should_insert(s: &PingResponse) -> bool {
    for banned_desc in BANNED_DESCRIPTIONS.iter() {
        if s.description_plaintext.contains(banned_desc) {
            return false;
        }
    }
    if let Some(version_name) = &s.version_name {
        for banned_version in BANNED_VERSIONS.iter() {
            if version_name.contains(banned_version) {
                return false;
            }
        }
    }

    true
}
