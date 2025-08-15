use std::{net::SocketAddrV4, path::PathBuf};

use serde::Deserialize;

use crate::scanner::SourcePort;

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub mongodb_uri: String,
    pub rate: u64,

    /// The number of seconds to sleep after each scan. You can set this to 0
    /// if you want, but it mostly helps avoid pings being associated to the
    /// wrong strategy.
    ///
    /// Defaults to 10 seconds.
    #[serde(default)]
    pub sleep_secs: Option<u64>,

    /// The port that we send packets from. You **must** firewall it, otherwise
    /// your OS will drop connections immediately.
    ///
    /// This can be either a number like 61000 or a range like "61000-65535"
    #[serde(default)]
    pub source_port: SourcePort,

    /// The maximum amount of time each scan will take. Defaults to 5 minutes.
    /// You should probably leave it as the default unless you're debugging
    /// something to do with switching strategies.
    #[serde(default)]
    pub scan_duration_secs: Option<u64>,

    /// The maximum amount of time to wait for a ping response before giving up.
    /// Defaults to 60 seconds.
    #[serde(default)]
    pub ping_timeout_secs: Option<u64>,

    pub target: TargetConfig,

    pub scanner: ScannerConfig,

    // useful if you want do be doing rescanning with different options
    #[serde(default)]
    pub rescan: RescanConfig,
    #[serde(default)]
    pub rescan2: RescanConfig,
    #[serde(default)]
    pub rescan3: RescanConfig,
    #[serde(default)]
    pub rescan4: RescanConfig,
    #[serde(default)]
    pub rescan5: RescanConfig,

    /// Log to a Discord webhook if a player with a given username joins a
    /// server. This works best if you're rescanning quickly and not
    /// distributed.
    #[serde(default)]
    pub snipe: SnipeConfig,

    #[serde(default)]
    pub fingerprinting: FingerprintingConfig,

    /// The directory where the rotating matscan.log files should be written to.
    /// None to disable logging to a file. Note that these logs aren't the same
    /// as the ones that are shown in stdout.
    #[serde(default)]
    pub logging_dir: Option<PathBuf>,

    #[serde(default)]
    pub debug: DebugConfig,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TargetConfig {
    pub addr: String,
    pub port: u16,
    pub protocol_version: i32,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ScannerConfig {
    pub enabled: bool,
    /// The list of strategies that we'll use to scan. By default all strategies
    /// are included. Strategy names are the same ones as in
    /// strategies.json.
    #[serde(default)]
    pub strategies: Option<Vec<String>>,
}

#[derive(Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct RescanConfig {
    pub enabled: bool,
    pub rescan_every_secs: u64,

    #[serde(default)]
    pub players_online_ago_max_secs: Option<u64>,

    /// The maximum number of seconds since the last ping to consider a server
    /// for rescanning.
    #[serde(default = "default_last_ping_ago_max_secs")]
    pub last_ping_ago_max_secs: u64,

    pub limit: Option<usize>,
    #[serde(default)]
    pub filter: toml::Table,
    #[serde(default)]
    pub sort: Option<crate::strategies::rescan::Sort>,

    /// Whether we should add some extra random IPs to scan, to avoid
    /// overloading our server from receiving too many valid responses at once.
    #[serde(default)]
    pub padded: bool,
}
fn default_last_ping_ago_max_secs() -> u64 {
    // 2 hours
    60 * 60 * 2
}

#[derive(Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct SnipeConfig {
    pub enabled: bool,
    pub webhook_url: String,
    pub usernames: Vec<String>,
    /// Whether we should log when a lot of anonymous players suddenly join a
    /// server.
    #[serde(default)]
    pub anon_players: bool,
}

#[derive(Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct FingerprintingConfig {
    /// Test quirks with the server's protocol implementation. This may cause
    /// errors to show up in the consoles of servers.
    ///
    /// If this is false then passive fingerprinting is still done but it won't
    /// be able to gather as much information as active fingerprinting.
    pub enabled: bool,
}

#[derive(Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct DebugConfig {
    /// If true, the program will exit after the first scan.
    #[serde(default)]
    pub exit_on_done: bool,

    /// Scanning will only send a ping to the given address.
    ///
    /// This also disables all other strategies like rescanning and
    /// fingerprinting. The exclude list is also ignored.
    #[serde(default)]
    pub only_scan_addr: Option<SocketAddrV4>,

    #[serde(default)]
    pub simulate_rx_loss: f32,
    #[serde(default)]
    pub simulate_tx_loss: f32,
}
