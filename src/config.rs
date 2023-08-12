use serde::Deserialize;

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub mongodb_uri: String,
    pub rate: u64,

    /// The number of seconds to sleep after each scan. You can set this to 0
    /// if you want, but it mostly helps avoid pings being associated to the
    /// wrong mode.
    ///
    /// Defaults to 10 seconds.
    #[serde(default)]
    pub sleep_secs: Option<u64>,

    /// If true, the program will exit after the first scan. This is primarily
    /// meant for for debugging purposes.
    #[serde(default)]
    pub exit_on_done: bool,

    /// The maximum amount of time each scan will take. Defaults to 5 minutes.
    /// You should probably leave it as the default unless you're debugging
    /// something to do with switching modes.
    #[serde(default)]
    pub scan_duration_secs: Option<u64>,

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
    #[serde(default)]
    pub last_ping_ago_max_secs: Option<u64>,

    pub limit: Option<usize>,
    #[serde(default)]
    pub filter: toml::Table,
    #[serde(default)]
    pub sort: Option<crate::modes::rescan::Sort>,
}

#[derive(Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct SnipeConfig {
    pub enabled: bool,
    pub webhook_url: String,
    pub usernames: Vec<String>,
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
