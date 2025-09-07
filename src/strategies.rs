use std::{collections::HashMap, fs, str::FromStr};

use rand::prelude::*;

use self::rescan::Sort;
use crate::{
    config::{Config, RescanConfig},
    database::Database,
    scanner::targets::ScanRange,
};

pub mod fingerprint;
pub mod rescan;
mod slash0;
mod slash16_a;
mod slash16_b;
mod slash24_a;
mod slash24_b;
mod slash24_c;
mod slash32;

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Hash, enum_utils::FromStr, enum_utils::IterVariants,
)]
pub enum ScanStrategy {
    Slash0,
    Slash16a,
    Slash16b,
    Slash24a,
    Slash24b,
    Slash24c,
    Slash32,

    Rescan1day,
    Rescan7days,
    Rescan30days,
    Rescan365days,
    RescanOlderThan365days,
}

pub struct StrategyPicker {
    // the number of new servers last attempt
    // defaults to a big number (so we try all of them first)
    // (we can't do usize::MAX because WeightedIndex breaks)
    strategies: HashMap<ScanStrategy, usize>,
}

const DEFAULT_FOUND: usize = 1_000_000;
impl Default for StrategyPicker {
    fn default() -> Self {
        // make a hashmap of { mode: servers fount last scan } and default to 2^16

        // backwards compat
        if !fs::exists("strategies.json").unwrap() {
            let _ = fs::rename("modes.json", "strategies.json");
        }

        // read strategies.json
        let mut modes = std::fs::read_to_string("strategies.json")
            .unwrap_or_default()
            .parse::<serde_json::Value>()
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()))
            .as_object()
            .expect("failed to parse strategies.json")
            .iter()
            .filter_map(|(mode, count)| {
                if let Ok(mode) = ScanStrategy::from_str(mode) {
                    Some((
                        mode,
                        count.as_u64().expect("couldn't parse count as number") as usize,
                    ))
                } else {
                    None
                }
            })
            .collect::<HashMap<_, _>>();

        for mode in ScanStrategy::iter() {
            modes.entry(mode).or_insert(DEFAULT_FOUND);
        }

        Self { strategies: modes }
    }
}

impl StrategyPicker {
    /// Picks a mode to scan with. You can optionally pass a list of modes to
    /// pick from, otherwise it'll use all of them.
    pub fn pick_strategy(&self, modes: Option<Vec<ScanStrategy>>) -> ScanStrategy {
        #[cfg(feature = "benchmark")]
        return ScanStrategy::Slash0;
        // return ScanMode::Slash32RangePorts;

        // if they're all 0, pick Slash0.
        // this mostly fixes a bug where some modes panic when the database is empty.
        if self
            .strategies
            .values()
            .all(|&count| count == 0 || count == DEFAULT_FOUND)
        {
            return ScanStrategy::Slash0;
        }

        let modes_vec = self
            .strategies
            .iter()
            .map(|(m, i)| (*m, *i))
            .collect::<Vec<_>>();
        // filter by the modes argument
        let modes_vec = if let Some(modes) = modes {
            modes_vec
                .into_iter()
                .filter(|(mode, _)| modes.contains(mode))
                .collect::<Vec<_>>()
        } else {
            modes_vec
        };

        // 1% chance to pick a random strategy
        if rand::random::<f64>() < 0.01 {
            return modes_vec
                .iter()
                .map(|(mode, _)| *mode)
                .choose(&mut rand::rng())
                .unwrap();
        }

        // otherwise, pick the best one
        let mut best_mode = ScanStrategy::Slash0;
        let mut best_score = 0;
        for (mode, score) in modes_vec.iter() {
            if *score > best_score {
                best_score = *score;
                best_mode = *mode;
            }
        }
        best_mode
    }

    pub fn update_strategy(&mut self, mode: ScanStrategy, score: usize) {
        self.strategies.insert(mode, score);

        // write strategies.json
        let mut modes = serde_json::Map::new();
        for (mode, count) in self.strategies.iter() {
            modes.insert(
                format!("{mode:?}"),
                serde_json::Value::Number((*count).into()),
            );
        }

        if let Err(err) = fs::write(
            "strategies.json",
            serde_json::to_string_pretty(&modes).unwrap(),
        ) {
            eprintln!("failed to write strategies.json: {err}");
        }
    }
}

impl ScanStrategy {
    pub async fn get_ranges(
        &self,
        database: &mut Database,
        config: &Config,
    ) -> eyre::Result<Vec<ScanRange>> {
        if let Some(only_scan_addr) = config.debug.only_scan_addr {
            let ip = *only_scan_addr.ip();
            let port = only_scan_addr.port();
            return Ok(vec![ScanRange {
                ip_start: ip,
                ip_end: ip,
                port_start: port,
                port_end: port,
            }]);
        }

        match self {
            ScanStrategy::Slash0 => slash0::get_ranges(database).await,
            ScanStrategy::Slash16a => slash16_a::get_ranges(database).await,
            ScanStrategy::Slash16b => slash16_b::get_ranges(database).await,
            ScanStrategy::Slash24a => slash24_a::get_ranges(database).await,
            ScanStrategy::Slash24b => slash24_b::get_ranges(database).await,
            ScanStrategy::Slash24c => slash24_c::get_ranges(database).await,
            ScanStrategy::Slash32 => slash32::get_ranges(database).await,

            ScanStrategy::Rescan1day => {
                rescan::get_ranges(
                    database,
                    &RescanConfig {
                        rescan_every_secs: 60 * 60 * 2,
                        last_ping_ago_max_secs: 60 * 60 * 24,
                        limit: Some(250_000),
                        sort: Some(Sort::Oldest),
                        padded: true,
                        ..Default::default()
                    },
                )
                .await
            }
            ScanStrategy::Rescan7days => {
                rescan::get_ranges(
                    database,
                    &RescanConfig {
                        rescan_every_secs: 60 * 60 * 24,
                        last_ping_ago_max_secs: 60 * 60 * 24 * 7,
                        limit: Some(250_000),
                        sort: Some(Sort::Oldest),
                        padded: true,
                        ..Default::default()
                    },
                )
                .await
            }
            ScanStrategy::Rescan30days => {
                rescan::get_ranges(
                    database,
                    &RescanConfig {
                        rescan_every_secs: 60 * 60 * 24 * 7,
                        last_ping_ago_max_secs: 60 * 60 * 24 * 30,
                        limit: Some(250_000),
                        sort: Some(Sort::Random),
                        padded: true,
                        ..Default::default()
                    },
                )
                .await
            }
            ScanStrategy::Rescan365days => {
                rescan::get_ranges(
                    database,
                    &RescanConfig {
                        rescan_every_secs: 60 * 60 * 24 * 30,
                        last_ping_ago_max_secs: 60 * 60 * 24 * 365,
                        limit: Some(500_000),
                        sort: Some(Sort::Random),
                        padded: true,
                        ..Default::default()
                    },
                )
                .await
            }
            ScanStrategy::RescanOlderThan365days => {
                rescan::get_ranges(
                    database,
                    &RescanConfig {
                        rescan_every_secs: 60 * 60 * 24 * 365,
                        last_ping_ago_max_secs: 60 * 60 * 24 * 365 * 10,
                        limit: Some(500_000),
                        sort: Some(Sort::Random),
                        padded: true,
                        ..Default::default()
                    },
                )
                .await
            }
        }
    }
}
