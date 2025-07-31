use std::{collections::HashMap, str::FromStr};

use rand::prelude::*;

use crate::{config::Config, database::Database, scanner::targets::ScanRange};

use self::rescan::Sort;

pub mod fingerprint;
pub mod rescan;
pub mod slash0;
pub mod slash24;
pub mod slash32;

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Hash, enum_utils::FromStr, enum_utils::IterVariants,
)]
pub enum ScanMode {
    Slash0,
    Slash24,
    Slash32,

    Rescan1day,
    Rescan7days,
    Rescan30days,
    Rescan365days,
    RescanOlderThan365days,
}

pub struct ModePicker {
    // the number of new servers last attempt
    // defaults to a big number (so we try all of them first)
    // (we can't do usize::MAX because WeightedIndex breaks)
    modes: HashMap<ScanMode, usize>,
}

const DEFAULT_FOUND: usize = 1_000_000;
impl Default for ModePicker {
    fn default() -> Self {
        // make a hashmap of { mode: servers fount last scan } and default to 2^16

        // read modes.json
        let mut modes = std::fs::read_to_string("modes.json")
            .unwrap_or_default()
            .parse::<serde_json::Value>()
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()))
            .as_object()
            .expect("failed to parse modes.json")
            .iter()
            .filter_map(|(mode, count)| {
                if let Ok(mode) = ScanMode::from_str(mode) {
                    Some((
                        mode,
                        count.as_u64().expect("couldn't parse count as number") as usize,
                    ))
                } else {
                    None
                }
            })
            .collect::<HashMap<_, _>>();

        for mode in ScanMode::iter() {
            modes.entry(mode).or_insert(DEFAULT_FOUND);
        }

        Self { modes }
    }
}

impl ModePicker {
    /// Picks a mode to scan with. You can optionally pass a list of modes to
    /// pick from, otherwise it'll use all of them.
    pub fn pick_mode(&self, modes: Option<Vec<ScanMode>>) -> ScanMode {
        #[cfg(feature = "benchmark")]
        return ScanMode::Slash0;
        // return ScanMode::Slash32RangePorts;

        // if they're all 0, pick Slash0.
        // this mostly fixes a bug where some modes panic when the database is empty.
        if self
            .modes
            .values()
            .all(|&count| count == 0 || count == DEFAULT_FOUND)
        {
            return ScanMode::Slash0;
        }

        let modes_vec = self.modes.iter().map(|(m, i)| (*m, *i)).collect::<Vec<_>>();
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
                .choose(&mut rand::thread_rng())
                .unwrap();
        }

        // otherwise, pick the best one
        let mut best_mode = ScanMode::Slash0;
        let mut best_score = 0;
        for (mode, score) in modes_vec.iter() {
            if *score > best_score {
                best_score = *score;
                best_mode = *mode;
            }
        }
        best_mode
    }

    pub fn update_mode(&mut self, mode: ScanMode, score: usize) {
        self.modes.insert(mode, score);

        // write modes.json
        let mut modes = serde_json::Map::new();
        for (mode, count) in self.modes.iter() {
            modes.insert(
                format!("{mode:?}"),
                serde_json::Value::Number((*count).into()),
            );
        }

        if let Err(err) =
            std::fs::write("modes.json", serde_json::to_string_pretty(&modes).unwrap())
        {
            eprintln!("failed to write modes.json: {err}");
        }
    }
}

impl ScanMode {
    pub async fn get_ranges(
        &self,
        database: &mut Database,
        config: &Config,
    ) -> anyhow::Result<Vec<ScanRange>> {
        if let Some(only_scan_addr) = config.debug.only_scan_addr {
            let ip = only_scan_addr.ip().clone();
            let port = only_scan_addr.port();
            return Ok(vec![ScanRange {
                addr_start: ip,
                addr_end: ip,
                port_start: port,
                port_end: port,
            }]);
        }

        match self {
            ScanMode::Slash0 => slash0::get_ranges(database).await,
            ScanMode::Slash24 => slash24::get_ranges(database).await,
            ScanMode::Slash32 => slash32::get_ranges(database).await,

            ScanMode::Rescan1day => {
                rescan::get_ranges(
                    database,
                    &Default::default(),
                    60 * 60 * 2,
                    None,
                    60 * 60 * 24,
                    Some(250_000),
                    Some(Sort::Oldest),
                )
                .await
            }
            ScanMode::Rescan7days => {
                rescan::get_ranges(
                    database,
                    &Default::default(),
                    60 * 60 * 24,
                    None,
                    60 * 60 * 24 * 7,
                    Some(250_000),
                    Some(Sort::Oldest),
                )
                .await
            }
            ScanMode::Rescan30days => {
                rescan::get_ranges(
                    database,
                    &Default::default(),
                    60 * 60 * 24 * 7,
                    None,
                    60 * 60 * 24 * 30,
                    Some(250_000),
                    Some(Sort::Random),
                )
                .await
            }
            ScanMode::Rescan365days => {
                rescan::get_ranges(
                    database,
                    &Default::default(),
                    60 * 60 * 24 * 30,
                    None,
                    60 * 60 * 24 * 365,
                    Some(500_000),
                    Some(Sort::Random),
                )
                .await
            }
            ScanMode::RescanOlderThan365days => {
                rescan::get_ranges(
                    database,
                    &Default::default(),
                    60 * 60 * 24 * 365,
                    None,
                    60 * 60 * 24 * 365 * 10,
                    Some(500_000),
                    Some(Sort::Random),
                )
                .await
            }
        }
    }
}
