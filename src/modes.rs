use std::{collections::HashMap, str::FromStr};

use rand::{distributions::WeightedIndex, prelude::*};

use crate::{database::Database, scanner::targets::ScanRange};

use self::rescan::Sort;

pub mod fingerprint;
pub mod rescan;
pub mod slash0;
pub mod slash0_few_ports;
pub mod slash0_filtered_by_asn;
pub mod slash0_filtered_by_asn_but_less;
pub mod slash0_filtered_by_slash24;
pub mod slash0_filtered_by_slash24_30d;
pub mod slash0_filtered_by_slash24_new;
pub mod slash0_filtered_by_slash24_top_1024_ports_uniform;
pub mod slash0_filtered_by_slash24_top_128_ports_uniform;
pub mod slash0_filtered_by_slash24_top_ports_weighted;
pub mod slash24;
pub mod slash24_all_ports;
pub mod slash24_all_ports_but_less;
pub mod slash24_all_ports_new;
pub mod slash24_few_ports;
pub mod slash24_few_ports_new;
pub mod slash24_new;
pub mod slash32_all_ports;
pub mod slash32_all_ports_new;
pub mod slash32_range_ports;
pub mod slash32_range_ports_new;

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Hash, enum_utils::FromStr, enum_utils::IterVariants,
)]
pub enum ScanMode {
    Slash0FewPorts,
    Slash0FilteredByAsn,
    Slash0FilteredByAsnButLess,
    Slash0FilteredBySlash24,
    Slash0FilteredBySlash2430d,
    Slash0FilteredBySlash24New,
    Slash0FilteredBySlash24Top128PortsUniform,
    Slash0FilteredBySlash24Top1024PortsUniform,
    Slash0FilteredBySlash24TopPortsWeighted,
    Slash0,
    Slash24AllPortsButLess,
    Slash24AllPortsNew,
    Slash24AllPorts,
    Slash24,
    Slash24FewPorts,
    Slash24FewPortsNew,
    Slash24New,
    Slash32AllPorts,
    Slash32AllPortsNew,
    Slash32RangePorts,
    Slash32RangePortsNew,

    Rescan1day,
    Rescan7days,
    Rescan30days,
    Rescan365days,
}

pub struct ModePicker {
    // the number of new servers last attempt
    // defaults to a big number (so we try all of them first)
    // (we can't do usize::MAX because WeightedIndex breaks)
    modes: HashMap<ScanMode, usize>,
}

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

        const DEFAULT_FOUND: usize = 1_000_000;
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

        let mut rng: rand::rngs::ThreadRng = rand::thread_rng();
        let modes_vec = self.modes.iter().collect::<Vec<_>>();

        // filter by the modes argument
        let modes_vec = if let Some(modes) = modes {
            modes_vec
                .into_iter()
                .filter(|(mode, _)| modes.contains(&mode))
                .collect::<Vec<_>>()
        } else {
            modes_vec
        };

        let dist = WeightedIndex::new(
            modes_vec
                .iter()
                // +1 so if it got 0 there's still a chance to do it again
                .map(|(_, &count)| (count.pow(2)) + 1)
                .collect::<Vec<usize>>(),
        )
        .unwrap();

        *modes_vec[dist.sample(&mut rng)].0
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
    pub async fn get_ranges(&self, database: &mut Database) -> anyhow::Result<Vec<ScanRange>> {
        match self {
            ScanMode::Slash0FewPorts => slash0_few_ports::get_ranges(database).await,
            ScanMode::Slash0 => slash0::get_ranges(database).await,
            ScanMode::Slash0FilteredByAsn => slash0_filtered_by_asn::get_ranges(database).await,
            ScanMode::Slash0FilteredByAsnButLess => {
                slash0_filtered_by_asn_but_less::get_ranges(database).await
            }
            ScanMode::Slash0FilteredBySlash24Top128PortsUniform => {
                slash0_filtered_by_slash24_top_128_ports_uniform::get_ranges(database).await
            }
            ScanMode::Slash0FilteredBySlash24Top1024PortsUniform => {
                slash0_filtered_by_slash24_top_1024_ports_uniform::get_ranges(database).await
            }
            ScanMode::Slash0FilteredBySlash24TopPortsWeighted => {
                slash0_filtered_by_slash24_top_ports_weighted::get_ranges(database).await
            }
            ScanMode::Slash0FilteredBySlash24 => {
                slash0_filtered_by_slash24::get_ranges(database).await
            }
            ScanMode::Slash0FilteredBySlash2430d => {
                slash0_filtered_by_slash24_30d::get_ranges(database).await
            }
            ScanMode::Slash0FilteredBySlash24New => {
                slash0_filtered_by_slash24_new::get_ranges(database).await
            }
            ScanMode::Slash24AllPortsButLess => {
                slash24_all_ports_but_less::get_ranges(database).await
            }
            ScanMode::Slash24AllPortsNew => slash24_all_ports_new::get_ranges(database).await,
            ScanMode::Slash24AllPorts => slash24_all_ports::get_ranges(database).await,
            ScanMode::Slash24FewPorts => slash24_few_ports::get_ranges(database).await,
            ScanMode::Slash24FewPortsNew => slash24_few_ports_new::get_ranges(database).await,
            ScanMode::Slash24New => slash24_new::get_ranges(database).await,
            ScanMode::Slash24 => slash24::get_ranges(database).await,
            ScanMode::Slash32AllPorts => slash32_all_ports::get_ranges(database).await,
            ScanMode::Slash32AllPortsNew => slash32_all_ports_new::get_ranges(database).await,
            ScanMode::Slash32RangePorts => slash32_range_ports::get_ranges(database).await,
            ScanMode::Slash32RangePortsNew => slash32_range_ports_new::get_ranges(database).await,

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
        }
    }
}
