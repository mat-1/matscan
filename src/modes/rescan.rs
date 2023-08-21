use std::{
    net::Ipv4Addr,
    time::{Duration, SystemTime},
};

use bson::{doc, Document};
use futures_util::StreamExt;
use mongodb::options::AggregateOptions;
use serde::Deserialize;

use crate::{
    database::{self, Database},
    scanner::targets::ScanRange,
};

#[derive(Deserialize, Clone, Copy, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Sort {
    Random,
    Oldest,
}

pub async fn get_ranges(
    database: &Database,
    extra_filter: &toml::Table,
    rescan_every_secs: u64,
    players_online_ago_max_secs: Option<u64>,
    last_ping_ago_max_secs: u64,
    limit: Option<usize>,
    sort: Option<Sort>,
) -> anyhow::Result<Vec<ScanRange>> {
    let mut ranges = Vec::new();

    let mut filter = doc! {
        "timestamp": {
            // up to 2 hours ago
            "$gt": bson::DateTime::from(SystemTime::now() - Duration::from_secs(last_ping_ago_max_secs)),
            "$lt": bson::DateTime::from(SystemTime::now() - Duration::from_secs(rescan_every_secs))
        }
    };

    for (key, value) in extra_filter {
        filter.insert(key, bson::to_bson(&value)?);
    }

    if let Some(players_online_ago_max_secs) = players_online_ago_max_secs {
        filter.insert(
            "lastActive",
            doc! {
                "$gt": bson::DateTime::from(SystemTime::now() - Duration::from_secs(players_online_ago_max_secs))
            },
        );
    }

    println!("filter: {:?}", filter);

    let mut bad_ips = database.shared.lock().bad_ips.to_owned();

    let mut pipeline: Vec<Document> = Vec::new();
    pipeline.push(doc! { "$match": filter });
    pipeline.push(doc! { "$project": { "addr": 1, "port": 1, "_id": 0 } });

    let sort = sort.unwrap_or(Sort::Oldest);

    match sort {
        Sort::Random => {
            pipeline.push(doc! { "$sample": { "size": limit.unwrap_or(10000000) as i64 } });
        }
        Sort::Oldest => {
            pipeline.push(doc! { "$sort": { "timestamp": 1 } });
            if let Some(limit) = limit {
                pipeline.push(doc! { "$limit": limit as i64 });
            }
        }
    }

    let mut cursor = database
        .servers_coll()
        .aggregate(
            pipeline,
            AggregateOptions::builder().batch_size(2000).build(),
        )
        .await
        .unwrap();

    while let Some(Ok(doc)) = cursor.next().await {
        if let Some(addr) = database::get_u32(&doc, "addr") {
            if let Some(port) = database::get_u32(&doc, "port") {
                // there shouldn't be any bad ips...
                let addr = Ipv4Addr::from(addr);
                if bad_ips.contains(&addr) && port != 25565 {
                    println!("we encountered a bad ip while getting ips to rescan :/ deleting {addr} from database.");
                    database
                        .client
                        .database("mcscanner")
                        .collection::<bson::Document>("servers")
                        .delete_many(
                            doc! {
                                "addr": u32::from(addr),
                                "port": { "$ne": 25565 }
                            },
                            None,
                        )
                        .await?;
                    // this doesn't actually remove it from the bad_ips database, it just makes it
                    // so we don't delete twice
                    bad_ips.remove(&addr);
                    continue;
                }

                ranges.push(ScanRange::single(addr, port as u16));
                if ranges.len() % 1000 == 0 {
                    println!("{} ips", ranges.len());
                }
            }
        }
    }

    Ok(ranges)
}
