use std::{
    net::{Ipv4Addr, SocketAddrV4},
    time::{Duration, SystemTime},
};

use bson::{doc, Document};
use futures_util::StreamExt;
use mongodb::options::AggregateOptions;

use crate::database::Database;

pub async fn get_addrs_and_protocol_versions(
    database: &Database,
) -> anyhow::Result<Vec<(SocketAddrV4, i32)>> {
    let mut results = Vec::new();

    let filter = doc! {
        "timestamp": {
            // must be online
            "$gt": bson::DateTime::from(SystemTime::now() - Duration::from_secs(60 * 60 * 2)),
        },
        "$or": [
            {
                "fingerprint.activeMinecraft.timestamp": {
                // the last active fingerprint must've been over a week ago
                    "$lt": bson::DateTime::from(SystemTime::now() - Duration::from_secs(60 * 60 * 24 * 7)),
                }
            },
            {
                "fingerprint.activeMinecraft": { "$exists": false }
            },
        ]
    };

    println!("filter: {:?}", filter);

    let mut pipeline: Vec<Document> = vec![doc! { "$match": filter }];
    pipeline.push(
        doc! { "$project": { "addr": 1, "port": 1, "minecraft.version.protocol": 1, "_id": 0 } },
    );
    pipeline.push(doc! { "$sort": { "timestamp": 1 } });

    let mut cursor = database
        .servers_coll()
        .aggregate(
            pipeline,
            AggregateOptions::builder().batch_size(2000).build(),
        )
        .await
        .unwrap();

    while let Some(Ok(doc)) = cursor.next().await {
        if let Some(addr) = Database::get_u32(&doc, "addr") {
            if let Some(port) = Database::get_u32(&doc, "port") {
                let Ok(minecraft) = doc.get_document("minecraft") else {
                    continue;
                };
                let Ok(version) = minecraft.get_document("version") else {
                    continue;
                };
                let protocol_version = version.get_i32("protocol").unwrap_or(47);

                let addr = Ipv4Addr::from(addr);
                results.push((SocketAddrV4::new(addr, port as u16), protocol_version));
                if results.len() % 1000 == 0 {
                    println!("{} ips", results.len());
                }
            }
        }
    }

    Ok(results)
}
