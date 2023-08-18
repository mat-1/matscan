pub mod minecraft;
pub mod minecraft_fingerprinting;

use std::{
    collections::{HashMap, VecDeque},
    mem,
    net::SocketAddrV4,
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use bson::{doc, Bson};
use parking_lot::Mutex;

use crate::{
    config::Config,
    database::{self, bulk_write::CollectionExt, Database},
};

pub struct SharedData {
    pub database: Database,
    /// The queue of servers to process, along with their server list ping
    /// response.
    pub queue: VecDeque<(SocketAddrV4, Vec<u8>)>,
    /// Data from the previous scan, used for identifying players that just
    /// joined or left a server.
    pub cached_servers: HashMap<SocketAddrV4, serde_json::Value>,

    pub total_new: usize,
    pub revived: usize,
    pub results: usize,

    /// Whether the processing task is currently processing something.
    pub is_processing: bool,
}

#[async_trait]
pub trait ProcessableProtocol: Send + 'static {
    fn process(
        shared: &Arc<Mutex<SharedData>>,
        config: &Config,
        target: SocketAddrV4,
        data: &[u8],
        database: &Database,
    ) -> Option<database::bulk_write::BulkUpdate>;
}

/// A task that processes pings from the queue.
pub async fn process_pings<P>(shared: Arc<Mutex<SharedData>>, config: Config)
where
    P: ProcessableProtocol + Send + 'static,
{
    let database = shared.lock().database.clone();
    loop {
        if shared.lock().queue.is_empty() {
            // wait a bit until next loop
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        }

        shared.lock().is_processing = true;

        let mut bulk_updates: Vec<database::bulk_write::BulkUpdate> = Vec::new();
        let updating = shared.lock().queue.drain(..).collect::<Vec<_>>();
        for (target, data) in updating {
            let Some(bulk_update) = P::process(&shared, &config, target, &data, &database) else {
                continue;
            };
            bulk_updates.push(bulk_update);
            if bulk_updates.len() >= 100 {
                if let Err(err) =
                    flush_bulk_updates(&database, mem::take(&mut bulk_updates), &shared).await
                {
                    eprintln!("{err}");
                }
            }
        }

        if !bulk_updates.is_empty() {
            if let Err(err) = flush_bulk_updates(&database, bulk_updates, &shared).await {
                eprintln!("{err}");
            }
        }

        shared.lock().is_processing = false;
        println!("\x1b[90m\x1b[3mprocessing task is now idle\x1b[m");
    }
}

async fn flush_bulk_updates(
    database: &Database,
    bulk_updates: Vec<database::bulk_write::BulkUpdate>,
    shared: &Arc<Mutex<SharedData>>,
) -> anyhow::Result<()> {
    // to detect what how many updates "revived" servers, we have to do two bulk
    // updates

    let reviving_cutoff = Bson::DateTime(bson::DateTime::from_system_time(
        SystemTime::now() - Duration::from_secs(60 * 60 * 2),
    ));

    let bulk_updates_not_reviving = bulk_updates
        .clone()
        .into_iter()
        .map(|mut bulk_update| {
            bulk_update.query.insert(
                "timestamp",
                doc! {
                    "$lt": reviving_cutoff.clone()
                },
            );
            bulk_update
        })
        .collect::<Vec<_>>();
    let bulk_updates_reviving = bulk_updates
        .into_iter()
        .map(|mut bulk_update| {
            bulk_update.query.insert(
                "timestamp",
                doc! {
                    "$gte": reviving_cutoff.clone()
                },
            );
            bulk_update
        })
        .collect::<Vec<_>>();

    let db = database.mcscanner_database();
    let result_not_reviving = db
        .collection::<bson::Document>("servers")
        .bulk_update(&db, bulk_updates_not_reviving)
        .await?;
    let result_reviving = db
        .collection::<bson::Document>("servers")
        .bulk_update(&db, bulk_updates_reviving)
        .await?;

    let revived_count = result_reviving
        .get("n")
        .and_then(|n| n.as_i32())
        .unwrap_or_default() as usize;
    let updated_but_not_revived_count = result_not_reviving
        .get("n")
        .and_then(|n| n.as_i32())
        .unwrap_or_default() as usize;
    let updated_count = revived_count + updated_but_not_revived_count;
    let inserted_count = result_reviving
        .get("upserted")
        .and_then(|n| n.as_array())
        .map(|n| n.len())
        .unwrap_or_default()
        + result_not_reviving
            .get("upserted")
            .and_then(|n| n.as_array())
            .map(|n| n.len())
            .unwrap_or_default();

    let mut shared = shared.lock();
    shared.results += updated_count;
    shared.total_new += inserted_count;
    shared.revived += revived_count;

    // updated
    const GRAY: &str = "\x1b[90m";
    // inserted
    const BLUE: &str = "\x1b[94m";
    // revived
    const GREEN: &str = "\x1b[32m";
    const BOLD: &str = "\x1b[1m";
    const RESET: &str = "\x1b[0m";

    let mut changes = Vec::new();
    if updated_but_not_revived_count > 0 {
        changes.push(format!(
            "{GRAY}updated {BOLD}{updated_but_not_revived_count}{RESET} {GRAY}({}/{}){RESET}",
            shared.results - shared.revived - shared.total_new,
            shared.results
        ));
    }
    if inserted_count > 0 {
        changes.push(format!(
            "{BLUE}added {BOLD}{inserted_count}{RESET} {GRAY}({}/{}){RESET}",
            shared.total_new, shared.results
        ));
    }
    if revived_count > 0 {
        changes.push(format!(
            "{GREEN}revived {BOLD}{revived_count}{RESET} {GRAY}({}/{}){RESET}",
            shared.revived, shared.results
        ));
    }

    if !changes.is_empty() {
        println!(
            "{}",
            changes
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ")
                .to_string()
        );
    }

    Ok(())
}
