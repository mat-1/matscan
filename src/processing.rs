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
use tracing::trace;

use crate::{
    config::Config,
    database::{self, bulk_write::CollectionExt, Database},
    terminal_colors::*,
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
    pub total_new_on_default_port: usize,
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
            // check if there's already a bulk update for this server
            let is_already_updating = bulk_updates.iter().any(|bulk_update| {
                database::get_u32(&bulk_update.query, "addr") == Some(u32::from(*target.ip()))
                    && database::get_u32(&bulk_update.query, "port") == Some(target.port() as u32)
            });
            if is_already_updating {
                continue;
            }
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
        // println!("\x1b[90m\x1b[3mprocessing task is now idle\x1b[m");
    }
}

async fn flush_bulk_updates(
    database: &Database,
    bulk_updates: Vec<database::bulk_write::BulkUpdate>,
    shared: &Arc<Mutex<SharedData>>,
) -> anyhow::Result<()> {
    let updated_count: usize;
    let updated_but_not_revived_count: usize;
    let inserted_count: usize;
    let inserted_on_default_port_count: usize;
    let revived_count: usize;

    let is_upserting = bulk_updates.iter().any(|bulk_update| {
        bulk_update
            .options
            .as_ref()
            .and_then(|options| options.upsert)
            .unwrap_or_default()
    });

    if is_upserting {
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
                        "$gt": &reviving_cutoff,
                    },
                );
                // disable upserting for not_reviving
                if let Some(options) = &mut bulk_update.options {
                    options.upsert = Some(false);
                }
                bulk_update
            })
            .collect::<Vec<_>>();
        let bulk_updates_reviving = bulk_updates
            .into_iter()
            .map(|mut bulk_update| {
                bulk_update
                    .query
                    .insert("timestamp", doc! { "$lte": &reviving_cutoff });
                bulk_update
            })
            .collect::<Vec<_>>();
        trace!("bulk_updates_not_reviving: {bulk_updates_not_reviving:?}");
        trace!("bulk_updates_reviving: {bulk_updates_reviving:?}");

        let db = database.mcscanner_database();
        let result_not_reviving = db
            .collection::<bson::Document>("servers")
            .bulk_update(&db, bulk_updates_not_reviving)
            .await?;
        let result_reviving = db
            .collection::<bson::Document>("servers")
            .bulk_update(&db, &bulk_updates_reviving)
            .await?;

        trace!("result_not_reviving: {result_not_reviving:?}");
        trace!("result_reviving: {result_reviving:?}");

        revived_count = result_reviving.nb_modified as usize;
        updated_but_not_revived_count = result_not_reviving.nb_modified as usize;
        inserted_count = result_reviving.upserted.len();

        updated_count = revived_count + updated_but_not_revived_count + inserted_count;

        inserted_on_default_port_count = result_reviving
            .upserted
            .iter()
            .filter(|server_update_result| {
                let server_update = &bulk_updates_reviving[server_update_result.index as usize];
                let port = database::get_i32(&server_update.query, "port").unwrap_or_default();
                port == 25565
            })
            .count();
    } else {
        // if we're not upserting then we're probably doing something like
        // fingerprinting so reviving/inserting doesn't make sense
        let db = database.mcscanner_database();
        let result = db
            .collection::<bson::Document>("servers")
            .bulk_update(&db, bulk_updates)
            .await?;
        updated_count = result.nb_modified as usize;
        updated_but_not_revived_count = 0;
        inserted_count = 0;
        revived_count = 0;
        inserted_on_default_port_count = 0;
    }

    let mut shared = shared.lock();
    shared.results += updated_count;
    shared.total_new += inserted_count;
    shared.total_new_on_default_port += inserted_on_default_port_count;
    shared.revived += revived_count;

    let mut changes = Vec::new();
    if updated_but_not_revived_count > 0 {
        changes.push(format!(
            "{YELLOW}updated {BOLD}{updated_but_not_revived_count}{RESET} {GRAY}({}){RESET}",
            shared.results - shared.revived - shared.total_new
        ));
    }
    if inserted_count > 0 {
        changes.push(format!(
            "{BLUE}added {BOLD}{inserted_count}{RESET} {GRAY}({}){RESET}",
            shared.total_new
        ));
    }
    if revived_count > 0 {
        changes.push(format!(
            "{GREEN}revived {BOLD}{revived_count}{RESET} {GRAY}({}){RESET}",
            shared.revived
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
