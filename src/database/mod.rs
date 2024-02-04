pub mod bulk_write;

use std::{
    collections::HashSet,
    net::{Ipv4Addr, SocketAddrV4},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use bson::{Bson, Document};
use futures_util::{stream::StreamExt, TryStreamExt};
use lru_cache::LruCache;
use mongodb::{
    bson::doc,
    options::{ClientOptions, FindOptions, Hint, ResolverConfig, UpdateOptions},
    Client, Collection,
};
use parking_lot::Mutex;
use serde::{Deserialize, Deserializer, Serializer};

#[derive(Clone)]
pub struct Database {
    pub client: Client,
    pub shared: Arc<Mutex<DatabaseSharedData>>,
}

pub struct DatabaseSharedData {
    pub ips_with_same_hash: LruCache<Ipv4Addr, (CachedIpHash, HashSet<u16>)>,

    pub bad_ips: HashSet<Ipv4Addr>,

    cached_all_servers_30_days: Option<(Vec<SocketAddrV4>, Instant)>,
    cached_all_servers_365_days: Option<(Vec<SocketAddrV4>, Instant)>,
    cached_all_servers_new: Option<(Vec<SocketAddrV4>, Instant)>,
}

pub struct CachedIpHash {
    /// The number of IPs found with the same hash. None if we already found an
    /// IP with a different hash.
    pub count: Option<usize>,
    pub hash: u64,
}

trait Ipv4Serialize: Sized {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer;

    fn deserialize<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>;
}

// Convert between bool and u8
impl Ipv4Serialize for Ipv4Addr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u32(u32::from(*self))
    }

    fn deserialize<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Ipv4Addr::from(u32::deserialize(deserializer)?))
    }
}

impl Database {
    pub async fn connect(mongodb_uri: &str) -> anyhow::Result<Self> {
        let client_options =
            ClientOptions::parse_with_resolver_config(mongodb_uri, ResolverConfig::cloudflare())
                .await?;

        let client = Client::with_options(client_options)?;

        // ping the database to make sure it's up
        client
            .database("mcscanner")
            .run_command(doc! {"ping": 1}, None)
            .await?;

        // download bad ips
        let mut bad_ips = HashSet::new();
        let mut cursor = client
            .database("mcscanner")
            .collection::<Document>("bad_servers")
            .find(None, None)
            .await
            .expect("bad servers collection must exist");
        while let Some(Ok(doc)) = cursor.next().await {
            if let Some(addr) = get_u32(&doc, "addr") {
                bad_ips.insert(Ipv4Addr::from(addr));
            }
        }

        let db = Self {
            client,
            shared: Arc::new(Mutex::new(DatabaseSharedData {
                // arbitrary capacity (2^20)
                ips_with_same_hash: LruCache::new(1048576),

                bad_ips,

                cached_all_servers_30_days: None,
                cached_all_servers_365_days: None,
                cached_all_servers_new: None,
            })),
        };

        let db_clone = db.clone();
        tokio::spawn(async move {
            loop {
                db_clone.delete_spam_historical_players().await;
                // every 4 hours
                tokio::time::sleep(Duration::from_secs(60 * 60 * 4)).await;
            }
        });

        Ok(db)
    }

    /// Some servers randomize the server list ping every time and fill up our
    /// database. This function deletes the `players` field from servers with
    /// more than 1000 historical players.
    pub async fn delete_spam_historical_players(&self) {
        let collection = self
            .client
            .database("mcscanner")
            .collection::<Document>("servers");

        let mut cursor = collection
            .aggregate(
                vec![
                    doc! {"$match": {"players": {"$exists": true}}},
                    doc! {"$project": {"playerCount": {"$size": {"$objectToArray": "$players"}}, "players": "$players"}},
                    doc! {"$match": {"playerCount": {"$gt": 1000}}},
                ],
                None,
            )
            .await
            .expect("servers collection must exist");

        while let Some(Ok(doc)) = cursor.next().await {
            // delete the players field and then add it again but with the 1000 most recent
            // players
            let update = doc! { "$unset": { "players": "" } };
            collection
                .update_one(
                    doc! {"_id": doc.get_object_id("_id").expect("_id must be present")},
                    update,
                    None,
                )
                .await
                .expect("updating must not fail");
            // it might not actually be necessary to do two updates here, i'm guessing it is
            // though

            // players looks like
            // ```
            // abcdundasheduuidefgh: { lastSeen: 2023-01-15T21:13:01.000Z, name: 'Herobrine' }
            // ```
            let players = doc
                .get_document("players")
                .expect("players must be present");
            let mut players = players.into_iter().collect::<Vec<(&String, &Bson)>>();
            players.sort_by(|(_, a), (_, b)| {
                let a = a
                    .as_document()
                    .unwrap()
                    .get_datetime("lastSeen")
                    .expect("lastSeen must be present");
                let b = b
                    .as_document()
                    .unwrap()
                    .get_datetime("lastSeen")
                    .expect("lastSeen must be present");
                a.cmp(b)
            });
            let players = players
                .into_iter()
                .rev()
                .take(500)
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<Vec<(String, Bson)>>();

            let update = doc! { "$set": { "players": bson::Document::from_iter(players) } };
            collection
                .update_one(
                    doc! {"_id": doc.get_object_id("_id").expect("_id must be present")},
                    update,
                    None,
                )
                .await
                .expect("updating must not fail");
        }
    }

    pub fn mcscanner_database(&self) -> mongodb::Database {
        self.client.database("mcscanner")
    }

    pub fn servers_coll(&self) -> Collection<Document> {
        self.mcscanner_database().collection::<Document>("servers")
    }

    pub async fn add_to_bad_ips(self, addr: Ipv4Addr) -> anyhow::Result<()> {
        self.shared.lock().bad_ips.insert(addr);

        self.client
            .database("mcscanner")
            .collection::<Document>("bad_servers")
            .update_one(
                doc! { "addr": u32::from(addr) },
                doc! {
                    "$set": {
                        "timestamp": Bson::DateTime(bson::DateTime::from_system_time(SystemTime::now())),
                    }
                },
                // upsert in case the server was already there
                UpdateOptions::builder().upsert(true).build(),
            )
            .await?;

        // delete all servers with this ip that aren't on 25565
        let r = self
            .client
            .database("mcscanner")
            .collection::<Document>("servers")
            .delete_many(
                doc! {
                    "addr": u32::from(addr),
                    "port": { "$ne": 25565 }
                },
                None,
            )
            .await?;

        println!("deleted {} bad servers", r.deleted_count);

        Ok(())
    }
}

pub fn get_u32(doc: &Document, key: &str) -> Option<u32> {
    get_i32(doc, key).map(|a| a as u32)
}

pub fn get_i32(doc: &Document, key: &str) -> Option<i32> {
    doc.get(key).and_then(|a| {
        if let Some(addr) = a.as_i32() {
            Some(addr)
        } else {
            a.as_i64().map(|a| a as i32)
        }
    })
}

pub enum UpdateResult {
    Inserted,
    UpdatedAndRevived,
    Updated,
}

pub enum CollectServersFilter {
    /// Was alive in the past 30 days
    Active30d,
    /// Was alive in the past 365 days
    Active365d,
    // Found in the past 7 days
    New,
}

pub async fn collect_all_servers(
    database: &Database,
    filter: CollectServersFilter,
) -> anyhow::Result<Vec<SocketAddrV4>> {
    let doc_filter: Document = match filter {
        CollectServersFilter::Active30d => {
            if let Some((cached, cached_time)) = &database.shared.lock().cached_all_servers_30_days
            {
                // if it was more than 24 hours ago, download again
                if cached_time.elapsed().as_secs() < 60 * 60 * 24 {
                    return Ok(cached.clone());
                }
            }

            doc! {
                "timestamp": {
                    // up to 30 days ago
                    "$gt": bson::DateTime::from(SystemTime::now() - std::time::Duration::from_secs(60 * 60 * 24 * 30)),
                }
            }
        }
        CollectServersFilter::New => {
            if let Some((cached, cached_time)) = &database.shared.lock().cached_all_servers_new {
                // if it was more than 24 hours ago, download again
                if cached_time.elapsed().as_secs() < 60 * 60 * 24 {
                    return Ok(cached.clone());
                }
            }
            // first 4 bytes are seconds since epoch
            // other 12 are 0
            let seconds_since_epoch = (SystemTime::now()
                - std::time::Duration::from_secs(60 * 60 * 24 * 7))
            .duration_since(UNIX_EPOCH)?
            .as_secs() as u32;

            doc! {
                "_id": {
                    // inserted in the past 7 days
                    "$gt": bson::oid::ObjectId::from_bytes([
                        (seconds_since_epoch >> 24) as u8,
                        (seconds_since_epoch >> 16) as u8,
                        (seconds_since_epoch >> 8) as u8,
                        seconds_since_epoch as u8,
                        0, 0, 0, 0, 0, 0, 0, 0
                    ])
                }
            }
        }
        CollectServersFilter::Active365d => {
            if let Some((cached, cached_time)) = &database.shared.lock().cached_all_servers_30_days
            {
                // if it was more than 24 hours ago, download again
                if cached_time.elapsed().as_secs() < 60 * 60 * 24 {
                    return Ok(cached.clone());
                }
            }

            doc! {
                "timestamp": {
                    // up to 365 days ago
                    "$gt": bson::DateTime::from(SystemTime::now() - std::time::Duration::from_secs(60 * 60 * 24 * 365)),
                }
            }
        }
    };

    let mut cursor = database
        .servers_coll()
        .find(
            doc_filter,
            FindOptions::builder()
                // prefer newest first
                // .sort(doc! {"_id": 1})
                .projection(doc! {"addr": 1, "port": 1, "_id": 0})
                .batch_size(2000)
                .hint(Some(Hint::Keys(doc! {"addr": 1, "port": 1})))
                .build(),
        )
        .await?;

    let mut servers = Vec::new();

    while let Some(doc) = cursor.try_next().await? {
        let Some(addr) = get_u32(&doc, "addr") else {
            continue;
        };
        let Some(port) = get_u32(&doc, "port") else {
            continue;
        };
        servers.push(SocketAddrV4::new(Ipv4Addr::from(addr), port as u16));

        if servers.len() % 10000 == 0 {
            println!("Collected {} servers", servers.len());
        }
    }

    match filter {
        CollectServersFilter::Active30d => {
            database.shared.lock().cached_all_servers_30_days =
                Some((servers.clone(), Instant::now()));
        }
        CollectServersFilter::New => {
            database.shared.lock().cached_all_servers_new = Some((servers.clone(), Instant::now()));
        }
        CollectServersFilter::Active365d => {
            database.shared.lock().cached_all_servers_365_days =
                Some((servers.clone(), Instant::now()));
        }
    };

    Ok(servers)
}
