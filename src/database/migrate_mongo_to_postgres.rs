use std::{
    collections::VecDeque,
    net::{Ipv4Addr, SocketAddrV4},
    time::Instant,
};

use futures_util::TryStreamExt;
use sqlx::QueryBuilder;
use uuid::Uuid;

pub async fn do_migration(mongodb_uri: &str, postgres_uri: &str) {
    let client_options = mongodb::options::ClientOptions::parse(mongodb_uri)
        .await
        .unwrap();

    let client = mongodb::Client::with_options(client_options).unwrap();
    let postgres_db = Database::connect(postgres_uri).await.unwrap();

    client
        .database("mcscanner")
        .run_command(mongodb::bson::doc! {"ping": 1})
        .await
        .unwrap();

    // don't bother migrating bad_servers -> ips_with_aliased_servers

    let mut i = 0;
    let started = Instant::now();

    let mut tasks = VecDeque::new();

    let mut cursor = client
        .database("mcscanner")
        .collection::<mongodb::bson::Document>("servers")
        .find(mongodb::bson::doc! {})
        .sort(mongodb::bson::doc! {"addr": 1})
        .await
        .expect("bad servers collection must exist");
    while let Some(doc) = cursor.try_next().await.unwrap() {
        let ip = doc
            .get_i64("addr")
            .ok()
            .unwrap_or_else(|| doc.get_i32("addr").unwrap() as i64) as u32;
        let ip = Ipv4Addr::from(ip);

        println!("{:?}", doc);
        println!("{ip} {} {:?}", i, started.elapsed());
        i += 1;

        let port = doc.get_i32("port").unwrap();
        let addr = SocketAddrV4::new(ip, port as u16);

        let Ok(minecraft) = doc.get_document("minecraft") else {
            continue;
        };
        let version = minecraft.get_document("version");
        let players = minecraft.get_document("players");

        let version_name = version
            .as_ref()
            .ok()
            .and_then(|v| v.get_str("name").ok())
            .map(String::from);
        let version_protocol = version.and_then(|v| v.get_i32("protocol")).ok();

        let online_players = players.as_ref().ok().and_then(|v| v.get_i32("online").ok());
        let max_players = players.as_ref().ok().and_then(|v| v.get_i32("max").ok());

        let is_online_mode = doc.get_bool("onlineMode").ok();
        let mut player_sample = Vec::new();
        if let Ok(players) = doc.get_document("players") {
            for (uuid, player) in players {
                let player = player.as_document().unwrap();
                let name = player.get_str("name").ok().map(String::from);
                let uuid = uuid.parse().ok();
                if name.is_none() || uuid.is_none() {
                    continue;
                }
                let last_seen = player.get_datetime("lastSeen").unwrap();
                player_sample.push(SamplePlayer {
                    name,
                    uuid,
                    seen: last_seen.to_system_time().into(),
                });
            }
        }

        let enforces_secure_chat = minecraft.get_bool("enforcesSecureChat").ok();
        let previews_chat = minecraft.get_bool("previewsChat").ok();

        let fingerprint = {
            let fingerprint = doc.get_document("fingerprint").ok();
            if let Some(fingerprint) = fingerprint {
                let fingerprint = fingerprint.get_document("minecraft").unwrap();
                let field_order = fingerprint.get_str("fieldOrder").ok().map(String::from);
                let is_incorrect_field_order = fingerprint.get_bool("incorrectOrder").unwrap();
                let is_empty_sample = fingerprint.get_bool("emptySample").unwrap();
                let is_empty_favicon = fingerprint.get_bool("emptyFavicon").unwrap();

                PingResponseFingerprint {
                    field_order,
                    is_incorrect_field_order,
                    is_empty_sample,
                    is_empty_favicon,
                }
            } else {
                // very old servers in matscan have this issue
                PingResponseFingerprint {
                    field_order: None,
                    is_incorrect_field_order: false,
                    is_empty_sample: false,
                    is_empty_favicon: false,
                }
            }
        };

        let prevents_chat_reports = minecraft.get_bool("preventsChatReports").ok();

        let is_modded = minecraft.get_bool("isModded").ok();

        let modpackdata = minecraft.get_document("modpackdata").ok();
        let modpackdata_project_id = modpackdata
            .as_ref()
            .and_then(|v| v.get_i32("projectId").ok());
        let modpackdata_name = modpackdata
            .as_ref()
            .and_then(|v| v.get_str("name").ok())
            .map(String::from);
        let modpackdata_version = modpackdata
            .as_ref()
            .and_then(|v| v.get_str("version").ok())
            .map(String::from);

        let first_pinged = doc
            .get_object_id("_id")
            .unwrap()
            .timestamp()
            .to_system_time()
            .into();
        let last_pinged = doc
            .get_datetime("timestamp")
            .unwrap()
            .to_system_time()
            .into();

        let last_time_player_online = doc
            .get_datetime("lastActive")
            .ok()
            .map(|v| v.to_system_time().into());
        let last_time_no_players_online = doc
            .get_datetime("lastEmpty")
            .ok()
            .map(|v| v.to_system_time().into());

        let s = PingResponse {
            description_json: None,
            description_plaintext: minecraft
                .get_str("description")
                .unwrap()
                .to_string()
                .replace('\0', ""),
            version_name,
            version_protocol,
            favicon: None,
            favicon_hash: None,
            online_players,
            max_players,
            is_online_mode,
            player_sample,
            enforces_secure_chat,
            previews_chat,
            fingerprint,
            prevents_chat_reports,
            // cleared
            forgedata_fml_network_version: None,
            modinfo_type: None,
            is_modded,
            modpackdata_project_id,
            modpackdata_name,
            modpackdata_version,
            first_pinged,
            last_pinged,
            last_time_player_online,
            last_time_no_players_online,
        };

        let postgres_db = postgres_db.clone();
        let task = tokio::spawn(async move {
            if let Err(e) = postgres_db.insert_server(addr, s).await {
                println!("bad: {doc:?}");
                panic!("Error inserting server {addr}: {e:?}");
            }
        });
        tasks.push_back(task);

        while tasks.len() >= 100 {
            tasks.pop_front().unwrap().await.unwrap();
        }
    }

    while let Some(task) = tasks.pop_front() {
        task.await.unwrap();
    }
}

#[derive(Clone)]
struct Database {
    pub pool: sqlx::PgPool,
}
impl Database {
    pub async fn connect(postgres_uri: &str) -> eyre::Result<Self> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect(postgres_uri)
            .await?;
        sqlx::migrate!().run(&pool).await?;

        Ok(Self { pool })
    }

    pub async fn insert_server(&self, addr: SocketAddrV4, s: PingResponse) -> sqlx::Result<()> {
        let mut tx = self.pool.begin().await?;
        if s.favicon.is_some() {
            sqlx::query(
                r#"
            INSERT INTO favicons (hash, data)
            VALUES ($1, $2)
            ON CONFLICT (hash) DO NOTHING
            "#,
            )
            .bind(s.favicon_hash)
            .bind(s.favicon)
            .execute(&mut *tx)
            .await?;
        }

        sqlx::query(
            r#"
            INSERT INTO servers (
                ip,
                port,
                last_pinged,
                is_online_mode,
                favicon_hash,
                description_json,
                description_plaintext,
                online_players,
                max_players,
                version_name,
                version_protocol,
                enforces_secure_chat,
                previews_chat,
                fingerprint_field_order,
                fingerprint_is_incorrect_field_order,
                fingerprint_is_empty_sample,
                fingerprint_is_empty_favicon,
                prevents_chat_reports,
                forgedata_fml_network_version,
                modinfo_type,
                is_modded,
                modpackdata_project_id,
                modpackdata_name,
                modpackdata_version,
                first_pinged,
                last_time_player_online,
                last_time_no_players_online
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27)
            ON CONFLICT (ip, port) DO UPDATE
            SET
                last_pinged = $3,
                is_online_mode = $4,
                favicon_hash = $5,
                description_json = $6,
                description_plaintext = $7,
                online_players = $8,
                max_players = $9,
                version_name = $10,
                version_protocol = $11,
                enforces_secure_chat = $12,
                previews_chat = $13,
                fingerprint_field_order = $14,
                fingerprint_is_incorrect_field_order = $15,
                fingerprint_is_empty_sample = $16,
                fingerprint_is_empty_favicon = $17,
                prevents_chat_reports = $18,
                forgedata_fml_network_version = $19,
                modinfo_type = $20,
                is_modded = $21,
                modpackdata_project_id = $22,
                modpackdata_name = $23,
                modpackdata_version = $24,
                first_pinged = $25,
                last_time_player_online = $26,
                last_time_no_players_online = $27
            "#,
        )
        .bind(addr.ip().to_bits() as i32)
        .bind(addr.port() as i16)
        .bind(s.last_pinged)
        .bind(s.is_online_mode)
        .bind(s.favicon_hash)
        .bind(s.description_json)
        .bind(s.description_plaintext)
        .bind(s.online_players)
        .bind(s.max_players)
        .bind(s.version_name)
        .bind(s.version_protocol)
        .bind(s.enforces_secure_chat)
        .bind(s.previews_chat)
        .bind(s.fingerprint.field_order)
        .bind(s.fingerprint.is_incorrect_field_order)
        .bind(s.fingerprint.is_empty_sample)
        .bind(s.fingerprint.is_empty_favicon)
        .bind(s.prevents_chat_reports)
        .bind(s.forgedata_fml_network_version)
        .bind(s.modinfo_type)
        .bind(s.is_modded)
        .bind(s.modpackdata_project_id)
        .bind(s.modpackdata_name)
        .bind(s.modpackdata_version)
        .bind(s.first_pinged)
        .bind(s.last_time_player_online)
        .bind(s.last_time_no_players_online)
        .execute(&mut *tx)
        .await?;

        // insert players in bulk
        if !s.player_sample.is_empty() {
            let mut query_builder = QueryBuilder::new(
                "INSERT INTO server_players (server_ip, server_port, uuid, username, online_mode, last_seen, first_seen) ",
            );
            query_builder.push_values(s.player_sample, |mut b, player| {
                b.push_bind(addr.ip().to_bits() as i32)
                    .push_bind(addr.port() as i16)
                    .push_bind(player.uuid)
                    .push_bind(player.name.map(|n| n.replace('\0', "")))
                    .push_bind(player.uuid.map(|u| match u.get_version_num() {
                        3 => Some(false),
                        4 => Some(true),
                        _ => None,
                    }))
                    .push_bind(player.seen)
                    .push_bind(player.seen);
            });
            query_builder.push("ON CONFLICT (server_ip, server_port, uuid) DO UPDATE SET last_seen = EXCLUDED.last_seen, username = EXCLUDED.username");
            let query = query_builder.build();
            query.execute(&mut *tx).await?;
        }

        tx.commit().await?;
        Ok(())
    }
}

#[derive(Debug)]
struct PingResponse {
    pub description_json: Option<String>,
    pub description_plaintext: String,
    pub version_name: Option<String>,
    pub version_protocol: Option<i32>,

    pub favicon: Option<String>,
    pub favicon_hash: Option<[u8; 16]>,

    pub online_players: Option<i32>,
    pub max_players: Option<i32>,
    pub is_online_mode: Option<bool>,
    pub player_sample: Vec<SamplePlayer>,

    pub enforces_secure_chat: Option<bool>,
    pub previews_chat: Option<bool>,

    pub fingerprint: PingResponseFingerprint,

    // non-vanilla fields

    // nochatreports and similar mods
    pub prevents_chat_reports: Option<bool>,
    // forge
    pub forgedata_fml_network_version: Option<i32>,
    // old forge servers
    pub modinfo_type: Option<String>,
    // neoforged
    pub is_modded: Option<bool>,
    // bettercompatibilitychecker
    pub modpackdata_project_id: Option<i32>,
    pub modpackdata_name: Option<String>,
    pub modpackdata_version: Option<String>,

    pub first_pinged: chrono::DateTime<chrono::Utc>,
    pub last_pinged: chrono::DateTime<chrono::Utc>,
    pub last_time_player_online: Option<chrono::DateTime<chrono::Utc>>,
    pub last_time_no_players_online: Option<chrono::DateTime<chrono::Utc>>,
}
#[derive(Debug)]
struct SamplePlayer {
    pub name: Option<String>,
    pub uuid: Option<Uuid>,

    pub seen: chrono::DateTime<chrono::Utc>,
}
#[derive(Debug)]
struct PingResponseFingerprint {
    /// Only present if the field order is incorrect.
    pub field_order: Option<String>,
    pub is_incorrect_field_order: bool,
    pub is_empty_sample: bool,
    pub is_empty_favicon: bool,
}
