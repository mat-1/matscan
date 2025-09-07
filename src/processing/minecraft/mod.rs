pub mod anti_abuse;
pub mod passive_fingerprint;
pub mod snipe;

use std::{
    collections::{HashSet, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    net::SocketAddrV4,
    sync::Arc,
};

use eyre::bail;
use parking_lot::Mutex;
use serde::Deserialize;
use sha2::Digest;
use simd_json::derived::{ValueObjectAccess, ValueObjectAccessAsArray, ValueObjectAccessAsScalar};
use sqlx::{Arguments, Postgres, QueryBuilder, postgres::PgArguments};
use tracing::error;
use uuid::Uuid;

use super::{ProcessableProtocol, SharedData};
use crate::{
    config::Config,
    database::{CachedIpHash, Database, sanitize_text_for_postgres},
    processing::minecraft::{
        passive_fingerprint::{PassiveMinecraftFingerprint, generate_passive_fingerprint},
        snipe::maybe_log_sniped,
    },
    scanner::protocols,
};

pub struct PingResponse {
    pub description_json: String,
    pub description_plaintext: String,
    pub version_name: Option<String>,
    pub version_protocol: Option<i32>,

    pub favicon: Option<String>,
    pub favicon_hash: Option<[u8; 16]>,

    pub online_players: Option<i32>,
    pub max_players: Option<i32>,
    pub is_online_mode: Option<bool>,
    pub player_sample: Vec<SamplePlayer>,
    /// Whether the sample doesn't seem real and should be ignored when
    /// inserting historical players.
    pub is_fake_sample: bool,

    pub enforces_secure_chat: Option<bool>,
    pub previews_chat: Option<bool>,

    pub fingerprint: PassiveMinecraftFingerprint,

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
}
#[derive(Clone)]
pub struct SamplePlayer {
    pub name: String,
    pub uuid: Uuid,
}

pub const ANONYMOUS_PLAYER_NAME: &str = "Anonymous Player";

impl ProcessableProtocol for protocols::Minecraft {
    async fn handle_response(
        shared: Arc<Mutex<SharedData>>,
        config: Arc<Config>,
        target: SocketAddrV4,
        data: Box<[u8]>,
        db: Database,
    ) -> eyre::Result<()> {
        let ping_res = parse_ping_response_json(&data)?;

        if !anti_abuse::should_insert(&ping_res) {
            bail!("Disallowed server response")
        }
        if let Some(&allowed_port) = db
            .shared
            .lock()
            .aliased_ips_to_allowed_port
            .get(target.ip())
            && target.port() != allowed_port
        {
            bail!("Aliased server on disallowed port");
        }

        if config.snipe.enabled {
            maybe_log_sniped(&shared, &config, target, &db, &ping_res);
        }

        // if let Some(cleaned_data) = clean_response_data(&data, passive_fingerprint) {
        //     let mongo_update = doc! { "$set": cleaned_data };
        //     match create_query(database, &target, mongo_update) {
        //         Ok(r) => Some(r),
        //         Err(err) => {
        //             error!("Error updating server {target}: {err}");
        //             None
        //         }
        //     }
        // } else {
        //     None
        // }

        insert_server_to_db(&db, &target, &ping_res).await
    }
}

pub fn parse_ping_response_json(d: &[u8]) -> eyre::Result<PingResponse> {
    let d = String::from_utf8_lossy(d);
    let d = sanitize_text_for_postgres(&d);
    let fingerprint = generate_passive_fingerprint(&d)?;
    let mut d = d.into_bytes();

    let v = match simd_json::to_owned_value(&mut d) {
        Ok(v) => v,
        Err(_) => {
            bail!("Failed to parse JSON: {:?}", String::from_utf8_lossy(&d));
        }
    };

    let description = v.get("description");
    let description_json = sanitize_text_for_postgres(&simd_json::to_string(&description)?);
    let description_plaintext = description
        .map(|description| {
            sanitize_text_for_postgres(
                &azalea_chat::FormattedText::deserialize(description)
                    .unwrap_or_default()
                    .to_string(),
            )
        })
        .unwrap_or_default();

    let version = v.get("version");
    let version_name = version
        .get_str("name")
        .map(|s| sanitize_text_for_postgres(s));
    let version_protocol = version.get_i32("protocol");

    let favicon = v.get_str("favicon").map(|s| sanitize_text_for_postgres(s));
    // filter out bad favicons
    let favicon = favicon.filter(|f| f.starts_with("data:image/png;base64,"));
    let favicon_hash = favicon.as_ref().map(|s| make_favicon_hash(s));

    let players = v.get("players");

    if description.is_none() && version.is_none() && players.is_none() {
        // some servers are missing one of these fields (even description isn't
        // technically required), but if they're missing all three then it's
        // probably not even a minecraft server

        bail!("Missing description, version, and players fields");
    }

    let online_players = players.get_i32("online");
    let max_players = players.get_i32("max");
    let mut is_online_mode = None;
    let mut seen_uuids = HashSet::new();

    // servers with this motd randomize the online players
    let mut is_fake_sample = description_plaintext
        == "To protect the privacy of this server and its\nusers, you must log in once to see ping data.";

    let player_sample = players
        .get_array("sample")
        .map(|a| {
            a.iter()
                .filter_map(|v| {
                    let Some(name) = v.get_str("name").map(|s| sanitize_text_for_postgres(s))
                    else {
                        // name is required
                        is_fake_sample = true;
                        return None;
                    };
                    let uuid_str = v.get_str("id");
                    let Some(uuid) = uuid_str.and_then(|s| Uuid::parse_str(s).ok()) else {
                        // uuid is required
                        is_fake_sample = true;
                        return None;
                    };
                    if seen_uuids.contains(&uuid) {
                        // no duplicate uuids allowed
                        is_fake_sample = true;
                        return None;
                    }
                    seen_uuids.insert(uuid);

                    // uuidv4
                    match uuid.get_version_num() {
                        4 => is_online_mode = Some(true),
                        3 => {
                            if is_online_mode.is_none() {
                                is_online_mode = Some(false);
                            }
                        }
                        _ if uuid.is_nil() && name == ANONYMOUS_PLAYER_NAME => {
                            // anonymous player doesn't give us any info
                        }
                        _ => is_fake_sample = true,
                    }

                    Some(SamplePlayer { name, uuid })
                })
                .collect()
        })
        .unwrap_or_default();

    let previews_chat = v.get_bool("previewsChat");
    let enforces_secure_chat = v.get_bool("enforcesSecureChat");

    let prevents_chat_reports = v.get_bool("preventsChatReports");
    let forge_data = v.get("forgeData");
    let forgedata_fml_network_version = forge_data.get_i32("fmlNetworkVersion");
    let mod_info = v.get("modinfo");
    let modinfo_type = mod_info
        .get_str("type")
        .map(|s| sanitize_text_for_postgres(s));
    let is_modded = v.get_bool("isModded");
    let modpack_data = v.get("modpackData");
    let modpackdata_project_id = modpack_data.get_i32("projectID");
    let modpackdata_name = modpack_data
        .get_str("name")
        .map(|s| sanitize_text_for_postgres(s));
    let modpackdata_version = modpack_data
        .get_str("version")
        .map(|s| sanitize_text_for_postgres(s));

    Ok(PingResponse {
        description_json,
        description_plaintext,

        version_name,
        version_protocol,
        favicon,
        favicon_hash,

        online_players,
        max_players,
        player_sample,
        is_online_mode,
        is_fake_sample,

        enforces_secure_chat,

        fingerprint,

        previews_chat,
        prevents_chat_reports,
        forgedata_fml_network_version,
        modinfo_type,
        is_modded,
        modpackdata_project_id,
        modpackdata_name,
        modpackdata_version,
    })
}

pub async fn insert_server_to_db(
    db: &Database,
    target: &SocketAddrV4,
    r: &PingResponse,
) -> eyre::Result<()> {
    let mut is_aliased_server = false;
    {
        let mut shared = db.shared.lock();
        let ips_with_same_hash = shared.ip_to_hash_and_ports.get_mut(target.ip());
        if let Some((data, previously_checked_ports)) = ips_with_same_hash {
            if !previously_checked_ports.contains(&target.port()) {
                if let Some(count) = &mut data.count {
                    let this_server_hash = make_ping_response_hash(r)?;

                    if this_server_hash == data.hash {
                        *count += 1;
                        previously_checked_ports.insert(target.port());

                        if *count >= 100 {
                            // too many servers with the same hash... add to bad ips!
                            println!("found a new bad ip: {} :(", target.ip());
                            // we call add_to_ips_with_aliased_servers later
                            is_aliased_server = true;
                        }
                    } else {
                        // this server has a different hash than the other servers with the same IP
                        data.count = None;
                    }
                }
            }
        } else {
            let this_server_hash = make_ping_response_hash(r)?;
            shared.ip_to_hash_and_ports.insert(
                *target.ip(),
                (
                    CachedIpHash {
                        count: Some(1),
                        hash: this_server_hash,
                    },
                    HashSet::from_iter(vec![target.port()]),
                ),
            );
        }
    }

    if is_aliased_server {
        let db = db.clone();
        let target = target.clone();
        tokio::spawn(async move {
            let _ = db
                // for now, assume 25565 is the only allowed port. might change this in the future.
                .add_to_ips_with_aliased_servers(*target.ip(), 25565)
                .await;
        });
        bail!("Aliased server: {target:?}");
    }

    let mut txn = db.pool.begin().await?;

    if r.favicon.is_some() {
        sqlx::query(
            r#"
            INSERT INTO favicons (hash, data)
            VALUES ($1, $2)
            ON CONFLICT (hash) DO NOTHING
            "#,
        )
        .bind(r.favicon_hash)
        .bind(r.favicon.clone())
        .execute(&mut *txn)
        .await?;
    }

    let mut qb = InsertServerQueryBuilder::new();
    let now = chrono::Utc::now();
    qb.field("ip", target.ip().to_bits() as i32);
    qb.field("port", target.port() as i16);
    qb.field("last_pinged", now);
    qb.field("is_online_mode", r.is_online_mode);
    qb.field("favicon_hash", r.favicon_hash);
    qb.field("description_json", r.description_json.clone());
    qb.field("description_plaintext", r.description_plaintext.clone());
    qb.field("online_players", r.online_players);
    qb.field("max_players", r.max_players);
    qb.field("version_name", r.version_name.clone());
    qb.field("version_protocol", r.version_protocol);
    qb.field("enforces_secure_chat", r.enforces_secure_chat);
    qb.field("previews_chat", r.previews_chat);

    qb.field("fingerprint_field_order", r.fingerprint.field_order.clone());
    qb.field(
        "fingerprint_is_incorrect_field_order",
        r.fingerprint.incorrect_order,
    );
    qb.field("fingerprint_is_empty_sample", r.fingerprint.empty_sample);
    qb.field("fingerprint_is_empty_favicon", r.fingerprint.empty_favicon);

    qb.field("prevents_chat_reports", r.prevents_chat_reports);
    qb.field(
        "forgedata_fml_network_version",
        r.forgedata_fml_network_version,
    );
    qb.field("modinfo_type", r.modinfo_type.clone());
    qb.field("is_modded", r.is_modded);
    qb.field("modpackdata_project_id", r.modpackdata_project_id);
    qb.field("modpackdata_name", r.modpackdata_name.clone());
    qb.field("modpackdata_version", r.modpackdata_version.clone());
    if r.player_sample.is_empty() {
        qb.field("last_time_no_players_online", now);
    } else {
        qb.field("last_time_player_online", now);
    }

    let mut qb = qb.into_querybuilder();
    let query = qb.build();
    query.execute(&mut *txn).await?;

    // insert players in bulk
    if !r.player_sample.is_empty() {
        let mut query_builder = QueryBuilder::new(
            "INSERT INTO server_players (server_ip, server_port, uuid, username, online_mode, last_seen) ",
        );
        query_builder.push_values(&r.player_sample, |mut b, player| {
            b.push_bind(target.ip().to_bits() as i32)
                .push_bind(target.port() as i16)
                .push_bind(player.uuid)
                .push_bind(player.name.clone())
                .push_bind(match player.uuid.get_version_num() {
                    3 => Some(false),
                    4 => Some(true),
                    _ => None,
                })
                .push_bind(chrono::Utc::now());
        });
        query_builder.push("ON CONFLICT (server_ip, server_port, uuid) DO UPDATE SET last_seen = EXCLUDED.last_seen, username = EXCLUDED.username");
        let query = query_builder.build();
        query.execute(&mut *txn).await?;
    }

    txn.commit().await?;
    Ok(())
}

/// This exists so we can insert a server into the database while having a
/// dynamic number of fields, and to reduce code duplication.
///
/// It's a little cursed, hopefully it's not too slow.
struct InsertServerQueryBuilder<'a> {
    pub qb: QueryBuilder<'a, Postgres>,
    pub field_names: Vec<String>,
    pub arguments: PgArguments,
}
impl<'a> InsertServerQueryBuilder<'a> {
    pub fn new() -> Self {
        Self {
            qb: QueryBuilder::new("INSERT INTO servers ("),
            field_names: Vec::new(),
            arguments: PgArguments::default(),
        }
    }

    pub fn field(
        &mut self,
        name: &str,
        value: impl sqlx::Encode<'a, Postgres> + sqlx::Type<sqlx::Postgres> + 'a,
    ) {
        if !self.field_names.is_empty() {
            self.qb.push(", ");
        }
        self.field_names.push(name.to_string());
        self.qb.push(name);
        if let Err(e) = self.arguments.add(value) {
            error!("Failed to add argument {name}: {e:?}");
        };
    }

    pub fn into_querybuilder(mut self) -> QueryBuilder<'a, Postgres> {
        self.qb.push(") VALUES (");
        let mut first = true;
        for _ in &self.field_names {
            if first {
                first = false;
            } else {
                self.qb.push(", ");
            }
            // the actual argument gets set later when we do with_arguments
            // i know this is evil
            self.qb.push_bind(0);
        }
        self.qb.push(") ON CONFLICT (ip, port) DO UPDATE SET ");
        let mut first = true;
        for name in &self.field_names {
            if name == "ip" || name == "port" {
                continue;
            }
            if first {
                first = false;
            } else {
                self.qb.push(", ");
            }
            self.qb.push(name);
            self.qb.push(" = EXCLUDED.");
            self.qb.push(name);
        }
        QueryBuilder::with_arguments(self.qb.into_sql(), self.arguments)
    }
}

fn make_ping_response_hash(ping_res: &PingResponse) -> eyre::Result<u64> {
    let description = &ping_res.description_plaintext;
    let version_name = ping_res.version_name.clone().unwrap_or_default();
    let version_protocol = ping_res.version_protocol.unwrap_or_default();
    let max_players = ping_res.max_players.unwrap_or_default();

    let mut hasher = DefaultHasher::new();
    (description, version_name, version_protocol, max_players).hash(&mut hasher);
    Ok(hasher.finish())
}

fn make_favicon_hash(favicon: &str) -> [u8; 16] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(favicon.as_bytes());
    let result = hasher.finalize();
    let mut hash = [0; 16];
    hash.copy_from_slice(&result[..16]);
    hash
}
