use std::{collections::HashMap, net::SocketAddrV4, sync::Arc};

use parking_lot::Mutex;

use crate::{config::Config, database::{Database, PgU16, PgU32}, processing::{SharedData, minecraft::{ANONYMOUS_PLAYER_NAME, PingResponse, }}};

pub fn maybe_log_sniped(
    shared: &Arc<Mutex<SharedData>>,
    config: &Config,
    target: SocketAddrV4,
    db: &Database,
    ping_res: &PingResponse
) {
    let mut previous_player_usernames = Vec::new();
    {
        let shared = shared.lock();
        let previous_sample = shared.cached_players_for_sniping.get(&target);
        // Usernames of players that were on the server last time we pinged it
        if let Some(sample) = previous_sample {
            for player in sample {
                previous_player_usernames.push(player.name.clone());
            }
        }
    }

    let mut current_player_usernames = Vec::new();

    for player in &ping_res.player_sample {
        current_player_usernames.push(player.name.clone());
    }

    let previous_anon_players_count = previous_player_usernames
        .iter()
        .filter(|&p| p == ANONYMOUS_PLAYER_NAME)
        .count();
    let current_anon_players_count = current_player_usernames
        .iter()
        .filter(|&p| p == ANONYMOUS_PLAYER_NAME)
        .count();

    for current_player in &current_player_usernames {
        if config.snipe.usernames.contains(current_player) {
            println!("snipe: {current_player} is in {target}");

            if !previous_player_usernames.contains(current_player) {
                tokio::task::spawn(send_to_webhook(
                    config.snipe.webhook_url.clone(),
                    format!("{current_player} joined {target}"),
                ));
            }
        }
    }
    for previous_player in &previous_player_usernames {
        if config.snipe.usernames.contains(previous_player)
            && !current_player_usernames.contains(previous_player)
        {
            tokio::task::spawn(send_to_webhook(
                config.snipe.webhook_url.clone(),
                format!("{previous_player} left {target}"),
            ));
        }
    }

    if config.snipe.anon_players {
        let online_players = ping_res.online_players.unwrap_or_default();

        let new_anon_players = current_anon_players_count - previous_anon_players_count;

        let meets_new_anon_player_req = !previous_player_usernames.is_empty()
            && current_anon_players_count > previous_anon_players_count
            && new_anon_players >= 2;

        let every_online_player_is_anon = current_player_usernames
            .iter()
            .all(|p| p == ANONYMOUS_PLAYER_NAME);

        // there's some servers that have a bunch of bots that leave and join, and
        // they're shown as anonymous players in the sample
        let too_many_anon_players = current_anon_players_count >= 8 && every_online_player_is_anon;

        if meets_new_anon_player_req
            && online_players < 25
            && !too_many_anon_players
        {
            tokio::task::spawn(send_to_webhook(
                config.snipe.webhook_url.clone(),
                format!("{new_anon_players} anonymous players joined **{target}**"),
            ));
        } else if previous_anon_players_count == 0
            && current_anon_players_count > 0
            && online_players < 25
        {
            let webhook_url = config.snipe.webhook_url.clone();
            let database = db.clone();
            tokio::task::spawn(async move {
                // check that there were no anonymous players before
                if let Ok(has_historical_anon_res) = sqlx::query(
                            "SELECT FROM server_players WHERE username = '$1' AND server_ip = $2 AND server_port = $3 LIMIT 1",
                        )
                            .bind(ANONYMOUS_PLAYER_NAME)
                            .bind(PgU32(target.ip().to_bits()))
                            .bind(PgU16(target.port())).fetch_optional(&database.pool).await {
                                let has_historical_anon = has_historical_anon_res.is_some();
                                if !has_historical_anon {
                                    send_to_webhook(
                                        webhook_url,
                                        format!("anonymous player joined **{target}** for the first time"),
                                    )
                                    .await;
                                }   
                            }
            });
        }
    }

    shared
        .lock()
        .cached_players_for_sniping
        .insert(target, ping_res.player_sample.clone());
}



async fn send_to_webhook(webhook_url: String, message: String) {
    let client = reqwest::Client::new();
    if let Err(e) = client
        .post(webhook_url)
        .json(
            &vec![("content".to_string(), message.to_string())]
                .into_iter()
                .collect::<HashMap<String, String>>(),
        )
        .send()
        .await
    {
        println!("{}", e);
    }
}