use std::net::Ipv4Addr;

use futures_util::StreamExt;
use serde::Deserialize;
use sqlx::{Postgres, QueryBuilder, Row};
use tracing::debug;

use crate::{config::RescanConfig, database::Database, scanner::targets::ScanRange};

#[derive(Deserialize, Clone, Copy, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Sort {
    Random,
    Oldest,
}

pub async fn get_ranges(database: &Database, opts: &RescanConfig) -> eyre::Result<Vec<ScanRange>> {
    let mut ranges = Vec::new();

    let mut qb: QueryBuilder<'_, Postgres> = QueryBuilder::new(
        "
    SELECT ip, port FROM servers
    WHERE
        last_pinged > NOW() - INTERVAL '$1 seconds'
        AND last_pinged < NOW() - INTERVAL '$1 seconds'
    ",
    );

    if !opts.filter_sql.is_empty() {
        // this could result in sql injection, but the config is considered to be
        // trusted
        qb.push(format!(" AND {}", opts.filter_sql));
    }
    if let Some(players_online_ago_max_secs) = opts.players_online_ago_max_secs {
        qb.push(format!(" AND last_time_player_online > NOW() - INTERVAL '{players_online_ago_max_secs} seconds'"));
    }

    let mut aliased_ips_to_allowed_port = database
        .shared
        .lock()
        .aliased_ips_to_allowed_port
        .to_owned();

    let sort = opts.sort.unwrap_or(Sort::Oldest);

    match sort {
        Sort::Random => {
            qb.push(" ORDER BY random()");
        }
        Sort::Oldest => {
            qb.push(" ORDER BY last_pinged");
        }
    }
    if let Some(limit) = opts.limit {
        qb.push(format!(" LIMIT {limit}"));
    }

    let sql = qb.into_sql();
    debug!("Doing rescan query with SQL: {sql}");
    let mut rows = sqlx::query(&sql)
        .bind(opts.last_ping_ago_max_secs as i64)
        .bind(opts.rescan_every_secs as i64)
        .fetch(&database.pool);

    while let Some(Ok(row)) = rows.next().await {
        let ip = Ipv4Addr::from_bits(row.get::<i32, _>(0) as u32);
        let port: u16 = row.get::<i16, _>(1) as u16;

        // there shouldn't be any aliased servers since we should've deleted them, but
        // this desync can happen if we're running multiple instances of matscan
        if let Some(&allowed_port) = aliased_ips_to_allowed_port.get(&ip)
            && port != allowed_port
        {
            println!(
                "We encountered an aliased server while getting servers to rescan. Deleting {ip} from database."
            );
            sqlx::query("DELETE FROM servers WHERE ip = $1 AND port != $2")
                .bind(ip.to_bits() as i32)
                .bind(allowed_port as i16)
                .execute(&database.pool)
                .await?;
            // this doesn't actually remove it from the database, it just makes it so we
            // don't delete twice
            aliased_ips_to_allowed_port.remove(&ip);
            continue;
        }

        ranges.push(ScanRange::single(ip, port as u16));
        if ranges.len() % 1000 == 0 {
            println!("{} ips", ranges.len());
        }
    }

    if opts.padded {
        ranges.push(ScanRange::single_port(
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
            25565,
        ));
    }

    Ok(ranges)
}
