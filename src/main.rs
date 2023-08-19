use std::{
    collections::{HashMap, VecDeque},
    sync::{atomic::AtomicBool, Arc},
    thread,
    time::{Duration, Instant},
};

use dotenv::dotenv;
use parking_lot::{Mutex, RwLock};
use tracing_subscriber::{prelude::*, EnvFilter};

use matscan::{
    config::{Config, RescanConfig},
    database::Database,
    exclude,
    modes::{ModePicker, ScanMode},
    processing::{process_pings, SharedData},
    scanner::{
        protocols::{self},
        targets::{Ipv4Range, Ipv4Ranges, ScanRange, ScanRanges},
        ScanSession, Scanner, ScannerReceiver,
    },
};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ModeCategory {
    Normal,
    Rescan,
    Fingerprint,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("Starting...");

    dotenv().ok();
    println!("dotenv");

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    // first command line argument is the location of the config file
    let config_file = std::env::args().nth(1).unwrap_or("config.toml".to_string());

    let config_file_path = std::path::Path::new(&config_file).canonicalize()?;
    println!(
        "parsing config at {}",
        config_file_path.as_os_str().to_string_lossy()
    );
    let config: Config = toml::from_str(&std::fs::read_to_string(config_file_path)?)?;

    println!("parsing exclude file");
    let exclude_ranges = exclude::parse_file("exclude.conf")?;

    let minecraft_protocol = protocols::Minecraft::new(
        &config.target.addr,
        config.target.port,
        config.target.protocol_version,
    );

    let mut database = Database::connect(&config.mongodb_uri).await?;
    let scanner = Scanner::new(config.source_port);
    let mut mode_picker = ModePicker::default();

    // the number of times we've done a scan, used for switching between rescanning
    // and scanning
    let mut i = 0;

    let rescan_enabled = config.rescan.enabled
        || config.rescan2.enabled
        || config.rescan3.enabled
        || config.rescan4.enabled
        || config.rescan5.enabled;

    // used by the sender loop
    let scanner_seed = scanner.seed;
    let scanner_writer = scanner.client.write.clone();

    let has_ended = Arc::new(AtomicBool::new(false));

    // we pick a different mode category each scan
    let mut mode_categories = vec![];
    if config.scanner.enabled {
        mode_categories.push(ModeCategory::Normal);
    }
    if rescan_enabled {
        mode_categories.push(ModeCategory::Rescan);
    }
    if config.fingerprinting.enabled {
        mode_categories.push(ModeCategory::Fingerprint);
    }

    if mode_categories.is_empty() {
        panic!("Scanner, rescanner, and fingerprinting are all disabled in the config. You should probably at least enable scanner.");
    }

    // the protocol set here will be overwritten later so it doesn't actually matter
    let protocol: Arc<RwLock<Box<dyn protocols::Protocol>>> =
        Arc::new(RwLock::new(Box::new(minecraft_protocol.clone())));

    let shared_process_data: Arc<Mutex<SharedData>> = Arc::new(Mutex::new(SharedData {
        database: database.clone(),
        queue: VecDeque::new(),
        // we use the cache to check if someone just joined a server, so this
        // will always stay empty if snipe mode is off
        cached_servers: HashMap::new(),

        total_new: 0,
        revived: 0,
        results: 0,

        is_processing: false,
    }));

    let mut receiver = ScannerReceiver {
        protocol: protocol.clone(),
        shared_process_data: shared_process_data.clone(),
        scanner,
        has_ended: has_ended.clone(),
    };
    let recv_loop_thread = thread::spawn(move || receiver.recv_loop());

    let mut processing_task = ProcessingTask::new(shared_process_data.clone(), config.clone());

    loop {
        let start_time = Instant::now();
        i += 1;

        let mut ranges = ScanRanges::new();

        let mode_category = mode_categories[i % mode_categories.len()];
        // if the mode is none then that means it's a special mode (either rescanning or
        // fingerprinting)
        let mut mode: Option<ScanMode> = None;
        match mode_category {
            ModeCategory::Normal => {
                let chosen_mode = mode_picker.pick_mode();

                println!("chosen mode: {chosen_mode:?}");

                let get_ranges_start = Instant::now();
                ranges.extend(chosen_mode.get_ranges(&mut database).await?);
                let get_ranges_end = Instant::now();
                println!("get_ranges took {:?}", get_ranges_end - get_ranges_start);

                mode = Some(chosen_mode);
                *protocol.write() = Box::new(minecraft_protocol.clone());
                processing_task.set_protocol::<protocols::Minecraft>();
            }
            ModeCategory::Rescan => {
                println!("chosen mode: rescanning");

                // add the ranges we're rescanning
                for rescan_config in [
                    &config.rescan,
                    &config.rescan2,
                    &config.rescan3,
                    &config.rescan4,
                    &config.rescan5,
                ] {
                    maybe_rescan_with_config(&database, &mut ranges, rescan_config).await?;
                }

                *protocol.write() = Box::new(minecraft_protocol.clone());
                processing_task.set_protocol::<protocols::Minecraft>();
            }
            ModeCategory::Fingerprint => {
                println!("chosen mode: fingerprinting");

                let mut fingerprint_ranges = Vec::new();
                let mut fingerprint_protocol_versions = HashMap::new();
                for (addr, protocol_version) in
                    matscan::modes::fingerprint::get_addrs_and_protocol_versions(&database)
                        .await?
                        .into_iter()
                        .collect::<Vec<_>>()
                {
                    fingerprint_ranges.push(ScanRange::single(*addr.ip(), addr.port()));
                    fingerprint_protocol_versions.insert(addr, protocol_version);
                }
                ranges.extend(fingerprint_ranges);

                *protocol.write() = Box::new(protocols::MinecraftFingerprinting::new(
                    fingerprint_protocol_versions,
                ));
                processing_task.set_protocol::<protocols::MinecraftFingerprinting>();
            }
        }

        ranges.apply_exclude(&exclude_ranges);

        let bad_ips = Ipv4Ranges::new(
            database
                .shared
                .lock()
                .bad_ips
                .clone()
                .into_iter()
                .map(Ipv4Range::single)
                .collect::<Vec<_>>(),
        );
        ranges.apply_exclude(&bad_ips);
        // for &ip in &database.shared.lock().bad_ips {
        //     // we still scan port 25565 on bad ips (ips that have the same server on
        // every     // port)
        //     let mut excluded_included = Vec::new();

        //     if  {
        //         excluded_included.push(ScanRange::single(ip, 25565));
        //     }
        //     if !excluded_included.is_empty() {
        //         ranges.extend(excluded_included);
        //     }
        // }

        let target_count = ranges.count();
        println!("scanning {target_count} targets");

        // this just spews out syn packets so it doesn't need to know what protocol
        // we're using
        let session = ScanSession::new(ranges);
        let mut scanner_writer = scanner_writer.clone();
        let scanner_thread = thread::spawn(move || {
            session.run(
                config.rate,
                &mut scanner_writer,
                scanner_seed,
                config.scan_duration_secs.unwrap_or(60 * 5),
            )
        });

        // wait until the scanner thread is done
        while !scanner_thread.is_finished() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let processing_start = Instant::now();
        // wait until shared_process_data.processing_count is 0
        while shared_process_data.lock().is_processing {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let processing_time = processing_start.elapsed();
        let original_sleep_secs = config.sleep_secs.unwrap_or(10);
        // subtract the processing time from the sleep time
        if original_sleep_secs > processing_time.as_secs() {
            let sleep_secs = original_sleep_secs - processing_time.as_secs();
            println!("sleeping for {sleep_secs} seconds");
            tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
        }

        // the thread should've finished by now so it'll join instantly
        println!("waiting for scanner thread to finish...");
        let packets_sent = scanner_thread.join().unwrap();

        let mut shared_process_data = shared_process_data.lock();
        process_results(
            &mut shared_process_data,
            start_time,
            mode,
            &mut mode_picker,
            packets_sent,
        );

        if config.exit_on_done {
            println!("exit_on_done is true, exiting");
            break;
        }
    }

    has_ended.store(true, std::sync::atomic::Ordering::Relaxed);
    println!("finished writing, telling recv loop to stop...");
    recv_loop_thread.join().unwrap();
    println!("done");

    Ok(())
}

/// Print the results of the scan, reset the counters, and update modes.json.
fn process_results(
    shared_process_data: &mut SharedData,
    start_time: Instant,
    mode: Option<ScanMode>,
    mode_picker: &mut ModePicker,
    packets_sent: u64,
) {
    let total_new = shared_process_data.total_new;
    let revived = shared_process_data.revived;
    let results = shared_process_data.results;
    shared_process_data.total_new = 0;
    shared_process_data.revived = 0;
    shared_process_data.results = 0;

    let end_time = Instant::now();
    let elapsed = end_time - start_time;

    if let Some(mode) = mode {
        let added_per_minute = ((total_new + revived) as f64 / elapsed.as_secs_f64()) * 60.0;
        println!(
            "OK finished adding to db after {} seconds (mode: {mode:?}, updated {results}/{packets_sent}, revived {revived}, added {total_new}, {added_per_minute:.2} new per minute)",
            elapsed.as_secs()
        );
        mode_picker.update_mode(mode, (added_per_minute * 60.).round() as usize);
    } else {
        println!(
            "ok finished rescanning after {} seconds (updated {results}/{packets_sent}, revived {revived}, {percent:.2}% replied)",
            elapsed.as_secs(),
            percent = (results as f64 / packets_sent as f64) * 100.0
        );
    }
}

/// Get targets to rescan based on the given config and add them to ranges
async fn maybe_rescan_with_config(
    database: &Database,
    ranges: &mut ScanRanges,
    rescan: &RescanConfig,
) -> anyhow::Result<()> {
    if rescan.enabled {
        ranges.extend(
            matscan::modes::rescan::get_ranges(
                database,
                &rescan.filter,
                rescan.rescan_every_secs,
                rescan.players_online_ago_max_secs,
                rescan.last_ping_ago_max_secs.unwrap_or(60 * 60 * 2),
                rescan.limit,
                rescan.sort,
            )
            .await?
            .into_iter()
            .collect::<Vec<_>>(),
        );
    }
    Ok(())
}

pub struct ProcessingTask {
    pub shared_process_data: Arc<Mutex<SharedData>>,
    pub config: Config,
    join_handle: Option<tokio::task::JoinHandle<()>>,
}

impl ProcessingTask {
    pub fn new(shared_process_data: Arc<Mutex<SharedData>>, config: Config) -> Self {
        Self {
            shared_process_data,
            config,
            join_handle: None,
        }
    }
    pub fn set_protocol<P: matscan::processing::ProcessableProtocol>(&mut self) {
        if let Some(join_handle) = &mut self.join_handle {
            join_handle.abort();
        }
        let shared_process_data = self.shared_process_data.clone();
        let join_handle =
            tokio::task::spawn(process_pings::<P>(shared_process_data, self.config.clone()));
        self.join_handle = Some(join_handle);
    }
}
