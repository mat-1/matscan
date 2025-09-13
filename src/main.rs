use std::{
    collections::{HashMap, VecDeque},
    env, fs, path,
    str::FromStr,
    sync::{Arc, atomic::AtomicBool},
    thread,
    time::{Duration, Instant},
};

use dotenv::dotenv;
use matscan::{
    config::{Config, RescanConfig},
    database::{Database, migrate_mongo_to_postgres},
    exclude,
    net::tcp::StatelessTcpWriteHalf,
    processing::{SharedData, process_pings},
    scanner::{
        ScanSession, Scanner, ScannerReceiver,
        protocols::{self},
        targets::{Ipv4Range, Ipv4Ranges, ScanRange, ScanRanges},
    },
    strategies::{ScanStrategy, StrategyPicker},
    terminal_colors::*,
    tracing::init_tracing,
};
use parking_lot::{Mutex, RwLock};
use tracing::info;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum StrategyCategory {
    Normal,
    Rescan,
    Fingerprint,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    println!("Starting...");

    dotenv().ok();
    println!("dotenv");

    let args = env::args().collect::<Box<[String]>>();
    if args.get(1) == Some(&"mongodb-migrate".to_string()) {
        let mongodb_uri = args
            .get(2)
            .expect("mongodb uri must be the second argument");
        let postgres_uri = args
            .get(3)
            .expect("postgres uri must be the third argument");

        migrate_mongo_to_postgres::do_migration(mongodb_uri, postgres_uri).await;
        println!("Done.");
        return Ok(());
    }

    // first command line argument is the location of the config file
    let config_file = args.get(1).cloned().unwrap_or("config.toml".to_string());

    let config_file_path = path::Path::new(&config_file).canonicalize()?;
    println!(
        "parsing config at {}",
        config_file_path.as_os_str().to_string_lossy()
    );
    let config: Config = toml::from_str(&fs::read_to_string(config_file_path)?)?;

    init_tracing(&config);
    info!("Logging initialized");

    println!("parsing exclude file");
    let mut exclude_ranges = exclude::parse_file("exclude.conf")?;
    println!(
        "excluding {} ips ({} ranges)",
        exclude_ranges.count(),
        exclude_ranges.ranges().len()
    );

    let minecraft_protocol = protocols::Minecraft::new(
        &config.target.addr,
        config.target.port,
        config.target.protocol_version,
    );

    let database = Database::connect(&config.postgres_uri).await?;
    let scanner = Scanner::new(&config);
    let mut strategy_picker = StrategyPicker::default();

    // the number of times we've done a scan, used for switching between different
    // strategy categories (rescanning and scanning)
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

    // we pick a different strategy category each scan
    let mut strategy_categories = vec![];
    if config.scanner.enabled {
        strategy_categories.push(StrategyCategory::Normal);
    }
    if rescan_enabled {
        strategy_categories.push(StrategyCategory::Rescan);
    }
    if config.fingerprinting.enabled {
        strategy_categories.push(StrategyCategory::Fingerprint);
    }

    if config.debug.only_scan_addr.is_some() {
        info!(
            "debug.only_scan_addr is set, setting only enabled strategy category to Normal and ignoring exclude ranges"
        );
        strategy_categories = vec![StrategyCategory::Normal];
        exclude_ranges = Ipv4Ranges::default();
    }

    if strategy_categories.is_empty() {
        panic!(
            "Scanner, rescanner, and fingerprinting are all disabled in the config. You should probably at least enable scanner."
        );
    }

    // the protocol set here will be overwritten later so it doesn't actually matter
    let protocol: Arc<RwLock<Box<dyn protocols::Protocol>>> =
        Arc::new(RwLock::new(Box::new(minecraft_protocol.clone())));

    let shared_process_data: Arc<Mutex<SharedData>> = Arc::new(Mutex::new(SharedData {
        database: database.clone(),
        queue: VecDeque::new(),
        // we use the cache to check if someone just joined a server, so this
        // will always stay empty if snipe mode is off
        cached_players_for_sniping: HashMap::new(),

        total_new: 0,
        total_new_on_default_port: 0,
        revived: 0,
        results: 0,

        is_processing: false,
    }));

    let mut receiver = ScannerReceiver {
        protocol: protocol.clone(),
        shared_process_data: shared_process_data.clone(),
        scanner,
        has_ended: has_ended.clone(),
        simulate_rx_loss: config.debug.simulate_rx_loss,
    };
    let recv_loop_thread = thread::spawn(move || {
        receiver.recv_loop(Duration::from_secs(config.ping_timeout_secs.unwrap_or(60)))
    });

    let mut processing_task = ProcessingTask::new(shared_process_data.clone(), config.clone());

    // make sure the strategies in config.scanner.strategies are valid
    let scan_strategies = config.scanner.strategies.as_ref().map(|strategies| {
        strategies
            .iter()
            .map(|strat| {
                ScanStrategy::from_str(strat).unwrap_or_else(|_| {
                    panic!("invalid strategy {strat:?} in config.scanner.strategies")
                })
            })
            .collect::<Vec<_>>()
    });

    let mut ctx = ScanContext {
        exclude_ranges,
        database,
        scanner_writer,
        config,
        scanner_seed,
        shared_process_data,
    };

    loop {
        let start_time = Instant::now();

        let mut ranges = ScanRanges::default();

        let strategy_category = strategy_categories[i % strategy_categories.len()];
        i += 1;

        // if the strategy is none then that means it's a special strategy (either
        // rescanning or fingerprinting)
        let mut strategy: Option<ScanStrategy> = None;
        match strategy_category {
            StrategyCategory::Normal => {
                let chosen_strategy = strategy_picker.pick_strategy(scan_strategies.clone());

                println!("chosen strategy: {chosen_strategy:?}");

                let get_ranges_start = Instant::now();
                ranges.extend(
                    chosen_strategy
                        .get_ranges(&mut ctx.database, &ctx.config)
                        .await?,
                );
                let get_ranges_end = Instant::now();
                println!("get_ranges took {:?}", get_ranges_end - get_ranges_start);

                strategy = Some(chosen_strategy);
                *protocol.write() = Box::new(minecraft_protocol.clone());
                processing_task.set_protocol::<protocols::Minecraft>();
            }
            StrategyCategory::Rescan => {
                println!("chosen strategy: rescanning");

                // add the ranges we're rescanning
                for rescan_config in [
                    &ctx.config.rescan,
                    &ctx.config.rescan2,
                    &ctx.config.rescan3,
                    &ctx.config.rescan4,
                    &ctx.config.rescan5,
                ] {
                    maybe_rescan_with_config(&ctx.database, &mut ranges, rescan_config).await?;
                }

                *protocol.write() = Box::new(minecraft_protocol.clone());
                processing_task.set_protocol::<protocols::Minecraft>();
            }
            StrategyCategory::Fingerprint => {
                println!("chosen strategy: fingerprinting");

                let mut fingerprint_ranges = Vec::new();
                let mut fingerprint_protocol_versions = HashMap::new();
                for (addr, protocol_version) in
                    matscan::strategies::fingerprint::get_addrs_and_protocol_versions(&ctx.database)
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

        perform_scan(&ctx, ranges, strategy, start_time, &mut strategy_picker).await;

        if ctx.config.debug.exit_on_done {
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

struct ScanContext {
    exclude_ranges: Ipv4Ranges,
    database: Database,
    scanner_writer: StatelessTcpWriteHalf,
    config: Config,
    scanner_seed: u64,
    shared_process_data: Arc<Mutex<SharedData>>,
}

async fn perform_scan(
    ctx: &ScanContext,
    mut ranges: ScanRanges,
    strategy: Option<ScanStrategy>,
    start_time: Instant,
    strategy_picker: &mut StrategyPicker,
) {
    let count_before_exclude = ranges.count();
    ranges.apply_exclude(&ctx.exclude_ranges);

    let bad_ips = Ipv4Ranges::new(
        ctx.database
            .shared
            .lock()
            .aliased_ips_to_allowed_port
            .clone()
            .into_keys()
            .map(Ipv4Range::single)
            .collect::<Vec<_>>(),
    );

    let mut default_port_ranges = Vec::new();
    for excluded_range in ranges.apply_exclude(&bad_ips) {
        // we still scan port 25565 on bad ips (ips that have the same
        // server on every port)
        default_port_ranges.push(ScanRange::single_port(
            excluded_range.start,
            excluded_range.end,
            25565,
        ));
    }
    ranges.extend(default_port_ranges);

    let target_count = ranges.count();
    let range_count = ranges.ranges().len();
    println!("scanning {target_count} targets ({range_count} ranges)");
    println!(
        "excluded {} targets from this scan",
        count_before_exclude - target_count
    );

    // this just spews out syn packets so it doesn't need to know what protocol
    // we're using
    let session = ScanSession::new(ranges);
    let mut scanner_writer = ctx.scanner_writer.clone();

    let max_packets_per_second = ctx.config.rate;
    let scanner_seed = ctx.scanner_seed;
    let scan_duration_secs = ctx.config.scan_duration_secs.unwrap_or(60 * 5);
    let scanner_thread = thread::spawn(move || {
        session.run(
            max_packets_per_second,
            &mut scanner_writer,
            scanner_seed,
            scan_duration_secs,
        )
    });

    // wait until the scanner thread is done
    while !scanner_thread.is_finished() {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    println!("waiting for processing to finish...");

    let processing_start = Instant::now();
    // wait until shared_process_data.processing_count is 0
    while ctx.shared_process_data.lock().is_processing {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let processing_time = processing_start.elapsed();
    let original_sleep_secs = ctx.config.sleep_secs.unwrap_or(10);
    // subtract the processing time from the sleep time
    if original_sleep_secs > processing_time.as_secs() {
        let sleep_secs = original_sleep_secs - processing_time.as_secs();
        println!("sleeping for {sleep_secs} seconds");
        tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
    }

    // the thread should've finished by now so it'll join instantly
    println!("joining scanner thread");
    let packets_sent = scanner_thread.join().unwrap();

    let mut shared_process_data = ctx.shared_process_data.lock();
    process_results(
        &mut shared_process_data,
        start_time,
        strategy,
        strategy_picker,
        packets_sent,
    );
}

/// Print the results of the scan, reset the counters, and update
/// strategies.json.
fn process_results(
    shared_process_data: &mut SharedData,
    start_time: Instant,
    strategy: Option<ScanStrategy>,
    strategy_picker: &mut StrategyPicker,
    packets_sent: u64,
) {
    let total_new = shared_process_data.total_new;
    let total_new_on_default_port = shared_process_data.total_new_on_default_port;
    let revived = shared_process_data.revived;
    let results = shared_process_data.results;
    shared_process_data.total_new = 0;
    shared_process_data.total_new_on_default_port = 0;
    shared_process_data.revived = 0;
    shared_process_data.results = 0;

    let end_time = Instant::now();
    let elapsed = end_time - start_time;

    let elapsed_secs = elapsed.as_secs();

    if let Some(strategy) = strategy {
        let added_per_minute = ((total_new + revived) as f64 / elapsed.as_secs_f64()) * 60.0;
        println!(
            "ok finished adding to db after {BOLD}{elapsed_secs}{RESET} seconds (strat: {BOLD}{strategy:?}{RESET}, {YELLOW}updated {BOLD}{results}{RESET}{YELLOW}/{packets_sent}{RESET}, {GREEN}revived {BOLD}{revived}{RESET}, {BLUE}added {total_new}{RESET}, {BOLD}{added_per_minute:.2}{RESET} new per minute)",
        );
        info!(
            "Finished adding to database after {elapsed_secs} seconds. Strat: {strategy:?}, updated {results}/{packets_sent}, revived {revived}, added {total_new}, {added_per_minute:.2} new per minute",
        );

        // prioritize finding servers on the default port since they're more likely to
        // last longer
        const TOTAL_NEW_MULTIPLIER: f64 = 1.0;
        const TOTAL_NEW_ON_DEFAULT_PORT_MULTIPLIER: f64 = 50.0;
        const REVIVED_MULTIPLIER: f64 = 0.1;

        let total_new_score = total_new as f64 * TOTAL_NEW_MULTIPLIER;
        let total_new_on_default_port_score =
            total_new_on_default_port as f64 * TOTAL_NEW_ON_DEFAULT_PORT_MULTIPLIER;
        let revived_score = revived as f64 * REVIVED_MULTIPLIER;

        let unnormalized_score = total_new_score + revived_score + total_new_on_default_port_score;

        // score ends up being servers per hour-ish
        // (we add 30 seconds so if a strategy finishes very quickly it's not super
        // biased towards it)
        let score = (unnormalized_score * 3600.0 / (elapsed.as_secs_f64() + 30.)).round() as usize;
        println!(
            "got score {score} from {unnormalized_score} = {total_new_score} + {revived_score} + {total_new_on_default_port_score}"
        );
        strategy_picker.update_strategy(strategy, score);
    } else {
        let percent_replied = (results as f64 / packets_sent as f64) * 100.0;
        println!(
            "ok finished rescanning after {BOLD}{elapsed_secs}{RESET} seconds ({YELLOW}updated {BOLD}{results}{RESET}{YELLOW}/{packets_sent}{RESET}, {GREEN}revived {BOLD}{revived}{RESET}, {BOLD}{percent_replied:.2}%{RESET} replied)",
        );
        info!(
            "Finished rescanning after {elapsed_secs} seconds. Sent {packets_sent} SYNs, updated {results}, revived {revived}, {percent_replied:.2}% replied",
        )
    }
}

/// Get targets to rescan based on the given config and add them to ranges
async fn maybe_rescan_with_config(
    database: &Database,
    ranges: &mut ScanRanges,
    rescan: &RescanConfig,
) -> eyre::Result<()> {
    if rescan.enabled {
        ranges.extend(matscan::strategies::rescan::get_ranges(database, rescan).await?);
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
