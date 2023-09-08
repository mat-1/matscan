pub mod protocols;
pub mod targets;
pub mod throttle;

use std::{
    borrow::BorrowMut,
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
    hash::{Hash, Hasher},
    net::SocketAddrV4,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use parking_lot::{Mutex, RwLock};
use perfect_rand::PerfectRng;
use pnet::packet::tcp::TcpFlags;
use serde::Deserialize;
use tracing::{debug, trace, warn};

use crate::{
    net::tcp::{StatelessTcp, StatelessTcpWriteHalf},
    processing::SharedData,
    scanner::protocols::{ParseResponseError, Response},
};

use self::{
    protocols::Protocol,
    targets::{ScanRanges, StaticScanRanges},
    throttle::Throttler,
};

pub struct Scanner {
    pub seed: u64,
    pub client: StatelessTcp,
    pub conns: HashMap<SocketAddrV4, ConnState>,
}

pub struct ActiveFingerprintingData {
    pub protocol_version: i32,
}

impl Scanner {
    pub fn new(source_port: SourcePort) -> Self {
        let seed = rand::random::<u64>();

        let mut client = StatelessTcp::new(source_port);

        client.write.fingerprint.mss = client.write.mtu();
        if client.write.has_ethernet_header() {
            client.write.fingerprint.mss -= 40;
        }

        Scanner {
            seed,
            client,
            conns: HashMap::<SocketAddrV4, ConnState>::new(),
        }
    }

    pub fn purge_old_conns(&mut self, ping_timeout: Duration) {
        let now = Instant::now();
        let mut to_delete = Vec::new();
        for (addr, conn) in &mut self.conns {
            if now - conn.started > ping_timeout {
                debug!("dropping connection to {addr} because it took too long");
                // if it took longer than 60 seconds to reply, then drop the connection
                to_delete.push(*addr)
            }
        }
        for key in &to_delete {
            self.conns.remove(key);
        }
    }
}

pub struct ScannerReceiver {
    pub protocol: Arc<RwLock<Box<dyn Protocol>>>,
    pub shared_process_data: Arc<Mutex<SharedData>>,
    pub scanner: Scanner,
    pub has_ended: Arc<AtomicBool>,
}

impl ScannerReceiver {
    pub fn recv_loop(&mut self, ping_timeout: Duration) {
        let mut received_from_ips = HashSet::<SocketAddrV4>::new();
        let mut syn_acks_received: usize = 0;
        let mut connections_started: usize = 0;

        let mut last_purge = Instant::now();

        loop {
            if self.has_ended.load(Ordering::Relaxed) {
                break;
            }

            // println!("switched to recv loop");
            let protocol = self.protocol.read();
            while let Some((ipv4, tcp)) = self.scanner.client.read.recv() {
                let address = SocketAddrV4::new(ipv4.source, tcp.source);

                if tcp.flags & TcpFlags::RST != 0 {
                    // RST
                    trace!("RST :( {}", address);

                    if self.scanner.conns.contains_key(&address) {
                        // the rst might have significance for this protocol
                        if let Ok(data) = protocol.parse_response(Response::Rst) {
                            self.shared_process_data
                                .lock()
                                .queue
                                .push_back((address, data));
                        }
                    }

                    continue;
                } else if tcp.flags & TcpFlags::FIN != 0 {
                    // FIN

                    if let Some(conn) = self.scanner.conns.get_mut(&address) {
                        self.scanner.client.write.send_ack(
                            address,
                            tcp.destination,
                            conn.local_seq,
                            tcp.sequence + 1,
                        );

                        if !conn.fin_sent {
                            self.scanner.client.write.send_fin(
                                address,
                                tcp.destination,
                                conn.local_seq,
                                tcp.sequence + 1,
                            );
                            conn.fin_sent = true;
                        }

                        if conn.data.is_empty() {
                            debug!("FIN with no data :( {}:{}", ipv4.source, tcp.source);
                            // if there was no data then parse that as a response
                            if let Ok(data) = protocol.parse_response(Response::Data(vec![])) {
                                self.shared_process_data
                                    .lock()
                                    .queue
                                    .push_back((address, data));
                            }
                        } else {
                            debug!("FIN {}:{}", ipv4.source, tcp.source);
                            self.scanner.conns.borrow_mut().remove(&address);
                        }
                    } else {
                        debug!(
                            "FIN with no connection, probably already forgotten by us {}:{}",
                            ipv4.source, tcp.source
                        );
                        self.scanner.client.write.send_ack(
                            address,
                            tcp.destination,
                            tcp.acknowledgement,
                            tcp.sequence + 1,
                        );
                    }

                    continue;
                } else if tcp.flags & TcpFlags::SYN != 0 && tcp.flags & TcpFlags::ACK != 0 {
                    trace!("SYN+ACK {}:{}", ipv4.source, tcp.source);

                    received_from_ips.insert(address);

                    // SYN+ACK
                    // verify that the ack is the cookie+1
                    let ack_number = tcp.acknowledgement;

                    let original_cookie = cookie(&address, self.scanner.seed);
                    let expected_ack = original_cookie + 1;
                    if ack_number != expected_ack {
                        warn!("cookie mismatch for {address} (expected {expected_ack}, got {ack_number})");
                        continue;
                    }

                    self.scanner.client.write.send_ack(
                        address,
                        tcp.destination,
                        tcp.acknowledgement,
                        tcp.sequence + 1,
                    );

                    let payload = protocol.payload(address);
                    if payload.is_empty() {
                        // this means we're skipping this server, give them an rst
                        self.scanner.client.write.send_rst(
                            address,
                            tcp.destination,
                            tcp.acknowledgement,
                            tcp.sequence + 1,
                        );
                        continue;
                    }
                    self.scanner.client.write.send_data(
                        address,
                        tcp.destination,
                        tcp.acknowledgement,
                        tcp.sequence + 1,
                        &payload,
                    );

                    syn_acks_received += 1;
                    trace!("syn acks: {syn_acks_received}");

                    // println!("ok sent first ACK+data");
                } else if tcp.flags & TcpFlags::ACK != 0 {
                    // ACK
                    trace!(
                        "ACK {address} with data: {}",
                        String::from_utf8_lossy(&tcp.payload)
                    );
                    // println!("ACK {}:{}", ipv4.source, tcp.source);

                    // cookie +packet size + 1
                    let ack_number = tcp.acknowledgement;

                    if tcp.payload.is_empty() {
                        // just an ack and not data
                        continue;
                    }

                    // check if it's already in the connections map
                    let (ping_response, is_tracked) = if let Some(conn) =
                        self.scanner.conns.get_mut(&address)
                    {
                        if tcp.sequence != conn.remote_seq {
                            let difference = tcp.sequence as i64 - conn.remote_seq as i64;
                            warn!(
                                "Got wrong seq number {}! expected {} (difference = {difference}). This is probably because of a re-transmission.",
                                tcp.sequence,
                                conn.remote_seq
                            );

                            self.scanner.client.write.send_ack(
                                address,
                                tcp.destination,
                                ack_number,
                                conn.remote_seq,
                            );

                            continue;
                        }
                        // this means it's adding more data to this connection
                        conn.data.extend(tcp.payload.clone());
                        conn.remote_seq = tcp.sequence + tcp.payload.len() as u32;
                        (
                            protocol.parse_response(Response::Data(conn.data.clone())),
                            true,
                        )
                    } else {
                        // this means it's the first data packet we got, verify it
                        let original_cookie = cookie(&address, self.scanner.seed);
                        // we never send anything other than the SYN and initial ping so this is
                        // fine
                        let packet_size = protocol.payload(address).len();
                        let cookie_offset = (packet_size + 1) as u32;

                        let expected_ack = original_cookie.wrapping_add(cookie_offset);
                        if ack_number != expected_ack {
                            warn!("cookie mismatch when reading data for {address} (expected {expected_ack}, got {ack_number}, initial was {original_cookie})");
                            continue;
                        }

                        let ping_response =
                            protocol.parse_response(Response::Data(tcp.payload.clone()));
                        (ping_response, false)
                    };

                    match ping_response {
                        Ok(data) => {
                            let data_string = String::from_utf8_lossy(&data);
                            trace!("\n\n{address} {data_string}");

                            if !is_tracked {
                                self.scanner.conns.borrow_mut().insert(
                                    address,
                                    ConnState {
                                        data: tcp.payload.to_vec(),
                                        remote_seq: tcp
                                            .sequence
                                            .wrapping_add(tcp.payload.len() as u32),
                                        local_seq: tcp.acknowledgement,
                                        started: Instant::now(),
                                        fin_sent: false,
                                    },
                                );
                                connections_started += 1;
                                debug!("connection #{connections_started} started");
                            }

                            let conn = self.scanner.conns.get(&address).unwrap();

                            self.shared_process_data
                                .lock()
                                .queue
                                .push_back((address, data));

                            self.scanner.client.write.send_ack(
                                address,
                                tcp.destination,
                                ack_number,
                                conn.remote_seq,
                            );
                            self.scanner.client.write.send_fin(
                                address,
                                tcp.destination,
                                ack_number,
                                conn.remote_seq,
                            );

                            if !is_tracked {
                                connections_started += 1;
                                debug!("connection #{connections_started} started and ended immediately");
                            }
                        }
                        Err(e) => {
                            match e {
                                ParseResponseError::Invalid => {
                                    trace!("packet error, ignoring");
                                }
                                ParseResponseError::Incomplete { .. } => {
                                    if !is_tracked {
                                        self.scanner.conns.borrow_mut().insert(
                                            address,
                                            ConnState {
                                                data: tcp.payload.to_vec(),
                                                remote_seq: tcp
                                                    .sequence
                                                    .wrapping_add(tcp.payload.len() as u32),
                                                local_seq: tcp.acknowledgement,
                                                started: Instant::now(),
                                                fin_sent: false,
                                            },
                                        );
                                        connections_started += 1;
                                        debug!("connection #{connections_started} started");
                                    }

                                    let conn = self.scanner.conns.get(&address).unwrap();
                                    // always ack whatever they send
                                    // a better tcp implementation would only ack every 2 packets or
                                    // after .5 seconds but this technically still follows the spec
                                    self.scanner.client.write.send_ack(
                                        address,
                                        tcp.destination,
                                        ack_number,
                                        conn.remote_seq,
                                    );
                                }
                            };
                        }
                    }
                }
            }
            drop(protocol);

            // sleep for 50ms
            thread::sleep(Duration::from_millis(50));

            if last_purge.elapsed() > Duration::from_secs(60) {
                self.scanner.purge_old_conns(ping_timeout);
                last_purge = Instant::now();
            }
        }

        self.scanner.purge_old_conns(ping_timeout);
    }
}

pub struct ScanSession {
    pub rng: PerfectRng,
    pub ranges: StaticScanRanges,
}

/// The state stored for active connections. We try to keep this existing for
/// the shortest amount of time possible.
pub struct ConnState {
    /// The data we've received so far.
    data: Vec<u8>,

    /// The (last received sequence number + payload length); aka the
    /// `ack_number` we send; aka the next expected starting sequence number.
    remote_seq: u32,

    /// The sequence number we send.
    local_seq: u32,

    /// The time that the connection was created. Connections are closed 30
    /// seconds after creation (if it wasn't closed earlier).
    started: Instant,

    /// Whether we've sent a fin packet.
    fin_sent: bool,
}

pub struct PingResponse {
    pub target: SocketAddrV4,
    pub data: String,
}

impl ScanSession {
    pub fn new(ranges: ScanRanges) -> Self {
        Self {
            rng: PerfectRng::from_range(ranges.count() as u64),
            ranges: ranges.to_static(),
        }
    }

    /// Run the scanner for `scan_duration_secs` and then sleep for
    /// `sleep_secs`.
    ///
    /// Returns the number of packets sent.
    pub fn run(
        self,
        max_packets_per_second: u64,
        scanner_writer: &mut StatelessTcpWriteHalf,
        seed: u64,
        scan_duration_secs: u64,
    ) -> u64 {
        let mut throttler = Throttler::new(max_packets_per_second);

        let mut packets_sent: u64 = 0;

        let target_count = u64::min(
            self.ranges.count as u64,
            max_packets_per_second * scan_duration_secs,
        );

        let start = Instant::now();

        let mut packets_sent_last_print = 0;
        let mut last_print_time = Instant::now();

        loop {
            // print info about packets per second every 5 seconds
            let time_since_last_print = Instant::now() - last_print_time;
            if packets_sent != 0 && time_since_last_print > Duration::from_secs(5) {
                let packets_per_second = (packets_sent - packets_sent_last_print) as f64
                    / (Instant::now() - last_print_time).as_secs_f64();

                let packets_per_info = if packets_per_second > 10_000_000. {
                    format!("{} mpps", (packets_per_second / 1_000_000.).round() as u64)
                } else if packets_per_second > 10_000. {
                    format!("{} kpps", (packets_per_second / 1_000.).round() as u64)
                } else {
                    format!("{} pps", packets_per_second.round() as u64)
                };

                let packets_per_second = throttler.estimated_packets_per_second() as f64;
                let throttler_packets_per_info = if packets_per_second > 10_000_000. {
                    format!("{} mpps", (packets_per_second / 1_000_000.).round() as u64)
                } else if packets_per_second > 10_000. {
                    format!("{} kpps", (packets_per_second / 1_000.).round() as u64)
                } else {
                    format!("{} pps", packets_per_second.round() as u64)
                };
                println!("packets_sent = {packets_sent} ({packets_per_info}, throttler estimate: {throttler_packets_per_info})");

                packets_sent_last_print = packets_sent;
                last_print_time = Instant::now();
            }

            let mut batch_size = throttler.next_batch();
            if packets_sent + batch_size > target_count {
                batch_size = target_count - packets_sent;
            }

            // tight packet-sending loop
            for _ in 0..batch_size {
                let shuffled_index = self.rng.shuffle(packets_sent);
                let destination_addr = self.ranges.index(shuffled_index as usize);
                trace!("sending syn to {destination_addr}");
                scanner_writer.send_syn(destination_addr, cookie(&destination_addr, seed));
                packets_sent += 1;
            }

            if packets_sent >= target_count {
                println!("Finished sending {packets_sent} packets.");
                break;
            }
            // if it's been more than 5 minutes since we started, finish the scan
            else if (Instant::now() - start).as_secs() > scan_duration_secs {
                println!("{scan_duration_secs} seconds passed, finishing scan.");
                break;
            }
        }

        packets_sent
    }
}

fn cookie(address: &SocketAddrV4, seed: u64) -> u32 {
    let mut hasher = DefaultHasher::new();
    (*address.ip(), address.port(), seed).hash(&mut hasher);
    hasher.finish() as u32
}

#[derive(Deserialize, Clone, Copy)]
#[serde(untagged)]
pub enum SourcePort {
    Number(u16),
    Range { min: u16, max: u16 },
}

impl SourcePort {
    /// Pick a source port based on the given seed.
    ///
    /// If the source port is a range, then the port is chosen uniformly from
    /// the range. Otherwise, the port is the given number.
    pub fn pick(&self, seed: u32) -> u16 {
        match self {
            SourcePort::Number(port) => *port,
            SourcePort::Range { min, max } => {
                let range = max - min;
                (seed % range as u32) as u16 + min
            }
        }
    }

    pub fn contains(&self, port: u16) -> bool {
        match self {
            SourcePort::Number(p) => *p == port,
            SourcePort::Range { min, max } => *min <= port && port <= *max,
        }
    }
}

impl Default for SourcePort {
    fn default() -> Self {
        SourcePort::Number(61000)
    }
}
