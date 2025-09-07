use std::{
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
    time::Duration,
};

use pnet::{
    datalink::{self, Channel, DataLinkReceiver, NetworkInterface},
    packet::{
        FromPacket, Packet,
        ethernet::EthernetPacket,
        ip::IpNextHeaderProtocols::{self},
        ipv4::{Ipv4, Ipv4Packet},
        tcp::{Tcp, TcpFlags, TcpOption, TcpPacket},
    },
    util::MacAddr,
};
use tracing::{trace, warn};

use super::{
    raw_sockets::RawSocket,
    tcp_template::{self, TemplatePacket},
};
use crate::{config::Config, net::tcp_template::TemplatePacketRepr, scanner::SourcePort};

pub const ETH_HEADER_LEN: usize = 14;

fn get_interface() -> NetworkInterface {
    let interface_name = default_net::get_default_interface().unwrap().name;
    println!("interface name: {interface_name}");

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    interfaces
        .into_iter()
        .find(|i| i.name == interface_name)
        .unwrap()
}

#[derive(Debug, Clone)]
pub struct TcpFingerprint {}
// TODO: make the fingerprint easily customizable
#[allow(clippy::derivable_impls)]
impl Default for TcpFingerprint {
    fn default() -> Self {
        Self {}
    }
}

#[derive(Debug, Clone)]
pub struct Fingerprint {
    /// Link type
    pub mss: u16,
    pub tcp: TcpFingerprint,
}

impl Default for Fingerprint {
    fn default() -> Self {
        let mss = 1360;

        Self {
            mss,
            tcp: Default::default(),
        }
    }
}

pub struct StatelessTcp {
    pub read: StatelessTcpReadHalf,
    pub write: StatelessTcpWriteHalf,
}

#[derive(Clone)]
pub struct StatelessTcpWriteHalf {
    source_ip: Ipv4Addr,
    source_port: SourcePort,

    gateway_mac: Option<MacAddr>,
    interface_mac: Option<MacAddr>,

    mtu: usize,

    #[cfg(not(feature = "benchmark"))]
    socket: RawSocket,

    pub fingerprint: Fingerprint,

    template_syn_packet: TemplatePacket,

    pub simulate_tx_loss: f32,
}

pub struct StatelessTcpReadHalf {
    interface_mac: Option<MacAddr>,
    source_port: SourcePort,

    // tx: Box<dyn DataLinkSender>,
    #[cfg(not(feature = "benchmark"))]
    rx: Box<dyn DataLinkReceiver>,
}

impl StatelessTcp {
    /// Create a new stateless TCP instance.
    ///
    /// For the source port I usually do 61000 and then firewall it with
    /// `iptables -A INPUT -p tcp --dport 61000 -j DROP`
    pub fn new(config: &Config) -> Self {
        let interface = get_interface();
        println!("interface: {:?}", interface);

        println!("{:?}", default_net::get_default_interface());
        let gateway_mac = if let Ok(default_gateway) = default_net::get_default_gateway() {
            Some(MacAddr::from(default_gateway.mac_addr.octets()))
        } else {
            None
        };

        // Create a channel to receive on
        #[cfg(not(feature = "benchmark"))]
        let (_tx, rx) = match datalink::channel(
            &interface,
            datalink::Config {
                read_timeout: Some(Duration::ZERO),
                // read_timeout: Some(Duration::from_secs(1)),
                ..Default::default()
            },
            // Config::default(),
        ) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("unhandled channel type"),
            Err(e) => panic!("unable to create channel: {}", e),
        };

        let interface_ipv4 = match interface.ips.iter().find(|ip| ip.is_ipv4()).unwrap().ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => panic!("ipv6 not supported"),
        };

        #[cfg(not(feature = "benchmark"))]
        let mut socket = RawSocket::new(&interface.name).unwrap();

        let interface_mac = interface.mac;

        #[cfg(feature = "benchmark")]
        let mut mtu = 1000; // idk
        #[cfg(not(feature = "benchmark"))]
        let mut mtu = socket.interface_mtu().unwrap();
        if interface_mac.is_some() {
            mtu += ETH_HEADER_LEN;
        }

        let fingerprint = Fingerprint::default();

        let write_half = StatelessTcpWriteHalf {
            source_ip: interface_ipv4,
            source_port: config.source_port,

            gateway_mac,
            interface_mac,
            mtu,

            #[cfg(not(feature = "benchmark"))]
            socket,

            template_syn_packet: TemplatePacket::new(TemplatePacketRepr {
                flags: TcpFlags::SYN,
                window: 32768,
                urgent_ptr: 0,
                options: vec![
                    TcpOption::mss(fingerprint.mss),
                    TcpOption::nop(),
                    TcpOption::nop(),
                    TcpOption::sack_perm(),
                ],
                gateway_mac,
                interface_mac,
                source_addr: interface_ipv4,
            }),

            fingerprint,
            simulate_tx_loss: config.debug.simulate_tx_loss,
        };

        StatelessTcp {
            read: StatelessTcpReadHalf {
                source_port: config.source_port,
                interface_mac,
                #[cfg(not(feature = "benchmark"))]
                rx,
            },
            write: write_half,
        }
    }
}

impl StatelessTcpWriteHalf {
    pub fn mtu(&self) -> u16 {
        self.mtu as u16
    }
    pub fn has_ethernet_header(&self) -> bool {
        self.gateway_mac.is_some() && self.interface_mac.is_some()
    }

    pub fn send_syn(&mut self, addr: SocketAddrV4, sequence: u32) {
        let packet = self.template_syn_packet.build(tcp_template::PacketRepr {
            dest_addr: *addr.ip(),
            dest_port: addr.port(),
            sequence,
            acknowledgement: 0,
            payload: &[],
            source_port: self.source_port.pick(sequence),
        });

        #[cfg(not(feature = "benchmark"))]
        self.socket.send_blocking(packet);
    }

    pub fn send_ack(
        &mut self,
        addr: SocketAddrV4,
        source_port: u16,
        sequence: u32,
        acknowledgement: u32,
    ) {
        self.send_tcp(PacketRepr {
            dest_addr: *addr.ip(),
            dest_port: addr.port(),
            sequence,
            acknowledgement,
            flags: TcpFlags::ACK,
            window: 32768,
            urgent_ptr: 0,
            options: &[TcpOption::nop(), TcpOption::nop(), TcpOption::sack_perm()],
            payload: &[],
            source_port,
        });
    }

    pub fn send_rst(
        &mut self,
        addr: SocketAddrV4,
        source_port: u16,
        sequence: u32,
        acknowledgement: u32,
    ) {
        self.send_tcp(PacketRepr {
            dest_addr: *addr.ip(),
            dest_port: addr.port(),
            source_port,
            sequence,
            acknowledgement,
            flags: TcpFlags::RST | TcpFlags::ACK,
            window: 32768,
            urgent_ptr: 0,
            options: &[TcpOption::nop(), TcpOption::nop(), TcpOption::sack_perm()],
            payload: &[],
        });
    }

    pub fn send_fin(
        &mut self,
        addr: SocketAddrV4,
        source_port: u16,
        sequence: u32,
        acknowledgement: u32,
    ) {
        self.send_tcp(PacketRepr {
            dest_addr: *addr.ip(),
            dest_port: addr.port(),
            source_port,
            sequence,
            acknowledgement,
            flags: TcpFlags::FIN | TcpFlags::ACK,
            window: 32768,
            urgent_ptr: 0,
            options: &[TcpOption::nop(), TcpOption::nop(), TcpOption::sack_perm()],
            payload: &[],
        });
    }

    pub fn send_data(
        &mut self,
        addr: SocketAddrV4,
        source_port: u16,
        sequence: u32,
        acknowledgement: u32,
        payload: &[u8],
    ) {
        self.send_tcp(PacketRepr {
            dest_addr: *addr.ip(),
            dest_port: addr.port(),
            source_port,
            sequence,
            acknowledgement,
            flags: TcpFlags::PSH | TcpFlags::ACK,
            window: 32768,
            urgent_ptr: 0,
            options: &[TcpOption::nop(), TcpOption::nop(), TcpOption::sack_perm()],
            payload,
        });
    }

    pub fn send_tcp(&mut self, repr: PacketRepr) {
        let source_addr = SocketAddrV4::new(self.source_ip, repr.source_port);

        if self.simulate_tx_loss > 0.0 && rand::random::<f32>() < self.simulate_tx_loss {
            warn!(
                "simulated tx loss, not sending packet to {}:{}",
                repr.dest_addr, repr.dest_port
            );
            return;
        }
        trace!(
            "sending packet to {}:{} with flags: {:?}",
            repr.dest_addr, repr.dest_port, repr.flags
        );

        let packet = build_tcp_packet(repr, self.gateway_mac, self.interface_mac, source_addr);
        #[cfg(not(feature = "benchmark"))]
        self.socket.send_blocking(&packet);
    }
}

fn build_tcp_packet(
    repr: PacketRepr,
    gateway_mac: Option<MacAddr>,
    interface_mac: Option<MacAddr>,
    source_addr: SocketAddrV4,
) -> Vec<u8> {
    let mut template = TemplatePacket::new(TemplatePacketRepr {
        flags: repr.flags,
        window: repr.window,
        urgent_ptr: repr.urgent_ptr,
        options: repr.options.to_vec(),
        gateway_mac,
        interface_mac,
        source_addr: *source_addr.ip(),
    });
    template
        .build(tcp_template::PacketRepr {
            dest_addr: repr.dest_addr,
            dest_port: repr.dest_port,
            source_port: repr.source_port,
            sequence: repr.sequence,
            acknowledgement: repr.acknowledgement,
            payload: repr.payload,
        })
        .to_vec()
}

impl StatelessTcpReadHalf {
    pub fn recv(&mut self) -> Option<(Ipv4, Tcp)> {
        #[cfg(not(feature = "benchmark"))]
        loop {
            match self.rx.next() {
                Ok(packet) => {
                    let payload_for_ipv4 = if self.interface_mac.is_some() {
                        let ethernet = EthernetPacket::new(packet).unwrap();
                        ethernet.payload().to_vec()
                    } else {
                        // no interface mac = no ethernet header
                        packet.to_vec()
                    };

                    if let Some(ipv4) = Ipv4Packet::new(&payload_for_ipv4)
                        && let Some(tcp) = process_ipv4(&ipv4)
                        && self.source_port.contains(tcp.destination)
                    {
                        return Some((ipv4.from_packet(), tcp));
                    }
                }
                Err(_) => return None,
            }
        }
        #[cfg(feature = "benchmark")]
        None
    }
}

#[derive(Debug)]
pub struct PacketRepr<'a> {
    pub dest_addr: Ipv4Addr,
    pub dest_port: u16,

    pub source_port: u16,

    pub sequence: u32,
    pub acknowledgement: u32,
    pub flags: u8,
    pub window: u16,
    pub urgent_ptr: u16,
    pub options: &'a [TcpOption],
    pub payload: &'a [u8],
}

fn process_ipv4(ipv4: &Ipv4Packet) -> Option<Tcp> {
    match ipv4.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                std::io::stdout().flush().unwrap();
                Some(tcp.from_packet())
            } else {
                None
            }
        }
        IpNextHeaderProtocols::Ipv4 => {
            if let Some(ipv4) = Ipv4Packet::new(ipv4.payload()) {
                process_ipv4(&ipv4)
            } else {
                None
            }
        }
        IpNextHeaderProtocols::IpComp => {
            warn!("Recieved an IpComp packet, but it's not supported.");
            None
        }
        _ => None,
    }
}
