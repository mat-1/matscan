use std::net::Ipv4Addr;

use pnet::{
    packet::{
        ethernet::{EtherTypes, Ethernet, MutableEthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::{self, MutableIpv4Packet},
        tcp::{MutableTcpPacket, TcpOption, TcpOptionPacket},
    },
    util::MacAddr,
};
use pnet_macros_support::packet::MutablePacket;
use pnet_macros_support::types::u3;

use crate::net::tcp::ETH_HEADER_LEN;

#[derive(Clone)]
pub struct TemplatePacket {
    packet: Vec<u8>,

    // source addr needs to be stored for the checksum
    source_addr: Ipv4Addr,

    eth_header_len: usize,
    // ipv4 header length is constant (20 bytes) so it doesn't need to be here
    // ipv4_header_len: usize,
    tcp_header_len: usize,
}

const IPV4_HEADER_LEN: usize = 20;

/// Parts of a packet that will be the same for every packet
pub struct TemplatePacketRepr {
    pub flags: u8,
    pub window: u16,
    pub urgent_ptr: u16,
    pub options: Vec<TcpOption>,
    pub ittl: u8,

    pub gateway_mac: Option<MacAddr>,
    pub interface_mac: Option<MacAddr>,
    pub source_addr: Ipv4Addr,
}

/// Parts of a packet that will be different for every packet
pub struct PacketRepr<'a> {
    pub dest_addr: Ipv4Addr,
    pub dest_port: u16,
    pub source_port: u16,
    pub sequence: u32,
    pub acknowledgement: u32,
    pub payload: &'a [u8],
}

impl TemplatePacket {
    pub fn new(repr: TemplatePacketRepr) -> Self {
        let tcp_options_length_as_bytes: usize =
            repr.options.iter().map(TcpOptionPacket::packet_size).sum();
        let tcp_options_length_as_words = (tcp_options_length_as_bytes + 3) / 4;

        // divide by 4 and round up
        let tcp_header_len: usize = 20 + tcp_options_length_as_words * 4;

        let eth_header_len = if repr.gateway_mac.is_some() {
            ETH_HEADER_LEN
        } else {
            0
        };

        let mut packet = vec![0u8; eth_header_len + IPV4_HEADER_LEN + tcp_header_len];

        // TCP
        let mut mutable_tcp_packet =
            MutableTcpPacket::new(&mut packet[eth_header_len + IPV4_HEADER_LEN..]).unwrap();
        // mutable_tcp_packet.set_source(repr.source_port);
        // mutable_tcp_packet.set_destination(repr.dest_port);
        // mutable_tcp_packet.set_sequence(repr.sequence);
        // mutable_tcp_packet.set_acknowledgement(repr.acknowledgement);
        mutable_tcp_packet.set_data_offset(5 + tcp_options_length_as_words as u8);
        mutable_tcp_packet.set_reserved(0);
        mutable_tcp_packet.set_flags(repr.flags);
        mutable_tcp_packet.set_window(repr.window);
        mutable_tcp_packet.set_urgent_ptr(repr.urgent_ptr);
        mutable_tcp_packet.set_options(&repr.options);
        // mutable_tcp_packet.payload_mut()[..data_len].copy_from_slice(repr.payload);
        // let checksum = ipv4_checksum(
        //     &mutable_tcp_packet.to_immutable(),
        //     &repr.source_addr,
        //     &repr.dest_addr,
        // );
        // mutable_tcp_packet.set_checksum(checksum);

        // IPv4
        assert_eq!(
            packet[..packet.len() - tcp_header_len],
            vec![0u8; eth_header_len + IPV4_HEADER_LEN]
        );
        let mut mutable_ipv4_packet: MutableIpv4Packet =
            MutableIpv4Packet::new(&mut packet[eth_header_len..]).unwrap();

        mutable_ipv4_packet.set_version(4); // ipv4 lol
        mutable_ipv4_packet.set_header_length(5); // linux always sets this to 5 - so do we
        mutable_ipv4_packet.set_dscp(0); // precedence and delay, don't care so 0
        mutable_ipv4_packet.set_ecn(0); // reserved
        mutable_ipv4_packet.set_identification(1); // https://github.com/torvalds/linux/blob/master/net/ipv4/ip_output.c#L165
        mutable_ipv4_packet.set_flags(0b010);
        mutable_ipv4_packet.set_fragment_offset(0); // fragmentation is disabled so 0
        mutable_ipv4_packet.set_ttl(repr.ittl);
        mutable_ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        mutable_ipv4_packet.set_source(repr.source_addr);
        // mutable_ipv4_packet.set_destination(ipv4_packet.destination);
        mutable_ipv4_packet.set_options(&[]);

        // ```
        // mutable_ipv4_packet.set_total_length((IPV4_HEADER_LEN + tcp_header_len) as u16);
        // mutable_ipv4_packet.set_checksum(ipv4::checksum(&mutable_ipv4_packet.to_immutable()));
        // ```

        if eth_header_len > 0 {
            // Ethernet
            let ethernet_packet = Ethernet {
                destination: repr.gateway_mac.unwrap(),
                source: repr.interface_mac.unwrap(),
                ethertype: EtherTypes::Ipv4,
                payload: vec![],
            };
            assert_eq!(
                packet[..packet.len() - tcp_header_len - IPV4_HEADER_LEN],
                vec![0u8; eth_header_len]
            );
            let mut mutable_ethernet_packet = MutableEthernetPacket::new(&mut packet).unwrap();
            mutable_ethernet_packet.set_destination(ethernet_packet.destination);
            mutable_ethernet_packet.set_source(ethernet_packet.source);
            mutable_ethernet_packet.set_ethertype(ethernet_packet.ethertype);
        }

        TemplatePacket {
            packet,

            source_addr: repr.source_addr,

            eth_header_len,
            tcp_header_len,
        }
    }

    /// Build the packet with the given options
    pub fn build(&mut self, repr: PacketRepr) -> &[u8] {
        self.packet.resize(
            self.eth_header_len + IPV4_HEADER_LEN + self.tcp_header_len + repr.payload.len(),
            0,
        );

        // TCP
        let mut mutable_tcp_packet =
            MutableTcpPacket::new(&mut self.packet[self.eth_header_len + IPV4_HEADER_LEN..])
                .unwrap();
        mutable_tcp_packet.set_source(repr.source_port);
        mutable_tcp_packet.set_destination(repr.dest_port);
        mutable_tcp_packet.set_sequence(repr.sequence);
        mutable_tcp_packet.set_acknowledgement(repr.acknowledgement);
        if !repr.payload.is_empty() {
            mutable_tcp_packet.payload_mut()[..repr.payload.len()].copy_from_slice(repr.payload);
        }
        let checksum = pnet::packet::tcp::ipv4_checksum(
            &mutable_tcp_packet.to_immutable(),
            &self.source_addr,
            &repr.dest_addr,
        );
        mutable_tcp_packet.set_checksum(checksum);

        // IPv4
        let mut mutable_ipv4_packet: MutableIpv4Packet =
            MutableIpv4Packet::new(&mut self.packet[self.eth_header_len..]).unwrap();
        mutable_ipv4_packet.set_destination(repr.dest_addr);
        mutable_ipv4_packet
            .set_total_length((IPV4_HEADER_LEN + self.tcp_header_len + repr.payload.len()) as u16);

        mutable_ipv4_packet.set_checksum(ipv4::checksum(&mutable_ipv4_packet.to_immutable()));

        // the ethernet fields are already good

        &self.packet
    }
}
