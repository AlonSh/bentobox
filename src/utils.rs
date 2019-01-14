use pnet::datalink::{self, NetworkInterface};

use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;

use std::env;
use std::io::{self, Write};
use std::net::IpAddr;
use std::process;

pub mod hexdump {
    use std::fmt::Write;
    use std::cmp;
    /// Dumps bytes at data to the screen as hex.
    /// Display may be one of:
    /// b        One-byte octal display.
    ///          Display the input offset in hexadecimal, followed by sixteen space-separated, three column, zero-filled, bytes of input data, in octal, per line.
    ///
    /// c        One-byte character display. One-byte character display.
    ///          Display the input offset in hexadecimal, followed by sixteen space-separated, three column, space-filled, characters of input data per line.
    ///
    /// C        Canonical hex display.
    ///          Display the input offset in hexadecimal, followed by sixteen space-separated, two column, hexadecimal bytes, followed by the same sixteen bytes in %_p format enclosed in ``|'' characters.
    ///
    /// d        Two-byte decimal display.
    /// o        Two-byte octal display.
    /// x        Two-byte hexadecimal display.
    ///          Display the input offset in hexadecimal, followed by eight, space separated, four column, zero-filled, two-byte quantities of input data, in hexadecimal, per line.
    pub fn hexdump(data: &[u8], offset: usize, display: char) -> String {
        let mut address = 0;

        let number_of_bytes = match display {
            'b' => 1,
            'c' => 1,
            'C' => 1,
            'd' => 2,
            'o' => 2,
            _ => 2,
        };

        let mut s = String::new();

        while address <= data.len() {
            // Read next 16 bytes of until end of data
            let end = cmp::min(address + 16, data.len());

            s += &line(
                &data[address..end],
                address + offset,
                display,
                number_of_bytes,
            );
            address = address + 16;
        }

        s
    }

    fn line(line: &[u8], address: usize, display: char, bytes: usize) -> String {
        let mut line_as_string = String::new();
        // print address (ex - 000000d0)
        write!(line_as_string, "\n{:08x}:", address);

        let words = match (line.len() % bytes) == 0 {
            true => line.len() / bytes,
            false => (line.len() / bytes) + 1,
        };

        for b in 0..words {
            let word = match bytes {
                1 => line[b] as u16,
                _ => match line.len() == bytes * b + 1 {
                    true => u16::from_be(((line[bytes * b] as u16) << 8) + 0),
                    false => {
                        u16::from_be(((line[bytes * b] as u16) << 8) + (line[bytes * b + 1] as u16))
                    }
                },
            };
            match display {
                'b' => write!(line_as_string, " {:03o}", word),
                'c' => match ((word as u8) as char).is_control() {
                    true => write!(line_as_string, " "),
                    false => write!(line_as_string, " {:03}", (word as u8) as char),
                },
                'C' => write!(line_as_string, " {:02x}", word),
                'x' => write!(line_as_string, " {:04x}", word),
                'o' => write!(line_as_string, " {:06o} ", word),
                'd' => write!(line_as_string, "  {:05} ", word),
                _ => write!(line_as_string, " {:04x}", word),
            };
        }

        // print ASCII repr
        if display != 'c' {
            if (line.len() % 16) > 0 {
                // align
                let words_left = (16 - line.len()) / bytes;
                let word_size = match display {
                    'b' => 4,
                    'c' => 4,
                    'C' => 3,
                    'x' => 5,
                    'o' => 8,
                    'd' => 8,
                    _ => 5,
                };
                for _ in 0..word_size * words_left {
                    write!(line_as_string, " ");
                }
            }

            write!(line_as_string, "  ");
            for c in line {
                // replace all control chars with dots
                match (*c as char).is_control() {
                    true => write!(line_as_string, "."),
                    false => write!(line_as_string, "{}", (*c as char)),
                };
            }
        }
        line_as_string
    }

}

fn handle_udp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        println!(
            "[{}]: UDP Packet: {}:{} > {}:{}; length: {}",
            interface_name,
            source,
            udp.get_source(),
            destination,
            udp.get_destination(),
            udp.get_length()
        );
    } else {
        println!("[{}]: Malformed UDP Packet", interface_name);
    }
}

pub fn dump_icmp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                println!(
                    "[{}]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                    interface_name,
                    source,
                    destination,
                    echo_reply_packet.get_sequence_number(),
                    echo_reply_packet.get_identifier()
                );
            }
            IcmpTypes::EchoRequest => {
                let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                println!(
                    "[{}]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
                    interface_name,
                    source,
                    destination,
                    echo_request_packet.get_sequence_number(),
                    echo_request_packet.get_identifier()
                );
            }
            _ => println!(
                "[{}]: ICMP packet {} -> {} (type={:?})",
                interface_name,
                source,
                destination,
                icmp_packet.get_icmp_type()
            ),
        }
    } else {
        println!("[{}]: Malformed ICMP Packet", interface_name);
    }
}

fn handle_icmpv6_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let icmpv6_packet = Icmpv6Packet::new(packet);
    if let Some(icmpv6_packet) = icmpv6_packet {
        println!(
            "[{}]: ICMPv6 packet {} -> {} (type={:?})",
            interface_name,
            source,
            destination,
            icmpv6_packet.get_icmpv6_type()
        )
    } else {
        println!("[{}]: Malformed ICMPv6 Packet", interface_name);
    }
}

fn handle_tcp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        println!(
            "[{}]: TCP Packet: {}:{} > {}:{}; length: {}",
            interface_name,
            source,
            tcp.get_source(),
            destination,
            tcp.get_destination(),
            packet.len()
        );
    } else {
        println!("[{}]: Malformed TCP Packet", interface_name);
    }
}

fn handle_transport_protocol(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
) {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            handle_udp_packet(interface_name, source, destination, packet)
        }
        IpNextHeaderProtocols::Tcp => {
            handle_tcp_packet(interface_name, source, destination, packet)
        }
        IpNextHeaderProtocols::Icmp => {
            dump_icmp_packet(interface_name, source, destination, packet)
        }
        IpNextHeaderProtocols::Icmpv6 => {
            handle_icmpv6_packet(interface_name, source, destination, packet)
        }
        _ => println!(
            "[{}]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
            interface_name,
            match source {
                IpAddr::V4(..) => "IPv4",
                _ => "IPv6",
            },
            source,
            destination,
            protocol,
            packet.len()
        ),
    }
}

fn handle_ipv4_packet(interface_name: &str, ethernet: &EthernetPacket) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
        );
    } else {
        println!("[{}]: Malformed IPv4 Packet", interface_name);
    }
}

fn handle_ipv6_packet(interface_name: &str, ethernet: &EthernetPacket) {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V6(header.get_source()),
            IpAddr::V6(header.get_destination()),
            header.get_next_header(),
            header.payload(),
        );
    } else {
        println!("[{}]: Malformed IPv6 Packet", interface_name);
    }
}

fn handle_arp_packet(interface_name: &str, ethernet: &EthernetPacket) {
    let header = ArpPacket::new(ethernet.payload());
    if let Some(header) = header {
        println!(
            "[{}]: ARP packet: {}({}) > {}({}); operation: {:?}",
            interface_name,
            ethernet.get_source(),
            header.get_sender_proto_addr(),
            ethernet.get_destination(),
            header.get_target_proto_addr(),
            header.get_operation()
        );
    } else {
        println!("[{}]: Malformed ARP Packet", interface_name);
    }
}

pub fn dump_packet(interface_name: &str, ethernet: &EthernetPacket) {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(interface_name, ethernet),
        EtherTypes::Ipv6 => handle_ipv6_packet(interface_name, ethernet),
        EtherTypes::Arp => handle_arp_packet(interface_name, ethernet),
        _ => println!(
            "[{}]: Unknown packet: {} > {}; ethertype: {:?} length: {}",
            interface_name,
            ethernet.get_source(),
            ethernet.get_destination(),
            ethernet.get_ethertype(),
            ethernet.packet().len()
        ),
    }
}
