extern crate pnet;
extern crate tun;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface, DataLinkReceiver};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::Packet;
use std::io::Write;
use std::net::IpAddr;

fn main() {
    let mut config = tun::Configuration::default();
    config
        .name("tun0")
        .address((10, 0, 1, 1))
        .netmask((255, 255, 255, 0))
        .mtu(1472)
        .up();

    let mut dev = tun::create(&config).unwrap();

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|iface| iface.name == "eth0")
        .next()
        .expect("eth0 not found");

    // Create a new channel, dealing with layer 2 packets
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                let packet = EthernetPacket::new(packet).unwrap();
                match packet.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        let ipv4 = Ipv4Packet::new(packet.payload()).unwrap();
                        match ipv4.get_next_level_protocol() {
                            IpNextHeaderProtocols::Icmp => {
                                let icmp_packet = IcmpPacket::new(ipv4.payload());
                                if let Some(icmp_packet) = icmp_packet {
                                    match icmp_packet.get_icmp_type() {
                                        IcmpTypes::EchoReply => {
                                            let echo_reply_packet =
                                                echo_reply::EchoReplyPacket::new(
                                                    icmp_packet.payload(),
                                                ).unwrap();
                                            println!(
                                                "ICMP echo reply (seq={:?}, id={:?})",
                                                echo_reply_packet.get_sequence_number(),
                                                echo_reply_packet.get_identifier()
                                            );
                                        }
                                        IcmpTypes::EchoRequest => {
                                            let echo_request_packet =
                                                echo_request::EchoRequestPacket::new(
                                                    icmp_packet.payload(),
                                                ).unwrap();
                                            println!(
                                                "ICMP echo request (seq={:?}, id={:?})",
                                                echo_request_packet.get_sequence_number(),
                                                echo_request_packet.get_identifier()
                                            );

                                            let data = &icmp_packet.payload()[4..];
                                            let underlying =
                                                Ipv4Packet::new(data).expect("Malformed payload");

                                            println!("{:?}", underlying);
                                            dev.write(underlying.packet())
                                                .expect("Failed to write");
                                        }
                                        _ => println!(
                                            "ICMP packet (type={:?})",
                                            icmp_packet.get_icmp_type()
                                        ),
                                    }
                                } else {
                                    println!("Malformed ICMP Packet");
                                }
                            }
                            _ => {}
                        }
                    }
                    _ => println!(
                        "Unknown packet: {} > {}; ethertype: {:?} length: {}",
                        packet.get_source(),
                        packet.get_destination(),
                        packet.get_ethertype(),
                        packet.packet().len()
                    ),
                }
            }
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
    println!("{:?}", config);
}
