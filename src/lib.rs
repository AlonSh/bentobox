#[macro_use]
extern crate log;
#[macro_use]
extern crate failure;

extern crate pnet;
extern crate tun;

use failure::Error;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, DataLinkReceiver, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::Packet;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use tun::platform::Device;

pub enum OperationMode {
    Client(Ipv4Addr),
    Server,
}

pub struct IcmpTunnel {
    // The TUN device used to send packets.
    dev: Device,
    operation_mode: OperationMode,
}

impl IcmpTunnel {
    pub fn client<S: AsRef<str>>(
        tunnel_iface_name: S,
        server_address: &Ipv4Addr,
    ) -> Result<IcmpTunnel, Error> {
        let mut config = tun::Configuration::default();
        config
            .name(tunnel_iface_name.as_ref())
            .address((10, 0, 1, 1))
            // We only support using the device on /24 netmask
            .netmask((255, 255, 255, 0))
            .mtu(1472)
            .up();

        let mut dev = tun::create(&config).ok().ok_or(format_err!(
            "Failed to create tunnel device {:?}",
            tunnel_iface_name.as_ref()
        ))?;

        debug!(
            "Tunnel {:?} was set up with config {:?}",
            tunnel_iface_name.as_ref(),
            &config
        );

        Ok(IcmpTunnel {
            dev,
            operation_mode: OperationMode::Client(server_address.clone()),
        })
    }

    pub fn server<S: AsRef<str>>(tunnel_iface_name: S) -> Result<IcmpTunnel, Error> {
        let mut config = tun::Configuration::default();
        config
            .name(tunnel_iface_name.as_ref())
            .address((10, 0, 1, 1))
            // We only support using the device on /24 netmask
            .netmask((255, 255, 255, 0))
            .mtu(1472)
            .up();

        let mut dev = tun::create(&config).ok().ok_or(format_err!(
            "Failed to create tunnel device {:?}",
            tunnel_iface_name.as_ref()
        ))?;

        debug!(
            "Tunnel {:?} was set up with config {:?}",
            tunnel_iface_name.as_ref(),
            &config
        );

        Ok(IcmpTunnel {
            dev,
            operation_mode: OperationMode::Server,
        })
    }

    pub fn listen_on<S: AsRef<str>>(&mut self, iface_name: S) -> Result<(), Error> {
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .filter(|iface| iface.name == iface_name.as_ref())
            .next()
            .ok_or(format_err!("eth0 not found"))?;

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
                    self.handle_ethernet_frame(&interface, &packet);
                }
                Err(e) => {
                    // If an error occurs, we can handle it here
                    panic!("An error occurred while reading: {}", e);
                }
            }
        }
        // The code will never reach here.
        Ok(())
    }

    fn handle_icmp_packet(
        &mut self,
        interface_name: &str,
        source: IpAddr,
        destination: IpAddr,
        packet: &[u8],
    ) {
        let icmp_packet = IcmpPacket::new(packet);
        if let Some(icmp_packet) = icmp_packet {
            match icmp_packet.get_icmp_type() {
                IcmpTypes::EchoReply => {
                    let echo_reply_packet =
                        echo_reply::EchoReplyPacket::new(icmp_packet.payload()).unwrap();
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
                    let echo_request_packet =
                        echo_request::EchoRequestPacket::new(icmp_packet.payload()).unwrap();
                    println!(
                        "[{}]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
                        interface_name,
                        source,
                        destination,
                        echo_request_packet.get_sequence_number(),
                        echo_request_packet.get_identifier()
                    );

                    let data = &icmp_packet.payload()[4..];
                    let underlying = Ipv4Packet::new(data).expect("Malformed payload");

                    println!("{:?}", underlying);
                    self.dev
                        .write(underlying.packet())
                        .expect("Failed to write");
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

    fn handle_transport_protocol(
        &mut self,
        interface_name: &str,
        source: IpAddr,
        destination: IpAddr,
        protocol: IpNextHeaderProtocol,
        packet: &[u8],
    ) {
        // We only need to handle ICMP packets.
        match protocol {
            IpNextHeaderProtocols::Icmp => {
                self.handle_icmp_packet(interface_name, source, destination, packet)
            }
            _ => debug!(
                "[{iface}]: {kind} packet: {src} > {dst}; protocol: {proto:?} length: {len}",
                iface = interface_name,
                kind = match source {
                    IpAddr::V4(..) => "IPv4",
                    _ => "IPv6",
                },
                src = source,
                dst = destination,
                proto = protocol,
                len = packet.len()
            ),
        }
    }

    fn handle_ipv4_packet(&mut self, interface_name: &str, ethernet_frame: &EthernetPacket) {
        let ipv4_packet = Ipv4Packet::new(ethernet_frame.payload());

        if let Some(header) = ipv4_packet {
            self.handle_transport_protocol(
                interface_name,
                IpAddr::V4(header.get_source()),
                IpAddr::V4(header.get_destination()),
                header.get_next_level_protocol(),
                header.payload(),
            );
        } else {
            error!("[{}]: Malformed IPv4 Packet", interface_name);
        }
    }

    fn handle_ethernet_frame(&mut self, interface: &NetworkInterface, ethernet: &EthernetPacket) {
        let interface_name = &interface.name[..];
        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => self.handle_ipv4_packet(interface_name, ethernet),
            _ => debug!(
                "Unknown packet: {} > {}; ethertype: {:?} length: {}",
                ethernet.get_source(),
                ethernet.get_destination(),
                ethernet.get_ethertype(),
                ethernet.packet().len()
            ),
        }
    }
}

fn main() {
    unimplemented!();
}
