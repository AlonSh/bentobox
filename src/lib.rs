#[macro_use]
extern crate log;
#[macro_use]
extern crate failure;

extern crate pnet;
extern crate tun;

use failure::Error;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, DataLinkReceiver, DataLinkSender, NetworkInterface};
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
    raw_sender: Box<DataLinkSender>,
    raw_receiver: Box<DataLinkReceiver>,
    tun_sender: Box<DataLinkSender>,
    tun_receiver: Box<DataLinkReceiver>,
}

impl IcmpTunnel {
    fn get_interface<T: AsRef<str>>(name: T) -> Result<NetworkInterface, Error> {
        Ok(datalink::interfaces()
            .into_iter()
            .filter(|iface| iface.name == name.as_ref())
            .next()
            .ok_or(format_err!("{} not found", name.as_ref()))?)
    }

    fn setup_tunnel_device<T: AsRef<str>>(name: T, address: Ipv4Addr) -> Result<Device, Error> {
        let mut config = tun::Configuration::default();
        config
            .name(name.as_ref())
            .address(address)
            // We only support using the device on /24 netmask
            .netmask((255, 255, 255, 0))
            .mtu(1472)
            .up();

        let mut dev = tun::create(&config).ok().ok_or(format_err!(
            "Failed to create tunnel device {:?}",
            name.as_ref()
        ))?;

        info!(
            "Tunnel {:?} was set up with config {:?}",
            name.as_ref(),
            &config
        );

        Ok(dev)
    }

    fn setup_tunnel(
        real_iface: &NetworkInterface,
        tunnel_iface: &NetworkInterface,
    ) -> Result<(
        (Box<DataLinkSender>, Box<DataLinkReceiver>),
        (Box<DataLinkSender>, Box<DataLinkReceiver>),
    ), Error> {
        // Create a new channel over our outgoing interface.
        let (mut raw_sender, mut raw_receiver) =
            match datalink::channel(real_iface, Default::default()) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => return Err(format_err!("Unhandled channel type")),
                Err(e) => {
                    return Err(format_err!(
                        "An error occurred when creating the datalink channel: {}",
                        e
                    ))
                }
            };

        let (mut tun_sender, mut tun_receiver) =
            match datalink::channel(tunnel_iface, Default::default()) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => return Err(format_err!("Unhandled channel type")),
                Err(e) => {
                    return Err(format_err!(
                        "An error occurred when creating the datalink channel: {}",
                        e
                    ))
                }
            };

        Ok(((raw_sender, raw_receiver), (tun_sender, tun_receiver)))
    }

    pub fn client<T: AsRef<str>, I: AsRef<str>>(
        real_iface_name: I,
        tunnel_iface_name: T,
        server_address: &Ipv4Addr,
    ) -> Result<IcmpTunnel, Error> {
        let tunnel =
            IcmpTunnel::setup_tunnel_device(&tunnel_iface_name, Ipv4Addr::new(10, 0, 2, 1))?;
        let raw_interface = IcmpTunnel::get_interface(&real_iface_name)?;
        let tunnel_interface = IcmpTunnel::get_interface(&tunnel_iface_name)?;

        let ((raw_sender, raw_receiver), (tun_sender, tun_receiver)) =
            IcmpTunnel::setup_tunnel(&raw_interface, &tunnel_interface)?;

        Ok(IcmpTunnel {
            dev: tunnel,
            operation_mode: OperationMode::Client(server_address.clone()),
            raw_sender,
            raw_receiver,
            tun_sender,
            tun_receiver,
        })
    }

    pub fn server<T: AsRef<str>, I: AsRef<str>>(
        real_iface_name: I,
        tunnel_iface_name: T,
    ) -> Result<IcmpTunnel, Error> {
        let tunnel =
            IcmpTunnel::setup_tunnel_device(&tunnel_iface_name, Ipv4Addr::new(10, 0, 1, 1))?;
        let raw_interface = IcmpTunnel::get_interface(&real_iface_name)?;
        let tunnel_interface = IcmpTunnel::get_interface(&tunnel_iface_name)?;

        let ((raw_sender, raw_receiver), (tun_sender, tun_receiver)) =
            IcmpTunnel::setup_tunnel(&raw_interface, &tunnel_interface)?;

        Ok(IcmpTunnel {
            dev: tunnel,
            operation_mode: OperationMode::Server,
            raw_sender,
            raw_receiver,
            tun_sender,
            tun_receiver,
        })
    }

    /// Starts the operation of the tunnel.
    /// If we are serving as a client, this will wrap outgoing traffic as ICMP.
    pub fn start<S: AsRef<str>>(&mut self, iface_name: S) -> Result<(), Error> {
        let raw_interface = IcmpTunnel::get_interface(iface_name)?;

        match self.operation_mode {
            OperationMode::Client(server_addr) => {
                loop {
                    // When we are running as a client, our "raw_receiver" channel will be the outgoing direction.
                    // We only look for incoming ICMPReplay packets, and we decode them and write to the tunnel.
                    match self.raw_receiver.next() {
                        Ok(packet) => {
                            let packet = EthernetPacket::new(packet).unwrap();
                            self.handle_ethernet_frame(&raw_interface, &packet);
                        }
                        Err(e) => {
                            // If an error occurs, we can handle it here
                            panic!("An error occurred while reading: {}", e);
                        }
                    }
                }
            }
            _ => unimplemented!(),
        };
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
                    match self.operation_mode {
                        OperationMode::Client(_) => {
                            let echo_reply_packet =
                                echo_reply::EchoReplyPacket::new(icmp_packet.payload()).unwrap();
                            info!(
                                "[{}]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                                interface_name,
                                source,
                                destination,
                                echo_reply_packet.get_sequence_number(),
                                echo_reply_packet.get_identifier()
                            );
                            let data = &icmp_packet.payload()[4..];
                            let underlying = Ipv4Packet::new(data).expect("Malformed payload");

                            match self.dev.write(underlying.packet()) {
                                Ok(bytes_written) => info!("Succsefully sent {} bytes", bytes_written),
                                Err(e) => error!(
                                    "Failed to write to tunnel device! Error - {:?}, data {:#?}",
                                    e, underlying
                                ),
                            };
                        }

                        _ => {}
                    }
                }
                IcmpTypes::EchoRequest => {
                    match self.operation_mode {
                        OperationMode::Server => {
                            let echo_request_packet =
                                echo_request::EchoRequestPacket::new(icmp_packet.payload()).unwrap();
                            info!(
                                "[{}]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
                                interface_name,
                                source,
                                destination,
                                echo_request_packet.get_sequence_number(),
                                echo_request_packet.get_identifier()
                            );

                            //                    let data = &icmp_packet.payload()[4..];
                            let data = &icmp_packet.payload()[4..];
                            let underlying = Ipv4Packet::new(data).expect("Malformed payload");

                            match self.dev.write(underlying.packet()) {
                                Ok(bytes_written) => info!("Succsefully sent {} bytes", bytes_written),
                                Err(e) => error!(
                                    "Failed to write to tunnel device! Error - {:?}, data {:#?}",
                                    e, underlying
                                ),
                            };
                        }
                        _ => {}
                    }
                }
                _ => debug!(
                    "[{}]: ICMP packet {} -> {} (type={:?})",
                    interface_name,
                    source,
                    destination,
                    icmp_packet.get_icmp_type()
                ),
            }
        } else {
            error!("[{}]: Malformed ICMP Packet", interface_name);
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
