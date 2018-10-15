#[macro_use]
extern crate log;
#[macro_use]
extern crate failure;

extern crate pnet;
extern crate tun;

use failure::Error;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::transport::{
    self, icmp_packet_iter, transport_channel, IcmpTransportChannelIterator, TransportReceiver,
    TransportSender,
};

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::echo_reply::MutableEchoReplyPacket;

use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::Packet;
use pnet::transport::TransportChannelType::Layer3;
use pnet::transport::TransportProtocol::Ipv4;
use std::cell::RefCell;
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
    raw_sender: RefCell<Box<TransportSender>>,
    raw_receiver: RefCell<Box<TransportReceiver>>,
    tun_sender: RefCell<Box<DataLinkSender>>,
    tun_receiver: RefCell<Box<DataLinkReceiver>>,
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
    ) -> Result<
        (
            (Box<TransportSender>, Box<TransportReceiver>),
            (Box<DataLinkSender>, Box<DataLinkReceiver>),
        ),
        Error,
    > {
        let icmp_proto = Layer3(IpNextHeaderProtocols::Icmp);

        // Create a new channel over our outgoing interface.
        let (mut raw_sender, mut raw_receiver) = match transport_channel(4096, icmp_proto) {
            Ok((tx, rx)) => (tx, rx),
            Err(e) => {
                return Err(format_err!(
                    "An error occurred when creating the transport channel over interface {:?}: {}",
                    &real_iface,
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

        Ok((
            (Box::new(raw_sender), Box::new(raw_receiver)),
            (tun_sender, tun_receiver),
        ))
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
            raw_sender: RefCell::new(raw_sender),
            raw_receiver: RefCell::new(raw_receiver),
            tun_sender: RefCell::new(tun_sender),
            tun_receiver: RefCell::new(tun_receiver),
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
            raw_sender: RefCell::new(raw_sender),
            raw_receiver: RefCell::new(raw_receiver),
            tun_sender: RefCell::new(tun_sender),
            tun_receiver: RefCell::new(tun_receiver),
        })
    }

    /// Starts the operation of the tunnel.
    /// If we are serving as a client, this will wrap outgoing traffic as ICMP.
    pub fn start<S: AsRef<str>>(&self, iface_name: S) -> Result<(), Error> {
        let raw_interface = IcmpTunnel::get_interface(&iface_name.as_ref())?;
        // When we are running as a client, our "raw_receiver" channel will be the outgoing direction.
        // We only look for incoming ICMPReplay packets, and we decode them and write to the tunnel.
        let mut raw_reciever = self.raw_receiver.borrow_mut();
        let mut incoming_icmp_packets = icmp_packet_iter(&mut raw_reciever);

        match self.operation_mode {
            OperationMode::Client(server_addr) => {
                loop {
                    match incoming_icmp_packets.next() {
                        // The addr should always be from the server
                        Ok((packet, addr)) => {
                            // Send to original packet into the tunnel
                            // We pass None as the destination since this a datalink channel
                            // (the data is already included in the packet).
                            debug!(
                                "[{}] recieved ICMP packet from {}",
                                &iface_name.as_ref(),
                                addr
                            );
                            debug!("sending {} bytes to tunnel", packet.payload().len());
                            self.tun_sender.borrow_mut().send_to(packet.payload(), None);
                        }
                        Err(e) => {
                            // If an error occurs, we can handle it here
                            panic!("An error occurred while reading: {}", e);
                        }
                    }
                    // Outgoing packets in the tunnel need to be wrapped in ICMP
                    match self.tun_receiver.borrow_mut().next() {
                        Ok(packet_data) => {
                            debug!(
                                "[{}] recieved packet of len from tunnel {}",
                                "tun0",
                                packet_data.len()
                            );
                            debug!(
                                "[{}] Sending ICMP packet to server - data len {}",
                                &iface_name.as_ref(),
                                packet_data.len()
                            );
                            let mut outgoing_buffer = [0_u8; 4096];
                            let mut icmp_request = MutableEchoRequestPacket::new(&mut outgoing_buffer).unwrap();
                            icmp_request.set_payload(packet_data);

                            self.raw_sender
                                .borrow_mut()
                                .send_to(icmp_request, IpAddr::V4(server_addr));
                        }
                        Err(e) => {
                            // If an error occurs, we can handle it here
                            panic!("An error occurred while reading: {}", e);
                        }
                    }
                }
            }
            OperationMode::Server => {
                loop {
                    // We currently don't really support multiple clients, since we don't keep track of sessions.
                    // We accept the first address that starts sending packets and reply to that address only.
                    let mut client_addr: Ipv4Addr = "0.0.0.0".parse().unwrap();

                    match incoming_icmp_packets.next() {
                        Ok((packet, client)) => {
                            // Send to original packet into the tunnel
                            // We pass None as the destination since this a datalink channel
                            // (the data is already included in the packet).
                            debug!(
                                "[{}] recieved ICMP packet from {}",
                                &iface_name.as_ref(),
                                client
                            );
                            match client {
                                IpAddr::V4(addr) => client_addr = addr,
                                IpAddr::V6(addr) => panic!("Ipv6 clients are not supported!")
                            };

                            debug!("sending {} bytes to tunnel", packet.payload().len());
                            self.tun_sender.borrow_mut().send_to(packet.payload(), None);
                        }
                        Err(e) => {
                            // If an error occurs, we can handle it here
                            panic!("An error occurred while reading: {}", e);
                        }
                    }
                    // Outgoing packets in the tunnel need to be wrapped in ICMP Replay
                    match self.tun_receiver.borrow_mut().next() {
                        Ok(packet_data) => {
                            debug!(
                                "[{}] recieved packet of len from tunnel {}",
                                "tun0",
                                packet_data.len()
                            );
                            // Craft reply packet
                            let mut outgoing_buffer = [0_u8; 4096];
                            let mut outgoing_packet = MutableEchoReplyPacket::new(&mut outgoing_buffer).unwrap();
                            outgoing_packet.set_payload(packet_data);

                            debug!(
                                "[{}] Sending ICMP packet to client {} - data len {}",
                                &iface_name.as_ref(),
                                &client_addr,
                                packet_data.len()
                            );
                            self.raw_sender
                                .borrow_mut()
                                .send_to(outgoing_packet, IpAddr::V4(client_addr));
                        }
                        Err(e) => {
                            // If an error occurs, we can handle it here
                            panic!("An error occurred while reading: {}", e);
                        }
                    }
                }
            }
        };
    }
}
