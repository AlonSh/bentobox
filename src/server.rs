use failure::{format_err, Error};
use log::{debug, error, info, log, log_enabled, trace, Level};

use crate::tunnel::{get_interface_by_name, setup_tun_device, setup_tunnel};
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::sync::RwLock;
use std::thread;

use crate::utils::hexdump;
use pnet::util::checksum;
use pnet::{
    packet::{
        ethernet::{EtherTypes, EthernetPacket},
        icmp::{
            echo_reply::{self, MutableEchoReplyPacket},
            echo_request::{self, MutableEchoRequestPacket},
            IcmpPacket, IcmpTypes,
        },
        ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
        ipv4::{Ipv4Packet, MutableIpv4Packet},
        Packet,
    },
    transport::{icmp_packet_iter, TransportChannelType::Layer3, TransportProtocol::Ipv4},
};
use rand::Rng;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

const SERVER_TUN_ADDR: &'static str = "10.0.1.1";

pub fn server_main(tunnel_iface_name: &str, real_iface_name: &str) -> Result<(), Error> {
    let mut tunnel = setup_tun_device(
        &tunnel_iface_name,
        SERVER_TUN_ADDR.parse().expect("This is a valid IPv4"),
    )?;

    let inet_iface = Arc::new(get_interface_by_name(&real_iface_name)?);
    let tun_iface = Arc::new(get_interface_by_name(&tunnel_iface_name)?);

    let ((mut raw_sender, mut raw_receiver), (mut tun_sender, mut tun_receiver)) =
        setup_tunnel(&inet_iface, &tun_iface)?;

    let inet_iface_name = Arc::new(inet_iface.name.clone());
    let tun_iface_name = Arc::new(tun_iface.name.clone());

    // We currently don't really support multiple clients, since we don't keep track of sessions.
    // We accept the first address that starts sending packets and reply to that address only.
    let mut client_addr = Arc::new(RwLock::new(None));

    let o_inet_iface_name = inet_iface_name.clone();
    let o_tun_iface_name = tun_iface_name.clone();
    let o_client_addr = client_addr.clone();

    info!("Starting to listen for packets.");

    let incoming = thread::spawn(move || {
        let mut incoming_icmp_packets = icmp_packet_iter(&mut raw_receiver);

        loop {
            match incoming_icmp_packets.next() {
                Ok((packet, client)) => {
                    // Send to original packet into the tunnel
                    // We pass None as the destination since this a datalink channel
                    // (the data is already included in the packet).
                    debug!(
                        "[SERVER_INCOMING] received ICMP packet at iface {} from {}",
                        &o_inet_iface_name, client
                    );
                    match client {
                        IpAddr::V4(addr) => {
                            let client_locked =
                                o_client_addr.read().expect("Lock poisoned").is_some();

                            if !client_locked {
                                let mut lock = o_client_addr.write().expect("Lock poisoned");
                                *lock = Some(addr);
                            } else {
                                let locked_addr = o_client_addr
                                    .read()
                                    .expect("Lock poisoned")
                                    .expect("Client is already locked");

                                if locked_addr != addr {
                                    debug!(
                                        "[SERVER_INCOMING] Ignoring ICMP packet from client {} - known client is {}",
                                        addr,
                                        locked_addr
                                    );
                                    continue;
                                }
                            }
                        }
                        IpAddr::V6(addr) => {
                            error!("[SERVER_INCOMING] Ipv6 clients are not supported!")
                        }
                    };

                    debug!(
                        "[SERVER_INCOMING] sending {} bytes to tunnel",
                        packet.payload().len()
                    );

                    if log_enabled!(Level::Trace) {
                        trace!("[CLIENT_OUTGOING] PACKET DATA:");
                        trace!("{}", hexdump::hexdump(packet.packet(), 0, 'C'));
                        trace!("[CLIENT_OUTGOING] PACKET PAYLOAD:");
                        trace!("{}", hexdump::hexdump(packet.payload(), 0, 'C'));
                    }
                    tunnel.write(&packet.payload()[4..]).expect("Failed to write to tunnel");
                }
                Err(e) => {
                    // If an error occurs, we can handle it here
                    error!("[SERVER_INCOMING] An error occurred while reading: {}", e);
                }
            }
        }
    });

    let i_inet_iface_name = inet_iface_name.clone();
    let i_tun_iface_name = tun_iface_name.clone();
    let i_client_addr = client_addr.clone();

    // Outgoing packets in the tunnel need to be wrapped in ICMP Replay
    let outgoing = thread::spawn(move || {
        let client_addr = loop {
            match *i_client_addr
                .read()
                .expect("[SERVER_OUTGOING] Lock poisoned")
            {
                Some(addr) => break addr,
                None => {
                    debug!("[SERVER_OUTGOING] Waiting for first client packet to arrive");
                    thread::sleep(Duration::from_secs(1));
                }
            }
        };

        let inet_iface = inet_iface.clone();
        let tun_iface = tun_iface.clone();

        loop {
            match tun_receiver.next() {
                Ok(packet_data) => {
                    debug!(
                        "[SERVER_OUTGOING] received packet of len {} from tunnel {}",
                        packet_data.len(),
                        &i_tun_iface_name,
                    );

                    let mut outgoing_buffer = vec![0; packet_data.len() + 64];

                    let mut icmp_reply = MutableEchoReplyPacket::new(&mut outgoing_buffer).unwrap();

                    icmp_reply.set_icmp_type(IcmpTypes::EchoReply);
                    let mut rng = rand::thread_rng();
                    icmp_reply.set_identifier(rng.gen::<u16>());
                    icmp_reply.set_sequence_number(1);
                    icmp_reply.set_icmp_code(echo_request::IcmpCodes::NoCode);
                    icmp_reply.set_payload(packet_data);
                    let checksum = checksum(icmp_reply.packet(), 1);
                    icmp_reply.set_checksum(checksum);
                    trace!("[SERVER_OUTGOING] Sending packet {:#?}", &icmp_reply);

                    debug!(
                        "[SERVER_OUTGOING] Sending ICMP packet to client {} over interface {} - data len {}",
                        &client_addr,
                        &i_inet_iface_name,
                        packet_data.len()
                    );

                    match raw_sender.send_to(icmp_reply, IpAddr::V4(client_addr)) {
                        Ok(bytes_written) => debug!(
                            "[SERVER_OUTGOING] Written {} bytes to {}",
                            bytes_written, &i_inet_iface_name
                        ),
                        Err(e) => error!(
                            "[SERVER_OUTGOING] Failed to write to {}!",
                            &i_inet_iface_name
                        ),
                    };
                }
                Err(e) => {
                    // If an error occurs, we can handle it here
                    error!(
                        "[SERVER_OUTGOING] An error occurred while reading from {}: {}",
                        &i_tun_iface_name, e
                    );
                }
            }
        }
    });

    incoming.join().unwrap();
    outgoing.join().unwrap();

    Ok(())
}
