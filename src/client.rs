use failure::{format_err, Error};
use log::{debug, error, info, log, log_enabled, trace, Level};

use crate::tunnel::{get_interface_by_name, setup_tun_device, setup_tunnel};
use crate::utils::hexdump;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::thread;

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
use std::sync::Arc;

const CLIENT_TUN_ADDR: &'static str = "10.0.1.2";
const ECHO_REPLY_HEADER_SIZE: usize = 64;

pub fn client_main(
    real_iface_name: &str,
    tunnel_iface_name: &str,
    server_addr: &Ipv4Addr,
) -> Result<(), Error> {
    let inet_iface = get_interface_by_name(&real_iface_name)?;
    let tun_iface = get_interface_by_name(&tunnel_iface_name)?;
    let ((mut raw_sender, mut raw_receiver), (mut tun_sender, mut tun_receiver)) =
        setup_tunnel(&inet_iface, &tun_iface)?;

    let inet_iface_name = Arc::new(inet_iface.name);
    let tun_iface_name = Arc::new(tun_iface.name);

    let server_addr = IpAddr::V4(server_addr.clone());

    let o_inet_iface_name = inet_iface_name.clone();
    let o_tun_iface_name = tun_iface_name.clone();

    let outgoing = thread::spawn(move || {
        info!(
            "[CLIENT_OUTGOING] thread started, {} -> {}",
            &o_tun_iface_name, &o_inet_iface_name
        );

        loop {
            // Outgoing packets in the tunnel need to be wrapped in ICMP
            match tun_receiver.next() {
                Ok(packet_data) => {
                    debug!(
                        "[CLIENT_OUTGOING] Read packet of len {} from tunnel {}",
                        packet_data.len(),
                        &o_tun_iface_name,
                    );

                    debug!(
                        "[CLIENT_OUTGOING] Sending ICMP packet to relay with data len {} over {}",
                        packet_data.len(),
                        &o_inet_iface_name.clone(),
                    );

                    trace!(
                        "[CLIENT_OUTGOING] Allocation buffer of size {}",
                        packet_data.len() + ECHO_REPLY_HEADER_SIZE
                    );
                    let mut outgoing_buffer = vec![0; packet_data.len() + ECHO_REPLY_HEADER_SIZE];

                    let mut icmp_request =
                        MutableEchoRequestPacket::new(&mut outgoing_buffer).unwrap();

                    icmp_request.set_icmp_type(IcmpTypes::EchoRequest);
                    let mut rng = rand::thread_rng();
                    icmp_request.set_identifier(rng.gen::<u16>());
                    icmp_request.set_sequence_number(1);
                    icmp_request.set_icmp_code(echo_request::IcmpCodes::NoCode);
                    icmp_request.set_payload(packet_data);
                    let checksum = checksum(icmp_request.packet(), 1);
                    icmp_request.set_checksum(checksum);
                    trace!(
                        "[CLIENT_OUTGOING] Sending packet to {}",
                        server_addr.clone(),
                    );

                    if log_enabled!(Level::Trace) {
                        trace!("[CLIENT_OUTGOING] PACKET DATA:");
                        trace!("{}", hexdump::hexdump(icmp_request.packet(), 0, 'C'));
                        trace!("[CLIENT_OUTGOING] PACKET PAYLOAD:");
                        trace!("{}", hexdump::hexdump(icmp_request.payload(), 0, 'C'));
                    }

                    match raw_sender.send_to(icmp_request, server_addr.clone()) {
                        Ok(bytes_written) => debug!(
                            "[CLIENT_OUTGOING] Written {} bytes to {}",
                            bytes_written, &o_inet_iface_name
                        ),
                        Err(e) => error!(
                            "[CLIENT_OUTGOING] An error occured while trying to send to {} - {}",
                            &o_inet_iface_name, e
                        ),
                    }
                }
                Err(e) => {
                    // If an error occurs, we can handle it here
                    error!("[CLIENT_OUTGOING] An error occurred while reading: {}", e);
                }
            }
        }
    });

    let i_inet_iface_name = inet_iface_name.clone();
    let i_tun_iface_name = tun_iface_name.clone();
    let incoming = thread::spawn(move || {
        let mut incoming_icmp_packets = icmp_packet_iter(&mut raw_receiver);

        info!(
            "[CLIENT_INCOMING] thread started, {} -> {}",
            &i_inet_iface_name, &i_tun_iface_name
        );

        loop {
            match incoming_icmp_packets.next() {
                // The addr should always be from the server
                Ok((packet, addr)) => {
                    if addr != server_addr {
                        debug!("Got an ICMP packet from {} (not server), ignoring.", addr);
                        continue;
                    }
                    // Send to original packet into the tunnel
                    // We pass None as the destination since this a datalink channel
                    // (the data is already included in the packet).
                    debug!(
                        "[CLIENT_INCOMING] Read ICMP packet at interface {} from server at {} - payload len {}",
                        &i_inet_iface_name,
                        addr,
                        packet.payload().len()
                    );
                    debug!(
                        "[CLIENT_INCOMING] sending {} bytes to tunnel {}",
                        packet.payload().len(),
                        &i_tun_iface_name,
                    );
                    match tun_sender.send_to(packet.payload(), None) {
                        Some(result) => match result {
                            Ok(_) => debug!(
                                "[CLIENT_INCOMING] packet sent to {}",
                                &i_tun_iface_name
                            ),
                            Err(e) => error!(
                                "[CLIENT_INCOMING] An error occured while trying to send to {} - {}",
                                &i_tun_iface_name, e
                            ),
                        },
                        None => error!("[CLIENT_INCOMING] no response")
                    }
                }
                Err(e) => {
                    error!("[CLIENT_INCOMING] An error occurred while reading: {}", e);
                }
            }
        }
    });

    incoming.join().unwrap();
    outgoing.join().unwrap();

    Ok(())
}
