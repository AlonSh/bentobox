use failure::{format_err, Error};
use log::{debug, error, info, trace};

use crate::tunnel::{get_interface_by_name, setup_tun_device, setup_tunnel};
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::sync::RwLock;
use std::thread;

use pnet::{
    packet::{
        ethernet::{EtherTypes, EthernetPacket},
        icmp::{
            echo_reply::MutableEchoReplyPacket, echo_request::MutableEchoRequestPacket, IcmpPacket,
            IcmpTypes,
        },
        ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
        ipv4::{Ipv4Packet, MutableIpv4Packet},
        Packet,
    },
    transport::{icmp_packet_iter, TransportChannelType::Layer3, TransportProtocol::Ipv4},
};
use std::sync::Arc;
use std::time::Duration;

const SERVER_TUN_ADDR: &'static str = "10.0.1.1";

pub fn server_main(tunnel_iface_name: &str, real_iface_name: &str) -> Result<(), Error> {
    let tunnel = setup_tun_device(
        &tunnel_iface_name,
        SERVER_TUN_ADDR.parse().expect("This is a valid IPv4"),
    )?;
    let inet_iface = Arc::new(get_interface_by_name(&real_iface_name)?);
    let tun_iface = Arc::new(get_interface_by_name(&tunnel_iface_name)?);

    let ((mut raw_sender, mut raw_receiver), (mut tun_sender, mut tun_receiver)) =
        setup_tunnel(&inet_iface, &tun_iface)?;

    let inet_iface_name = Arc::new(format!("{}", inet_iface));
    let tun_iface_name = Arc::new(format!("{}", tun_iface));

    // We currently don't really support multiple clients, since we don't keep track of sessions.
    // We accept the first address that starts sending packets and reply to that address only.
    let mut client_addr = Arc::new(RwLock::new(None));

    let o_inet_iface_name = inet_iface_name.clone();
    let o_tun_iface_name = tun_iface_name.clone();
    let o_client_addr = client_addr.clone();
    let datalink_sr = thread::spawn(move || {
        let mut incoming_icmp_packets = icmp_packet_iter(&mut raw_receiver);

        loop {
            match incoming_icmp_packets.next() {
                Ok((packet, client)) => {
                    // Send to original packet into the tunnel
                    // We pass None as the destination since this a datalink channel
                    // (the data is already included in the packet).
                    debug!(
                        "[{}] recieved ICMP packet from {}",
                        &o_inet_iface_name.as_ref(),
                        client
                    );
                    match client {
                        IpAddr::V4(addr) => {
                            let client_locked =
                                o_client_addr.read().expect("Lock poisoned").is_some();

                            if !client_locked {
                                let mut lock = o_client_addr.write().expect("Lock poisoned");
                                *lock = Some(addr);
                            }
                        }
                        IpAddr::V6(addr) => panic!("Ipv6 clients are not supported!"),
                    };

                    debug!("sending {} bytes to tunnel", packet.payload().len());
                    tun_sender.send_to(packet.payload(), None);
                }
                Err(e) => {
                    // If an error occurs, we can handle it here
                    panic!("An error occurred while reading: {}", e);
                }
            }
        }
    });

    let i_inet_iface_name = inet_iface_name.clone();
    let i_tun_iface_name = tun_iface_name.clone();
    let i_client_addr = client_addr.clone();

    // Outgoing packets in the tunnel need to be wrapped in ICMP Replay
    let raw_sr = thread::spawn(move || {
        let client_addr = loop {
            match *i_client_addr.read().expect("RAW_SR: Lock poisoned") {
                Some(addr) => break addr,
                None => {
                    debug!("Waiting for first client packet to arrive");
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
                        "[{}] recieved packet of len from tunnel {}",
                        &i_tun_iface_name,
                        packet_data.len()
                    );
                    // Craft reply packet
                    let mut outgoing_buffer = [0_u8; 4096];
                    let mut outgoing_packet =
                        MutableEchoReplyPacket::new(&mut outgoing_buffer).unwrap();
                    outgoing_packet.set_payload(packet_data);

                    debug!(
                        "[{}] Sending ICMP packet to client {} - data len {}",
                        &i_inet_iface_name,
                        &client_addr,
                        packet_data.len()
                    );
                    raw_sender
                        .send_to(outgoing_packet, IpAddr::V4(client_addr))
                        .expect("Failed to write to tunnel device!");
                }
                Err(e) => {
                    // If an error occurs, we can handle it here
                    panic!("An error occurred while reading: {}", e);
                }
            }
        }
    });

    datalink_sr.join().unwrap();
    raw_sr.join().unwrap();

    Ok(())
}
