use failure::{format_err, Error};
use log::{debug, error, info, trace};

use crate::tunnel::{get_interface_by_name, setup_tun_device, setup_tunnel};
use std::net::IpAddr;
use std::net::Ipv4Addr;
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

const CLIENT_TUN_ADDR: &'static str = "10.0.2.1";

pub fn client_main(
    real_iface_name: &str,
    tunnel_iface_name: &str,
    server_addr: &Ipv4Addr,
) -> Result<(), Error> {
    let inet_iface = get_interface_by_name(&real_iface_name)?;
    let tun_iface = get_interface_by_name(&tunnel_iface_name)?;
    let tun_dev = setup_tun_device(
        &tunnel_iface_name,
        CLIENT_TUN_ADDR.parse().expect("This is a valid IPv4"),
    )?;
    let ((mut raw_sender, mut raw_receiver), (mut tun_sender, mut tun_receiver)) =
        setup_tunnel(&inet_iface, &tun_iface)?;

    let inet_iface_name = Arc::new(format!("{}", inet_iface));
    let tun_iface_name = Arc::new(format!("{}", tun_iface));

    let server_addr = IpAddr::V4(server_addr.clone());

    let o_inet_iface_name = inet_iface_name.clone();
    let o_tun_iface_name = tun_iface_name.clone();
    let outgoing = thread::spawn(move || {
        loop {
            // Outgoing packets in the tunnel need to be wrapped in ICMP
            match tun_receiver.next() {
                Ok(packet_data) => {
                    debug!(
                        "[{}] received packet of len {} from tunnel {}",
                        &o_tun_iface_name.clone(),
                        &o_inet_iface_name.clone(),
                        packet_data.len()
                    );

                    debug!(
                        "[{}] Sending ICMP packet to server - data len {}",
                        &o_inet_iface_name.clone(),
                        packet_data.len()
                    );
                    let mut outgoing_buffer = [0_u8; 4096];
                    let mut icmp_request =
                        MutableEchoRequestPacket::new(&mut outgoing_buffer).unwrap();
                    icmp_request.set_payload(packet_data);

                    raw_sender
                        .send_to(icmp_request, server_addr.clone())
                        .expect("Failed to write to tunnel device!");
                    trace!("packet send");
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
    let incoming = thread::spawn(move || {
        let mut incoming_icmp_packets = icmp_packet_iter(&mut raw_receiver);

        loop {
            match incoming_icmp_packets.next() {
                // The addr should always be from the server
                Ok((packet, addr)) => {
                    // Send to original packet into the tunnel
                    // We pass None as the destination since this a datalink channel
                    // (the data is already included in the packet).
                    debug!(
                        "[{}] received ICMP packet from {}",
                        &i_inet_iface_name.clone(),
                        addr
                    );
                    debug!(
                        "[{}] sending {} bytes to tunnel",
                        &i_tun_iface_name.clone(),
                        packet.payload().len()
                    );
                    tun_sender.send_to(packet.payload(), None);
                }
                Err(e) => {
                    // If an error occurs, we can handle it here
                    panic!("An error occurred while reading: {}", e);
                }
            }
        }
    });

    Ok(())
}
