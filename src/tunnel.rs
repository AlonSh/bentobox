use failure::{format_err, Error};
use log::{debug, error, info, trace};

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::transport::{
    self, icmp_packet_iter, transport_channel, IcmpTransportChannelIterator, TransportReceiver,
    TransportSender,
};

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::echo_reply::MutableEchoReplyPacket;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};

use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::Packet;
use pnet::transport::TransportChannelType::{Layer3, Layer4};
use pnet::transport::TransportProtocol::Ipv4;

use tun::platform::Device;

use crate::{DatalinkPair, TransportPair};
use std::net::Ipv4Addr;

pub fn get_interface_by_name(name: impl AsRef<str>) -> Result<NetworkInterface, Error> {
    Ok(datalink::interfaces()
        .into_iter()
        .filter(|iface| iface.name == name.as_ref())
        .next()
        .ok_or(format_err!("{} not found", name.as_ref()))?)
}

/// Instantiates a TUN0 device.
pub fn setup_tun_device(name: impl AsRef<str>, address: Ipv4Addr) -> Result<Device, Error> {
    let mut config = tun::Configuration::default();
    config
        .name(name.as_ref())
        .address(address)
        // We only support using the device on /24 netmask
        .netmask((255, 255, 255, 0))
        .mtu(1472)
        .up();

    let mut dev = tun::create(&config).map_err(|e| {
        format_err!(
            "Failed to create tunnel device {:?} - {:?}",
            name.as_ref(),
            e
        )
    })?;

    info!(
        "Tunnel {:?} was set up with config {:?}",
        name.as_ref(),
        &config
    );

    Ok(dev)
}

/// Creates a tunnel over two interfaces:
///     - `real_iface` will be used as the gateway to the internet, and will be handled at layer 4 (Transport)
///     - `tunnel_iface` will be where application logic happens, and transport will be manipulated at the datalink level.
pub fn setup_tunnel(
    real_iface: &NetworkInterface,
    tunnel_iface: &NetworkInterface,
) -> Result<(TransportPair, DatalinkPair), Error> {
    let icmp_proto = Layer4(Ipv4(IpNextHeaderProtocols::Icmp));

    // Create a new channel over our outgoing interface.
    let (mut raw_sender, mut raw_receiver) = match transport_channel(4096, icmp_proto) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            return Err(format_err!(
                "An error occurred when creating the transport channel over interface {:?}: {}",
                &real_iface,
                e
            ));
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
                ));
            }
        };

    Ok((
        (Box::new(raw_sender), Box::new(raw_receiver)),
        (tun_sender, tun_receiver),
    ))
}
