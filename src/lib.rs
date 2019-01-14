#![allow(unused_imports)]

use failure::{format_err, Error};
use log::{debug, error, info, trace};

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::transport::{
    self, icmp_packet_iter, transport_channel, IcmpTransportChannelIterator, TransportReceiver,
    TransportSender,
};

mod utils;
pub mod client;
pub mod server;
pub mod tunnel;

pub type TransportPair = (Box<TransportSender>, Box<TransportReceiver>);
pub type DatalinkPair = (Box<DataLinkSender>, Box<DataLinkReceiver>);