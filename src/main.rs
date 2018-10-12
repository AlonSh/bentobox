#[macro_use]
extern crate failure;
#[macro_use]
extern crate log;
extern crate env_logger;

extern crate bentobox;
extern crate clap;
extern crate libc;

use failure::Error;

use bentobox::IcmpTunnel;
use clap::{App, Arg, SubCommand};
use std::fs::File;
use std::io::Write;
use std::process::Command;

fn is_running_as_root() -> bool {
    unsafe { libc::setuid(0) == 0 }
}

fn setup_server_machine() -> Result<(), Error> {
    info!("Preventing the kernel to reply to any ICMP pings");
    let mut icmp_echo_ignore_all = File::open("/proc/sys/net/ipv4/icmp_echo_ignore_all")?;
    icmp_echo_ignore_all.write(b"1")?;

    info!("Enabling IP forwarding");
    let mut ip_forward = File::open("/proc/sys/net/ipv4/ip_forward")?;
    ip_forward.write(b"1")?;

    info!("Adding an iptables rule to masquerade for 10.0.0.0/8");
    Command::new("iptables")
        .args(&[
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            "10.0.0.0/8",
            "-j",
            "MASQUERADE",
        ])
        .spawn()?;

    Ok(())
}

fn main() {
    env_logger::init();
    let matches = {
        let client_subcommand = SubCommand::with_name("client").arg(
            Arg::with_name("server-ip")
                .takes_value(true)
                .required(true)
                .help("IP address of the relay server"),
        );

        let app = App::new("Bentobox")
            .version("2018-10")
            .arg(
                Arg::with_name("iface")
                    .takes_value(true)
                    .required(true)
                    .help("The interface to send packets on."),
            )
            .subcommand(SubCommand::with_name("server"))
            .subcommand(client_subcommand);

        app.get_matches()
    };

    if !is_running_as_root() {
        error!("bentobox needs to run as root.");
        ::std::process::exit(-1);
    }

    match matches.subcommand() {
        ("server", Some(matches)) => {
            info!("Running as server.");
            setup_server_machine().expect("Failed to set up server");

            let iface = matches.value_of("iface").expect("A required argument");
            info!("Setting up tunnel interface 'tun0'");
            let mut tunnel = IcmpTunnel::server("tun0").expect("Failed to create tunnel");

            info!("Starting to listen for packets.");
            // Run server.
            tunnel.listen_on(iface).expect("Something bad happened");
        },
        _ => unimplemented!()
    }
}
