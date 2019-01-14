use failure::{format_err, Error};
use log::{debug, error, info, trace};

use bentobox::client::client_main;
use bentobox::server::server_main;
use clap::{App, Arg, SubCommand};
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::process::Command;

const IPV4_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";
const ICMP_ECHO_IGNORE_ALL: &str = "/proc/sys/net/ipv4/icmp_echo_ignore_all";

fn is_running_as_root() -> bool {
    unsafe { libc::setuid(0) == 0 }
}

fn setup_server_machine() -> Result<(), Error> {
    info!("Preventing the kernel to reply to any ICMP pings");

    match OpenOptions::new().write(true).open(ICMP_ECHO_IGNORE_ALL) {
        Ok(mut f) => f.write_all(String::from("1\n").as_bytes()),
        Err(e) => {
            return Err(format_err!(
                "Unable to set icmp_echo_ignore_all, error - {}",
                e
            ));
        }
    }?;

    info!("Enabling IP forwarding");
    match OpenOptions::new().write(true).open(IPV4_FORWARD) {
        Ok(mut f) => f.write_all(String::from("1\n").as_bytes()),
        Err(e) => return Err(format_err!("Unable to enable IP forwarding, error - {}", e)),
    }?;

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

fn setup_client_machine<S: AsRef<str>>(server: &Ipv4Addr, iface: S) -> Result<(), Error> {
    info!("Modifying IP routing tables");

    // Deletes the default route from the machine, to cleanup old configuration.
    Command::new("route").args(&["del", "default"]).spawn()?;

    // Adds a specific route to the internet facing device that points to the server.
    Command::new("route")
        .args(&[
            "add",
            "-host",
            &format!("{}", &server),
            "gw",
            "255.255.255.0",
            "dev",
            iface.as_ref(),
        ])
        .spawn()?;

    // Route everything else via the tunnel.
    Command::new("route")
        .args(&["add", "default", "gw", "10.0.1.2", "tun0"])
        .spawn()?;

    Ok(())
}

fn main() {
    env_logger::init();
    info!("bentobox started.");

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

    let iface = matches.value_of("iface").expect("A required argument");

    match matches.subcommand() {
        ("server", Some(matches)) => {
            info!("Running as server.");
            setup_server_machine().expect("Failed to set up server");

            info!("Setting up tunnel interface 'tun0'");
            info!("Starting to listen for packets.");
            server_main("tun0", iface).expect("Main loop failed");
        }
        ("client", Some(matches)) => {
            info!("Running as client.");
            let server_ip_str = matches.value_of("server-ip").expect("A required argument");
            let server_ip: IpAddr = server_ip_str
                .parse()
                .expect(&format!("{} is not a valid ip", &server_ip_str));

            let server_addr_ipv4 = match server_ip {
                IpAddr::V4(addr) => addr,
                IpAddr::V6(addr) => panic!("Ipv6 addresses are not supported"),
            };

            info!("Setting up tunnel interface 'tun0'");
            setup_client_machine(&server_addr_ipv4, iface).expect("Failed to set up client");
            client_main(iface, "tun0", &server_addr_ipv4).expect("Main loop failed");
        }
        _ => unimplemented!(),
    }
}
