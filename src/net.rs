use std::collections::HashSet;
use std::net::IpAddr;

use anyhow::{bail, Result};
use pnet::datalink::NetworkInterface;
use pnet::ipnetwork::IpNetwork;

use crate::cli::Cli;
use crate::text;

pub fn select_interfaces(
    interfaces: &[NetworkInterface],
    cli: &Cli,
) -> Result<Vec<NetworkInterface>> {
    let mut selected = if cli.interfaces.is_empty() {
        let mut selected = interfaces
            .iter()
            .filter(|iface| {
                iface.is_up()
                    && !iface.is_loopback()
                    && (has_ipv4(iface) || (cli.ipv6 && has_global_ipv6(iface)))
            })
            .cloned()
            .collect::<Vec<_>>();

        // Pure IPv6 hosts may only have link-local addresses on the interface.
        if selected.is_empty() && cli.ipv6 {
            selected = interfaces
                .iter()
                .filter(|iface| iface.is_up() && !iface.is_loopback() && has_ipv6(iface))
                .cloned()
                .collect();
        }
        selected
    } else {
        let mut selected = Vec::new();
        for requested in &cli.interfaces {
            let Some(iface) = interfaces.iter().find(|iface| iface.name == *requested) else {
                bail!("unknown interface {requested:?} (use --list to see available interfaces)");
            };
            if !selected
                .iter()
                .any(|seen: &NetworkInterface| seen.name == iface.name)
            {
                selected.push(iface.clone());
            }
        }
        selected
    };

    if cli.loopback {
        for iface in interfaces {
            if iface.is_up()
                && iface.is_loopback()
                && !selected.iter().any(|seen| seen.name == iface.name)
            {
                selected.push(iface.clone());
            }
        }
    }

    if selected.is_empty() {
        bail!("no suitable interfaces found (use --list and --interface)");
    }

    Ok(selected)
}

pub fn has_ipv4(iface: &NetworkInterface) -> bool {
    iface.ips.iter().any(|ip| matches!(ip, IpNetwork::V4(_)))
}

pub fn has_ipv6(iface: &NetworkInterface) -> bool {
    iface.ips.iter().any(|ip| matches!(ip, IpNetwork::V6(_)))
}

fn has_global_ipv6(iface: &NetworkInterface) -> bool {
    iface.ips.iter().any(|ip| {
        matches!(
            ip,
            IpNetwork::V6(network) if !network.ip().is_unicast_link_local()
        )
    })
}

pub fn local_ips(interfaces: &[NetworkInterface]) -> HashSet<IpAddr> {
    interfaces
        .iter()
        .flat_map(|iface| iface.ips.iter())
        .map(|ip| match ip {
            IpNetwork::V4(network) => IpAddr::V4(network.ip()),
            IpNetwork::V6(network) => IpAddr::V6(network.ip()),
        })
        .collect()
}

pub fn list_interfaces(interfaces: &[NetworkInterface]) {
    if interfaces.is_empty() {
        println!("no interfaces found");
        return;
    }

    let width = interfaces
        .iter()
        .map(|iface| text::sanitize(&iface.name).len())
        .max()
        .unwrap_or(0)
        .max(9);

    for iface in interfaces {
        let name = text::sanitize(&iface.name);
        let state = if iface.is_up() { "up" } else { "down" };
        let kind = if iface.is_loopback() {
            "loopback"
        } else if iface.is_point_to_point() {
            "point-to-point"
        } else {
            "ethernet"
        };

        println!(
            "{:<width$}  {:<4}  {:<14}  {}",
            name,
            state,
            kind,
            iface
                .mac
                .map(|mac| mac.to_string())
                .unwrap_or_else(|| "-".to_string()),
            width = width
        );

        for ip in &iface.ips {
            println!("{:<width$}  {}", "", ip, width = width);
        }
    }
}

pub fn permission_hint(message: &str) -> &'static str {
    let lower = message.to_ascii_lowercase();
    if lower.contains("permission") || lower.contains("not permitted") {
        if cfg!(target_os = "macos") {
            "\n  hint: capture on macOS requires root (sudo emping ...)"
        } else {
            "\n  hint: run as root or grant the binary CAP_NET_RAW (sudo setcap cap_net_raw=eip <path-to-emping>)"
        }
    } else {
        ""
    }
}
