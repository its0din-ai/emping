use std::io::ErrorKind;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use pnet::datalink::{self, Channel, Config, DataLinkReceiver, NetworkInterface};

/// Set to false by the SIGINT/SIGTERM handler.
static RUNNING: AtomicBool = AtomicBool::new(true);
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

pub enum Message {
    Frame {
        interface: String,
        data: Vec<u8>,
        at: Instant,
    },
    Error {
        interface: String,
        error: String,
    },
    Stopped,
}

pub fn running() -> bool {
    RUNNING.load(Ordering::Relaxed)
}

pub fn was_interrupted() -> bool {
    INTERRUPTED.load(Ordering::Relaxed)
}

/// Ask every capture thread to stop. Used by the TUI and by signal handlers.
pub fn request_shutdown() {
    INTERRUPTED.store(true, Ordering::Relaxed);
    RUNNING.store(false, Ordering::Relaxed);
}

pub fn open(interface: &NetworkInterface, promiscuous: bool) -> Result<Box<dyn DataLinkReceiver>> {
    let config = Config {
        read_timeout: Some(Duration::from_millis(100)),
        promiscuous,
        ..Default::default()
    };

    match datalink::channel(interface, config) {
        Ok(Channel::Ethernet(_, receiver)) => Ok(receiver),
        Ok(_) => bail!("unsupported data-link channel type (expected an Ethernet-like interface)"),
        Err(err) => Err(err.into()),
    }
}

pub fn spawn(
    interface: String,
    mut receiver: Box<dyn DataLinkReceiver>,
    sender: Sender<Message>,
    ipv6: bool,
) -> JoinHandle<()> {
    thread::Builder::new()
        .name(format!("capture-{interface}"))
        .spawn(move || {
            while running() {
                match receiver.next() {
                    Ok(frame) => {
                        // Copy only ICMP frames into the processing thread. This keeps a
                        // busy network from flooding the channel with unrelated traffic.
                        if !looks_like_icmp(frame, ipv6) {
                            continue;
                        }

                        let at = Instant::now();
                        if sender
                            .send(Message::Frame {
                                interface: interface.clone(),
                                data: frame.to_vec(),
                                at,
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(err)
                        if matches!(
                            err.kind(),
                            ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::Interrupted
                        ) =>
                    {
                        continue;
                    }
                    Err(err) => {
                        let _ = sender.send(Message::Error {
                            interface: interface.clone(),
                            error: err.to_string(),
                        });
                        break;
                    }
                }
            }

            let _ = sender.send(Message::Stopped);
        })
        .expect("spawn capture thread")
}

/// Cheap pre-filter applied before a frame is copied out of the capture buffer.
fn looks_like_icmp(frame: &[u8], ipv6: bool) -> bool {
    const ETHERNET_HEADER_LEN: usize = 14;
    const IPV4_MIN_HEADER_LEN: usize = 20;
    const IPV6_HEADER_LEN: usize = 40;

    if frame.len() < ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN {
        return false;
    }

    // Only plain Ethernet is considered. VLAN-tagged frames are ignored; they are
    // uncommon for host-directed ICMP.
    match u16::from_be_bytes([frame[12], frame[13]]) {
        0x0800 => {
            let ihl = usize::from(frame[14] & 0x0f) * 4;
            if ihl < IPV4_MIN_HEADER_LEN || frame.len() < ETHERNET_HEADER_LEN + ihl {
                return false;
            }
            // IPv4 protocol 1 == ICMP.
            frame[14 + 9] == 1
        }
        0x86dd if ipv6 => {
            if frame.len() < ETHERNET_HEADER_LEN + IPV6_HEADER_LEN {
                return false;
            }
            // Only direct ICMPv6 is handled; IPv6 extension headers are skipped.
            frame[14 + 6] == 58
        }
        _ => false,
    }
}

pub fn install_signal_handlers() {
    unsafe {
        libc::signal(libc::SIGINT, handle_signal as libc::sighandler_t);
        libc::signal(libc::SIGTERM, handle_signal as libc::sighandler_t);
    }
}

extern "C" fn handle_signal(_signal: libc::c_int) {
    request_shutdown();
}

#[cfg(test)]
mod tests {
    use super::looks_like_icmp;

    fn frame(ethertype: u16, protocol: u8) -> Vec<u8> {
        let mut frame = vec![0u8; 14 + 40];
        frame[12..14].copy_from_slice(&ethertype.to_be_bytes());
        frame[14] = 0x45;
        frame[14 + 9] = protocol;
        frame
    }

    fn ipv6_frame(next_header: u8) -> Vec<u8> {
        let mut frame = vec![0u8; 14 + 40];
        frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        frame[14] = 0x60;
        frame[14 + 6] = next_header;
        frame
    }

    #[test]
    fn accepts_icmpv4() {
        assert!(looks_like_icmp(&frame(0x0800, 1), false));
    }

    #[test]
    fn rejects_other_ip_protocols() {
        assert!(!looks_like_icmp(&frame(0x0800, 6), false));
    }

    #[test]
    fn accepts_icmpv6_only_when_enabled() {
        assert!(looks_like_icmp(&ipv6_frame(58), true));
        assert!(!looks_like_icmp(&ipv6_frame(58), false));
        assert!(!looks_like_icmp(&ipv6_frame(6), true));
    }

    #[test]
    fn rejects_short_frames() {
        assert!(!looks_like_icmp(&[0u8; 20], false));
    }

    #[test]
    fn prefilter_accepts_a_frame_the_processor_tracks() {
        use std::net::{IpAddr, Ipv4Addr};
        use std::time::Instant;

        use crate::tracker::{Event, Processor};

        let local_v4 = Ipv4Addr::new(192, 0, 2, 10);
        let peer_v4 = Ipv4Addr::new(192, 0, 2, 50);
        let local = IpAddr::V4(local_v4);
        let peer = IpAddr::V4(peer_v4);

        let mut icmp = vec![0u8; 8];
        icmp[0] = 8; // echo request
        icmp[4..6].copy_from_slice(&7u16.to_be_bytes());
        icmp[6..8].copy_from_slice(&1u16.to_be_bytes());

        let mut frame = vec![0u8; 14 + 20 + icmp.len()];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&((20 + icmp.len()) as u16).to_be_bytes());
        frame[22] = 64;
        frame[23] = 1;
        frame[26..30].copy_from_slice(&peer_v4.octets());
        frame[30..34].copy_from_slice(&local_v4.octets());
        frame[34..].copy_from_slice(&icmp);

        assert!(looks_like_icmp(&frame, false));

        let mut processor = Processor::new([local], None);
        let events = processor.handle_frame("test0", &frame, Instant::now());
        assert!(matches!(
            events.as_slice(),
            [Event::EchoRequest {
                peer: seen_peer,
                local: seen_local,
                ..
            }] if *seen_peer == peer && *seen_local == local
        ));
    }

    #[test]
    fn prefilter_accepts_an_ipv6_frame_the_processor_tracks() {
        use std::net::{IpAddr, Ipv6Addr};
        use std::time::Instant;

        use crate::tracker::{Event, Processor};

        let local = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let peer = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

        let mut icmp = vec![0u8; 8];
        icmp[0] = 128; // ICMPv6 echo request
        icmp[4..6].copy_from_slice(&7u16.to_be_bytes());
        icmp[6..8].copy_from_slice(&1u16.to_be_bytes());

        let mut frame = vec![0u8; 14 + 40 + icmp.len()];
        frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        frame[14] = 0x60;
        frame[18..20].copy_from_slice(&(icmp.len() as u16).to_be_bytes());
        frame[14 + 6] = 58;
        frame[14 + 7] = 64;
        frame[14 + 8..14 + 24].copy_from_slice(&peer.octets());
        frame[14 + 24..14 + 40].copy_from_slice(&local.octets());
        frame[14 + 40..].copy_from_slice(&icmp);

        assert!(looks_like_icmp(&frame, true));

        let mut processor = Processor::new([IpAddr::V6(local)], None);
        let events = processor.handle_frame("test0", &frame, Instant::now());
        assert!(matches!(
            events.as_slice(),
            [Event::EchoRequest {
                peer: seen_peer,
                local: seen_local,
                ..
            }] if *seen_peer == IpAddr::V6(peer) && *seen_local == IpAddr::V6(local)
        ));
    }

    #[test]
    fn random_frames_do_not_panic_in_prefilter() {
        let mut seed = 0x1234_5678_9abc_def0u64;
        for _ in 0..20_000 {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let len = (seed as usize) % 2_000;
            let mut frame = vec![0u8; len];
            for byte in &mut frame {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                *byte = (seed >> 33) as u8;
            }
            let _ = looks_like_icmp(&frame, false);
            let _ = looks_like_icmp(&frame, true);
        }
    }
}
