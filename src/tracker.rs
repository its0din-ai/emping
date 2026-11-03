use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use serde::{Deserialize, Serialize};

const MAX_PENDING: usize = 100_000;
const FLOOD_WINDOW: Duration = Duration::from_secs(1);
const FLOOD_THRESHOLD: usize = 15;
const FLOOD_BLOCK: Duration = Duration::from_secs(60 * 60);
const MAX_LIMIT_PEERS: usize = 4_096;

/// Something worth printing. Events are produced by [`Processor`] and rendered by
/// the output layer, which keeps packet handling testable without touching stdout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Event {
    /// An echo request was seen on its way to one of our addresses.
    EchoRequest {
        interface: String,
        peer: IpAddr,
        local: IpAddr,
        id: u16,
        seq: u16,
        duplicate: bool,
    },
    /// An echo reply was seen leaving one of our addresses.
    EchoReply {
        interface: String,
        peer: IpAddr,
        local: IpAddr,
        id: u16,
        seq: u16,
        rtt: Option<Duration>,
        tracked: bool,
    },
    /// A previously seen echo request never got a matching reply.
    EchoTimeout {
        interface: String,
        peer: IpAddr,
        local: IpAddr,
        id: u16,
        seq: u16,
        after: Duration,
    },
    /// A peer exceeded the flood threshold and was temporarily ignored.
    FloodDetected {
        interface: String,
        peer: IpAddr,
        local: IpAddr,
        blocked_for: Duration,
    },
    /// An ICMP error report that embeds the header of an original TCP flow.
    IcmpTcpError {
        interface: String,
        reporter: IpAddr,
        original_src: IpAddr,
        original_dst: IpAddr,
        src_port: u16,
        dst_port: u16,
        icmp_type: u8,
        icmp_code: u8,
    },
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct Stats {
    pub requests: u64,
    pub replied: u64,
    pub unanswered: u64,
    pub duplicates: u64,
    pub untracked_replies: u64,
    pub icmp_tcp_errors: u64,
    pub pending: u64,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct EchoKey {
    peer: IpAddr,
    local: IpAddr,
    id: u16,
    seq: u16,
}

struct Pending {
    interface: String,
    started: Instant,
}

pub struct Processor {
    local_ips: HashSet<IpAddr>,
    pending: HashMap<EchoKey, Pending>,
    timeout: Option<Duration>,
    enforce_limit: bool,
    request_times: HashMap<IpAddr, VecDeque<Instant>>,
    blocked_until: HashMap<IpAddr, Instant>,
    stats: Stats,
}

impl Processor {
    #[cfg(test)]
    pub fn new(local_ips: impl IntoIterator<Item = IpAddr>, timeout: Option<Duration>) -> Self {
        Self::new_with_limit(local_ips, timeout, true)
    }

    pub fn new_with_limit(
        local_ips: impl IntoIterator<Item = IpAddr>,
        timeout: Option<Duration>,
        enforce_limit: bool,
    ) -> Self {
        Self {
            local_ips: local_ips.into_iter().collect(),
            pending: HashMap::new(),
            timeout,
            enforce_limit,
            request_times: HashMap::new(),
            blocked_until: HashMap::new(),
            stats: Stats::default(),
        }
    }

    /// Inspect one captured Ethernet frame.
    ///
    /// `now` is passed in so tests (and batching code) control the clock.
    pub fn handle_frame(&mut self, interface: &str, frame: &[u8], now: Instant) -> Vec<Event> {
        let Some(ethernet) = EthernetPacket::new(frame) else {
            return Vec::new();
        };

        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => self.handle_ipv4(interface, ethernet.payload(), now),
            EtherTypes::Ipv6 => self.handle_ipv6(interface, ethernet.payload(), now),
            _ => Vec::new(),
        }
    }

    fn handle_ipv4(&mut self, interface: &str, bytes: &[u8], now: Instant) -> Vec<Event> {
        let Some(ip) = Ipv4Packet::new(bytes) else {
            return Vec::new();
        };
        if ip.get_version() != 4
            || ip.get_next_level_protocol() != IpNextHeaderProtocols::Icmp
            || ip.get_fragment_offset() != 0
            || (ip.get_flags() & 0x1) != 0
        {
            return Vec::new();
        }

        let Some(icmp) = IcmpPacket::new(ip.payload()) else {
            return Vec::new();
        };

        let src: IpAddr = ip.get_source().into();
        let dst: IpAddr = ip.get_destination().into();
        let icmp_type = icmp.get_icmp_type();

        if icmp_type == IcmpTypes::EchoRequest {
            let Some((id, seq)) = echo_id_seq(icmp.payload()) else {
                return Vec::new();
            };
            self.handle_echo_request(interface, src, dst, id, seq, now)
        } else if icmp_type == IcmpTypes::EchoReply {
            let Some((id, seq)) = echo_id_seq(icmp.payload()) else {
                return Vec::new();
            };
            self.handle_echo_reply(interface, dst, src, id, seq, now)
        } else if icmp_type == IcmpTypes::DestinationUnreachable
            || icmp_type == IcmpTypes::TimeExceeded
            || icmp_type == IcmpTypes::ParameterProblem
        {
            self.handle_ipv4_error(interface, src, dst, &icmp)
        } else {
            Vec::new()
        }
    }

    fn handle_ipv6(&mut self, interface: &str, bytes: &[u8], now: Instant) -> Vec<Event> {
        let Some(ip) = Ipv6Packet::new(bytes) else {
            return Vec::new();
        };
        if ip.get_version() != 6 || ip.get_next_header() != IpNextHeaderProtocols::Icmpv6 {
            return Vec::new();
        }

        let Some(icmp) = Icmpv6Packet::new(ip.payload()) else {
            return Vec::new();
        };

        let src: IpAddr = ip.get_source().into();
        let dst: IpAddr = ip.get_destination().into();
        let icmp_type = icmp.get_icmpv6_type();

        if icmp_type == Icmpv6Types::EchoRequest {
            let Some((id, seq)) = echo_id_seq(icmp.payload()) else {
                return Vec::new();
            };
            self.handle_echo_request(interface, src, dst, id, seq, now)
        } else if icmp_type == Icmpv6Types::EchoReply {
            let Some((id, seq)) = echo_id_seq(icmp.payload()) else {
                return Vec::new();
            };
            self.handle_echo_reply(interface, dst, src, id, seq, now)
        } else if icmp_type == Icmpv6Types::DestinationUnreachable
            || icmp_type == Icmpv6Types::PacketTooBig
            || icmp_type == Icmpv6Types::TimeExceeded
            || icmp_type == Icmpv6Types::ParameterProblem
        {
            self.handle_ipv6_error(interface, src, dst, &icmp)
        } else {
            Vec::new()
        }
    }

    fn handle_echo_request(
        &mut self,
        interface: &str,
        peer: IpAddr,
        local: IpAddr,
        id: u16,
        seq: u16,
        now: Instant,
    ) -> Vec<Event> {
        // An echo request sent *to this host* has a local destination. Outbound pings
        // (local source, remote destination) are not what this tool watches.
        if !self.local_ips.contains(&local) {
            return Vec::new();
        }

        if self.enforce_limit && self.is_blocked(peer, now) {
            return Vec::new();
        }

        let key = EchoKey {
            peer,
            local,
            id,
            seq,
        };
        let duplicate = self.pending.contains_key(&key);

        // Count only new requests. A packet captured twice on a loopback or bridge
        // should not accelerate the flood threshold.
        if !duplicate && self.enforce_limit && self.record_flood(peer, now) {
            self.block_peer(peer, now);
            return vec![Event::FloodDetected {
                interface: interface.to_string(),
                peer,
                local,
                blocked_for: FLOOD_BLOCK,
            }];
        }

        if duplicate {
            self.stats.duplicates += 1;
        } else {
            if self.pending.len() >= MAX_PENDING {
                if let Some(oldest) = self.pending.keys().next().copied() {
                    self.pending.remove(&oldest);
                }
            }
            self.pending.insert(
                key,
                Pending {
                    interface: interface.to_string(),
                    started: now,
                },
            );
            self.stats.requests += 1;
        }

        vec![Event::EchoRequest {
            interface: interface.to_string(),
            peer: key.peer,
            local: key.local,
            id,
            seq,
            duplicate,
        }]
    }

    fn handle_echo_reply(
        &mut self,
        interface: &str,
        peer: IpAddr,
        local: IpAddr,
        id: u16,
        seq: u16,
        now: Instant,
    ) -> Vec<Event> {
        // An echo reply sent *by this host* has a local source. Replies observed
        // between two other hosts (possible in promiscuous mode) are ignored.
        if !self.local_ips.contains(&local) {
            return Vec::new();
        }
        if self.enforce_limit && self.is_blocked(peer, now) {
            return Vec::new();
        }

        let key = EchoKey {
            peer,
            local,
            id,
            seq,
        };

        let (rtt, tracked) = match self.pending.remove(&key) {
            Some(pending) => {
                self.stats.replied += 1;
                (Some(now.saturating_duration_since(pending.started)), true)
            }
            None => {
                self.stats.untracked_replies += 1;
                (None, false)
            }
        };

        vec![Event::EchoReply {
            interface: interface.to_string(),
            peer: key.peer,
            local: key.local,
            id,
            seq,
            rtt,
            tracked,
        }]
    }

    fn handle_ipv4_error(
        &mut self,
        interface: &str,
        reporter: IpAddr,
        local: IpAddr,
        icmp: &IcmpPacket<'_>,
    ) -> Vec<Event> {
        // ICMP errors are sent to the host that originated the offending packet.
        if !self.local_ips.contains(&local) {
            return Vec::new();
        }

        // All relevant error messages have a 4-byte type-specific field before the
        // embedded original IP header.
        let Some(inner_bytes) = icmp.payload().get(4..) else {
            return Vec::new();
        };
        let Some(inner_ip) = Ipv4Packet::new(inner_bytes) else {
            return Vec::new();
        };
        if inner_ip.get_version() != 4
            || inner_ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp
        {
            return Vec::new();
        }

        // Commonly only the first 8 bytes of the TCP header are echoed back, which is
        // enough for the ports but not for a full pnet TcpPacket. Parse them directly.
        let Some((src_port, dst_port)) = tcp_ports(inner_ip.payload()) else {
            return Vec::new();
        };

        self.stats.icmp_tcp_errors += 1;

        vec![Event::IcmpTcpError {
            interface: interface.to_string(),
            reporter,
            original_src: inner_ip.get_source().into(),
            original_dst: inner_ip.get_destination().into(),
            src_port,
            dst_port,
            icmp_type: icmp.get_icmp_type().0,
            icmp_code: icmp.get_icmp_code().0,
        }]
    }

    fn handle_ipv6_error(
        &mut self,
        interface: &str,
        reporter: IpAddr,
        local: IpAddr,
        icmp: &Icmpv6Packet<'_>,
    ) -> Vec<Event> {
        if !self.local_ips.contains(&local) {
            return Vec::new();
        }

        let Some(inner_bytes) = icmp.payload().get(4..) else {
            return Vec::new();
        };
        let Some(inner_ip) = Ipv6Packet::new(inner_bytes) else {
            return Vec::new();
        };
        if inner_ip.get_version() != 6 || inner_ip.get_next_header() != IpNextHeaderProtocols::Tcp {
            return Vec::new();
        }

        let Some((src_port, dst_port)) = tcp_ports(inner_ip.payload()) else {
            return Vec::new();
        };

        self.stats.icmp_tcp_errors += 1;

        vec![Event::IcmpTcpError {
            interface: interface.to_string(),
            reporter,
            original_src: inner_ip.get_source().into(),
            original_dst: inner_ip.get_destination().into(),
            src_port,
            dst_port,
            icmp_type: icmp.get_icmpv6_type().0,
            icmp_code: icmp.get_icmpv6_code().0,
        }]
    }

    fn is_blocked(&mut self, peer: IpAddr, now: Instant) -> bool {
        match self.blocked_until.get(&peer).copied() {
            Some(until) if now < until => true,
            Some(_) => {
                self.blocked_until.remove(&peer);
                false
            }
            None => false,
        }
    }

    fn record_flood(&mut self, peer: IpAddr, now: Instant) -> bool {
        if self.request_times.len() >= MAX_LIMIT_PEERS && !self.request_times.contains_key(&peer) {
            if let Some(key) = self.request_times.keys().next().copied() {
                self.request_times.remove(&key);
            }
        }

        let times = self.request_times.entry(peer).or_default();
        while let Some(front) = times.front() {
            if now.saturating_duration_since(*front) > FLOOD_WINDOW {
                times.pop_front();
            } else {
                break;
            }
        }
        times.push_back(now);

        if times.len() > FLOOD_THRESHOLD {
            self.request_times.remove(&peer);
            true
        } else {
            false
        }
    }

    fn block_peer(&mut self, peer: IpAddr, now: Instant) {
        if self.blocked_until.len() >= MAX_LIMIT_PEERS && !self.blocked_until.contains_key(&peer) {
            if let Some(key) = self.blocked_until.keys().next().copied() {
                self.blocked_until.remove(&key);
            }
        }

        let until = now.checked_add(FLOOD_BLOCK).unwrap_or(now);
        self.blocked_until.insert(peer, until);
        self.pending.retain(|key, _| key.peer != peer);
    }

    /// Report requests whose reply window has elapsed.
    pub fn expire(&mut self, now: Instant) -> Vec<Event> {
        self.blocked_until.retain(|_, until| *until > now);
        self.request_times.retain(|_, times| {
            times
                .back()
                .is_some_and(|at| now.saturating_duration_since(*at) <= FLOOD_WINDOW)
        });

        let Some(timeout) = self.timeout else {
            return Vec::new();
        };

        let expired = self
            .pending
            .iter()
            .filter(|(_, pending)| now.saturating_duration_since(pending.started) >= timeout)
            .map(|(key, _)| *key)
            .collect::<Vec<_>>();

        let mut events = Vec::with_capacity(expired.len());
        for key in expired {
            if let Some(pending) = self.pending.remove(&key) {
                self.stats.unanswered += 1;
                events.push(Event::EchoTimeout {
                    interface: pending.interface,
                    peer: key.peer,
                    local: key.local,
                    id: key.id,
                    seq: key.seq,
                    after: timeout,
                });
            }
        }

        events
    }

    pub fn stats(&self) -> Stats {
        Stats {
            pending: self.pending.len() as u64,
            ..self.stats
        }
    }
}

fn echo_id_seq(payload: &[u8]) -> Option<(u16, u16)> {
    if payload.len() < 4 {
        return None;
    }
    Some((
        u16::from_be_bytes([payload[0], payload[1]]),
        u16::from_be_bytes([payload[2], payload[3]]),
    ))
}

fn tcp_ports(payload: &[u8]) -> Option<(u16, u16)> {
    if payload.len() < 4 {
        return None;
    }
    Some((
        u16::from_be_bytes([payload[0], payload[1]]),
        u16::from_be_bytes([payload[2], payload[3]]),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
    const PEER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 50);
    const REMOTE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);

    fn ipv4_bytes(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> Vec<u8> {
        let total_len = 20 + payload.len();
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64; // TTL
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&src.octets());
        packet[16..20].copy_from_slice(&dst.octets());
        packet[20..].copy_from_slice(payload);
        packet
    }

    fn ethernet_frame(ip: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 14 + ip.len()];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        frame[14..].copy_from_slice(ip);
        frame
    }

    fn ipv6_bytes(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 40 + payload.len()];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        packet[6] = next_header;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&src.octets());
        packet[24..40].copy_from_slice(&dst.octets());
        packet[40..].copy_from_slice(payload);
        packet
    }

    fn ethernet_frame_v6(ip: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 14 + ip.len()];
        frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        frame[14..].copy_from_slice(ip);
        frame
    }

    fn echo6_frame(src: Ipv6Addr, dst: Ipv6Addr, icmp_type: u8, id: u16, seq: u16) -> Vec<u8> {
        let mut icmp = vec![0u8; 8];
        icmp[0] = icmp_type;
        icmp[4..6].copy_from_slice(&id.to_be_bytes());
        icmp[6..8].copy_from_slice(&seq.to_be_bytes());
        ethernet_frame_v6(&ipv6_bytes(src, dst, 58, &icmp))
    }

    fn icmp6_error_frame(
        reporter: Ipv6Addr,
        local: Ipv6Addr,
        original_src: Ipv6Addr,
        original_dst: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut original_tcp = vec![0u8; 8];
        original_tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
        original_tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        let original_ip = ipv6_bytes(original_src, original_dst, 6, &original_tcp);

        let mut icmp = vec![0u8; 8];
        icmp[0] = 1; // destination unreachable
        icmp[1] = 4; // port unreachable
        icmp[4..].copy_from_slice(&[0, 0, 0, 0]);
        icmp.extend_from_slice(&original_ip);

        ethernet_frame_v6(&ipv6_bytes(reporter, local, 58, &icmp))
    }

    fn echo_frame(src: Ipv4Addr, dst: Ipv4Addr, icmp_type: u8, id: u16, seq: u16) -> Vec<u8> {
        echo_frame_with_payload(src, dst, icmp_type, id, seq, &[])
    }

    fn echo_frame_with_payload(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        icmp_type: u8,
        id: u16,
        seq: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut icmp = vec![0u8; 8 + payload.len()];
        icmp[0] = icmp_type;
        icmp[4..6].copy_from_slice(&id.to_be_bytes());
        icmp[6..8].copy_from_slice(&seq.to_be_bytes());
        icmp[8..].copy_from_slice(payload);
        ethernet_frame(&ipv4_bytes(src, dst, 1, &icmp))
    }

    fn icmp_error_frame(
        reporter: Ipv4Addr,
        local: Ipv4Addr,
        original_src: Ipv4Addr,
        original_dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut original_tcp = vec![0u8; 8];
        original_tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
        original_tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        let original_ip = ipv4_bytes(original_src, original_dst, 6, &original_tcp);

        let mut icmp = vec![0u8; 8];
        icmp[0] = 3; // destination unreachable
        icmp[1] = 3; // port unreachable
        icmp[4..].copy_from_slice(&[0, 0, 0, 0]);
        icmp.extend_from_slice(&original_ip);

        ethernet_frame(&ipv4_bytes(reporter, local, 1, &icmp))
    }

    fn processor() -> Processor {
        Processor::new(
            [LOCAL.into(), Ipv4Addr::LOCALHOST.into()],
            Some(Duration::from_secs(2)),
        )
    }

    #[test]
    fn tracks_request_and_reply() {
        let mut processor = processor();
        let start = Instant::now();

        let events = processor.handle_frame("eth0", &echo_frame(PEER, LOCAL, 8, 7, 1), start);
        assert_eq!(
            events,
            vec![Event::EchoRequest {
                interface: "eth0".into(),
                peer: PEER.into(),
                local: LOCAL.into(),
                id: 7,
                seq: 1,
                duplicate: false,
            }]
        );

        let events = processor.handle_frame(
            "eth0",
            &echo_frame(LOCAL, PEER, 0, 7, 1),
            start + Duration::from_micros(750),
        );
        assert_eq!(
            events,
            vec![Event::EchoReply {
                interface: "eth0".into(),
                peer: PEER.into(),
                local: LOCAL.into(),
                id: 7,
                seq: 1,
                rtt: Some(Duration::from_micros(750)),
                tracked: true,
            }]
        );

        let stats = processor.stats();
        assert_eq!(stats.requests, 1);
        assert_eq!(stats.replied, 1);
        assert_eq!(stats.pending, 0);
    }

    #[test]
    fn reports_unanswered_request_after_timeout() {
        let mut processor = processor();
        let start = Instant::now();

        processor.handle_frame("eth0", &echo_frame(PEER, LOCAL, 8, 9, 2), start);
        assert!(processor
            .expire(start + Duration::from_millis(1999))
            .is_empty());

        let events = processor.expire(start + Duration::from_millis(2000));
        assert_eq!(
            events,
            vec![Event::EchoTimeout {
                interface: "eth0".into(),
                peer: PEER.into(),
                local: LOCAL.into(),
                id: 9,
                seq: 2,
                after: Duration::from_secs(2),
            }]
        );
        assert_eq!(processor.stats().unanswered, 1);
        assert_eq!(processor.stats().pending, 0);
    }

    #[test]
    fn ignores_requests_not_addressed_to_the_host() {
        let mut processor = processor();
        let start = Instant::now();

        // Our own outbound ping.
        assert!(processor
            .handle_frame("eth0", &echo_frame(LOCAL, REMOTE, 8, 1, 1), start)
            .is_empty());
        // Request between two other hosts.
        assert!(processor
            .handle_frame("eth0", &echo_frame(PEER, REMOTE, 8, 1, 1), start)
            .is_empty());
        assert_eq!(processor.stats().requests, 0);
    }

    #[test]
    fn ignores_replies_not_sent_by_the_host() {
        let mut processor = processor();
        let start = Instant::now();

        assert!(processor
            .handle_frame("eth0", &echo_frame(PEER, LOCAL, 0, 1, 1), start)
            .is_empty());
        assert_eq!(processor.stats().untracked_replies, 0);
    }

    #[test]
    fn marks_duplicate_requests_without_resetting_the_timer() {
        let mut processor = processor();
        let start = Instant::now();
        let frame = echo_frame(PEER, LOCAL, 8, 3, 4);

        processor.handle_frame("eth0", &frame, start);
        let events = processor.handle_frame("eth0", &frame, start + Duration::from_millis(500));

        assert!(matches!(
            events.as_slice(),
            [Event::EchoRequest {
                duplicate: true,
                ..
            }]
        ));
        assert_eq!(processor.stats().requests, 1);
        assert_eq!(processor.stats().duplicates, 1);

        // RTT is measured from the first request.
        let events = processor.handle_frame(
            "eth0",
            &echo_frame(LOCAL, PEER, 0, 3, 4),
            start + Duration::from_millis(800),
        );
        assert!(matches!(
            events.as_slice(),
            [Event::EchoReply {
                rtt: Some(rtt),
                ..
            }] if *rtt == Duration::from_millis(800)
        ));
    }

    #[test]
    fn reports_untracked_replies() {
        let mut processor = processor();
        let start = Instant::now();

        let events = processor.handle_frame("eth0", &echo_frame(LOCAL, PEER, 0, 5, 6), start);
        assert_eq!(
            events,
            vec![Event::EchoReply {
                interface: "eth0".into(),
                peer: PEER.into(),
                local: LOCAL.into(),
                id: 5,
                seq: 6,
                rtt: None,
                tracked: false,
            }]
        );
        assert_eq!(processor.stats().untracked_replies, 1);
    }

    #[test]
    fn parses_tcp_flow_embedded_in_icmp_error() {
        let mut processor = processor();
        let start = Instant::now();
        let frame = icmp_error_frame(REMOTE, LOCAL, LOCAL, REMOTE, 54321, 443);

        let events = processor.handle_frame("eth0", &frame, start);
        assert_eq!(
            events,
            vec![Event::IcmpTcpError {
                interface: "eth0".into(),
                reporter: REMOTE.into(),
                original_src: LOCAL.into(),
                original_dst: REMOTE.into(),
                src_port: 54321,
                dst_port: 443,
                icmp_type: 3,
                icmp_code: 3,
            }]
        );
        assert_eq!(processor.stats().icmp_tcp_errors, 1);
    }

    #[test]
    fn ignores_icmp_errors_sent_elsewhere() {
        let mut processor = processor();
        let start = Instant::now();
        let frame = icmp_error_frame(REMOTE, PEER, PEER, REMOTE, 1234, 80);

        assert!(processor.handle_frame("eth0", &frame, start).is_empty());
    }

    #[test]
    fn ignores_truncated_frames() {
        let mut processor = processor();
        let start = Instant::now();
        let frame = echo_frame(PEER, LOCAL, 8, 1, 1);

        assert!(processor
            .handle_frame("eth0", &frame[..frame.len() - 1], start)
            .is_empty());
        assert!(processor
            .handle_frame("eth0", &frame[..20], start)
            .is_empty());
    }

    #[test]
    fn loopback_request_and_reply_match() {
        let mut processor = processor();
        let start = Instant::now();
        let loopback = Ipv4Addr::LOCALHOST;

        let events = processor.handle_frame("lo", &echo_frame(loopback, loopback, 8, 1, 1), start);
        assert!(matches!(events.as_slice(), [Event::EchoRequest { .. }]));

        let events = processor.handle_frame(
            "lo",
            &echo_frame(loopback, loopback, 0, 1, 1),
            start + Duration::from_micros(100),
        );
        assert!(matches!(
            events.as_slice(),
            [Event::EchoReply { tracked: true, .. }]
        ));
    }

    #[test]
    fn tracks_icmpv6_request_and_reply() {
        let local = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let peer = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let mut processor = Processor::new([local.into()], Some(Duration::from_secs(2)));
        let start = Instant::now();

        let events = processor.handle_frame("eth0", &echo6_frame(peer, local, 128, 9, 1), start);
        assert_eq!(
            events,
            vec![Event::EchoRequest {
                interface: "eth0".into(),
                peer: peer.into(),
                local: local.into(),
                id: 9,
                seq: 1,
                duplicate: false,
            }]
        );

        let events = processor.handle_frame(
            "eth0",
            &echo6_frame(local, peer, 129, 9, 1),
            start + Duration::from_micros(600),
        );
        assert_eq!(
            events,
            vec![Event::EchoReply {
                interface: "eth0".into(),
                peer: peer.into(),
                local: local.into(),
                id: 9,
                seq: 1,
                rtt: Some(Duration::from_micros(600)),
                tracked: true,
            }]
        );
    }

    #[test]
    fn parses_tcp_flow_embedded_in_icmpv6_error() {
        let local = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let reporter = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9);
        let remote = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10);
        let mut processor = Processor::new([local.into()], Some(Duration::from_secs(2)));
        let start = Instant::now();

        let events = processor.handle_frame(
            "eth0",
            &icmp6_error_frame(reporter, local, local, remote, 54321, 443),
            start,
        );
        assert_eq!(
            events,
            vec![Event::IcmpTcpError {
                interface: "eth0".into(),
                reporter: reporter.into(),
                original_src: local.into(),
                original_dst: remote.into(),
                src_port: 54321,
                dst_port: 443,
                icmp_type: 1,
                icmp_code: 4,
            }]
        );
    }

    #[test]
    fn flood_limiter_blocks_after_sixteen_requests() {
        let mut processor = processor();
        let start = Instant::now();

        for seq in 0..15 {
            let events = processor.handle_frame(
                "eth0",
                &echo_frame(PEER, LOCAL, 8, 42, seq),
                start + Duration::from_millis(u64::from(seq)),
            );
            assert!(matches!(events.as_slice(), [Event::EchoRequest { .. }]));
        }

        let events = processor.handle_frame(
            "eth0",
            &echo_frame(PEER, LOCAL, 8, 42, 15),
            start + Duration::from_millis(15),
        );
        assert!(matches!(
            events.as_slice(),
            [Event::FloodDetected {
                peer,
                blocked_for,
                ..
            }] if *peer == IpAddr::V4(PEER) && *blocked_for == FLOOD_BLOCK
        ));

        assert!(processor
            .handle_frame(
                "eth0",
                &echo_frame(PEER, LOCAL, 8, 42, 16),
                start + Duration::from_millis(16),
            )
            .is_empty());

        let events = processor.handle_frame(
            "eth0",
            &echo_frame(PEER, LOCAL, 8, 42, 17),
            start + FLOOD_BLOCK + Duration::from_secs(2),
        );
        assert!(matches!(events.as_slice(), [Event::EchoRequest { .. }]));
    }

    #[test]
    fn flood_limiter_allows_slow_traffic() {
        let mut processor = processor();
        let start = Instant::now();

        for seq in 0..30 {
            let events = processor.handle_frame(
                "eth0",
                &echo_frame(PEER, LOCAL, 8, 43, seq),
                start + Duration::from_millis(u64::from(seq) * 200),
            );
            assert!(matches!(events.as_slice(), [Event::EchoRequest { .. }]));
        }
        assert!(!matches!(
            processor
                .handle_frame(
                    "eth0",
                    &echo_frame(PEER, LOCAL, 8, 43, 30),
                    start + Duration::from_millis(30 * 200),
                )
                .as_slice(),
            [Event::FloodDetected { .. }]
        ));
    }

    #[test]
    fn no_limit_bypasses_flood_limiter() {
        let mut processor =
            Processor::new_with_limit([LOCAL.into()], Some(Duration::from_secs(2)), false);
        let start = Instant::now();

        for seq in 0..100 {
            let events = processor.handle_frame(
                "eth0",
                &echo_frame(PEER, LOCAL, 8, 44, seq),
                start + Duration::from_millis(u64::from(seq)),
            );
            assert!(matches!(events.as_slice(), [Event::EchoRequest { .. }]));
        }
        assert_eq!(processor.stats().requests, 100);
    }

    #[test]
    fn tracks_large_unfragmented_echo_payload() {
        let mut processor = processor();
        let start = Instant::now();
        let frame = echo_frame_with_payload(PEER, LOCAL, 8, 50, 1, &vec![0x41; 6_000]);

        let events = processor.handle_frame("eth0", &frame, start);
        assert!(matches!(events.as_slice(), [Event::EchoRequest { .. }]));

        // The capture buffer is 4096 bytes. Headers and the echo id/sequence are at
        // the front, so a truncated capture of a jumbo frame is still trackable.
        let truncated = &frame[..4_096];
        let events = processor.handle_frame("eth0", truncated, start + Duration::from_millis(1));
        assert!(matches!(events.as_slice(), [Event::EchoRequest { .. }]));
    }

    #[test]
    fn ignores_fragmented_large_echo() {
        let mut processor = processor();
        let start = Instant::now();
        let mut frame = echo_frame_with_payload(PEER, LOCAL, 8, 51, 1, &vec![0x42; 6_000]);

        // Ethernet 14 + IPv4 flags/fragment offset at bytes 20..22; set MF.
        frame[20..22].copy_from_slice(&0x2000u16.to_be_bytes());
        assert!(processor.handle_frame("eth0", &frame, start).is_empty());
    }

    #[test]
    fn random_frames_do_not_panic() {
        let mut processor = Processor::new(
            [LOCAL.into(), IpAddr::V6(Ipv6Addr::LOCALHOST)],
            Some(Duration::from_secs(2)),
        );
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;

        for iteration in 0..20_000u64 {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let len = (seed as usize) % 1_500;
            let mut frame = vec![0u8; len];
            for byte in &mut frame {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                *byte = (seed >> 33) as u8;
            }

            if frame.len() >= 14 {
                let ipv6 = iteration % 2 == 0;
                let ethertype = if ipv6 { 0x86ddu16 } else { 0x0800u16 };
                frame[12..14].copy_from_slice(&ethertype.to_be_bytes());
                if frame.len() >= 34 {
                    if ipv6 {
                        frame[14] = 0x60;
                        if frame.len() > 20 {
                            frame[20] = 58;
                        }
                    } else {
                        frame[14] = 0x45;
                        frame[23] = 1;
                    }
                }
            }

            let now = Instant::now();
            let _ = processor.handle_frame("fuzz0", &frame, now);
            if iteration % 100 == 0 {
                let _ = processor.expire(Instant::now());
            }
        }
    }
}
