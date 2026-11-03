use std::io::{self, Write};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::text;
use crate::tracker::{Event, Stats};

pub struct Printer {
    json: bool,
    started: Instant,
}

impl Printer {
    pub fn new(json: bool) -> Self {
        Self {
            json,
            started: Instant::now(),
        }
    }

    pub fn emit(&self, event: &Event) {
        self.emit_at(event, self.started.elapsed());
    }

    /// Emit an event using a caller-supplied elapsed time (service attaches).
    pub fn emit_at(&self, event: &Event, elapsed: std::time::Duration) {
        let line = if self.json {
            render_json(event, elapsed).to_string()
        } else {
            render_human(event, elapsed)
        };

        let stdout = io::stdout();
        let mut out = stdout.lock();
        let _ = writeln!(out, "{line}");
    }

    pub fn summary(&self, stats: &Stats) {
        let line = if self.json {
            json!({
                "event": "summary",
                "requests": stats.requests,
                "replied": stats.replied,
                "unanswered": stats.unanswered,
                "pending": stats.pending,
                "duplicates": stats.duplicates,
                "untracked_replies": stats.untracked_replies,
                "icmp_tcp_errors": stats.icmp_tcp_errors,
            })
            .to_string()
        } else {
            format!(
                "summary: requests={} replied={} unanswered={} pending={} duplicates={} untracked_replies={} icmp_tcp_errors={}",
                stats.requests,
                stats.replied,
                stats.unanswered,
                stats.pending,
                stats.duplicates,
                stats.untracked_replies,
                stats.icmp_tcp_errors,
            )
        };

        let stdout = io::stdout();
        let mut out = stdout.lock();
        let _ = writeln!(out, "{line}");
    }
}

fn render_human(event: &Event, elapsed: Duration) -> String {
    match event {
        Event::EchoRequest {
            interface,
            peer,
            local,
            id,
            seq,
            duplicate,
        } => {
            let interface = text::sanitize(interface);
            format!(
                "[{:>9.3}s] request   peer={peer:<15} local={local:<15} id={id:<5} seq={seq:<5} replied=pending duplicate={} iface={interface}",
                elapsed.as_secs_f64(),
                yes_no(*duplicate),
            )
        }
        Event::EchoReply {
            interface,
            peer,
            local,
            id,
            seq,
            rtt,
            tracked,
        } => {
            let interface = text::sanitize(interface);
            format!(
                "[{:>9.3}s] reply     peer={peer:<15} local={local:<15} id={id:<5} seq={seq:<5} replied=yes rtt={} tracked={} iface={interface}",
                elapsed.as_secs_f64(),
                rtt.map(format_duration).unwrap_or_else(|| "-".to_string()),
                yes_no(*tracked),
            )
        }
        Event::EchoTimeout {
            interface,
            peer,
            local,
            id,
            seq,
            after,
        } => {
            let interface = text::sanitize(interface);
            format!(
                "[{:>9.3}s] timeout   peer={peer:<15} local={local:<15} id={id:<5} seq={seq:<5} replied=no after={} iface={interface}",
                elapsed.as_secs_f64(),
                format_duration(*after),
            )
        }
        Event::FloodDetected { peer, .. } => format!(
            "[{:>9.3}s] flood     Possible Flood, Skip Capture {peer}\nUse --no-limit to skip this security features.",
            elapsed.as_secs_f64(),
        ),
        Event::IcmpTcpError {
            interface,
            reporter,
            original_src,
            original_dst,
            src_port,
            dst_port,
            icmp_type,
            icmp_code,
        } => {
            let interface = text::sanitize(interface);
            format!(
                "[{:>9.3}s] icmp-tcp  reporter={reporter:<15} original={original_src}:{src_port} -> {original_dst}:{dst_port} type={icmp_type} code={icmp_code} iface={interface}",
                elapsed.as_secs_f64(),
            )
        }
    }
}

fn render_json(event: &Event, elapsed: Duration) -> Value {
    let elapsed_ms = elapsed.as_secs_f64() * 1000.0;

    match event {
        Event::EchoRequest {
            interface,
            peer,
            local,
            id,
            seq,
            duplicate,
        } => json!({
            "event": "echo_request",
            "interface": interface,
            "peer": peer.to_string(),
            "local": local.to_string(),
            "id": id,
            "seq": seq,
            "duplicate": duplicate,
            "elapsed_ms": elapsed_ms,
        }),
        Event::EchoReply {
            interface,
            peer,
            local,
            id,
            seq,
            rtt,
            tracked,
        } => json!({
            "event": "echo_reply",
            "interface": interface,
            "peer": peer.to_string(),
            "local": local.to_string(),
            "id": id,
            "seq": seq,
            "rtt_ms": rtt.map(|duration| duration.as_secs_f64() * 1000.0),
            "tracked": tracked,
            "elapsed_ms": elapsed_ms,
        }),
        Event::EchoTimeout {
            interface,
            peer,
            local,
            id,
            seq,
            after,
        } => json!({
            "event": "echo_timeout",
            "interface": interface,
            "peer": peer.to_string(),
            "local": local.to_string(),
            "id": id,
            "seq": seq,
            "after_ms": after.as_secs_f64() * 1000.0,
            "elapsed_ms": elapsed_ms,
        }),
        Event::FloodDetected {
            interface,
            peer,
            local,
            blocked_for,
        } => json!({
            "event": "flood_skipped",
            "interface": interface,
            "peer": peer.to_string(),
            "local": local.to_string(),
            "blocked_for_ms": blocked_for.as_secs_f64() * 1000.0,
            "message": format!("Possible Flood, Skip Capture {peer}"),
            "hint": "Use --no-limit to skip this security features.",
            "elapsed_ms": elapsed_ms,
        }),
        Event::IcmpTcpError {
            interface,
            reporter,
            original_src,
            original_dst,
            src_port,
            dst_port,
            icmp_type,
            icmp_code,
        } => json!({
            "event": "icmp_tcp_error",
            "interface": interface,
            "reporter": reporter.to_string(),
            "original_src": original_src.to_string(),
            "original_dst": original_dst.to_string(),
            "src_port": src_port,
            "dst_port": dst_port,
            "icmp_type": icmp_type,
            "icmp_code": icmp_code,
            "elapsed_ms": elapsed_ms,
        }),
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

pub(crate) fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs_f64();
    if seconds >= 1.0 {
        format!("{seconds:.3}s")
    } else if seconds >= 0.001 {
        format!("{:.3}ms", seconds * 1000.0)
    } else {
        format!("{:.0}us", seconds * 1_000_000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
    const PEER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 50);

    #[test]
    fn human_reply_clearly_reports_the_host_replied() {
        let event = Event::EchoReply {
            interface: "eth0".into(),
            peer: PEER.into(),
            local: LOCAL.into(),
            id: 7,
            seq: 1,
            rtt: Some(Duration::from_micros(412)),
            tracked: true,
        };

        let line = render_human(&event, Duration::from_millis(1204));
        assert!(line.contains("replied=yes"));
        assert!(line.contains("rtt=412us"));
        assert!(line.contains("tracked=yes"));
    }

    #[test]
    fn human_timeout_clearly_reports_no_reply() {
        let event = Event::EchoTimeout {
            interface: "eth0".into(),
            peer: PEER.into(),
            local: LOCAL.into(),
            id: 7,
            seq: 2,
            after: Duration::from_secs(2),
        };

        let line = render_human(&event, Duration::from_millis(3204));
        assert!(line.contains("replied=no"));
        assert!(line.contains("after=2.000s"));
    }

    #[test]
    fn flood_warning_includes_peer_and_hint() {
        let event = Event::FloodDetected {
            interface: "eth0".into(),
            peer: PEER.into(),
            local: LOCAL.into(),
            blocked_for: Duration::from_secs(3600),
        };

        let line = render_human(&event, Duration::from_millis(10));
        assert!(line.contains("Possible Flood, Skip Capture 192.0.2.50"));
        assert!(line.contains('\n'));
        assert!(line.contains("Use --no-limit"));

        let value = render_json(&event, Duration::from_millis(10));
        assert_eq!(value["event"], "flood_skipped");
        assert_eq!(value["blocked_for_ms"], 3_600_000.0);
    }

    #[test]
    fn escapes_control_characters_in_interface_names() {
        let event = Event::EchoRequest {
            interface: "eth0\x1b[2J".into(),
            peer: PEER.into(),
            local: LOCAL.into(),
            id: 1,
            seq: 1,
            duplicate: false,
        };

        let line = render_human(&event, Duration::from_millis(10));
        assert!(line.contains("eth0\\x1b[2J"));
        assert!(!line.contains('\x1b'));
    }

    #[test]
    fn json_reply_uses_null_for_untracked_rtt() {
        let event = Event::EchoReply {
            interface: "eth0".into(),
            peer: PEER.into(),
            local: LOCAL.into(),
            id: 7,
            seq: 1,
            rtt: None,
            tracked: false,
        };

        let value = render_json(&event, Duration::from_millis(10));
        assert_eq!(value["event"], "echo_reply");
        assert_eq!(value["tracked"], false);
        assert!(value["rtt_ms"].is_null());
    }

    #[test]
    fn json_icmp_tcp_error_contains_original_flow() {
        let event = Event::IcmpTcpError {
            interface: "eth0".into(),
            reporter: PEER.into(),
            original_src: LOCAL.into(),
            original_dst: PEER.into(),
            src_port: 54321,
            dst_port: 443,
            icmp_type: 3,
            icmp_code: 3,
        };

        let value = render_json(&event, Duration::from_millis(10));
        assert_eq!(value["event"], "icmp_tcp_error");
        assert_eq!(value["src_port"], 54321);
        assert_eq!(value["dst_port"], 443);
    }
}
