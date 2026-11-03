use serde::{Deserialize, Serialize};

use crate::tracker::{Event, Stats};

/// Bump this when the wire format changes in an incompatible way.
pub const VERSION: u32 = 3;

/// Messages sent by the service to a connected client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    Hello(Hello),
    Event {
        elapsed_ms: f64,
        event: Event,
        stats: Stats,
    },
    Status(Status),
    Summary {
        stats: Stats,
        uptime_ms: f64,
    },
    Heartbeat,
    Stopping,
    Error {
        message: String,
    },
}

/// Initial snapshot sent immediately after a client subscribes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub version: u32,
    pub pid: u32,
    pub interfaces: Vec<String>,
    pub ipv6: bool,
    pub timeout_ms: Option<f64>,
    pub uptime_ms: f64,
    pub stats: Stats,
    /// A bounded tail of recent events, so a newly attached console is not empty.
    pub events: Vec<TimedEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimedEvent {
    pub elapsed_ms: f64,
    pub event: Event,
}

/// Response to a status request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub version: u32,
    pub pid: u32,
    pub interfaces: Vec<String>,
    pub ipv6: bool,
    pub timeout_ms: Option<f64>,
    pub uptime_ms: f64,
    pub stats: Stats,
}

/// Requests accepted on a new connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum ClientRequest {
    Subscribe,
    Status,
    Stop,
}

pub fn encode(message: &ServerMessage) -> String {
    serde_json::to_string(message).expect("serialize service message")
}

pub fn decode_server(line: &str) -> serde_json::Result<ServerMessage> {
    serde_json::from_str(line)
}

pub fn decode_request(line: &str) -> serde_json::Result<ClientRequest> {
    serde_json::from_str(line)
}

impl ServerMessage {
    pub fn error(message: impl Into<String>) -> Self {
        Self::Error {
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    #[test]
    fn round_trips_events() {
        let message = ServerMessage::Event {
            elapsed_ms: 12.5,
            event: Event::EchoRequest {
                interface: "eth0".into(),
                peer: Ipv4Addr::new(192, 0, 2, 50).into(),
                local: Ipv4Addr::new(192, 0, 2, 10).into(),
                id: 7,
                seq: 1,
                duplicate: false,
            },
            stats: Stats {
                requests: 1,
                ..Stats::default()
            },
        };

        let line = encode(&message);
        let decoded = decode_server(&line).unwrap();
        match decoded {
            ServerMessage::Event {
                elapsed_ms,
                event,
                stats,
            } => {
                assert_eq!(elapsed_ms, 12.5);
                assert_eq!(
                    event,
                    Event::EchoRequest {
                        interface: "eth0".into(),
                        peer: Ipv4Addr::new(192, 0, 2, 50).into(),
                        local: Ipv4Addr::new(192, 0, 2, 10).into(),
                        id: 7,
                        seq: 1,
                        duplicate: false,
                    }
                );
                assert_eq!(stats.requests, 1);
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn decodes_requests() {
        assert!(matches!(
            decode_request(r#"{"cmd":"subscribe"}"#).unwrap(),
            ClientRequest::Subscribe
        ));
        assert!(matches!(
            decode_request(r#"{"cmd":"status"}"#).unwrap(),
            ClientRequest::Status
        ));
        assert!(matches!(
            decode_request(r#"{"cmd":"stop"}"#).unwrap(),
            ClientRequest::Stop
        ));
    }

    #[test]
    fn round_trips_durations_in_events() {
        let message = ServerMessage::Event {
            elapsed_ms: 0.0,
            event: Event::EchoReply {
                interface: "lo".into(),
                peer: Ipv4Addr::LOCALHOST.into(),
                local: Ipv4Addr::LOCALHOST.into(),
                id: 1,
                seq: 2,
                rtt: Some(Duration::from_micros(412)),
                tracked: true,
            },
            stats: Stats::default(),
        };

        let decoded = decode_server(&encode(&message)).unwrap();
        match decoded {
            ServerMessage::Event {
                event: Event::EchoReply { rtt: Some(rtt), .. },
                ..
            } => assert_eq!(rtt, Duration::from_micros(412)),
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn malformed_protocol_lines_do_not_panic() {
        let samples = [
            "",
            "{",
            "null",
            "[]",
            r#"{"cmd":"subscribe"}"#,
            r#"{"cmd":123}"#,
            r#"{"type":"event"}"#,
            r#"{"type":"hello"}"#,
            r#"{"type":"event","elapsed_ms":1e999}"#,
            r#"{"type":"summary","stats":null}"#,
        ];
        for sample in samples {
            let _ = decode_server(sample);
            let _ = decode_request(sample);
        }

        let mut seed = 0xdead_beef_cafe_babeu64;
        for _ in 0..10_000 {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let len = (seed as usize) % 256;
            let mut text = String::new();
            for _ in 0..len {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                text.push(char::from(b' ' + (seed % 95) as u8));
            }
            let _ = decode_server(&text);
            let _ = decode_request(&text);
        }
    }
}
