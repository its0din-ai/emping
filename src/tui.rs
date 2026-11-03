use std::collections::HashMap;
use std::io::{self, Stdout};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossterm::cursor::{Hide, Show};
use crossterm::event::{self, Event as TerminalEvent, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Cell, Paragraph, Row, Table};
use ratatui::{Frame, Terminal};

use crate::output::format_duration;
use crate::text;
use crate::tracker::{Event, Stats};

const MAX_LOG_LINES: usize = 5_000;
const MAX_PEERS: usize = 1_024;
const OPERATION: &str = "SILENT ECHO";

const BG: Color = Color::Rgb(7, 7, 10);
const PANEL: Color = Color::Rgb(12, 12, 16);
const RED: Color = Color::Rgb(255, 48, 64);
const RED_DIM: Color = Color::Rgb(104, 24, 32);
const AMBER: Color = Color::Rgb(255, 176, 0);
const GREEN: Color = Color::Rgb(0, 226, 154);
const CYAN: Color = Color::Rgb(86, 204, 242);
const MAGENTA: Color = Color::Rgb(214, 93, 255);
const TEXT: Color = Color::Rgb(222, 222, 230);
const DIM: Color = Color::Rgb(108, 108, 122);

pub struct Tui {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    state: UiState,
    restored: bool,
}

struct UiState {
    started: Instant,
    interfaces: String,
    timeout: Option<Duration>,
    ipv6: bool,
    attached_pid: Option<u32>,
    log: Vec<LogLine>,
    peers: HashMap<IpAddr, Peer>,
    scroll_back: usize,
    follow: bool,
    quit: bool,
    errors: Vec<String>,
}

struct LogLine {
    body: LogBody,
}

enum LogBody {
    Event(Event),
    System(String),
    Spacer,
}

struct Peer {
    requests: u64,
    replies: u64,
    misses: u64,
    last_rtt: Option<Duration>,
    last_seen: Option<Instant>,
    state: PeerState,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PeerState {
    Pending,
    Replied,
    NoReply,
    Untracked,
    Flood,
}

impl Peer {
    fn new() -> Self {
        Self {
            requests: 0,
            replies: 0,
            misses: 0,
            last_rtt: None,
            last_seen: None,
            state: PeerState::Pending,
        }
    }
}

impl PeerState {
    fn label(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Replied => "REPLIED",
            Self::NoReply => "NO REPLY",
            Self::Untracked => "UNTRACKED",
            Self::Flood => "FLOOD",
        }
    }

    fn color(self) -> Color {
        match self {
            Self::Pending => AMBER,
            Self::Replied => GREEN,
            Self::NoReply => RED,
            Self::Untracked => MAGENTA,
            Self::Flood => RED,
        }
    }
}

impl Tui {
    pub fn new(interfaces: String, timeout: Option<Duration>, ipv6: bool) -> Result<Self> {
        Self::new_with(interfaces, timeout, ipv6, Duration::ZERO, None)
    }

    /// Open the console attached to a background service.
    pub fn new_attached(
        interfaces: String,
        timeout: Option<Duration>,
        ipv6: bool,
        uptime: Duration,
        pid: u32,
    ) -> Result<Self> {
        Self::new_with(interfaces, timeout, ipv6, uptime, Some(pid))
    }

    fn new_with(
        interfaces: String,
        timeout: Option<Duration>,
        ipv6: bool,
        uptime: Duration,
        attached_pid: Option<u32>,
    ) -> Result<Self> {
        enable_raw_mode().context("enable terminal raw mode")?;

        if let Err(err) = execute!(io::stdout(), EnterAlternateScreen, Hide) {
            let _ = disable_raw_mode();
            return Err(err.into());
        }

        let terminal = match Terminal::new(CrosstermBackend::new(io::stdout())) {
            Ok(terminal) => terminal,
            Err(err) => {
                let _ = disable_raw_mode();
                let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
                return Err(err.into());
            }
        };

        install_panic_hook();

        let interfaces = text::sanitize(&interfaces);
        let started = Instant::now()
            .checked_sub(uptime)
            .unwrap_or_else(Instant::now);

        Ok(Self {
            terminal,
            state: UiState {
                started,
                interfaces,
                timeout,
                ipv6,
                attached_pid,
                log: Vec::new(),
                peers: HashMap::new(),
                scroll_back: 0,
                follow: true,
                quit: false,
                errors: Vec::new(),
            },
            restored: false,
        })
    }

    pub fn push_event(&mut self, event: Event) {
        let elapsed = self.state.started.elapsed();
        self.push_event_at(event, elapsed);
    }

    /// Push an event with the service's elapsed timestamp.
    pub fn push_event_at(&mut self, event: Event, elapsed: Duration) {
        let seen_at = self
            .state
            .started
            .checked_add(elapsed)
            .unwrap_or_else(Instant::now);
        let flood = matches!(event, Event::FloodDetected { .. });
        let pair_complete = matches!(event, Event::EchoReply { .. } | Event::EchoTimeout { .. });
        self.state.observe(&event, seen_at);
        self.state.log.push(LogLine {
            body: LogBody::Event(event),
        });
        if flood {
            self.state.log.push(LogLine {
                body: LogBody::System("Use --no-limit to skip this security features.".to_string()),
            });
        }
        if pair_complete {
            self.state.log.push(LogLine {
                body: LogBody::Spacer,
            });
        }
        self.state.trim_log();
    }

    /// Add an informational line to the signal feed.
    pub fn push_system(&mut self, message: impl Into<String>) {
        let message = text::sanitize(&message.into());
        self.state.log.push(LogLine {
            body: LogBody::System(message),
        });
        self.state.trim_log();
    }

    pub fn push_error(&mut self, interface: &str, error: &str) {
        let message = format!("capture on {interface} stopped: {error}");
        self.state.errors.push(text::sanitize(&message));
        self.push_system(message);
    }

    pub fn poll(&mut self) -> Result<()> {
        while event::poll(Duration::ZERO)? {
            let TerminalEvent::Key(key) = event::read()? else {
                continue;
            };
            if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                continue;
            }
            if key.modifiers.contains(KeyModifiers::CONTROL)
                && matches!(key.code, KeyCode::Char('c'))
            {
                self.state.quit = true;
                continue;
            }

            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => self.state.quit = true,
                KeyCode::Up | KeyCode::Char('k') => {
                    self.state.follow = false;
                    self.state.scroll_back = self.state.scroll_back.saturating_add(1);
                }
                KeyCode::Down | KeyCode::Char('j') => self.scroll_down(1),
                KeyCode::PageUp => {
                    self.state.follow = false;
                    self.state.scroll_back = self.state.scroll_back.saturating_add(10);
                }
                KeyCode::PageDown => self.scroll_down(10),
                KeyCode::Home => {
                    self.state.follow = false;
                    self.state.scroll_back = self.state.log.len();
                }
                KeyCode::End => {
                    self.state.follow = true;
                    self.state.scroll_back = 0;
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn scroll_down(&mut self, amount: usize) {
        self.state.scroll_back = self.state.scroll_back.saturating_sub(amount);
        if self.state.scroll_back == 0 {
            self.state.follow = true;
        }
    }

    pub fn quit_requested(&self) -> bool {
        self.state.quit
    }

    pub fn draw(&mut self, stats: &Stats) -> Result<()> {
        let state = &self.state;
        self.terminal
            .draw(|frame| render(frame, state, stats))
            .context("draw console")?;
        Ok(())
    }

    pub fn finish(&mut self) -> Result<()> {
        self.restore()
    }

    pub fn take_errors(&mut self) -> Vec<String> {
        std::mem::take(&mut self.state.errors)
    }

    fn restore(&mut self) -> Result<()> {
        if self.restored {
            return Ok(());
        }
        self.restored = true;

        disable_raw_mode().ok();
        execute!(io::stdout(), LeaveAlternateScreen, Show).context("restore terminal")?;
        Ok(())
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

impl UiState {
    fn observe(&mut self, event: &Event, seen_at: Instant) {
        match event {
            Event::EchoRequest {
                peer, duplicate, ..
            } => {
                let entry = self.peer_entry(*peer);
                entry.last_seen = Some(seen_at);
                if *duplicate {
                    entry.state = PeerState::Pending;
                } else {
                    entry.requests += 1;
                    entry.state = PeerState::Pending;
                }
            }
            Event::EchoReply {
                peer, rtt, tracked, ..
            } => {
                let entry = self.peer_entry(*peer);
                entry.last_seen = Some(seen_at);
                if *tracked {
                    entry.replies += 1;
                    entry.last_rtt = *rtt;
                    entry.state = PeerState::Replied;
                } else {
                    entry.state = PeerState::Untracked;
                }
            }
            Event::EchoTimeout { peer, .. } => {
                let entry = self.peer_entry(*peer);
                entry.last_seen = Some(seen_at);
                entry.misses += 1;
                entry.state = PeerState::NoReply;
            }
            Event::FloodDetected { peer, .. } => {
                let entry = self.peer_entry(*peer);
                entry.last_seen = Some(seen_at);
                entry.state = PeerState::Flood;
            }
            Event::IcmpTcpError { .. } => {}
        }
    }

    fn peer_entry(&mut self, peer: IpAddr) -> &mut Peer {
        if !self.peers.contains_key(&peer) && self.peers.len() >= MAX_PEERS {
            if let Some(oldest) = self
                .peers
                .iter()
                .min_by_key(|(_, entry)| entry.last_seen)
                .map(|(address, _)| *address)
            {
                self.peers.remove(&oldest);
            }
        }
        self.peers.entry(peer).or_insert_with(Peer::new)
    }

    fn trim_log(&mut self) {
        if self.log.len() > MAX_LOG_LINES {
            let excess = self.log.len() - MAX_LOG_LINES;
            self.log.drain(0..excess);
        }
    }

    fn uptime(&self) -> Duration {
        self.started.elapsed()
    }
}

fn install_panic_hook() {
    let original = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
        original(info);
    }));
}

fn render(frame: &mut Frame<'_>, state: &UiState, stats: &Stats) {
    let area = frame.area();
    frame.render_widget(Block::default().style(Style::default().bg(BG)), area);

    if area.width < 76 || area.height < 20 {
        let message = Paragraph::new(vec![
            Line::from(Span::styled(
                "EMPING",
                Style::default().fg(RED).add_modifier(Modifier::BOLD),
            )),
            Line::from("terminal too small"),
            Line::from(format!(
                "{}x{} (need at least 76x20)",
                area.width, area.height
            ))
            .style(Style::default().fg(DIM)),
        ])
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(RED_DIM)),
        );
        frame.render_widget(message, area);
        return;
    }

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(5),
            Constraint::Length(1),
        ])
        .split(area);

    render_classification(frame, outer[0]);
    render_header(frame, outer[1], state);
    render_main(frame, outer[2], state);
    render_telemetry(frame, outer[3], state, stats);
    render_footer(frame, outer[4], state);
}

fn render_classification(frame: &mut Frame<'_>, area: ratatui::layout::Rect) {
    let banner = Line::from(Span::styled(
        format!(
            "EMPING - ICMP CAPTURE CONSOLE v{}",
            env!("CARGO_PKG_VERSION")
        ),
        Style::default()
            .fg(Color::Rgb(220, 58, 72))
            .add_modifier(Modifier::BOLD),
    ));

    frame.render_widget(
        Paragraph::new(banner)
            .alignment(Alignment::Center)
            .style(Style::default().bg(Color::Rgb(32, 5, 9))),
        area,
    );
}

fn render_header(frame: &mut Frame<'_>, area: ratatui::layout::Rect, state: &UiState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(RED_DIM))
        .title(Line::from(Span::styled(
            " EMPING ",
            Style::default().fg(RED).add_modifier(Modifier::BOLD),
        )))
        .style(Style::default().bg(PANEL));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(20), Constraint::Length(27)])
        .split(inner);

    let left = Line::from(vec![
        Span::styled("OPERATION ", Style::default().fg(DIM)),
        Span::styled(
            OPERATION,
            Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
        ),
    ]);
    let (status, status_color) = match state.attached_pid {
        Some(_) => ("[ ATTACHED ]".to_string(), CYAN),
        None => ("[ LIVE ]".to_string(), GREEN),
    };
    let right = Line::from(vec![
        Span::styled(
            status,
            Style::default()
                .fg(status_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  UP {}", format_uptime(state.uptime())),
            Style::default().fg(DIM),
        ),
    ]);

    frame.render_widget(Paragraph::new(left), columns[0]);
    frame.render_widget(
        Paragraph::new(right).alignment(Alignment::Right),
        columns[1],
    );
}

fn render_main(frame: &mut Frame<'_>, area: ratatui::layout::Rect, state: &UiState) {
    if area.width >= 110 {
        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(64), Constraint::Percentage(36)])
            .spacing(1)
            .split(area);
        render_feed(frame, columns[0], state);
        render_peers(frame, columns[1], state);
    } else {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .spacing(1)
            .split(area);
        render_feed(frame, rows[0], state);
        render_peers(frame, rows[1], state);
    }
}

fn render_feed(frame: &mut Frame<'_>, area: ratatui::layout::Rect, state: &UiState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(RED_DIM))
        .title(Line::from(vec![
            Span::styled(
                " SIGNAL FEED ",
                Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                if state.ipv6 {
                    "[ICMPv4, ICMPv6] "
                } else {
                    "[ICMPv4] "
                },
                Style::default().fg(DIM),
            ),
        ]))
        .style(Style::default().bg(PANEL));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.height == 0 || inner.width == 0 {
        return;
    }

    if state.log.is_empty() {
        render_placeholder(frame, inner, "AWAITING ICMP TRAFFIC");
        return;
    }

    let height = usize::from(inner.height);
    let total = state.log.len();
    let max_back = total.saturating_sub(height);
    let back = state.scroll_back.min(max_back);
    let end = total.saturating_sub(back);
    let start = end.saturating_sub(height);

    let rendered = state.log[start..end]
        .iter()
        .map(render_log_line)
        .collect::<Vec<_>>();

    // Terminals feed from the bottom: keep the newest event on the last row.
    let mut lines = Vec::with_capacity(height);
    for _ in 0..height.saturating_sub(rendered.len()) {
        lines.push(Line::from(""));
    }
    lines.extend(rendered);

    frame.render_widget(
        Paragraph::new(lines).style(Style::default().bg(PANEL)),
        inner,
    );
}

fn render_peers(frame: &mut Frame<'_>, area: ratatui::layout::Rect, state: &UiState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(RED_DIM))
        .title(Line::from(vec![
            Span::styled(
                " TARGETS ",
                Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("[{} PEERS] ", state.peers.len()),
                Style::default().fg(DIM),
            ),
        ]))
        .style(Style::default().bg(PANEL));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.height == 0 || inner.width == 0 {
        return;
    }

    if state.peers.is_empty() {
        render_placeholder(frame, inner, "NO PEERS OBSERVED");
        return;
    }

    let wide = inner.width >= 50;
    let mut peers = state.peers.iter().collect::<Vec<_>>();
    peers.sort_by(|left, right| {
        right
            .1
            .last_seen
            .cmp(&left.1.last_seen)
            .then_with(|| left.0.cmp(right.0))
    });

    let rows = peers
        .iter()
        .take(usize::from(inner.height).saturating_sub(1))
        .map(|(address, peer)| {
            let mut cells = vec![
                Cell::from(display_peer(address)).style(Style::default().fg(TEXT)),
                count_cell(peer.requests, TEXT),
                count_cell(peer.replies, GREEN),
                count_cell(peer.misses, RED),
            ];
            if wide {
                cells.push(
                    Cell::from(
                        peer.last_rtt
                            .map(format_duration)
                            .unwrap_or_else(|| "-".to_string()),
                    )
                    .style(Style::default().fg(DIM)),
                );
            }
            cells.push(
                Cell::from(peer.state.label()).style(
                    Style::default()
                        .fg(peer.state.color())
                        .add_modifier(Modifier::BOLD),
                ),
            );
            Row::new(cells)
        });

    let headers = if wide {
        vec!["PEER", "REQ", "REP", "LOST", "RTT", "STATE"]
    } else {
        vec!["PEER", "REQ", "REP", "LOST", "STATE"]
    };
    let widths = if wide {
        vec![
            Constraint::Length(15),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(4),
            Constraint::Length(8),
            Constraint::Min(8),
        ]
    } else {
        vec![
            Constraint::Length(15),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(4),
            Constraint::Min(8),
        ]
    };

    let table = Table::new(rows, widths)
        .header(Row::new(headers).style(Style::default().fg(RED).add_modifier(Modifier::BOLD)))
        .column_spacing(1)
        .style(Style::default().bg(PANEL));

    frame.render_widget(table, inner);
}

fn render_telemetry(
    frame: &mut Frame<'_>,
    area: ratatui::layout::Rect,
    state: &UiState,
    stats: &Stats,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(RED_DIM))
        .title(Line::from(Span::styled(
            " TELEMETRY ",
            Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
        )))
        .style(Style::default().bg(PANEL));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.height == 0 || inner.width == 0 {
        return;
    }

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
        .spacing(2)
        .split(inner);

    let left = vec![
        Line::from(vec![
            label("INTERFACES  "),
            Span::styled(state.interfaces.clone(), Style::default().fg(TEXT)),
        ]),
        Line::from(vec![
            label("TIMEOUT     "),
            Span::styled(
                match state.timeout {
                    Some(timeout) => format_duration(timeout),
                    None => "disabled".to_string(),
                },
                Style::default().fg(TEXT),
            ),
        ]),
        Line::from(vec![
            label("UPTIME      "),
            Span::styled(format_uptime(state.uptime()), Style::default().fg(TEXT)),
        ]),
    ];

    let right = vec![
        Line::from(vec![
            label("REQUESTS "),
            value(stats.requests, TEXT),
            label("  REPLIED "),
            value(stats.replied, GREEN),
            label("  LOST "),
            value(stats.unanswered, RED),
        ]),
        Line::from(vec![
            label("PENDING "),
            value(stats.pending, AMBER),
            label("  DUP "),
            value(stats.duplicates, DIM),
            label("  UNTRACKED "),
            value(stats.untracked_replies, MAGENTA),
        ]),
        Line::from(vec![label("ICMP/TCP "), value(stats.icmp_tcp_errors, CYAN)]),
    ];

    frame.render_widget(
        Paragraph::new(left).style(Style::default().bg(PANEL)),
        columns[0],
    );
    frame.render_widget(
        Paragraph::new(right).style(Style::default().bg(PANEL)),
        columns[1],
    );
}

fn render_footer(frame: &mut Frame<'_>, area: ratatui::layout::Rect, state: &UiState) {
    let hints = Line::from(vec![
        key("Q"),
        label(" quit  "),
        key("UP/DN"),
        label(" scroll  "),
        key("PGUP/PGDN"),
        label(" page  "),
        key("HOME"),
        label(" oldest  "),
        key("END"),
        label(" live"),
    ]);

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(30), Constraint::Length(22)])
        .split(area);

    frame.render_widget(Paragraph::new(hints), columns[0]);

    let status = if !state.follow {
        Some(Line::from(Span::styled(
            format!("SCROLLBACK // -{}", state.scroll_back),
            Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
        )))
    } else if state.attached_pid.is_none() {
        Some(Line::from(Span::styled(
            "FOLLOW // LIVE",
            Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
        )))
    } else {
        None
    };

    if let Some(status) = status {
        frame.render_widget(
            Paragraph::new(status).alignment(Alignment::Right),
            columns[1],
        );
    }
}

fn render_log_line(entry: &LogLine) -> Line<'static> {
    match &entry.body {
        LogBody::Spacer => Line::from(""),
        LogBody::System(message) => Line::from(vec![
            Span::styled(
                "SYS  ",
                Style::default().fg(RED).add_modifier(Modifier::BOLD),
            ),
            Span::styled(message.clone(), Style::default().fg(RED)),
        ]),
        LogBody::Event(event) => match event {
            Event::EchoRequest {
                peer,
                local,
                id,
                seq,
                duplicate,
                ..
            } => {
                let mut spans = vec![
                    Span::styled(
                        "REQ  ",
                        Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(display_peer(peer), Style::default().fg(TEXT)),
                    Span::styled(" -> ", Style::default().fg(DIM)),
                    Span::styled(display_peer(local), Style::default().fg(DIM)),
                    Span::styled(format!("  #{id}/{seq}"), Style::default().fg(DIM)),
                    Span::styled("  PENDING", Style::default().fg(AMBER)),
                ];
                if *duplicate {
                    spans.push(Span::styled(" RETRY", Style::default().fg(RED)));
                }
                Line::from(spans)
            }
            Event::EchoReply {
                peer,
                local,
                id,
                seq,
                rtt,
                tracked,
                ..
            } => {
                let (state, color) = if *tracked {
                    ("REPLIED", GREEN)
                } else {
                    ("UNTRACKED", MAGENTA)
                };
                Line::from(vec![
                    Span::styled(
                        "REP  ",
                        Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(display_peer(local), Style::default().fg(DIM)),
                    Span::styled(" -> ", Style::default().fg(DIM)),
                    Span::styled(display_peer(peer), Style::default().fg(TEXT)),
                    Span::styled(format!("  #{id}/{seq}"), Style::default().fg(DIM)),
                    Span::styled(
                        format!(
                            " rtt={}",
                            rtt.map(format_duration).unwrap_or_else(|| "-".to_string())
                        ),
                        Style::default().fg(DIM),
                    ),
                    Span::styled(format!(" {state}"), Style::default().fg(color)),
                ])
            }
            Event::EchoTimeout {
                peer,
                local,
                id,
                seq,
                after,
                ..
            } => Line::from(vec![
                Span::styled(
                    "LOST ",
                    Style::default().fg(RED).add_modifier(Modifier::BOLD),
                ),
                Span::styled(display_peer(peer), Style::default().fg(TEXT)),
                Span::styled(" -> ", Style::default().fg(DIM)),
                Span::styled(display_peer(local), Style::default().fg(DIM)),
                Span::styled(format!("  #{id}/{seq}"), Style::default().fg(DIM)),
                Span::styled("  NO REPLY", Style::default().fg(RED)),
                Span::styled(
                    format!(" {}", format_duration(*after)),
                    Style::default().fg(DIM),
                ),
            ]),
            Event::FloodDetected { peer, .. } => Line::from(vec![
                Span::styled(
                    "FLOOD ",
                    Style::default().fg(RED).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("Possible Flood, Skip Capture {}", display_peer(peer)),
                    Style::default().fg(RED),
                ),
            ]),
            Event::IcmpTcpError {
                reporter,
                original_src,
                original_dst,
                src_port,
                dst_port,
                icmp_type,
                icmp_code,
                ..
            } => Line::from(vec![
                Span::styled(
                    "ICMP ",
                    Style::default().fg(MAGENTA).add_modifier(Modifier::BOLD),
                ),
                Span::styled(display_peer(reporter), Style::default().fg(TEXT)),
                Span::styled(": ", Style::default().fg(DIM)),
                Span::styled(
                    format!("{}:{}", display_peer(original_src), src_port),
                    Style::default().fg(DIM),
                ),
                Span::styled(" -> ", Style::default().fg(DIM)),
                Span::styled(
                    format!("{}:{}", display_peer(original_dst), dst_port),
                    Style::default().fg(TEXT),
                ),
                Span::styled(
                    format!(" ({icmp_type}/{icmp_code})"),
                    Style::default().fg(DIM),
                ),
            ]),
        },
    }
}

fn render_placeholder(frame: &mut Frame<'_>, area: ratatui::layout::Rect, text: &str) {
    let mut lines = Vec::new();
    for _ in 0..area.height.saturating_sub(1) / 2 {
        lines.push(Line::from(""));
    }
    lines.push(Line::from(Span::styled(
        text,
        Style::default().fg(DIM).add_modifier(Modifier::DIM),
    )));
    frame.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .style(Style::default().bg(PANEL)),
        area,
    );
}

fn label(text: &'static str) -> Span<'static> {
    Span::styled(text, Style::default().fg(DIM))
}

fn key(text: &'static str) -> Span<'static> {
    Span::styled(text, Style::default().fg(RED).add_modifier(Modifier::BOLD))
}

fn value(value: u64, color: Color) -> Span<'static> {
    let color = if value == 0 { DIM } else { color };
    Span::styled(value.to_string(), Style::default().fg(color))
}

fn count_cell(value: u64, color: Color) -> Cell<'static> {
    let color = if value == 0 { DIM } else { color };
    Cell::from(value.to_string()).style(Style::default().fg(color))
}

fn display_peer(address: &IpAddr) -> String {
    match address {
        IpAddr::V4(address) => address.to_string(),
        IpAddr::V6(address) => {
            let value = address.to_string();
            if value.len() <= 15 {
                value
            } else {
                let head = &value[..6];
                let tail = &value[value.len() - 6..];
                format!("{head}..{tail}")
            }
        }
    }
}

fn format_uptime(duration: Duration) -> String {
    let seconds = duration.as_secs();
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    let seconds = seconds % 60;

    if days > 0 {
        format!("{days}d {hours:02}:{minutes:02}:{seconds:02}")
    } else {
        format!("{hours:02}:{minutes:02}:{seconds:02}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
    const PEER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 50);

    fn sample_state() -> UiState {
        let mut state = UiState {
            started: Instant::now(),
            interfaces: "eth0, lo".to_string(),
            timeout: Some(Duration::from_secs(2)),
            ipv6: false,
            attached_pid: None,
            log: Vec::new(),
            peers: HashMap::new(),
            scroll_back: 0,
            follow: true,
            quit: false,
            errors: Vec::new(),
        };

        let request = Event::EchoRequest {
            interface: "eth0".into(),
            peer: PEER.into(),
            local: LOCAL.into(),
            id: 7,
            seq: 1,
            duplicate: false,
        };
        state.observe(&request, Instant::now());
        state.log.push(LogLine {
            body: LogBody::Event(request),
        });

        let reply = Event::EchoReply {
            interface: "eth0".into(),
            peer: PEER.into(),
            local: LOCAL.into(),
            id: 7,
            seq: 1,
            rtt: Some(Duration::from_micros(412)),
            tracked: true,
        };
        state.observe(&reply, Instant::now());
        state.log.push(LogLine {
            body: LogBody::Event(reply),
        });
        state.log.push(LogLine {
            body: LogBody::Spacer,
        });

        state
    }

    fn render_to_text(width: u16, height: u16, state: &UiState, stats: &Stats) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render(frame, state, stats)).unwrap();

        let buffer = terminal.backend().buffer();
        buffer
            .content()
            .chunks(usize::from(buffer.area.width))
            .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn renders_operation_console_at_wide_size() {
        let state = sample_state();
        let stats = Stats {
            requests: 1,
            replied: 1,
            pending: 0,
            ..Stats::default()
        };

        let text = render_to_text(120, 40, &state, &stats);
        assert!(!text.contains("ICMP OPERATIONS CONSOLE"));
        assert!(!text.contains("// PASSIVE"));
        assert!(!text.contains("PASSIVE COLLECTION"));
        assert!(text.contains("OPERATION SILENT ECHO"));
        assert!(text.contains(&format!(
            "EMPING - ICMP CAPTURE CONSOLE v{}",
            env!("CARGO_PKG_VERSION")
        )));
        assert!(text.contains("SIGNAL FEED [ICMPv4]"));
        assert!(text.contains("TARGETS [1 PEERS]"));
        assert!(text.contains("REPLIED"));
        assert!(text.contains("192.0.2.50"));
        assert!(text.contains("TELEMETRY"));
        assert!(text.contains("FOLLOW // LIVE"));
    }

    #[test]
    fn renders_compact_layout_at_80_columns() {
        let state = sample_state();
        let stats = Stats {
            requests: 1,
            replied: 1,
            ..Stats::default()
        };

        let text = render_to_text(80, 24, &state, &stats);
        assert!(text.contains("SIGNAL FEED"));
        assert!(text.contains("TARGETS"));
        assert!(text.contains("192.0.2.50"));
    }

    #[test]
    fn shows_size_guard_on_tiny_terminals() {
        let state = sample_state();
        let text = render_to_text(40, 10, &state, &Stats::default());
        assert!(text.contains("terminal too small"));
    }

    #[test]
    fn renders_attached_console_state() {
        let mut state = sample_state();
        state.attached_pid = Some(1234);
        let stats = Stats {
            requests: 1,
            replied: 1,
            ..Stats::default()
        };

        let text = render_to_text(120, 40, &state, &stats);
        assert!(text.contains("[ ATTACHED ]"));
        assert!(!text.contains("FOLLOW // ATTACHED"));
    }

    #[test]
    fn renders_dual_stack_feed_title_when_ipv6_enabled() {
        let mut state = sample_state();
        state.ipv6 = true;
        let text = render_to_text(120, 40, &state, &Stats::default());
        assert!(text.contains("SIGNAL FEED [ICMPv4, ICMPv6]"));
    }

    #[test]
    fn shortens_ipv6_peer_addresses() {
        let address = IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x0db8, 0xabcd, 0x1234, 0x5678, 0x9abc, 0xdef0, 0x1234,
        ));
        let text = display_peer(&address);
        assert!(text.len() <= 15);
        assert!(text.contains(".."));
    }

    #[test]
    fn formats_uptime() {
        assert_eq!(format_uptime(Duration::from_secs(5)), "00:00:05");
        assert_eq!(format_uptime(Duration::from_secs(3_661)), "01:01:01");
        assert_eq!(format_uptime(Duration::from_secs(90_061)), "1d 01:01:01");
    }
}
