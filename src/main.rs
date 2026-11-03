mod capture;
mod cli;
mod net;
mod output;
mod protocol;
mod service;
mod text;
mod tracker;
mod tui;

use std::io::{self, IsTerminal};
use std::process::ExitCode;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use clap::Parser;
use pnet::datalink;

use crate::cli::{Cli, Command};
use crate::output::Printer;
use crate::tracker::{Event, Processor};
use crate::tui::Tui;

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("emping: {}", text::sanitize(&format!("{err:#}")));
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();

    if cli.list {
        net::list_interfaces(&datalink::interfaces());
        return Ok(ExitCode::SUCCESS);
    }

    let timeout = parse_timeout(cli.timeout)?;

    match cli.command {
        Some(Command::Run) => run_standalone(&cli, timeout),
        Some(Command::Daemon) => service::run_daemon(&cli, timeout),
        Some(Command::Start) => service::start(&cli, timeout),
        Some(Command::Stop) => service::stop(&cli),
        Some(Command::Status) => service::status(&cli),
        Some(Command::Tui) => {
            capture::install_signal_handlers();
            service::attach_tui(&cli)
        }
        None => run_default(&cli, timeout),
    }
}

fn run_default(cli: &Cli, timeout: Option<Duration>) -> Result<ExitCode> {
    let interactive =
        !cli.json && !cli.plain && io::stdout().is_terminal() && io::stdin().is_terminal();

    if !interactive {
        if service::is_running(cli) {
            warn_ignored_options(cli);
            capture::install_signal_handlers();
            service::attach_stream(cli)
        } else {
            run_standalone(cli, timeout)
        }
    } else {
        if service::is_running(cli) {
            warn_ignored_options(cli);
        } else {
            service::start(cli, timeout)?;
        }
        capture::install_signal_handlers();
        service::attach_tui(cli)
    }
}

fn warn_ignored_options(cli: &Cli) {
    if !cli.interfaces.is_empty() || cli.loopback || cli.promisc || cli.ipv6 || cli.no_limit {
        eprintln!(
            "emping: service is already running; capture options apply only when it is started"
        );
    }
}

fn run_standalone(cli: &Cli, timeout: Option<Duration>) -> Result<ExitCode> {
    let interfaces = datalink::interfaces();
    let selected = net::select_interfaces(&interfaces, cli)?;
    let local_ips = net::local_ips(&interfaces);

    capture::install_signal_handlers();

    let mut receivers = Vec::new();
    for iface in &selected {
        match capture::open(iface, cli.promisc) {
            Ok(receiver) => receivers.push((iface.name.clone(), receiver)),
            Err(err) => {
                let error = text::sanitize(&format!("{err:#}"));
                let name = text::sanitize(&iface.name);
                eprintln!(
                    "emping: cannot capture on {name}: {error}{}",
                    net::permission_hint(&error)
                );
            }
        }
    }

    if receivers.is_empty() {
        bail!("no interfaces could be opened (try --list, --interface, or run as root)");
    }

    let (tx, rx) = mpsc::channel();
    let mut opened = Vec::with_capacity(receivers.len());
    for (name, receiver) in receivers {
        let handle = capture::spawn(name.clone(), receiver, tx.clone(), cli.ipv6);
        opened.push((name, handle));
    }
    drop(tx);

    let interface_list = opened
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(", ");

    let interactive =
        !cli.json && !cli.plain && io::stdout().is_terminal() && io::stdin().is_terminal();
    let mut tui = if interactive {
        match Tui::new(interface_list.clone(), timeout, cli.ipv6) {
            Ok(tui) => Some(tui),
            Err(err) => {
                eprintln!("emping: cannot start console: {err:#}; falling back to line output");
                None
            }
        }
    } else {
        None
    };

    if tui.is_none() {
        let protocols = if cli.ipv6 { "ICMPv4/ICMPv6" } else { "ICMPv4" };
        eprintln!(
            "emping: watching {protocols} echo on {}{}",
            text::sanitize(&interface_list),
            match timeout {
                Some(t) => format!(" (reply timeout {:.3}s)", t.as_secs_f64()),
                None => " (reply timeout disabled)".to_string(),
            }
        );
    }

    let mut processor = Processor::new_with_limit(local_ips, timeout, !cli.no_limit);
    let printer = Printer::new(cli.json);
    let mut alive = opened.len();
    let mut capture_failed = false;

    while capture::running() && alive > 0 {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(capture::Message::Frame {
                interface,
                data,
                at,
            }) => {
                for event in processor.handle_frame(&interface, &data, at) {
                    present(&mut tui, &printer, event);
                }
            }
            Ok(capture::Message::Error { interface, error }) => {
                if let Some(tui) = tui.as_mut() {
                    tui.push_error(&interface, &error);
                } else {
                    let message =
                        text::sanitize(&format!("capture on {interface} stopped: {error}"));
                    eprintln!("emping: {message}{}", net::permission_hint(&error));
                }
                capture_failed = true;
            }
            Ok(capture::Message::Stopped) => {
                alive = alive.saturating_sub(1);
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }

        for event in processor.expire(Instant::now()) {
            present(&mut tui, &printer, event);
        }

        if let Some(tui) = tui.as_mut() {
            tui.poll()?;
            tui.draw(&processor.stats())?;
            if tui.quit_requested() {
                capture::request_shutdown();
                break;
            }
        }
    }

    if let Some(mut tui) = tui {
        tui.finish()?;
        for error in tui.take_errors() {
            eprintln!("emping: {error}");
        }
    }

    printer.summary(&processor.stats());

    if capture_failed && !capture::was_interrupted() {
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

fn present(tui: &mut Option<Tui>, printer: &Printer, event: Event) {
    match tui {
        Some(tui) => tui.push_event(event),
        None => printer.emit(&event),
    }
}

fn parse_timeout(value: f64) -> Result<Option<Duration>> {
    match value {
        t if !t.is_finite() || t < 0.0 => {
            bail!("--timeout must be a finite, non-negative number")
        }
        0.0 => Ok(None),
        t => Ok(Some(
            Duration::try_from_secs_f64(t)
                .map_err(|_| anyhow::anyhow!("--timeout is too large"))?,
        )),
    }
}
