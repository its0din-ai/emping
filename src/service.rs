use std::collections::VecDeque;
use std::fs::{self, OpenOptions, Permissions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use pnet::datalink;
use serde_json::json;

use crate::capture;
use crate::cli::Cli;
use crate::net;
use crate::output::Printer;
use crate::protocol::{self, ClientRequest, Hello, ServerMessage, Status, TimedEvent, VERSION};
use crate::text;
use crate::tracker::{Event, Processor, Stats};
use crate::tui::Tui;

const RECENT_EVENTS: usize = 1_000;
const CLIENT_BUFFER: usize = 256;
const START_TIMEOUT: Duration = Duration::from_secs(3);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_REQUEST_BYTES: usize = 8 * 1024;
const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
const MAX_CLIENTS: usize = 64;
const MAX_CONNECTIONS: usize = 128;

#[derive(Debug, Clone)]
pub struct Paths {
    pub runtime_dir: PathBuf,
    pub socket: PathBuf,
    pub pid_file: PathBuf,
    pub log_file: PathBuf,
}

pub fn paths(cli: &Cli) -> Result<Paths> {
    let socket = match &cli.socket {
        Some(path) => absolute(path)?,
        None => default_runtime_dir().join("emping.sock"),
    };
    let runtime_dir = socket
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/"));

    let pid_file = match &cli.pid_file {
        Some(path) => absolute(path)?,
        None => runtime_dir.join("emping.pid"),
    };
    let log_file = match &cli.log_file {
        Some(path) => absolute(path)?,
        None => runtime_dir.join("emping.log"),
    };

    Ok(Paths {
        runtime_dir,
        socket,
        pid_file,
        log_file,
    })
}

fn absolute(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

fn root_runtime_dir() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/var/run/emping")
    } else {
        PathBuf::from("/run/emping")
    }
}

fn default_runtime_dir() -> PathBuf {
    if euid() == 0 {
        return root_runtime_dir();
    }

    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir).join("emping");
        }
    }

    PathBuf::from(format!("/tmp/emping-{}", euid()))
}

fn ensure_dir(dir: &Path) -> Result<()> {
    if dir.as_os_str().is_empty() {
        return Ok(());
    }

    if !dir.exists() {
        fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        let mode = if euid() == 0 { 0o755 } else { 0o700 };
        fs::set_permissions(dir, Permissions::from_mode(mode)).ok();
    }

    let metadata =
        fs::symlink_metadata(dir).with_context(|| format!("inspect {}", dir.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("{} is not a real directory", dir.display());
    }
    let private_fallback = dir
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == format!("emping-{}", euid()));
    if private_fallback && euid() != 0 && metadata.uid() != euid() {
        bail!("{} is not owned by the current user", dir.display());
    }
    Ok(())
}

pub fn is_running(cli: &Cli) -> bool {
    paths(cli)
        .ok()
        .and_then(|paths| status_request(&paths).ok())
        .is_some()
}

fn lock_path(socket: &Path) -> PathBuf {
    let mut name = socket.file_name().unwrap_or_default().to_os_string();
    name.push(".lock");
    socket.with_file_name(name)
}

struct ServiceLock {
    _file: fs::File,
}

fn acquire_service_lock(socket: &Path) -> Result<ServiceLock> {
    let path = lock_path(socket);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .with_context(|| format!("open lock {}", path.display()))?;

    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == -1 {
        bail!("another emping service is already starting or running");
    }

    Ok(ServiceLock { _file: file })
}

pub fn status(cli: &Cli) -> Result<ExitCode> {
    let paths = paths(cli)?;

    match status_request(&paths) {
        Ok(status) => {
            if cli.json {
                println!(
                    "{}",
                    json!({
                        "running": true,
                        "pid": status.pid,
                        "socket": paths.socket.display().to_string(),
                        "interfaces": status.interfaces,
                        "ipv6": status.ipv6,
                        "timeout_ms": status.timeout_ms,
                        "uptime_ms": status.uptime_ms,
                        "stats": status.stats,
                    })
                );
            } else {
                println!("emping service: running");
                println!("  pid         {}", status.pid);
                println!("  socket      {}", paths.socket.display());
                println!(
                    "  interfaces  {}",
                    text::sanitize(&status.interfaces.join(", "))
                );
                println!(
                    "  protocols   {}",
                    if status.ipv6 {
                        "ICMPv4, ICMPv6"
                    } else {
                        "ICMPv4"
                    }
                );
                println!("  timeout     {}", format_timeout(status.timeout_ms));
                println!(
                    "  uptime      {}",
                    format_uptime(Duration::from_secs_f64(status.uptime_ms / 1000.0))
                );
                println!(
                    "  requests    {}  replied {}  unanswered {}  pending {}",
                    status.stats.requests,
                    status.stats.replied,
                    status.stats.unanswered,
                    status.stats.pending
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(err) => {
            if cli.json {
                println!("{}", json!({"running": false, "error": format!("{err:#}")}));
            } else {
                eprintln!("emping service: not running");
                eprintln!("  {}", text::sanitize(&format!("{err:#}")));
            }
            Ok(ExitCode::from(3))
        }
    }
}

pub fn stop(cli: &Cli) -> Result<ExitCode> {
    let paths = paths(cli)?;

    match stop_request(&paths) {
        Ok(()) => {
            let deadline = Instant::now() + Duration::from_secs(5);
            while paths.socket.exists() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(100));
            }

            if paths.socket.exists() {
                eprintln!(
                    "emping: service did not remove {}; it may still be shutting down",
                    paths.socket.display()
                );
            }

            if cli.json {
                println!("{}", json!({"running": false, "stopped": true}));
            } else {
                println!("emping service stopped");
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(_) => {
            if cli.json {
                println!("{}", json!({"running": false, "stopped": false}));
            } else {
                println!("emping service is not running");
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

pub fn start(cli: &Cli, timeout: Option<Duration>) -> Result<ExitCode> {
    let paths = paths(cli)?;
    ensure_dir(&paths.runtime_dir)?;
    if let Some(parent) = paths.log_file.parent() {
        ensure_dir(parent)?;
    }

    if let Ok(status) = status_request(&paths) {
        if cli.json {
            println!(
                "{}",
                json!({
                    "running": true,
                    "already_running": true,
                    "pid": status.pid,
                    "socket": paths.socket.display().to_string(),
                })
            );
        } else {
            println!("emping service already running (pid {})", status.pid);
        }
        return Ok(ExitCode::SUCCESS);
    }

    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o640)
        .open(&paths.log_file)
        .with_context(|| format!("open log {}", paths.log_file.display()))?;
    fs::set_permissions(&paths.log_file, Permissions::from_mode(0o640)).ok();

    let executable = std::env::current_exe().context("resolve current executable")?;
    let mut command = Command::new(executable);
    command
        .arg("daemon")
        .arg("--socket")
        .arg(&paths.socket)
        .arg("--pid-file")
        .arg(&paths.pid_file)
        .arg("--timeout")
        .arg(format!(
            "{}",
            timeout.map(|value| value.as_secs_f64()).unwrap_or(0.0)
        ));

    for interface in &cli.interfaces {
        command.arg("--interface").arg(interface);
    }
    if cli.loopback {
        command.arg("--loopback");
    }
    if cli.promisc {
        command.arg("--promisc");
    }
    if cli.ipv6 {
        command.arg("--ipv6");
    }
    if cli.no_limit {
        command.arg("--no-limit");
    }

    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .current_dir("/");

    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            libc::umask(0o027);
            Ok(())
        });
    }

    let mut child = command.spawn().context("spawn emping service")?;

    let deadline = Instant::now() + START_TIMEOUT;
    while Instant::now() < deadline {
        if let Ok(status) = status_request(&paths) {
            if cli.json {
                println!(
                    "{}",
                    json!({
                        "running": true,
                        "already_running": false,
                        "pid": status.pid,
                        "socket": paths.socket.display().to_string(),
                        "log": paths.log_file.display().to_string(),
                    })
                );
            } else {
                println!("emping service started (pid {})", status.pid);
                println!("  socket  {}", paths.socket.display());
                println!("  log     {}", paths.log_file.display());
                println!(
                    "  attach  {}",
                    if euid() == 0 { "sudo emping" } else { "emping" }
                );
            }
            return Ok(ExitCode::SUCCESS);
        }

        if let Some(exit) = child.try_wait()? {
            if let Ok(status) = status_request(&paths) {
                if cli.json {
                    println!(
                        "{}",
                        json!({
                            "running": true,
                            "already_running": true,
                            "pid": status.pid,
                            "socket": paths.socket.display().to_string(),
                        })
                    );
                } else {
                    println!("emping service already running (pid {})", status.pid);
                }
                return Ok(ExitCode::SUCCESS);
            }
            let tail = read_tail(&paths.log_file, 12);
            bail!(
                "service exited during startup ({exit}); log: {}{tail}",
                paths.log_file.display()
            );
        }

        thread::sleep(Duration::from_millis(100));
    }

    let _ = child.kill();
    let _ = fs::remove_file(&paths.socket);
    let _ = fs::remove_file(&paths.pid_file);
    bail!(
        "service did not become ready; see {}",
        paths.log_file.display()
    )
}

pub fn run_daemon(cli: &Cli, timeout: Option<Duration>) -> Result<ExitCode> {
    let paths = paths(cli)?;
    ensure_dir(&paths.runtime_dir)?;
    let _lock = acquire_service_lock(&paths.socket)?;

    // Restrictive default for the socket, PID file, and any future files even if a
    // chmod below fails.
    unsafe {
        libc::umask(0o077);
    }

    let interfaces = datalink::interfaces();
    let selected = net::select_interfaces(&interfaces, cli)?;
    let local_ips = net::local_ips(&interfaces);

    capture::install_signal_handlers();

    let mut receivers = Vec::new();
    for interface in &selected {
        match capture::open(interface, cli.promisc) {
            Ok(receiver) => receivers.push((interface.name.clone(), receiver)),
            Err(err) => {
                let error = text::sanitize(&format!("{err:#}"));
                let name = text::sanitize(&interface.name);
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

    let listener = bind_listener(&paths.socket)?;
    let _guard = RuntimeGuard {
        socket: paths.socket.clone(),
        pid_file: paths.pid_file.clone(),
    };

    fs::set_permissions(&paths.socket, Permissions::from_mode(0o600)).ok();
    write_pid(&paths.pid_file)?;

    let interface_names = receivers
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    let timeout_ms = timeout.map(|value| value.as_secs_f64() * 1000.0);

    eprintln!(
        "emping service listening on {} (pid {})",
        paths.socket.display(),
        std::process::id()
    );

    let (capture_tx, capture_rx) = mpsc::channel();
    let mut alive = receivers.len();
    for (name, receiver) in receivers {
        capture::spawn(name, receiver, capture_tx.clone(), cli.ipv6);
    }
    drop(capture_tx);

    let (request_tx, request_rx) = mpsc::channel();
    let mut processor = Processor::new_with_limit(local_ips, timeout, !cli.no_limit);
    let started = Instant::now();
    let mut recent = VecDeque::with_capacity(RECENT_EVENTS);
    let mut clients: Vec<Client> = Vec::new();
    let mut shutdown = false;
    let mut last_heartbeat = Instant::now();
    let active_connections = Arc::new(AtomicUsize::new(0));

    while capture::running() {
        match capture_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(capture::Message::Frame {
                interface,
                data,
                at,
            }) => {
                for event in processor.handle_frame(&interface, &data, at) {
                    publish_event(
                        event,
                        processor.stats(),
                        &started,
                        &mut recent,
                        &mut clients,
                    );
                }
            }
            Ok(capture::Message::Error { interface, error }) => {
                let message = format!("capture on {interface} stopped: {error}");
                eprintln!(
                    "emping: {}{}",
                    text::sanitize(&message),
                    net::permission_hint(&error)
                );
                broadcast_message(&ServerMessage::error(message), &mut clients);
            }
            Ok(capture::Message::Stopped) => {
                alive = alive.saturating_sub(1);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }

        for event in processor.expire(Instant::now()) {
            publish_event(
                event,
                processor.stats(),
                &started,
                &mut recent,
                &mut clients,
            );
        }

        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    if active_connections.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
                        drop(stream);
                        continue;
                    }
                    active_connections.fetch_add(1, Ordering::Relaxed);
                    let sender = request_tx.clone();
                    let counter = Arc::clone(&active_connections);
                    thread::spawn(move || {
                        handle_connection(stream, sender);
                        counter.fetch_sub(1, Ordering::Relaxed);
                    });
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) => {
                    eprintln!("emping: accept failed: {err}");
                    break;
                }
            }
        }

        while let Ok(request) = request_rx.try_recv() {
            match request {
                Incoming::Subscribe(stream) => {
                    if clients.len() >= MAX_CLIENTS {
                        let mut stream = stream;
                        let _ = stream.set_write_timeout(Some(REQUEST_TIMEOUT));
                        let message = protocol::encode(&ServerMessage::error("too many clients"));
                        let _ = write_line(&mut stream, &message);
                        continue;
                    }
                    let hello = Hello {
                        version: VERSION,
                        pid: std::process::id(),
                        interfaces: interface_names.clone(),
                        ipv6: cli.ipv6,
                        timeout_ms,
                        uptime_ms: started.elapsed().as_secs_f64() * 1000.0,
                        stats: processor.stats(),
                        events: recent.iter().cloned().collect(),
                    };
                    register_client(stream, hello, &mut clients);
                }
                Incoming::Status(reply) => {
                    let status = Status {
                        version: VERSION,
                        pid: std::process::id(),
                        interfaces: interface_names.clone(),
                        ipv6: cli.ipv6,
                        timeout_ms,
                        uptime_ms: started.elapsed().as_secs_f64() * 1000.0,
                        stats: processor.stats(),
                    };
                    let _ = reply.send(protocol::encode(&ServerMessage::Status(status)));
                }
                Incoming::Stop(reply) => {
                    let _ = reply.send(protocol::encode(&ServerMessage::Stopping));
                    shutdown = true;
                    capture::request_shutdown();
                    break;
                }
            }
        }

        if shutdown || alive == 0 {
            break;
        }

        if last_heartbeat.elapsed() >= Duration::from_secs(5) {
            broadcast_message(&ServerMessage::Heartbeat, &mut clients);
            last_heartbeat = Instant::now();
        }
    }

    let stats = processor.stats();
    let summary = protocol::encode(&ServerMessage::Summary {
        stats,
        uptime_ms: started.elapsed().as_secs_f64() * 1000.0,
    });
    broadcast_line(&summary, &mut clients);
    thread::sleep(Duration::from_millis(100));
    clients.clear();

    if !shutdown && !capture::was_interrupted() && alive == 0 {
        bail!("all capture interfaces stopped");
    }

    eprintln!("emping service stopped");
    Ok(ExitCode::SUCCESS)
}

pub fn attach_tui(cli: &Cli) -> Result<ExitCode> {
    let subscription = subscribe(cli)?;
    let hello = &subscription.hello;

    let timeout = hello
        .timeout_ms
        .map(|value| Duration::from_secs_f64(value / 1000.0));
    let uptime = Duration::from_secs_f64(hello.uptime_ms / 1000.0);

    let mut tui = Tui::new_attached(
        hello.interfaces.join(", "),
        timeout,
        hello.ipv6,
        uptime,
        hello.pid,
    )?;

    for timed in &hello.events {
        tui.push_event_at(
            timed.event.clone(),
            Duration::from_secs_f64(timed.elapsed_ms / 1000.0),
        );
    }

    let mut stats = hello.stats;
    let mut service_stopped = false;
    let mut lost_connection = false;

    while capture::running() {
        match subscription.events.recv_timeout(Duration::from_millis(100)) {
            Ok(ClientEvent::Message(ServerMessage::Event {
                elapsed_ms,
                event,
                stats: new_stats,
            })) => {
                stats = new_stats;
                tui.push_event_at(event, Duration::from_secs_f64(elapsed_ms / 1000.0));
            }
            Ok(ClientEvent::Message(ServerMessage::Summary { .. })) => {
                service_stopped = true;
                break;
            }
            Ok(ClientEvent::Message(ServerMessage::Error { message })) => {
                tui.push_system(format!("service: {message}"));
            }
            Ok(ClientEvent::Message(ServerMessage::Stopping)) => {
                tui.push_system("service is stopping");
            }
            Ok(ClientEvent::Message(_)) => {}
            Ok(ClientEvent::Closed(reason)) => {
                if !service_stopped {
                    tui.push_system(format!("service connection closed: {reason}"));
                    lost_connection = true;
                }
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }

        tui.poll()?;
        tui.draw(&stats)?;
        if tui.quit_requested() {
            break;
        }
    }

    let user_quit = tui.quit_requested();
    tui.finish()?;

    if service_stopped {
        eprintln!("emping: service stopped");
    } else if user_quit {
        eprintln!(
            "emping: detached from service (pid {}); it is still running",
            hello.pid
        );
    } else if lost_connection {
        eprintln!("emping: lost connection to service");
    }

    if lost_connection {
        Ok(ExitCode::FAILURE)
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

pub fn attach_stream(cli: &Cli) -> Result<ExitCode> {
    let subscription = subscribe(cli)?;
    let hello = &subscription.hello;
    let printer = Printer::new(cli.json);
    let mut stats = hello.stats;

    if !cli.json {
        eprintln!(
            "emping: attached to service pid {} on {}",
            hello.pid,
            text::sanitize(&hello.interfaces.join(", "))
        );
    }

    let mut lost_connection = false;

    while capture::running() {
        match subscription.events.recv_timeout(Duration::from_millis(100)) {
            Ok(ClientEvent::Message(ServerMessage::Event {
                elapsed_ms,
                event,
                stats: new_stats,
            })) => {
                stats = new_stats;
                printer.emit_at(&event, Duration::from_secs_f64(elapsed_ms / 1000.0));
            }
            Ok(ClientEvent::Message(ServerMessage::Summary {
                stats: new_stats, ..
            })) => {
                stats = new_stats;
                break;
            }
            Ok(ClientEvent::Message(ServerMessage::Error { message })) => {
                eprintln!("emping: service: {}", text::sanitize(&message));
            }
            Ok(ClientEvent::Message(ServerMessage::Stopping)) => {}
            Ok(ClientEvent::Message(_)) => {}
            Ok(ClientEvent::Closed(reason)) => {
                eprintln!("emping: lost connection to service: {reason}");
                lost_connection = true;
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    printer.summary(&stats);

    if lost_connection && !capture::was_interrupted() {
        Ok(ExitCode::FAILURE)
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

pub struct Subscription {
    pub hello: Hello,
    pub events: Receiver<ClientEvent>,
}

#[derive(Debug)]
pub enum ClientEvent {
    Message(ServerMessage),
    Closed(String),
}

fn subscribe(cli: &Cli) -> Result<Subscription> {
    subscribe_paths(&paths(cli)?)
}

fn subscribe_paths(paths: &Paths) -> Result<Subscription> {
    let mut stream = connect(paths)?;
    stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;
    send_request(&mut stream, &ClientRequest::Subscribe)?;

    let read_stream = stream.try_clone()?;
    read_stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    let mut reader = BufReader::new(read_stream);

    let hello = match read_message(&mut reader)? {
        ServerMessage::Hello(hello) => hello,
        ServerMessage::Error { message } => bail!("{message}"),
        other => bail!("unexpected handshake response: {other:?}"),
    };
    if hello.version != VERSION {
        bail!(
            "service protocol version {} does not match client version {}",
            hello.version,
            VERSION
        );
    }

    reader.get_ref().set_read_timeout(None)?;
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || loop {
        match read_message(&mut reader) {
            Ok(message) => {
                if sender.send(ClientEvent::Message(message)).is_err() {
                    break;
                }
            }
            Err(err) => {
                let _ = sender.send(ClientEvent::Closed(format!("{err:#}")));
                break;
            }
        }
    });

    Ok(Subscription {
        hello,
        events: receiver,
    })
}

enum Incoming {
    Subscribe(UnixStream),
    Status(Sender<String>),
    Stop(Sender<String>),
}

struct Client {
    tx: SyncSender<String>,
}

fn handle_connection(mut stream: UnixStream, sender: Sender<Incoming>) {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(REQUEST_TIMEOUT)).ok();

    let reader = match stream.try_clone() {
        Ok(stream) => BufReader::new(stream),
        Err(_) => return,
    };
    let mut reader = reader;
    let line = match read_line_limited(&mut reader, MAX_REQUEST_BYTES) {
        Ok(Some(line)) => line,
        _ => return,
    };

    let request = match protocol::decode_request(&line) {
        Ok(request) => request,
        Err(err) => {
            let message = protocol::encode(&ServerMessage::error(format!("bad request: {err}")));
            let _ = write_line(&mut stream, &message);
            return;
        }
    };

    match request {
        ClientRequest::Subscribe => {
            let _ = sender.send(Incoming::Subscribe(stream));
        }
        ClientRequest::Status => {
            let (reply_tx, reply_rx) = mpsc::channel();
            if sender.send(Incoming::Status(reply_tx)).is_ok() {
                if let Ok(line) = reply_rx.recv_timeout(REQUEST_TIMEOUT) {
                    let _ = write_line(&mut stream, &line);
                }
            }
        }
        ClientRequest::Stop => {
            let (reply_tx, reply_rx) = mpsc::channel();
            if sender.send(Incoming::Stop(reply_tx)).is_ok() {
                if let Ok(line) = reply_rx.recv_timeout(REQUEST_TIMEOUT) {
                    let _ = write_line(&mut stream, &line);
                }
            }
        }
    }
}

fn register_client(stream: UnixStream, hello: Hello, clients: &mut Vec<Client>) {
    let hello = protocol::encode(&ServerMessage::Hello(hello));
    let (tx, rx) = mpsc::sync_channel::<String>(CLIENT_BUFFER);
    if tx.try_send(hello).is_err() {
        return;
    }

    let mut stream = stream;
    thread::spawn(move || {
        if stream.set_write_timeout(Some(REQUEST_TIMEOUT)).is_err() {
            return;
        }
        for line in rx {
            if write_line(&mut stream, &line).is_err() {
                break;
            }
        }
    });
    clients.push(Client { tx });
}

fn publish_event(
    event: Event,
    stats: Stats,
    started: &Instant,
    recent: &mut VecDeque<TimedEvent>,
    clients: &mut Vec<Client>,
) {
    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
    let message = ServerMessage::Event {
        elapsed_ms,
        event: event.clone(),
        stats,
    };
    broadcast_line(&protocol::encode(&message), clients);

    if recent.len() >= RECENT_EVENTS {
        recent.pop_front();
    }
    recent.push_back(TimedEvent { elapsed_ms, event });
}

fn broadcast_message(message: &ServerMessage, clients: &mut Vec<Client>) {
    broadcast_line(&protocol::encode(message), clients);
}

fn broadcast_line(line: &str, clients: &mut Vec<Client>) {
    clients.retain(|client| match client.tx.try_send(line.to_string()) {
        Ok(()) => true,
        Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => false,
    });
}

fn bind_listener(socket: &Path) -> Result<UnixListener> {
    if socket.exists() {
        let metadata = fs::symlink_metadata(socket)
            .with_context(|| format!("inspect {}", socket.display()))?;
        if !metadata.file_type().is_socket() {
            bail!("{} exists and is not a Unix socket", socket.display());
        }
        if UnixStream::connect(socket).is_ok() {
            bail!(
                "another emping service is already running at {}",
                socket.display()
            );
        }
        fs::remove_file(socket).ok();
    }

    let listener =
        UnixListener::bind(socket).with_context(|| format!("bind {}", socket.display()))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

fn write_pid(path: &Path) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("write pid file {}", path.display()))?;
    writeln!(file, "{}", std::process::id())?;
    fs::set_permissions(path, Permissions::from_mode(0o644)).ok();
    Ok(())
}

struct RuntimeGuard {
    socket: PathBuf,
    pid_file: PathBuf,
}

impl Drop for RuntimeGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket);
        let _ = fs::remove_file(&self.pid_file);
    }
}

fn connect(paths: &Paths) -> Result<UnixStream> {
    UnixStream::connect(&paths.socket).with_context(|| {
        let mut message = format!(
            "cannot connect to emping service at {}",
            paths.socket.display()
        );
        if euid() != 0 {
            let root_socket = root_runtime_dir().join("emping.sock");
            if root_socket != paths.socket && root_socket.exists() {
                message.push_str(
                    "\n  hint: a service may be running as root; try the same command with sudo",
                );
            }
        }
        message
    })
}

fn status_request(paths: &Paths) -> Result<Status> {
    let mut stream = connect(paths)?;
    stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
    stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;
    send_request(&mut stream, &ClientRequest::Status)?;
    let mut reader = BufReader::new(stream);
    match read_message(&mut reader)? {
        ServerMessage::Status(status) => Ok(status),
        ServerMessage::Error { message } => bail!("{message}"),
        other => bail!("unexpected status response: {other:?}"),
    }
}

fn stop_request(paths: &Paths) -> Result<()> {
    let mut stream = connect(paths)?;
    stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
    stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;
    send_request(&mut stream, &ClientRequest::Stop)?;
    let mut reader = BufReader::new(stream);
    match read_message(&mut reader)? {
        ServerMessage::Stopping => Ok(()),
        ServerMessage::Error { message } => bail!("{message}"),
        other => bail!("unexpected stop response: {other:?}"),
    }
}

fn send_request(stream: &mut UnixStream, request: &ClientRequest) -> Result<()> {
    let line = serde_json::to_string(request)?;
    write_line(stream, &line)?;
    Ok(())
}

fn read_message(reader: &mut BufReader<UnixStream>) -> Result<ServerMessage> {
    let Some(line) = read_line_limited(reader, MAX_MESSAGE_BYTES)? else {
        bail!("service closed the connection");
    };
    protocol::decode_server(&line).context("decode service message")
}

fn read_line_limited<R: BufRead>(reader: &mut R, max: usize) -> Result<Option<String>> {
    let mut bytes = Vec::new();
    let read = reader
        .by_ref()
        .take(max as u64 + 1)
        .read_until(b'\n', &mut bytes)?;
    if read == 0 {
        return Ok(None);
    }
    let has_newline = bytes.last() == Some(&b'\n');
    let content_len = bytes.len() - usize::from(has_newline);
    if content_len > max {
        bail!("message exceeds {max} bytes");
    }
    let text = String::from_utf8(bytes).context("message is not UTF-8")?;
    Ok(Some(text.trim_end_matches(['\r', '\n']).to_string()))
}

fn write_line(stream: &mut UnixStream, line: &str) -> io::Result<()> {
    stream.write_all(line.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()
}

fn read_tail(path: &Path, count: usize) -> String {
    let Ok(text) = fs::read_to_string(path) else {
        return String::new();
    };
    let lines = text.lines().collect::<Vec<_>>();
    let start = lines.len().saturating_sub(count);
    format!(
        "\n--- {} (last {} lines) ---\n{}",
        path.display(),
        count,
        lines[start..].join("\n")
    )
}

fn format_timeout(timeout_ms: Option<f64>) -> String {
    match timeout_ms {
        Some(value) => format!("{:.3}s", value / 1000.0),
        None => "disabled".to_string(),
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
    use std::net::Ipv4Addr;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_socket(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        PathBuf::from("/tmp").join(format!(
            "emping-test-{}-{tag}-{nanos}.sock",
            std::process::id()
        ))
    }

    fn test_paths(socket: &Path) -> Paths {
        Paths {
            runtime_dir: socket.parent().unwrap().to_path_buf(),
            socket: socket.to_path_buf(),
            pid_file: socket.with_extension("pid"),
            log_file: socket.with_extension("log"),
        }
    }

    fn sample_event(seq: u16) -> Event {
        Event::EchoRequest {
            interface: "eth0".into(),
            peer: Ipv4Addr::new(192, 0, 2, 50).into(),
            local: Ipv4Addr::new(192, 0, 2, 10).into(),
            id: 7,
            seq,
            duplicate: false,
        }
    }

    fn test_cli(socket: &Path) -> Cli {
        Cli {
            command: None,
            interfaces: Vec::new(),
            loopback: false,
            timeout: 2.0,
            promisc: false,
            ipv6: false,
            no_limit: false,
            json: true,
            plain: false,
            socket: Some(socket.to_path_buf()),
            pid_file: None,
            log_file: None,
            list: false,
        }
    }

    #[test]
    fn service_lock_is_exclusive() {
        let socket = temp_socket("lock");
        let first = acquire_service_lock(&socket).unwrap();
        assert!(acquire_service_lock(&socket).is_err());
        drop(first);

        let second = acquire_service_lock(&socket).unwrap();
        drop(second);

        fs::remove_file(lock_path(&socket)).ok();
    }

    #[test]
    fn oversized_requests_are_rejected() {
        // Use an in-memory reader so this test cannot block on a small macOS
        // Unix-socket send buffer.
        let data = vec![b'x'; MAX_REQUEST_BYTES + 1];
        let mut reader = BufReader::new(data.as_slice());
        assert!(read_line_limited(&mut reader, MAX_REQUEST_BYTES).is_err());
    }

    #[test]
    fn maximum_sized_requests_are_accepted() {
        let mut data = vec![b'y'; MAX_REQUEST_BYTES];
        data.push(b'\n');
        let mut reader = BufReader::new(data.as_slice());
        let line = read_line_limited(&mut reader, MAX_REQUEST_BYTES)
            .unwrap()
            .unwrap();
        assert_eq!(line.len(), MAX_REQUEST_BYTES);
    }

    #[test]
    fn client_queries_status_over_socket() {
        let socket = temp_socket("status");
        let listener = UnixListener::bind(&socket).unwrap();
        let paths = test_paths(&socket);

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (sender, receiver) = mpsc::channel();
            let connection = thread::spawn(move || handle_connection(stream, sender));

            match receiver.recv_timeout(Duration::from_secs(2)).unwrap() {
                Incoming::Status(reply) => {
                    let status = Status {
                        version: VERSION,
                        pid: 4242,
                        interfaces: vec!["eth0".into()],
                        ipv6: false,
                        timeout_ms: Some(2000.0),
                        uptime_ms: 1234.0,
                        stats: Stats::default(),
                    };
                    reply
                        .send(protocol::encode(&ServerMessage::Status(status)))
                        .unwrap();
                }
                _ => panic!("expected a status request"),
            }

            connection.join().unwrap();
        });

        let status = status_request(&paths).unwrap();
        assert_eq!(status.pid, 4242);
        assert_eq!(status.interfaces, vec!["eth0".to_string()]);
        server.join().unwrap();
        fs::remove_file(&socket).ok();
    }

    #[test]
    fn client_stops_service_over_socket() {
        let socket = temp_socket("stop");
        let listener = UnixListener::bind(&socket).unwrap();
        let paths = test_paths(&socket);

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (sender, receiver) = mpsc::channel();
            let connection = thread::spawn(move || handle_connection(stream, sender));

            match receiver.recv_timeout(Duration::from_secs(2)).unwrap() {
                Incoming::Stop(reply) => {
                    reply
                        .send(protocol::encode(&ServerMessage::Stopping))
                        .unwrap();
                }
                _ => panic!("expected a stop request"),
            }

            connection.join().unwrap();
        });

        stop_request(&paths).unwrap();
        server.join().unwrap();
        fs::remove_file(&socket).ok();
    }

    #[test]
    fn client_receives_hello_and_live_events() {
        let socket = temp_socket("subscribe");
        let listener = UnixListener::bind(&socket).unwrap();
        let paths = test_paths(&socket);

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (sender, receiver) = mpsc::channel();
            let connection = thread::spawn(move || handle_connection(stream, sender));

            match receiver.recv_timeout(Duration::from_secs(2)).unwrap() {
                Incoming::Subscribe(stream) => {
                    let mut clients = Vec::new();
                    let hello = Hello {
                        version: VERSION,
                        pid: 77,
                        interfaces: vec!["lo".into()],
                        ipv6: false,
                        timeout_ms: None,
                        uptime_ms: 100.0,
                        stats: Stats::default(),
                        events: vec![TimedEvent {
                            elapsed_ms: 50.0,
                            event: sample_event(1),
                        }],
                    };
                    register_client(stream, hello, &mut clients);

                    let event = protocol::encode(&ServerMessage::Event {
                        elapsed_ms: 200.0,
                        event: sample_event(2),
                        stats: Stats {
                            requests: 1,
                            ..Stats::default()
                        },
                    });
                    clients[0].tx.try_send(event).unwrap();

                    let summary = protocol::encode(&ServerMessage::Summary {
                        stats: Stats::default(),
                        uptime_ms: 300.0,
                    });
                    clients[0].tx.try_send(summary).unwrap();
                    thread::sleep(Duration::from_millis(200));
                }
                _ => panic!("expected a subscribe request"),
            }

            connection.join().unwrap();
        });

        let subscription = subscribe_paths(&paths).unwrap();
        assert_eq!(subscription.hello.pid, 77);
        assert_eq!(subscription.hello.events.len(), 1);

        match subscription
            .events
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
        {
            ClientEvent::Message(ServerMessage::Event {
                elapsed_ms,
                event,
                stats,
            }) => {
                assert_eq!(elapsed_ms, 200.0);
                assert_eq!(event, sample_event(2));
                assert_eq!(stats.requests, 1);
            }
            other => panic!("unexpected message: {other:?}"),
        }

        match subscription
            .events
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
        {
            ClientEvent::Message(ServerMessage::Summary { uptime_ms, .. }) => {
                assert_eq!(uptime_ms, 300.0);
            }
            other => panic!("unexpected message: {other:?}"),
        }

        server.join().unwrap();
        fs::remove_file(&socket).ok();
    }

    #[test]
    fn attached_stream_processes_live_events() {
        let socket = temp_socket("attach");
        let listener = UnixListener::bind(&socket).unwrap();
        let cli = test_cli(&socket);

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (sender, receiver) = mpsc::channel();
            let connection = thread::spawn(move || handle_connection(stream, sender));

            match receiver.recv_timeout(Duration::from_secs(2)).unwrap() {
                Incoming::Subscribe(stream) => {
                    let mut clients = Vec::new();
                    let hello = Hello {
                        version: VERSION,
                        pid: 123,
                        interfaces: vec!["lo".into()],
                        ipv6: false,
                        timeout_ms: Some(2000.0),
                        uptime_ms: 10.0,
                        stats: Stats::default(),
                        events: Vec::new(),
                    };
                    register_client(stream, hello, &mut clients);

                    let event = protocol::encode(&ServerMessage::Event {
                        elapsed_ms: 42.0,
                        event: sample_event(3),
                        stats: Stats {
                            requests: 1,
                            ..Stats::default()
                        },
                    });
                    clients[0].tx.try_send(event).unwrap();

                    let summary = protocol::encode(&ServerMessage::Summary {
                        stats: Stats {
                            requests: 1,
                            replied: 1,
                            ..Stats::default()
                        },
                        uptime_ms: 100.0,
                    });
                    clients[0].tx.try_send(summary).unwrap();
                    thread::sleep(Duration::from_millis(200));
                }
                _ => panic!("expected a subscribe request"),
            }

            connection.join().unwrap();
        });

        let code = attach_stream(&cli).unwrap();
        assert_eq!(code, ExitCode::SUCCESS);
        server.join().unwrap();
        fs::remove_file(&socket).ok();
    }
}
