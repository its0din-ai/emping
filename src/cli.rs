use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Passively watch ICMPv4 echo requests sent to this host and report whether
/// the host sends an echo reply back.
#[derive(Debug, Parser)]
#[command(
    name = "emping",
    version,
    about = "Watch ICMP echo requests sent to this host and whether it replies",
    after_help = "EXAMPLES:\n  sudo emping start            start the background service\n  sudo emping start --ipv6     also capture ICMPv6\n  sudo emping start --no-limit disable flood protection\n  sudo emping                  attach the console (start the service if needed)\n  sudo emping status           show service status\n  sudo emping stop             stop the background service\n  sudo emping run --plain      foreground capture, old line output\n  sudo emping daemon           foreground service (systemd/launchd)"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Interface to listen on (repeatable).
    ///
    /// Defaults to every up, non-loopback interface that has an IPv4 address.
    #[arg(short = 'i', long = "interface", value_name = "NAME", global = true)]
    pub interfaces: Vec<String>,

    /// Also listen on the loopback interface.
    #[arg(long, global = true)]
    pub loopback: bool,

    /// How long to wait for a matching echo reply before reporting "no reply".
    /// 0 disables the timeout.
    #[arg(
        short = 't',
        long,
        value_name = "SECS",
        default_value_t = 2.0,
        global = true
    )]
    pub timeout: f64,

    /// Enable promiscuous mode (needs CAP_NET_ADMIN on Linux).
    #[arg(long, global = true)]
    pub promisc: bool,

    /// Also capture ICMPv6 echo traffic. IPv4 is always enabled.
    #[arg(long, global = true)]
    pub ipv6: bool,

    /// Disable the per-peer flood limiter (15 requests/second; 1 hour block).
    #[arg(long, global = true)]
    pub no_limit: bool,

    /// Print one JSON object per line instead of human-readable text.
    #[arg(long, conflicts_with = "plain", global = true)]
    pub json: bool,

    /// Force line-based output instead of the full-screen console.
    #[arg(long, conflicts_with = "json", global = true)]
    pub plain: bool,

    /// Unix socket used by the service and its clients.
    #[arg(long, value_name = "PATH", global = true)]
    pub socket: Option<PathBuf>,

    /// PID file used by the background service.
    #[arg(long, value_name = "PATH", global = true)]
    pub pid_file: Option<PathBuf>,

    /// Log file used when the service is detached.
    #[arg(long, value_name = "PATH", global = true)]
    pub log_file: Option<PathBuf>,

    /// List network interfaces and exit.
    #[arg(long)]
    pub list: bool,
}

#[derive(Debug, Clone, Copy, Subcommand)]
pub enum Command {
    /// Attach the console to a running service. Does not start it.
    Tui,

    /// Run capture in the foreground without a service.
    Run,

    /// Start the background service and exit.
    Start,

    /// Stop the background service.
    Stop,

    /// Show whether the service is running.
    Status,

    /// Run the service in the foreground. Used by systemd/launchd and init scripts.
    Daemon,
}
