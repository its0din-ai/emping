# emping

`emping` is a small, passive ICMP echo monitor for Linux and macOS.

It listens on one or more network interfaces, spots **ICMPv4 echo requests sent to
this host** (and, with `--ipv6`, **ICMPv6 echo requests**), and reports **whether the
host sends an echo reply back**. It can also decode ICMP error messages that embed an
original TCP flow, which is useful when troubleshooting "ping works, TCP does not" or
MTU/firewall problems.

The tool never sends probe packets. It only observes.

The architecture is split in two, similar to how Nyx attaches to a running Tor
daemon:

- **`emping daemon`** captures packets and serves an event stream over a Unix socket.
- **`emping` / `emping tui`** is a client that attaches the console to that service.

Quitting the console does **not** stop capture. The service keeps running in the
background until you explicitly stop it.

```
  EMPING - ICMP CAPTURE CONSOLE v0.2.2

 ╭ EMPING ──────────────────────────────────────────────────────────────────────╮
 │ OPERATION SILENT ECHO                                          [ ATTACHED ]  │
 ╰──────────────────────────────────────────────────────────────────────────────╯
 ╭ SIGNAL FEED [ICMPv4] ──────────────────────────╮ ╭ TARGETS [2 PEERS] ─────────╮
 │ REQ  192.0.2.50 -> 192.0.2.10 ...              │ │ PEER         REQ REP LOST  │
 │ REP  192.0.2.10 -> 192.0.2.50 ...              │ │ 192.0.2.50   1   1   0     │
 │                                                │ │ 198.51.100.7 1   0   1     │
 │ LOST 192.0.2.50 -> 192.0.2.10 ...              │ │                            │
 ╰────────────────────────────────────────────────╯ ╰────────────────────────────╯
 ╭ TELEMETRY ───────────────────────────────────────────────────────────────────╮
 │ INTERFACES  eth0   TIMEOUT 2.000s   REQUESTS 2  REPLIED 1  LOST 1            │
 ╰──────────────────────────────────────────────────────────────────────────────╯
 Q quit  UP/DN scroll  PGUP/PGDN page  HOME oldest  END live
```

The banner and codename are presentation only. In the signal feed, local interface
addresses are dimmed, and a blank line separates completed request/reply pairs.

## Quick start

```sh
cargo build --release
sudo install -m 0755 target/release/emping /usr/local/bin/emping

# Start the background capture service.
sudo emping start

# Attach the console. Quitting with Q detaches; the service keeps running.
sudo emping

# Inspect or stop it.
sudo emping status
sudo emping stop
```

If you simply run `sudo emping` and no service is running yet, it starts one with
the current capture options and then attaches. Later runs attach to the existing
service.

To keep the old single-process behavior (console and capture in one process), use:

```sh
sudo emping run
```

## Commands

| Command | Purpose |
| --- | --- |
| `emping` | Attach the console; auto-start the service if needed |
| `emping tui` | Attach the console only; fail if the service is not running |
| `emping start` | Start the background service and exit |
| `emping stop` | Stop the background service |
| `emping status` | Show service status and counters |
| `emping daemon` | Run the service in the foreground (systemd/launchd/init) |
| `emping run` | Run capture in the foreground without a service |
| `emping --list` | List interfaces |

`--plain` and `--json` work in both modes:

```sh
# No service: old foreground line/JSON output.
sudo emping --json

# Service running: attach as a live line/JSON consumer.
sudo emping --plain
sudo emping --json

# Force foreground capture even if a service is running.
sudo emping run --plain

# Enable ICMPv6 capture as well (IPv4 remains enabled).
sudo emping start --ipv6

# The SIGNAL FEED title then becomes:
#   SIGNAL FEED [ICMPv4, ICMPv6]

# Disable the per-peer flood limiter (use only for legitimate high-rate peers).
sudo emping start --no-limit
```

When a service is already running, `--interface`, `--loopback`, `--promisc`,
`--ipv6`, `--no-limit`, and `--timeout` belong to the service that is already active.
Stop it first to change them:

```sh
sudo emping stop
sudo emping start -i eth0 -i wlan0 --timeout 1.5
```

`emping start` writes:

- a Unix socket (default: `/run/emping/emping.sock` when started as root),
- a PID file (`emping.pid` in the same directory),
- a log file (`emping.log` in the same directory).

Override them with `--socket`, `--pid-file`, and `--log-file`.

## How it decides

1. Local IPv4 addresses (and IPv6 addresses, when enabled) are collected from all
   interfaces.
2. An **echo request** is tracked when its destination is a local address. The key is
   `(peer, local, icmp id, icmp sequence)`.
3. An **echo reply** is matched when its source is a local address and the same key
   was seen before. The round-trip time is measured from capture timestamps.
4. If no matching reply is observed within `--timeout` (default 2 s), the request is
   reported as unanswered.
5. ICMP destination-unreachable, time-exceeded, and parameter-problem messages sent
   to this host are inspected for an embedded IPv4/IPv6 + TCP header. The original
   TCP flow is printed as `icmp-tcp`.

IPv4 is always captured. IPv6 is only captured when `--ipv6` is set; the console then
shows `SIGNAL FEED [ICMPv4, ICMPv6]`. Only ICMPv6 packets whose IPv6 next header is
58 are handled; IPv6 extension headers are not walked.

Only frames that are actually visible on the selected interfaces can be tracked. If
capture starts after the request, or the reply is generated by another device (NAT,
load balancer, proxy), it cannot be observed. Likewise, `replied=yes` means the reply
frame left the host; delivery to the peer is beyond what a passive monitor can prove.

## Flood limiter

By default, if one peer sends **more than 15 unique echo requests within one second**,
that peer is blocked for **one hour** and the following warning is shown. Duplicate
captures of the same ICMP id/sequence (common on loopback/bridges) do not count toward
the threshold.

```text
Possible Flood, Skip Capture 192.0.2.50
Use --no-limit to skip this security features.
```

While blocked, requests and replies for that peer are ignored before tracking and
event processing, and pending entries for that peer are removed. The rule is removed
automatically after one hour; the peer is then counted from scratch.

Use `--no-limit` when a peer legitimately emits at a high rate, or when running on
hardware where the flood is not a concern:

```sh
sudo emping start --no-limit
sudo emping run --no-limit
```

The limiter reduces user-space tracking/event/TUI/socket work. It does **not** stop
raw frames from reaching the packet socket; use kernel ICMP rate limits or a BPF
capture filter as well if the raw packet rate itself is overwhelming the host.

## Requirements

- Linux: `CAP_NET_RAW` (root, or a file capability).
- macOS: root is required to open BPF devices.
- ICMPv4 is always handled. ICMPv6 requires `--ipv6`; direct ICMPv6 only, no IPv6
  extension-header walking.

### Linux permissions

The service normally runs as root, so `sudo emping start` is enough. If you prefer a
non-root service, grant the capability and use a user runtime directory:

```sh
sudo setcap cap_net_raw=eip /usr/local/bin/emping
emping start
```

Promiscuous mode (`--promisc`) additionally needs `CAP_NET_ADMIN`:

```sh
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/emping
```

### macOS permissions

```sh
cargo build --release
sudo ./target/release/emping start
sudo ./target/release/emping
```

macOS has a limited number of BPF devices. If several capture tools are running, or
you select too many interfaces, opening a channel may fail. Prefer an explicit
`--interface en0`.

## Socket paths and access

| Context | Default socket |
| --- | --- |
| root on Linux | `/run/emping/emping.sock` |
| root on macOS | `/var/run/emping/emping.sock` |
| non-root with `XDG_RUNTIME_DIR` | `$XDG_RUNTIME_DIR/emping/emping.sock` |
| non-root without `XDG_RUNTIME_DIR` | `/tmp/emping-<uid>/emping.sock` |

The socket is created with mode `0600`. Attach as the same user that started the
service, or as root. This is intentional: the socket is a local control channel and
is never exposed over TCP.

## Non-systemd service management

The `start`, `stop`, and `status` commands are self-contained on Linux and macOS and
do not need systemd. `start` creates a new session (`setsid`), redirects the daemon's
output to the log file, and detaches.

```sh
sudo emping start
sudo emping status
sudo emping stop
```

To run under any supervisor (OpenRC, runit, s6, a SysV init script, `supervisord`,
etc.), run the foreground service command and let the supervisor manage the process:

```sh
emping daemon
```

The service handles `SIGTERM` gracefully and removes its socket and PID file.

After upgrading `emping`, restart the service so the daemon and console use the same
internal protocol version:

```sh
sudo emping stop
sudo emping start
```

A ready-to-adapt SysV/init wrapper is provided at
[`contrib/init.d/emping`](contrib/init.d/emping).

The service log records startup, shutdown, and capture errors. Event history is
served to attached clients; detached mode does not write every packet to the log.

## systemd

Install the sample unit:

```sh
sudo install -m 0644 contrib/systemd/emping.service /etc/systemd/system/emping.service
sudo systemctl daemon-reload
sudo systemctl enable --now emping
```

The unit runs `emping daemon` in the foreground and lets systemd manage restart and
logging:

```sh
systemctl status emping
journalctl -u emping -f

# The console still attaches to the service:
sudo emping
```

The unit grants `CAP_NET_RAW`; uncomment the `CAP_NET_ADMIN` line in the unit if you
need `--promisc`. The socket is under `/run/emping`, so attach with `sudo` unless you
adjust ownership/permissions.

To change interfaces or timeout, edit `ExecStart`:

```ini
ExecStart=/usr/local/bin/emping daemon --interface eth0 --timeout 1.5
# Add --ipv6 to also capture ICMPv6.
```

Then `sudo systemctl daemon-reload && sudo systemctl restart emping`.

When systemd manages the service, use `systemctl start|stop|restart emping` rather than
`emping start|stop`, so systemd remains the owner of the process. `emping` itself only
attaches the console.

## macOS launchd

A sample LaunchDaemon is provided at
[`contrib/launchd/dev.emping.plist`](contrib/launchd/dev.emping.plist):

```sh
sudo cp contrib/launchd/dev.emping.plist /Library/LaunchDaemons/dev.emping.plist
sudo launchctl load -w /Library/LaunchDaemons/dev.emping.plist

# Attach with sudo because the daemon runs as root.
sudo emping
```

Logs go to `/var/log/emping.log`.

## Console controls

| Key | Action |
| --- | --- |
| `Q`, `Esc`, `Ctrl-C` | Detach (the service keeps running) |
| `Up`/`Down`, `K`/`J` | Scroll the signal feed |
| `PageUp`/`PageDown` | Scroll a page at a time |
| `Home` | Jump to the oldest event |
| `End` | Return to live follow mode |

When attaching, the console replays up to the last 1,000 events so it is not empty.
`--plain` and `--json` attaches stream live events only.

## Line and JSON output

With `--plain` / `--json` and no service, output is one line/object per event. With a
service running, the same formats are produced from the live socket stream.

```text
[    1.204s] request   peer=192.0.2.50    local=192.0.2.10    id=4660  seq=1     replied=pending duplicate=no iface=eth0
[    1.205s] reply     peer=192.0.2.50    local=192.0.2.10    id=4660  seq=1     replied=yes rtt=412us tracked=yes iface=eth0
[    3.204s] timeout   peer=192.0.2.50    local=192.0.2.10    id=4660  seq=2     replied=no after=2.000s iface=eth0
summary: requests=2 replied=1 unanswered=1 pending=0 duplicates=0 untracked_replies=0 icmp_tcp_errors=0
```

JSON events:

```json
{"elapsed_ms":1204.4,"event":"echo_request","id":4660,"interface":"eth0","local":"192.0.2.10","peer":"192.0.2.50","seq":1,"duplicate":false}
{"elapsed_ms":1205.1,"event":"echo_reply","id":4660,"interface":"eth0","local":"192.0.2.10","peer":"192.0.2.50","seq":1,"rtt_ms":0.412,"tracked":true}
{"elapsed_ms":3204.2,"event":"echo_timeout","after_ms":2000.0,"id":4660,"interface":"eth0","local":"192.0.2.10","peer":"192.0.2.50","seq":2}
{"event":"summary","requests":2,"replied":1,"unanswered":1,"pending":0,"duplicates":0,"untracked_replies":0,"icmp_tcp_errors":0}
```

Event types: `echo_request`, `echo_reply`, `echo_timeout`, `icmp_tcp_error`, and a
final `summary`. Untracked replies have `"tracked": false` and `"rtt_ms": null`.

## Build and architecture support

Rust 1.88 or newer is required (ratatui 0.30 uses edition 2024).

```sh
cargo build --release
```

Generated release bundles live under `dist/release/`; `dist/` is intentionally
ignored by git. The full CI matrix is available via manual `workflow_dispatch`;
automatic builds run only for tagged `v*` releases, which publish Linux amd64/aarch64
archives.

Packet capture is delegated to `pnet` (AF_PACKET on Linux, BPF on macOS). The service
layer uses Unix primitives (`flock`, `setsid`, signals) available on both platforms,
and the application code has no architecture-specific assumptions.

| OS | Architectures |
| --- | --- |
| Linux | x86_64, aarch64, armv7* |
| macOS | x86_64 (Intel), aarch64 (Apple silicon), universal |

\* Any target supported by Rust + `pnet` should work. The manual full-matrix workflow
builds the four primary targets plus a universal macOS binary; tagged releases publish
Linux amd64/aarch64 archives.

### Cross-compilation

For Linux targets from a Linux host, [`cross`](https://github.com/cross-rs/cross) is
the easiest route:

```sh
cargo install cross
cross build --release --target aarch64-unknown-linux-gnu
cross build --release --target armv7-unknown-linux-gnueabihf
```

For macOS, build on the matching machine (Intel or Apple silicon) or use the GitHub
Actions matrix. Cross-linking a macOS binary generally requires the Apple SDK and is
not supported by `cross`.

## Tests

```sh
cargo test
```

The tests cover synthetic Ethernet/IPv4/IPv6/ICMP frames, large and fragmented
packets, console rendering, protocol serialization, flood limiting, malformed input,
and the Unix-socket status/stop/subscribe handshakes. They do not require root or a
network interface.

## Security notes

- The control channel is a Unix socket only; no TCP listener is opened. The socket
  is created with mode `0600`, and the service sets a restrictive `umask`.
- The service normally runs as root because raw capture requires `CAP_NET_RAW`. A
  non-root setup with `setcap cap_net_raw=eip` is supported.
- Starting a second daemon is serialized with an exclusive `flock` on a lock file
  next to the socket, preventing stale-socket races.
- Socket, PID, and lock paths reject symlinks. Custom `--socket`/`--pid-file`/
  `--log-file` paths are trusted administrator input.
- IPC messages are newline-delimited JSON with bounded line sizes. Subscribed
  clients, pending handshakes, pending echo requests, TUI peers, and event history
  are all capped to avoid unbounded memory growth.
- The packet parser is safe Rust (`pnet`); no packet data is used to build shell
  commands or dynamically loaded code. The daemon re-executes only its own binary,
  and the command arguments contain no shell interpretation.
- A passive monitor can still be flooded with ICMP traffic. Unlike `ping`, which only
  waits for replies to its own probes, `emping` parses and tracks every inbound ICMP
  frame, so a high-rate flood can consume CPU even though memory is bounded. The
  per-peer flood limiter (15 requests/second, one hour) is enabled by default and can
  be disabled with `--no-limit`. It stops tracking/event work for the offending peer,
  but raw packets still reach the capture socket; use kernel ICMP rate limits or a
  BPF filter if the raw rate itself is too high. Also consider keeping `--promisc`
  disabled and selecting only the needed interfaces.
- Interface names and error text are escaped before terminal output. Control
  characters, ANSI escapes, and bidi overrides are rendered as visible escape
  sequences, so a crafted interface name cannot inject terminal commands.

A root-only security smoke-test harness is provided at
[`contrib/security/`](contrib/security/):

```sh
cargo build --release
sudo TARGET_USER="$USER" ./contrib/security/run.sh
cargo audit
```

## Limitations

- ICMPv6 is opt-in with `--ipv6`; the IPv6 next header must be 58 (extension headers
  are not walked), so pings that use extension headers are ignored.
- The TUI abbreviates long IPv6 addresses in the signal feed and peer table; use
  `--json` or `--plain` for full addresses.
- Large pings that require IP fragmentation are ignored: IPv4 fragments (MF/offset)
  and IPv6 fragment headers are skipped. Large unfragmented/jumbo echo frames are
  still tracked by their headers, but the capture buffer is 4 KiB and payload bytes
  are not stored or reported.
- VLAN-tagged frames are ignored by the fast pre-filter.
- Packets must be visible on the selected interface. The tool cannot see replies
  produced by another hop.
- Checksums are deliberately not validated: captured outgoing frames may carry a
  checksum that is still to be filled in by hardware offload.
- `--promisc` lets you observe traffic not addressed to the host, but events are still
  filtered to local source/destination addresses.
- `--timeout 0` disables expiry, so unanswered requests stay in memory until the
  service exits. Leave the default in long-running deployments.
- The service keeps only the most recent 1,000 events for console replay. It is not a
  historical packet store; use `--json` or a PCAP workflow if you need a full record.
- The detached service writes lifecycle/error logs, not every event, to its log file.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the version history.

## License

MIT. See [LICENSE](LICENSE).
