# Changelog

All notable changes to `emping` are documented here. Versions follow semantic
versioning for the application; the internal service protocol has its own version.

## [0.2.2] - 2026-11-03

### Changed

- Removed the elapsed-time prefix from the TUI signal feed.
- Dimmed local interface addresses in the signal feed so remote peers stand out.
- Added a blank line between completed request/reply and request/timeout pairs.
- Refreshed the release bundle in `dist/release/`.
- Release tarballs now include `CHANGELOG.md`.
- Added a tag-triggered GitHub release workflow for Linux amd64/aarch64 binaries.

### Fixed

- Updated the TUI screenshot, flood-limit wording, and stale build notes in the
  README.

## [0.2.1] - 2026-11-03

### Added

- Per-peer flood limiter:
  - more than 15 unique echo requests in a one-second window;
  - one-hour block for the offending peer;
  - `Possible Flood, Skip Capture <peer>` warning with a `--no-limit` hint;
  - automatic block expiry.
- `--no-limit` to bypass the flood limiter for legitimate high-rate peers or
  high-capacity hosts.
- Terminal-escape sanitization for interface names, service messages, and error
  output. ANSI escapes, control characters, and bidi overrides are displayed as
  visible escape sequences.
- Large-ping tests and documentation:
  - large unfragmented/jumbo echoes are tracked by header;
  - fragmented IPv4/IPv6 pings are ignored;
  - payload bytes are not stored or reported.
- Service lock, bounded IPC messages, client/connection limits, pending-request and
  TUI-peer caps, restrictive umask, symlink-safe socket/PID/lock handling, and
  removal of the PID-file `SIGTERM` fallback.
- Security test harness under `contrib/security/`.

### Changed

- Service protocol version 3.
- Release packaging includes the README, LICENSE, and contrib files.

### Fixed

- Concurrent `start` against a stale socket could unlink a newly bound socket; starts
  are now serialized with `flock`.
- A losing start now reports an already-running service instead of a misleading
  startup failure.
- Terminal-injection risk from crafted interface names.
- Unbounded IPC reads and connection/request growth are now capped.

## [0.2.0] - 2026-11-03

### Added

- APT-style full-screen TUI:
  - signal feed;
  - TARGETS peer table;
  - telemetry;
  - scrollback and follow mode.
- Service/client architecture over a Unix socket:
  - `emping daemon` foreground service;
  - `emping start`, `stop`, `status`;
  - `emping tui` and console attach/detach;
  - quitting the console no longer stops capture.
- Non-systemd process management (`start`/`stop`/`status` plus `setsid`), a systemd
  unit, a macOS launchd plist, and a SysV/init wrapper.
- Optional ICMPv6 support with `--ipv6`:
  - ICMPv6 echo request/reply tracking;
  - ICMPv6 error parsing with embedded TCP flow;
  - dual-stack signal-feed title.
- `--plain` and `--json` modes for standalone capture or live service attach.
- Auto-start behavior for `emping` when no service is running.
- Multi-architecture CI coverage for Linux and macOS, including a universal macOS
  binary.

### Changed

- Event addresses generalized from IPv4-only to IPv4/IPv6.
- Service protocol version 2.
- Interface selection includes IPv6-only interfaces when `--ipv6` is enabled.

## [0.1.0] - 2026-11-03

### Added

- Initial passive ICMPv4 echo monitor for Linux and macOS.
- Echo request/reply matching by `(peer, local, id, sequence)`, with RTT and
  unanswered-request timeout reporting.
- ICMP destination-unreachable, time-exceeded, and parameter-problem parsing for
  embedded IPv4 + TCP flows.
- Interface selection, loopback mode, promiscuous mode, and configurable timeout.
- Human-readable and newline-delimited JSON output.
- Multi-architecture build support and CI for x86_64/aarch64 Linux and macOS.
- Unit tests using synthetic Ethernet/IPv4/ICMP frames.
