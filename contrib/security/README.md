# Security smoke tests

Root-only checks for the service socket, forged packets, lifecycle races, and
filesystem handling. These tests create temporary services under `/tmp` and do not
touch the default `/run/emping` service.

```sh
cargo build --release
sudo TARGET_USER="$USER" ./contrib/security/run.sh
```

What it covers:

- Service lifecycle and socket/PID/log/lock permissions.
- Malformed Unix-socket requests: bad JSON, missing newlines, oversized lines,
  premature disconnects, and 200 idle connections.
- Forged IPv4 and IPv6 ICMP traffic, including truncated headers, fragments, bad IHL,
  oversized payloads, and ICMP/ICMPv6 error payloads.
- Flood limiter behavior: 15 allowed requests, one flood warning, and `--no-limit`
  bypass.
- Eight concurrent `start` invocations against a stale socket: exactly one daemon
  must survive.
- Socket-path and lock-file symlink rejection.
- Optional non-root service run using `setcap cap_net_raw=eip`.

The script prints `PASS`/`FAIL` lines and exits non-zero on failure. It removes its
temporary files and file capability on exit.

Do not run it against production services. The packet forging tests send traffic on
the loopback interface only.
