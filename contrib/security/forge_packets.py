import socket
import struct
import sys
import time


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4(src, dst, proto, payload, ident=1, flags_frag=0, ihl=5, total_len=None, ttl=64):
    options = b""
    if ihl > 5:
        options = b"\x01" * ((ihl - 5) * 4)
    total = total_len if total_len is not None else ihl * 4 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | ihl,
        0,
        total,
        ident,
        flags_frag,
        ttl,
        proto,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    ) + options
    value = checksum(header)
    header = header[:10] + struct.pack("!H", value) + header[12:]
    return header + payload


def icmpv4(icmp_type, code, payload=b"", ident=1, seq=1):
    body = struct.pack("!BBH", icmp_type, code, 0)
    if icmp_type in (0, 8):
        body += struct.pack("!HH", ident, seq) + payload
    else:
        body += b"\0\0\0\0" + payload
    value = checksum(body)
    return body[:2] + struct.pack("!H", value) + body[4:]


def send4(packet, dst="127.0.0.1"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sock.sendto(packet, (dst, 0))
    sock.close()


def icmpv6(icmp_type, code, payload=b"", ident=1, seq=1):
    body = struct.pack("!BBH", icmp_type, code, 0)
    if icmp_type in (128, 129):
        body += struct.pack("!HH", ident, seq) + payload
    else:
        body += b"\0\0\0\0" + payload
    pseudo = (
        socket.inet_pton(socket.AF_INET6, "::1")
        + socket.inet_pton(socket.AF_INET6, "::1")
        + struct.pack("!I", len(body))
        + b"\0\0\0"
        + bytes([58])
    )
    value = checksum(pseudo + body)
    return body[:2] + struct.pack("!H", value) + body[4:]


def send6(payload):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    sock.sendto(payload, ("::1", 0, 0, 0))
    sock.close()


def main():
    # Valid IPv4 echo requests.
    for size in (0, 32, 1200):
        payload = b"A" * size
        packet = ipv4("127.0.0.2", "127.0.0.1", 1, icmpv4(8, 0, payload, 42, size))
        send4(packet)
        time.sleep(0.05)

    # Truncated / malformed IPv4 ICMP.
    send4(ipv4("127.0.0.2", "127.0.0.1", 1, struct.pack("!BBH", 8, 0, 0)))
    send4(ipv4("127.0.0.2", "127.0.0.1", 1, b"\x08\x00"))
    send4(ipv4("127.0.0.2", "127.0.0.1", 1, icmpv4(8, 0, b"B" * 8, 1, 1), ihl=15))
    send4(
        ipv4(
            "127.0.0.2",
            "127.0.0.1",
            1,
            icmpv4(8, 0, b"C" * 8, 2, 1),
            flags_frag=0x2000,
        )
    )
    send4(
        ipv4(
            "127.0.0.2",
            "127.0.0.1",
            1,
            icmpv4(8, 0, b"D" * 8, 3, 1),
            flags_frag=0x0001,
        )
    )
    send4(
        ipv4(
            "127.0.0.2",
            "127.0.0.1",
            1,
            icmpv4(8, 0, b"E" * 8, 4, 1),
            total_len=9999,
        )
    )

    # ICMP error with a complete embedded IPv4 + TCP header.
    tcp = struct.pack("!HH", 54321, 443) + b"\0" * 4
    inner = ipv4("127.0.0.1", "192.0.2.1", 6, tcp)
    send4(ipv4("203.0.113.9", "127.0.0.1", 1, icmpv4(3, 3, inner)))

    # ICMP error with a truncated embedded IPv4 header.
    send4(ipv4("203.0.113.9", "127.0.0.1", 1, icmpv4(3, 3, b"\x45" + b"\0" * 7)))

    # IPv6 echo requests and an ICMPv6 error with embedded IPv6 + TCP.
    try:
        for size in (0, 64):
            send6(icmpv6(128, 0, b"F" * size, 7, size))
            time.sleep(0.05)

        # 4-byte truncated ICMPv6 header.
        body = struct.pack("!BBH", 128, 0, 0)
        pseudo = (
            socket.inet_pton(socket.AF_INET6, "::1")
            + socket.inet_pton(socket.AF_INET6, "::1")
            + struct.pack("!I", len(body))
            + b"\0\0\0"
            + bytes([58])
        )
        value = checksum(pseudo + body)
        send6(body[:2] + struct.pack("!H", value) + body[4:])

        inner6 = (
            struct.pack("!IHBB", 6 << 28, 8, 6, 64)
            + socket.inet_pton(socket.AF_INET6, "::1")
            + socket.inet_pton(socket.AF_INET6, "2001:db8::99")
            + struct.pack("!HH", 12345, 443)
            + b"\0\0\0\0"
        )
        send6(icmpv6(1, 4, inner6))
    except OSError as err:
        print("ipv6 send skipped:", err)

    print("packet tests complete")


if __name__ == "__main__":
    main()
