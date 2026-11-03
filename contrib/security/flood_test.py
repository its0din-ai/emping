import sys

from forge_packets import icmpv4, ipv4, send4

# 20 fast echo requests from one peer. The default limiter should allow 15,
# emit one flood event, and drop the rest.
for seq in range(20):
    packet = ipv4(
        "127.0.0.3",
        "127.0.0.1",
        1,
        icmpv4(8, 0, b"X" * 8, 77, seq),
    )
    send4(packet)

print("flood test sent 20 requests")
