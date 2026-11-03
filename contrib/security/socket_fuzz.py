import json
import socket
import sys
import time

sock_path = sys.argv[1]


def connect():
    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stream.settimeout(3)
    stream.connect(sock_path)
    return stream


def read_line(stream):
    data = b""
    while not data.endswith(b"\n"):
        chunk = stream.recv(65536)
        if not chunk:
            break
        data += chunk
        if len(data) > 8 * 1024 * 1024:
            break
    return data


print("socket: invalid JSON")
stream = connect()
stream.sendall(b"{not json}\n")
response = read_line(stream)
print("  response:", response[:160])
stream.close()

print("socket: request without newline, then close")
stream = connect()
stream.sendall(b'{"cmd":"status"}')
stream.close()

print("socket: oversized line")
stream = connect()
stream.sendall(b"x" * (9 * 1024))
time.sleep(0.2)
stream.close()

print("socket: subscribe and close")
stream = connect()
stream.sendall(b'{"cmd":"subscribe"}\n')
hello = read_line(stream)
try:
    message = json.loads(hello)
    print("  hello type:", message.get("type"), "version:", message.get("version"))
except Exception as err:
    print("  hello parse error:", err)
stream.close()

print("socket: 200 idle connections")
streams = []
for index in range(200):
    try:
        streams.append(connect())
    except Exception as err:
        print("  connection", index, "failed:", err)
        break
time.sleep(0.5)
for stream in streams:
    stream.close()

print("socket tests complete")
