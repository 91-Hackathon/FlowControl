"""T00 sink: a listener that records everything that reaches it (TCP and UDP on one port).

If a probe from the runner ever shows up here, something got out. The control container's
probes SHOULD show up here: that proves the sink works.

usage: python3 sink.py BIND_ADDR PORT LOGFILE
"""
import json
import socket
import sys
import threading
import time

addr, port, logfile = sys.argv[1], int(sys.argv[2]), sys.argv[3]
lock = threading.Lock()


def log(kind, peer, data):
    with lock, open(logfile, "a") as f:
        f.write(json.dumps({"t": time.time(), "kind": kind, "peer": str(peer), "data": data[:200]}) + "\n")


def tcp_conn(conn, peer):
    conn.settimeout(5)
    try:
        data = conn.recv(4096).decode("utf-8", "replace")
    except OSError:
        data = ""
    log("tcp", peer, data)
    conn.close()


def tcp_loop():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, port))
    s.listen(16)
    while True:
        conn, peer = s.accept()
        threading.Thread(target=tcp_conn, args=(conn, peer), daemon=True).start()


def udp_loop():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((addr, port))
    while True:
        data, peer = s.recvfrom(4096)
        log("udp", peer, data.decode("utf-8", "replace"))


open(logfile, "a").close()
threading.Thread(target=udp_loop, daemon=True).start()
print(f"sink listening on {addr}:{port}", flush=True)
tcp_loop()
