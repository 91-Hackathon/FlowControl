"""T00 sniffer: watch every network interface of the Docker VM for packets carrying a marker.

Runs in a container with --net=host (the Docker VM's own network namespace) and CAP_NET_RAW,
so it sees traffic on every bridge and on the VM's uplink: an observer that doesn't depend on
the gateway or the runner. Used mainly for DNS: a query for "<marker>.example.com" that
leaves the VM shows up here even if the probe itself got no answer.

Each sighting records the interface and, when the packet parses, protocol, addresses and ports,
so a reader can tell a real attempt (e.g. UDP to port 53) from anything else.

usage: python3 sniff.py LOGFILE MARKER_FILE [MARKER_FILE...]
  Markers are read from files, never passed on a command line (see probes.py).
"""
import ipaddress
import json
import socket
import struct
import sys
import time

logfile = sys.argv[1]
markers = [open(p).read().strip().encode() for p in sys.argv[2:]]
ETH_P_ALL = 0x0003
PROTO = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6"}


def headers(pkt):
    """Best-effort parse of Ethernet/IP/TCP/UDP. Returns a dict, possibly empty."""
    off = None
    if len(pkt) >= 14 and pkt[12:14] in (b"\x08\x00", b"\x86\xdd"):
        off = 14
    elif pkt and pkt[0] >> 4 in (4, 6):
        off = 0
    if off is None:
        return {}
    ver = pkt[off] >> 4
    try:
        if ver == 4:
            ihl = (pkt[off] & 0x0F) * 4
            proto = pkt[off + 9]
            src, dst = str(ipaddress.IPv4Address(pkt[off + 12:off + 16])), str(ipaddress.IPv4Address(pkt[off + 16:off + 20]))
            l4 = off + ihl
        elif ver == 6:
            proto = pkt[off + 6]
            src, dst = str(ipaddress.IPv6Address(pkt[off + 8:off + 24])), str(ipaddress.IPv6Address(pkt[off + 24:off + 40]))
            l4 = off + 40
        else:
            return {}
        info = {"proto": PROTO.get(proto, str(proto)), "src": src, "dst": dst}
        if proto in (6, 17) and len(pkt) >= l4 + 4:
            info["sport"], info["dport"] = struct.unpack("!HH", pkt[l4:l4 + 4])
        return info
    except (IndexError, ValueError):
        return {}


s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
with open(logfile, "a") as f:
    f.write(json.dumps({"t": time.time(), "ready": True}) + "\n")
print("sniffer ready", flush=True)

while True:
    data, (ifname, _proto, pkttype, *_rest) = s.recvfrom(65535)
    for m in markers:
        if m in data:
            row = {"t": time.time(), "marker": m.decode(), "iface": ifname, "pkttype": pkttype, "len": len(data)}
            row.update(headers(data))
            with open(logfile, "a") as f:
                f.write(json.dumps(row) + "\n")
