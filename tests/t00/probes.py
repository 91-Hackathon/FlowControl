"""T00 probes: every way we can think of for code in the runner to reach the outside without the gateway.

Runs inside a container (the runner, or a control container with a normal network) and prints
one JSON object per probe:
  {"id", "what", "outcome", "detail"}
outcome is one of:
  "blocked"  - the attempt failed (refused, unreachable, timed out, permission denied, no answer)
  "open"     - the attempt worked: connected, resolved, got a reply, or the thing exists
  "reached"  - (gateway_model_route only) the request went through the gateway and upstream answered

usage: python3 probes.py MARKER_FILE HOST_SINK EGRESS_SINK
  MARKER_FILE  file holding a unique string sent in every payload / DNS name, so captures can
               be matched. Read from a file, not the command line: a command line travels over
               the Docker API, and the sniffer would see that as marker traffic.
  HOST_SINK    host:port of a listener on the developer's machine
  EGRESS_SINK  ip:port of a listener on the gateway's outside network
"""
import json
import os
import random
import socket
import struct
import subprocess
import sys
import urllib.error
import urllib.request

MARKER = open(sys.argv[1]).read().strip()
HOST_SINK, EGRESS_SINK = sys.argv[2], sys.argv[3]
TIMEOUT = 3
results = []


def record(pid, what, outcome, detail=""):
    results.append({"id": pid, "what": what, "outcome": outcome, "detail": str(detail)[:200]})


def tcp(pid, what, host, port, family=socket.AF_UNSPEC):
    """Open a TCP connection and send the marker. Connected = open."""
    try:
        infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
    except OSError as e:
        return record(pid, what, "blocked", f"no address: {e}")
    last = None
    for fam, typ, proto, _, addr in infos:
        s = socket.socket(fam, typ, proto)
        s.settimeout(TIMEOUT)
        try:
            s.connect(addr)
            s.sendall(f"{MARKER} {pid}\n".encode())
            return record(pid, what, "open", f"connected to {addr}")
        except OSError as e:
            last = e
        finally:
            s.close()
    record(pid, what, "blocked", last)


def dns_query_packet(name):
    qid = random.randint(0, 65535)
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return header + qname + struct.pack("!HH", 1, 1)


def dns_udp(pid, what, server):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    try:
        s.sendto(dns_query_packet(f"{MARKER}-{pid}.example.com"), (server, 53))
        s.recvfrom(512)
        record(pid, what, "open", "got a DNS reply")
    except OSError as e:
        record(pid, what, "blocked", e)
    finally:
        s.close()


def resolve(pid, what, name):
    try:
        addrs = {a[4][0] for a in socket.getaddrinfo(name, 443)}
        record(pid, what, "open", f"resolved to {sorted(addrs)}")
    except OSError as e:
        record(pid, what, "blocked", e)


def udp_send(pid, what, host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.sendto(f"{MARKER} {pid}".encode(), (host, port))
        # UDP has no handshake: "sent" only means it left this socket. The sniffer decides.
        record(pid, what, "open", "datagram handed to the network (check capture)")
    except OSError as e:
        record(pid, what, "blocked", e)
    finally:
        s.close()


def child(pid, what, argv):
    """Same attempt from a child process: descendants must be constrained too."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT * 3)
        ok = p.returncode == 0
        record(pid, what, "open" if ok else "blocked", (p.stdout + p.stderr).strip() or f"exit {p.returncode}")
    except (OSError, subprocess.TimeoutExpired) as e:
        record(pid, what, "blocked", e)


def http(pid, what, url, headers=None, method="GET", data=None, reached_is=None):
    """HTTP request. reached_is: outcome to record when any HTTP response comes back."""
    req = urllib.request.Request(url, headers=headers or {}, method=method, data=data)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT * 2) as r:
            record(pid, what, reached_is or "open", f"HTTP {r.status}")
    except urllib.error.HTTPError as e:
        body = e.read()[:160].decode("utf-8", "replace")
        if "FlowControl gateway" in body:  # refused by the gateway itself, not answered upstream
            record(pid, what, "blocked", f"HTTP {e.code} from gateway: {body}")
        else:
            record(pid, what, reached_is or "open", f"HTTP {e.code}: {body}")
    except (OSError, urllib.error.URLError) as e:
        record(pid, what, "blocked", e)


token = os.environ.get("ANTHROPIC_API_KEY", "")
host_sink_host, host_sink_port = HOST_SINK.rsplit(":", 1)
egress_ip, egress_port = EGRESS_SINK.rsplit(":", 1)

# --- direct network, by IP and by name -------------------------------------------------
tcp("tcp_public_ip", "TCP to a public IP (1.1.1.1:443)", "1.1.1.1", 443)
tcp("tcp_public_name", "TCP to a public name (api.anthropic.com:443)", "api.anthropic.com", 443)
tcp("tcp_host_sink", "TCP to a listener on the developer's machine", host_sink_host, int(host_sink_port))
tcp("tcp_egress_sink", "TCP to a listener on the gateway's outside network", egress_ip, int(egress_port))
tcp("tcp_metadata", "TCP to the cloud metadata address (169.254.169.254:80)", "169.254.169.254", 80)
udp_send("udp_public", "UDP datagram to a public IP (1.1.1.1:443)", "1.1.1.1", 443)

# --- DNS --------------------------------------------------------------------------------
resolve("dns_resolver_public", "Resolve a public name with the system resolver", "example.com")
resolve("dns_resolver_marker", "Resolve a unique name (DNS exfiltration attempt)", f"{MARKER}-resolver.example.com")
dns_udp("dns_direct_google", "DNS query straight to 8.8.8.8", "8.8.8.8")
dns_udp("dns_direct_cloudflare", "DNS query straight to 1.1.1.1", "1.1.1.1")
tcp("dns_direct_tcp", "DNS over TCP straight to 8.8.8.8:53", "8.8.8.8", 53)

# --- IPv6 -------------------------------------------------------------------------------
tcp("ipv6_public", "TCP over IPv6 to a public address", "2606:4700:4700::1111", 443, socket.AF_INET6)
try:
    with open("/proc/net/if_inet6") as f:
        globals_v6 = [l.split()[0] for l in f if l.split()[3] == "00" and l.split()[5] != "lo"]
    record("ipv6_global_address", "Container has a global IPv6 address", "open" if globals_v6 else "blocked",
           globals_v6 or "none")
except OSError as e:
    record("ipv6_global_address", "Container has a global IPv6 address", "blocked", e)

# --- privileges and host access ----------------------------------------------------------
try:
    socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP).close()
    record("raw_socket", "Open a raw socket (needed for ICMP / packet crafting)", "open", "allowed")
except OSError as e:
    record("raw_socket", "Open a raw socket (needed for ICMP / packet crafting)", "blocked", e)
record("docker_socket", "Docker socket available inside", "open" if os.path.exists("/var/run/docker.sock") else "blocked",
       "/var/run/docker.sock")

# --- child processes ---------------------------------------------------------------------
child("child_curl", "curl from a child process to a public IP", ["curl", "-sS", "--max-time", str(TIMEOUT), "-o", "/dev/null", "https://1.1.1.1"])
child("child_node", "Node.js from a child process to a public IP",
      ["node", "-e", "require('https').get('https://1.1.1.1',r=>process.exit(0)).on('error',e=>{console.error(e.code);process.exit(1)}).setTimeout(3000,function(){this.destroy(new Error('timeout'))})"])
child("child_proxy_env", "curl with an explicit proxy setting pointing outside", ["curl", "-sS", "--max-time", str(TIMEOUT), "-x", "http://1.1.1.1:80", "-o", "/dev/null", "http://example.com"])

# --- the gateway itself: only the model route should be usable ----------------------------
auth = {"x-api-key": token, "anthropic-version": "2023-06-01", "content-type": "application/json"}
tiny = json.dumps({"model": "claude-haiku-5-5", "max_tokens": 1, "messages": [{"role": "user", "content": "hi"}]}).encode()
http("gateway_model_route", "Model API through the gateway (the one allowed route)",
     "http://gateway:8787/v1/messages", auth, method="POST", data=tiny, reached_is="reached")
http("gateway_generic_relay", "Non-model API path through the gateway (/v1/files)",
     "http://gateway:8787/v1/files", auth)
http("gateway_live_feed", "Gateway's dashboard feed / command channel (port 8080)", "http://gateway:8080/")

for r in results:
    print(json.dumps(r))
