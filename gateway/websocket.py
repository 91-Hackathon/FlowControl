"""Just enough of the WebSocket protocol (RFC 6455) for the live feed, stdlib only.

Server -> browser: text frames (events). Browser -> server: text frames (commands),
plus ping/close handling. No extensions, no compression.
"""
import base64
import hashlib
import struct

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OP_CONT, OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA


def accept_key(client_key):
    """The Sec-WebSocket-Accept value for a client's Sec-WebSocket-Key."""
    digest = hashlib.sha1((client_key.strip() + _GUID).encode()).digest()
    return base64.b64encode(digest).decode()


def encode_frame(payload, opcode=OP_TEXT):
    """One unmasked, unfragmented frame (servers never mask)."""
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    header = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        header += bytes([n])
    elif n < 65536:
        header += bytes([126]) + struct.pack("!H", n)
    else:
        header += bytes([127]) + struct.pack("!Q", n)
    return header + payload


class ConnectionClosed(Exception):
    pass


def read_message(rfile, max_size=1 << 20):
    """Read one complete message. Returns (opcode, payload_bytes).

    Control frames (ping/pong/close) are returned as they arrive; fragmented data
    frames are reassembled. Raises ConnectionClosed if the socket ends.
    """
    parts, first_opcode = [], None
    while True:
        b0, b1 = _read_exact(rfile, 2)
        fin, opcode = b0 & 0x80, b0 & 0x0F
        masked, length = b1 & 0x80, b1 & 0x7F
        if length == 126:
            (length,) = struct.unpack("!H", _read_exact(rfile, 2))
        elif length == 127:
            (length,) = struct.unpack("!Q", _read_exact(rfile, 8))
        if length > max_size:
            raise ConnectionClosed("frame too large")
        mask = _read_exact(rfile, 4) if masked else None
        payload = _read_exact(rfile, length)
        if mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))

        if opcode >= OP_CLOSE:          # control frame: never fragmented
            return opcode, payload
        if opcode != OP_CONT:
            first_opcode = opcode
        parts.append(payload)
        if fin:
            return first_opcode, b"".join(parts)


def _read_exact(rfile, n):
    data = rfile.read(n) if n else b""
    if len(data) < n:
        raise ConnectionClosed("socket closed")
    return data
