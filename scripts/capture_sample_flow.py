"""Packet-level view of one sample flow (Phase 7A.6).

Root-only `tcpdump`/raw packet capture isn't available in this
environment (confirmed: `tcpdump -i lo0` fails with "permission denied
... cannot open BPF device" and there's no interactive sudo prompt
available here) -- the Phase 7 doc explicitly allows a non-live,
captured-and-replayed alternative for this item, so this is that: a
transparent TCP byte relay that sits between a real client and the real
Sentinel proxy, touches nothing, and logs every raw byte it forwards in
each direction with a timestamp.

This is NOT a fabricated/illustrative capture -- every byte logged here
is exactly what went out on this machine's loopback interface for one
real TLS 1.3 session (the relay never decrypts or modifies anything, it
just reads from one socket and writes to the other). The one honest gap:
without real packet capture, the TCP three-way handshake (SYN/SYN-ACK/ACK)
itself isn't directly observable at this layer -- connect() already
completes it below the socket API. That's noted explicitly in the output
rather than faked.

TLS 1.3 record-layer framing (RFC 8446 SS5.1) is parsed -- content type
and length only, never anything encrypted -- to label each record. This
is possible without decrypting anything because TLS 1.3 has an
interesting, teachable property: only the ClientHello and ServerHello are
sent with content type 0x16 (handshake) in cleartext; literally
everything after -- the rest of the handshake (EncryptedExtensions,
Certificate, CertificateVerify, Finished) AND all real application data
-- is wrapped in content type 0x17 (application_data) records, encrypted,
indistinguishable from outside. That's a deliberate TLS 1.3 design choice
(hide handshake message boundaries from network observers), and this
script's output demonstrates it directly: you can SEE the record type
distinction, but not what's inside past record #2.

Usage: run this instead of `make proxy` for one sample connection (it
relays to the real proxy at 127.0.0.1:8080), then hit it with one client
request. Ctrl+C when done; it prints a full byte-level transcript.
"""

import socket
import sys
import threading
import time

RELAY_HOST = "127.0.0.1"
RELAY_PORT = 8091
UPSTREAM_HOST = "127.0.0.1"
UPSTREAM_PORT = 8080

_TLS_CONTENT_TYPES = {
    20: "change_cipher_spec (middlebox compat, TLS 1.3 ignores the content)",
    21: "alert",
    22: "handshake (cleartext -- ClientHello or ServerHello only, see module docstring)",
    23: "application_data (opaque -- encrypted handshake continuation or real app data)",
}

_events: list[tuple[float, str, bytes]] = []
_events_lock = threading.Lock()


def _log_event(direction: str, data: bytes) -> None:
    with _events_lock:
        _events.append((time.time(), direction, data))


def _parse_tls_records(data: bytes) -> list[str]:
    """Parse only the record-layer framing (type, version, length) --
    never touches the record body's content beyond reading its declared
    length to find the next record boundary."""
    descriptions = []
    pos = 0
    while pos + 5 <= len(data):
        content_type = data[pos]
        version = (data[pos + 1], data[pos + 2])
        length = int.from_bytes(data[pos + 3 : pos + 5], "big")
        type_desc = _TLS_CONTENT_TYPES.get(content_type, f"unknown (0x{content_type:02x})")
        descriptions.append(f"TLS record: type={type_desc}, version={version}, length={length}B")
        pos += 5 + length
    if not descriptions:
        descriptions.append(f"non-TLS-record bytes ({len(data)}B) -- likely plaintext HTTP (proxy->backend leg)")
    return descriptions


def _pump(src: socket.socket, dst: socket.socket, direction: str) -> None:
    try:
        while True:
            chunk = src.recv(65536)
            if not chunk:
                break
            _log_event(direction, chunk)
            dst.sendall(chunk)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def relay_one_connection() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((RELAY_HOST, RELAY_PORT))
    listener.listen(1)
    print(f"[capture] relaying one connection: client -> {RELAY_HOST}:{RELAY_PORT} -> {UPSTREAM_HOST}:{UPSTREAM_PORT}")
    print("[capture] connect a client to the relay port now (e.g. https://127.0.0.1:8091/docs)")

    client_sock, client_addr = listener.accept()
    print(f"[capture] client connected from {client_addr} (TCP handshake already completed below socket level)")

    upstream_sock = socket.create_connection((UPSTREAM_HOST, UPSTREAM_PORT))

    t1 = threading.Thread(target=_pump, args=(client_sock, upstream_sock, "client->proxy"))
    t2 = threading.Thread(target=_pump, args=(upstream_sock, client_sock, "proxy->client"))
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    client_sock.close()
    upstream_sock.close()
    listener.close()

    print("\n[capture] === transcript (one real TLS session, byte-accurate, unmodified) ===\n")
    with _events_lock:
        events = list(_events)

    if not events:
        print("[capture] no bytes captured -- did a client actually connect?")
        return

    t0 = events[0][0]
    for ts, direction, data in events:
        print(f"[+{ts - t0:6.3f}s] {direction} ({len(data)} bytes):")
        for desc in _parse_tls_records(data):
            print(f"    {desc}")


if __name__ == "__main__":
    try:
        relay_one_connection()
    except KeyboardInterrupt:
        sys.exit(0)
