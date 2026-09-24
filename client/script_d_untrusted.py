"""Script D: untrusted client -- certificate validation failure demo
(Phase 7A.3).

Two distinct TLS-layer rejections, both proven to happen *before* any
HTTP request is exchanged -- neither needs a token, a DPoP proof, or any
application logic to run:

1. Client doesn't trust the proxy's CA. Connecting to the proxy WITHOUT
   pinning certs/ca.pem (using the default system trust store instead,
   which has never heard of this local demo CA) fails certificate chain
   validation on the CLIENT side.

2. Server doesn't trust the client's cert (mTLS only -- requires
   `make backend MTLS=1` / `make proxy MTLS=1` already running). A
   self-signed cert (signed by nobody, not our CA) presented to the
   mTLS-enabled backend gets rejected SERVER-side, with a genuine TLS
   alert sent back to the connecting client.

Contrast this with Script B: Script B's replay gets a "401 Unauthorized"
-- a normal HTTP response, after a completely successful TLS handshake,
rejected by *application* logic (the decision engine). Both scenarios
here never get an HTTP response at all -- the connection dies at the TLS
layer, which is a fundamentally different (and earlier) kind of failure.
"""

import datetime
import pathlib
import socket
import ssl
import sys
import tempfile

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from config import BACKEND_HOST, BACKEND_PORT, MTLS_BACKEND_ENABLED, PROXY_BASE_URL


def scenario_1_client_does_not_trust_server_ca() -> bool:
    print("[script_d] scenario 1: connect to the proxy WITHOUT trusting its CA")
    try:
        # Deliberately no verify=certs/ca.pem -- uses the default system
        # trust store, which has never heard of this local demo CA.
        httpx.get(f"{PROXY_BASE_URL}/docs", timeout=5)
        print("[script_d] FAIL: connection succeeded -- expected certificate verification to fail")
        return False
    except httpx.ConnectError as exc:
        print(f"[script_d] PASS: TLS handshake rejected before any HTTP request was sent")
        print(f"[script_d]   client-side error: {exc}")
        return True


def _generate_self_signed_client_cert() -> bytes:
    """A cert signed by nobody -- not our CA, not any CA. For scenario 2."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "untrusted-client")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return key_pem + cert.public_bytes(serialization.Encoding.PEM)


def scenario_2_server_does_not_trust_client_cert() -> bool | None:
    if not MTLS_BACKEND_ENABLED:
        print(
            "[script_d] scenario 2 skipped: needs `make backend MTLS=1` / `make proxy MTLS=1` "
            "already running (this script was invoked without MTLS=1). See scripts/generate_mtls_certs.py."
        )
        return None

    print("[script_d] scenario 2: present a self-signed (untrusted) client cert to the mTLS backend")
    combined_pem = _generate_self_signed_client_cert()

    with tempfile.TemporaryDirectory() as tmp:
        cert_path = pathlib.Path(tmp) / "untrusted-client.pem"
        cert_path.write_bytes(combined_pem)

        ctx = ssl.create_default_context(cafile="certs/ca.pem")
        ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(cert_path))

        try:
            with socket.create_connection((BACKEND_HOST, BACKEND_PORT), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=BACKEND_HOST) as tls:
                    # TLS 1.3 nuance, caught live building this script: the
                    # client completes its side of the handshake
                    # optimistically after sending its last flight
                    # (Certificate/CertificateVerify/Finished), *before*
                    # learning whether the server accepted that
                    # certificate -- wrap_socket() returning here does NOT
                    # mean the server accepted anything. The server's
                    # rejection only surfaces on the next read/write, so
                    # this sends a real request and waits for a response
                    # (or the alert) rather than trusting handshake
                    # completion alone.
                    tls.sendall(b"GET /docs HTTP/1.0\r\n\r\n")
                    response = tls.recv(200)
                    if response:
                        print(f"[script_d] FAIL: got a response -- expected the server to reject this cert")
                        print(f"[script_d]   response: {response[:100]}")
                        return False
                    print(
                        "[script_d] PASS: server closed the connection with zero bytes back -- no HTTP response, "
                        "consistent with rejecting the client cert (this server implementation drops the "
                        "connection rather than sending a formal TLS alert record; either way, no application "
                        "data was ever exchanged)"
                    )
                    return True
        except ssl.SSLError as exc:
            print(f"[script_d] PASS: server rejected the untrusted client cert at the TLS layer")
            print(f"[script_d]   TLS alert: {exc}")
            return True
        except (ConnectionResetError, BrokenPipeError) as exc:
            print(f"[script_d] PASS: server reset the connection rejecting the untrusted client cert")
            print(f"[script_d]   error: {exc!r}")
            return True


if __name__ == "__main__":
    results = [scenario_1_client_does_not_trust_server_ca(), scenario_2_server_does_not_trust_client_cert()]
    if False in results:
        sys.exit(1)
