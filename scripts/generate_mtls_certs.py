"""Generate leaf certificates for the optional mTLS proxy<->backend leg
(Phase 7A.1). Separate from generate_ca.py deliberately: mTLS is a
toggleable capability (MTLS_BACKEND_ENABLED), not part of the base demo,
so it gets its own opt-in setup step (`make setup-mtls`) rather than
running unconditionally inside `make setup`.

Both leaf certs are signed by the same local CA generate_ca.py produces
(certs/ca.pem / ca.key), so each side can verify the other against that
one CA rather than disabling verification (doc 04 SS5: "should not
blanket-disable verification; if you must trust the demo backend's
self-signed cert, pin it explicitly"). Produces:

  - certs/backend-server.key + certs/backend-server.pem
      Leaf cert/key for uvicorn's --ssl-certfile/--ssl-keyfile. SAN
      includes 127.0.0.1 (IP) since modern TLS clients (mitmproxy's
      upstream verification included) match against SAN, not CN.

  - certs/proxy-client.pem
      Combined key+cert leaf for mitmproxy's `client_certs` option --
      confirmed against mitmproxy 11.0.2's tlsconfig.py /
      net/tls.py (use_privatekey_file + use_certificate_chain_file on
      the SAME path), same single-combined-PEM pattern as
      certs/mitmproxy-ca.pem.
"""

import datetime
import ipaddress
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

CERTS_DIR = pathlib.Path(__file__).resolve().parent.parent / "certs"
CA_KEY_PATH = CERTS_DIR / "ca.key"
CA_CERT_PATH = CERTS_DIR / "ca.pem"

BACKEND_KEY_PATH = CERTS_DIR / "backend-server.key"
BACKEND_CERT_PATH = CERTS_DIR / "backend-server.pem"
PROXY_CLIENT_PATH = CERTS_DIR / "proxy-client.pem"

VALID_DAYS = 365


def _load_ca() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    if not (CA_KEY_PATH.exists() and CA_CERT_PATH.exists()):
        raise SystemExit(f"CA not found at {CA_CERT_PATH} -- run `make setup` first (generates the CA).")
    ca_key = serialization.load_pem_private_key(CA_KEY_PATH.read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
    return ca_key, ca_cert


def _issue_leaf_cert(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    common_name: str,
    san: x509.SubjectAlternativeName,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(san, critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return leaf_key, cert


def _write_pem(key: ec.EllipticCurvePrivateKey, cert: x509.Certificate, key_path: pathlib.Path, cert_path: pathlib.Path) -> None:
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_path.write_bytes(key_pem)
    key_path.chmod(0o600)
    cert_path.write_bytes(cert_pem)


def generate_mtls_certs() -> None:
    if BACKEND_KEY_PATH.exists() and BACKEND_CERT_PATH.exists() and PROXY_CLIENT_PATH.exists():
        print(f"mTLS leaf certs already exist under {CERTS_DIR}, skipping (delete them to regenerate).")
        return

    ca_key, ca_cert = _load_ca()

    backend_key, backend_cert = _issue_leaf_cert(
        ca_key,
        ca_cert,
        common_name="financial-api-sentinel-backend",
        san=x509.SubjectAlternativeName(
            [x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.DNSName("localhost")]
        ),
    )
    _write_pem(backend_key, backend_cert, BACKEND_KEY_PATH, BACKEND_CERT_PATH)

    proxy_key, proxy_cert = _issue_leaf_cert(
        ca_key,
        ca_cert,
        common_name="financial-api-sentinel-proxy-client",
        san=x509.SubjectAlternativeName([x509.DNSName("sentinel-proxy")]),
    )
    # mitmproxy's client_certs option expects one file: private key PEM
    # immediately followed by the certificate PEM (see module docstring).
    proxy_key_pem = proxy_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    proxy_cert_pem = proxy_cert.public_bytes(serialization.Encoding.PEM)
    PROXY_CLIENT_PATH.write_bytes(proxy_key_pem + proxy_cert_pem)
    PROXY_CLIENT_PATH.chmod(0o600)

    print(
        "Generated mTLS leaf certs (both signed by the local CA):\n"
        f"  backend server cert+key: {BACKEND_CERT_PATH}, {BACKEND_KEY_PATH}\n"
        f"  proxy client cert (combined): {PROXY_CLIENT_PATH}\n"
        "Enable with: make backend MTLS=1   /   make proxy MTLS=1"
    )


if __name__ == "__main__":
    generate_mtls_certs()
