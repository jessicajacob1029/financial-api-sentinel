"""Generate a local demo CA for Financial API Sentinel.

Run via `make setup`. Produces:
  - certs/ca.key         EC P-256 private key (our canonical copy)
  - certs/ca.pem          self-signed CA certificate
  - certs/mitmproxy-ca.pem   the same key+cert, concatenated, in the exact
    layout mitmproxy's CertStore.from_files() expects (private key PEM
    immediately followed by the certificate PEM in one file). Passing
    `--set confdir=./certs` to mitmproxy makes it load and use this CA
    directly instead of generating its own separate one in ~/.mitmproxy --
    confirmed against mitmproxy 11.0.2's certs.py (CONF_BASENAME
    "mitmproxy" -> "<confdir>/mitmproxy-ca.pem").

This CA is for local demo TLS interception only — it is never committed to
git (see .gitignore) and should be removed from any system trust store
after the demo.
"""

import datetime
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

CERTS_DIR = pathlib.Path(__file__).resolve().parent.parent / "certs"
KEY_PATH = CERTS_DIR / "ca.key"
CERT_PATH = CERTS_DIR / "ca.pem"
MITMPROXY_CA_PATH = CERTS_DIR / "mitmproxy-ca.pem"
VALID_DAYS = 365


def generate_ca() -> None:
    if KEY_PATH.exists() and CERT_PATH.exists() and MITMPROXY_CA_PATH.exists():
        print(f"CA already exists at {CERT_PATH}, skipping (delete all three files to regenerate).")
        return

    CERTS_DIR.mkdir(parents=True, exist_ok=True)

    private_key = ec.generate_private_key(ec.SECP256R1())

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Financial API Sentinel Demo CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Financial API Sentinel (local demo only)"),
        ]
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
        .sign(private_key, hashes.SHA256())
    )

    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    KEY_PATH.write_bytes(key_pem)
    KEY_PATH.chmod(0o600)

    CERT_PATH.write_bytes(cert_pem)

    # mitmproxy's own PEM loader (cryptography.load_pem_private_key)
    # auto-detects PKCS8 vs. SEC1, so writing the same PKCS8 key bytes
    # here (rather than the TraditionalOpenSSL/SEC1 format mitmproxy uses
    # for its own self-generated CAs) works and keeps this file byte-for-
    # byte consistent with ca.key.
    MITMPROXY_CA_PATH.write_bytes(key_pem + cert_pem)
    MITMPROXY_CA_PATH.chmod(0o600)

    print(f"Generated demo CA:\n  key:  {KEY_PATH}\n  cert: {CERT_PATH}\n  mitmproxy-format: {MITMPROXY_CA_PATH}")
    print("This CA is for local demo use only. Do not commit it, do not reuse it elsewhere.")


if __name__ == "__main__":
    generate_ca()
