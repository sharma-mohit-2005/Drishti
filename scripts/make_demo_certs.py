"""Generate the demo certificates and keys for demo/bharat-finserve.

These are throwaway keys for a fictional company, created only so the scanner
has real X.509 material to parse. Never use them for anything else.
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

DEMO = Path(__file__).resolve().parent.parent / "demo" / "bharat-finserve"
NOW = dt.datetime.now(dt.timezone.utc)


def name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Bharat FinServe (demo)"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def cert(subject_cn, key, issuer_cn, issuer_key, days_from, days_to, ca=False, hash_alg=None):
    b = (x509.CertificateBuilder().subject_name(name(subject_cn)).issuer_name(name(issuer_cn))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(NOW + dt.timedelta(days=days_from)).not_valid_after(NOW + dt.timedelta(days=days_to))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    return b.sign(issuer_key, hash_alg or hashes.SHA256())


def pem(c):
    return c.public_bytes(serialization.Encoding.PEM)


def main():
    (DEMO / "edge" / "certs").mkdir(parents=True, exist_ok=True)
    (DEMO / "kyc-service" / "keys").mkdir(parents=True, exist_ok=True)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    ca = cert("Bharat FinServe Internal Root CA", ca_key, "Bharat FinServe Internal Root CA", ca_key, -30, 3650, ca=True)
    (DEMO / "edge" / "certs" / "ca.crt").write_bytes(pem(ca))

    srv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    srv = cert("pay.bharatfinserve.example", srv_key, "Bharat FinServe Internal Root CA", ca_key, -10, 395)
    (DEMO / "edge" / "certs" / "server.crt").write_bytes(pem(srv))
    (DEMO / "edge" / "certs" / "server.key").write_bytes(srv_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))

    partner_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    try:
        partner = cert("sftp.partner-bank.example", partner_key, "sftp.partner-bank.example", partner_key, -800, -30, hash_alg=hashes.SHA1())
    except Exception:
        partner = cert("sftp.partner-bank.example", partner_key, "sftp.partner-bank.example", partner_key, -800, -30)
    (DEMO / "payments-svc" / "src" / "main" / "resources" / "partner-bank.pem").write_bytes(pem(partner))

    jwt_key = ec.generate_private_key(ec.SECP256R1())
    (DEMO / "kyc-service" / "keys" / "jwt-signing.pem").write_bytes(jwt_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    host_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = host_key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    (DEMO / "infra" / "ssh_host_rsa_key.pub").write_bytes(pub + b" root@bastion\n")
    print("demo certificates and keys written under", DEMO)


if __name__ == "__main__":
    main()
