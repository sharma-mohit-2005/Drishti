"""Certificates, keys and keystores: PEM/DER X.509, private/public keys, SSH keys."""
from __future__ import annotations

import base64
import hashlib
import re
import warnings
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, ed448, ed25519, rsa, x448, x25519
from cryptography.x509.oid import ExtensionOID

from .. import registry as R
from ..models import RawFinding

CERT_EXTS = {".pem", ".crt", ".cer", ".der", ".key", ".pub", ".cert", ".ca-bundle"}
_PEM = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----\r?\n(.*?)-----END \1-----", re.S)
_SSH_PUB = re.compile(rb"^(ssh-rsa|ssh-dss|ecdsa-sha2-nistp\d+|ssh-ed25519) (AAAA[0-9A-Za-z+/=]+)", re.M)


def key_params(key) -> tuple[str, dict]:
    """(canonical, params) for a cryptography public or private key object."""
    if isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        return "RSA", {"size": key.key_size}
    if isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        return "EC", {"curve": R.normalize_curve(key.curve.name)}
    if isinstance(key, (dsa.DSAPublicKey, dsa.DSAPrivateKey)):
        return "DSA", {"size": key.key_size}
    if isinstance(key, (dh.DHPublicKey, dh.DHPrivateKey)):
        return "DH", {"size": key.key_size}
    if isinstance(key, (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey)):
        return "Ed25519", {}
    if isinstance(key, (ed448.Ed448PublicKey, ed448.Ed448PrivateKey)):
        return "Ed448", {}
    if isinstance(key, (x25519.X25519PublicKey, x25519.X25519PrivateKey)):
        return "X25519", {}
    if isinstance(key, (x448.X448PublicKey, x448.X448PrivateKey)):
        return "X448", {}
    return "UNKNOWN", {}


def _line_of(data: bytes, offset: int) -> int:
    return data.count(b"\n", 0, offset) + 1


def cert_finding(cert: x509.Certificate, path: str, line: int | None, scanner: str = "certificate") -> RawFinding:
    pub = cert.public_key()
    kc, kp = key_params(pub)
    try:
        h = cert.signature_hash_algorithm
        sig_hash = R.normalize(h.name)[0] if h and R.normalize(h.name) else None
    except Exception:
        sig_hash = None
    sig_name = cert.signature_algorithm_oid._name
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        is_ca = bool(bc.ca)
    except x509.ExtensionNotFound:
        is_ca = False
    not_after = cert.not_valid_after_utc
    not_before = cert.not_valid_before_utc
    now = datetime.now(timezone.utc)
    fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    subject = cert.subject.rfc4514_string() or "(empty subject)"
    comps: list[tuple[str, dict, str]] = [(kc if kc != "EC" else "ECDSA", kp, "sign")]
    if sig_hash:
        comps.append((sig_hash, {}, "digest"))
    return RawFinding(
        scanner=scanner, kind="certificate", identifier=subject, path=path, line=line,
        snippet=f"X.509 {subject} · {R.display_name(kc, kp)} · {sig_name}",
        canonical=kc, params=kp, usage="sign", confidence=1.0, rule_id="x509-certificate", agility="n/a",
        extra={
            "fingerprint": fp, "subject": subject, "issuer": cert.issuer.rfc4514_string(),
            "not_before": not_before.isoformat(), "not_after": not_after.isoformat(),
            "expired": not_after < now, "days_left": (not_after - now).days, "is_ca": is_ca,
            "self_signed": cert.issuer == cert.subject, "signature_algorithm": sig_name,
            "serial": format(cert.serial_number, "x"),
        },
        components=comps,
    )


def scan_cert_file(data: bytes, rel_path: str) -> list[RawFinding]:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")      # malformed test certs (e.g. negative serials) are still inventoried
        return _scan_cert_file(data, rel_path)


def _scan_cert_file(data: bytes, rel_path: str) -> list[RawFinding]:
    out: list[RawFinding] = []
    for m in _PEM.finditer(data):
        label = m.group(1).decode()
        block = m.group(0)
        line = _line_of(data, m.start())
        try:
            if label in ("CERTIFICATE", "TRUSTED CERTIFICATE"):
                out.append(cert_finding(x509.load_pem_x509_certificate(block), rel_path, line))
            elif label.endswith("PRIVATE KEY") and "ENCRYPTED" not in label and label != "OPENSSH PRIVATE KEY":
                key = serialization.load_pem_private_key(block, password=None)
                out.append(_key_finding(key, "private-key", rel_path, line, label))
            elif label == "OPENSSH PRIVATE KEY":
                key = serialization.load_ssh_private_key(block, password=None)
                out.append(_key_finding(key, "private-key", rel_path, line, label))
            elif label in ("PUBLIC KEY", "RSA PUBLIC KEY"):
                key = serialization.load_pem_public_key(block)
                out.append(_key_finding(key, "public-key", rel_path, line, label))
            elif "ENCRYPTED" in label:
                out.append(RawFinding(scanner="certificate", kind="key", identifier=label, path=rel_path, line=line,
                                      snippet=f"-----BEGIN {label}----- (password protected)", canonical="UNKNOWN",
                                      params={}, usage="storage", confidence=0.9, rule_id="pem-encrypted-key",
                                      agility="n/a", extra={"material": "private-key", "encrypted": True}))
        except Exception:
            continue
    for m in _SSH_PUB.finditer(data):
        try:
            key = serialization.load_ssh_public_key(m.group(0))
        except Exception:
            continue
        out.append(_key_finding(key, "public-key", rel_path, _line_of(data, m.start()), m.group(1).decode(),
                                rule="ssh-public-key"))
    if not out and rel_path.lower().endswith((".der", ".cer", ".crt")) and not data.lstrip().startswith(b"-----"):
        try:
            out.append(cert_finding(x509.load_der_x509_certificate(data), rel_path, None))
        except Exception:
            pass
    return out


def _key_finding(key, material: str, path: str, line: int, label: str, rule: str = "pem-key") -> RawFinding:
    kc, kp = key_params(key)
    fp = hashlib.sha256(f"{path}:{line}:{label}".encode()).hexdigest()
    return RawFinding(
        scanner="certificate", kind="key", identifier=label, path=path, line=line,
        snippet=f"{label} · {R.display_name(kc, kp)}", canonical=kc, params=kp,
        usage="storage", confidence=1.0, rule_id=rule, agility="n/a",
        extra={"material": material, "fingerprint": fp, "encrypted": False},
    )


def looks_like_cert_file(name: str, head: bytes) -> bool:
    low = name.lower()
    return (any(low.endswith(e) for e in CERT_EXTS) or b"-----BEGIN " in head
            or low in ("authorized_keys", "known_hosts") or bool(_SSH_PUB.search(head)))


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()
