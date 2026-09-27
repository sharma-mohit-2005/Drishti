"""Live TLS endpoints: supported protocol versions, negotiated cipher, and the server certificate."""
from __future__ import annotations

import socket
import ssl

from cryptography import x509

from .. import registry as R
from ..models import RawFinding
from .certs import cert_finding

_VERSIONS = [("1.0", ssl.TLSVersion.TLSv1), ("1.1", ssl.TLSVersion.TLSv1_1),
             ("1.2", ssl.TLSVersion.TLSv1_2), ("1.3", ssl.TLSVersion.TLSv1_3)]


def _ctx(version: ssl.TLSVersion | None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if version is not None:
        try:
            ctx.minimum_version = version
            ctx.maximum_version = version
        except ValueError:
            pass
        if version < ssl.TLSVersion.TLSv1_2:
            try:
                ctx.set_ciphers("ALL:@SECLEVEL=0")
            except ssl.SSLError:
                pass
    return ctx


def _handshake(host: str, port: int, version, timeout: float):
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with _ctx(version).wrap_socket(sock, server_hostname=host) as s:
            return s.version(), s.cipher(), s.getpeercert(binary_form=True)


def scan_endpoint(target: str, timeout: float = 4.0) -> list[RawFinding]:
    host, _, port_s = target.rpartition(":")
    if not host:
        host, port_s = target, "443"
    port = int(port_s)
    where = f"{host}:{port}"
    out: list[RawFinding] = []
    supported = []
    for label, v in _VERSIONS:
        try:
            _handshake(host, port, v, timeout)
            supported.append(label)
        except (ssl.SSLError, OSError, ValueError):
            continue
    for label in supported:
        parts = R.parse_tls_version(f"TLSv{label}")
        out.append(RawFinding(scanner="endpoint", kind="protocol", identifier=f"TLS {label}", path=where, line=None,
                              snippet=f"{where} accepts TLS {label}", canonical="TLS", params={"version": label},
                              usage="protocol", confidence=1.0, rule_id="tls-version-probe", agility="config",
                              components=parts[1:]))
    try:
        ver, cipher, der = _handshake(host, port, None, timeout)
    except (ssl.SSLError, OSError) as e:
        if not supported:
            out.append(RawFinding(scanner="endpoint", kind="protocol", identifier="unreachable", path=where, line=None,
                                  snippet=f"{where}: {e}", canonical="TLS", params={"version": "unreachable"},
                                  usage="protocol", confidence=0.5, rule_id="tls-unreachable", agility="n/a"))
        return out
    name = cipher[0] if cipher else ""
    parts = R.parse_cipher_suite(name)
    if ver == "TLSv1.3":
        # TLS 1.3 suites carry no key exchange; Python's OpenSSL negotiates (EC)DHE, usually X25519.
        parts = [("X25519", {}, "key-agree")] + parts
    if parts:
        statuses = [R.assess(c, p)["status"] for c, p, _ in parts]
        out.append(RawFinding(scanner="endpoint", kind="suite", identifier=name, path=where, line=None,
                              snippet=f"{where} negotiated {name} over {ver}", canonical=None, params={"suite": name},
                              usage="protocol", confidence=1.0, rule_id="tls-negotiated-suite", agility="config",
                              extra={"worst": R.worst(statuses), "negotiated_version": ver}, components=parts))
    if der:
        try:
            out.append(cert_finding(x509.load_der_x509_certificate(der), where, None, scanner="endpoint"))
        except ValueError:
            pass
    return out
