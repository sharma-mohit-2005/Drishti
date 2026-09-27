"""Configuration files: nginx, Apache, HAProxy, sshd/ssh, openssl.cnf, Spring Boot, Java security."""
from __future__ import annotations

import re

from .. import registry as R
from ..models import RawFinding

_SKIP_CIPHER_TOKENS = {"HIGH", "MEDIUM", "LOW", "ALL", "DEFAULT", "COMPLEMENTOFDEFAULT", "EXPORT",
                       "ECDHE", "EECDH", "EDH", "AESGCM", "AES256", "AES128", "SHA", "SHA256", "SHA384",
                       "CHACHA20", "RSA", "DHE", "KRSA", "AES", "ANULL", "ENULL", "NULL", "MD5", "3DES", "RC4"}


def is_config(name: str, text_head: str) -> str | None:
    low = name.lower()
    if low in ("sshd_config", "ssh_config") or low.endswith(("sshd_config", ".sshd")):
        return "ssh"
    if low in ("openssl.cnf", "openssl.conf") or low.endswith("openssl.cnf"):
        return "openssl"
    if low.startswith("application") and low.endswith((".properties", ".yml", ".yaml")):
        return "spring"
    if low == "java.security":
        return "javasec"
    if low.endswith((".conf", ".cfg", ".config", ".vhost")) or low in ("nginx.conf", "httpd.conf", "haproxy.cfg"):
        if re.search(r"ssl_protocols|ssl_ciphers|SSLProtocol|SSLCipherSuite|ssl-default-bind|ssl-min-ver|ssl_ecdh_curve", text_head):
            return "web"
    return None


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _f(kind, ident, path, line, snippet, parts, rule, usage="protocol", extra=None) -> RawFinding:
    canonical, params, u = parts[0]
    return RawFinding(scanner="config", kind=kind, identifier=ident, path=path, line=line,
                      snippet=snippet.strip()[:220], canonical=canonical, params=params,
                      usage=u or usage, confidence=0.95, rule_id=rule, agility="config",
                      extra=extra or {}, components=parts[1:])


def _suite_findings(names: list[str], path: str, line: int, snippet: str, rule: str) -> list[RawFinding]:
    out = []
    for n in names:
        n = n.strip().strip('"\'')
        if not n or n[0] in "!-+@" or n.upper() in _SKIP_CIPHER_TOKENS or n.upper().startswith("@SECLEVEL"):
            continue
        parts = R.parse_cipher_suite(n)
        if not parts:
            continue
        statuses = [R.assess(c, p)["status"] for c, p, _ in parts]
        out.append(RawFinding(scanner="config", kind="suite", identifier=n, path=path, line=line,
                              snippet=snippet.strip()[:220], canonical=None, params={"suite": n},
                              usage="protocol", confidence=0.95, rule_id=rule, agility="config",
                              extra={"worst": R.worst(statuses)}, components=parts))
    return out


def _groups(names: list[str], path: str, line: int, snippet: str, rule: str) -> list[RawFinding]:
    out = []
    for g in names:
        n = R.normalize(g.strip())
        if not n:
            continue
        c, p = n
        if c == "EC":
            c = "ECDH"
        out.append(_f("algorithm", g.strip(), path, line, snippet, [(c, p, "key-agree")], rule))
    return out


def _versions(tokens: list[str], path, line, snippet, rule) -> list[RawFinding]:
    out = []
    for t in tokens:
        t = t.strip().strip('"\',')
        if not t or t.startswith(("-", "!")) or t.lower() in ("all", "+all"):
            continue
        parts = R.parse_tls_version(t.lstrip("+"))
        if parts:
            out.append(_f("protocol", t, path, line, snippet, parts, rule))
    return out


def scan_config(text: str, rel_path: str, kind: str) -> list[RawFinding]:
    out: list[RawFinding] = []
    if kind == "web":
        for m in re.finditer(r"^[ \t]*(ssl_protocols|SSLProtocol|ssl-min-ver)[ \t]+([^;\n]+)", text, re.M):
            out += _versions(m.group(2).split(), rel_path, _line(text, m.start()), m.group(0), "tls-protocols")
        for m in re.finditer(r"^[ \t]*(ssl_ciphers|SSLCipherSuite|ssl-default-bind-ciphers|ssl-default-server-ciphers|ssl-default-bind-ciphersuites)[ \t]+['\"]?([^;'\"\n]+)", text, re.M):
            out += _suite_findings(re.split(r"[:,\s]+", m.group(2)), rel_path, _line(text, m.start()), m.group(0), "tls-ciphers")
        for m in re.finditer(r"^[ \t]*(ssl_ecdh_curve|ssl_conf_command\s+Groups|SSLOpenSSLConfCmd\s+(?:Curves|Groups))[ \t]+([^;\n]+)", text, re.M):
            out += _groups(re.split(r"[:,\s]+", m.group(2)), rel_path, _line(text, m.start()), m.group(0), "tls-groups")
    elif kind == "ssh":
        sections = {"kexalgorithms": "kex", "ciphers": "cipher", "macs": "mac", "hostkeyalgorithms": "hostkey",
                    "pubkeyacceptedalgorithms": "hostkey", "pubkeyacceptedkeytypes": "hostkey"}
        for m in re.finditer(r"^[ \t]*(\w+)[ \t]+(.+)$", text, re.M):
            key, value = m.group(1).lower(), m.group(2).strip()
            line = _line(text, m.start())
            if key in sections:
                for name in value.split(","):
                    name = name.strip().lstrip("+-^")
                    parts = R.parse_ssh(name, sections[key])
                    if parts:
                        out.append(_f("algorithm", name, rel_path, line, m.group(0), parts, f"ssh-{sections[key]}"))
            elif key == "hostkey":
                low = value.lower()
                guess = ("RSA", {}) if "rsa" in low else ("ECDSA", {}) if "ecdsa" in low else \
                        ("Ed25519", {}) if "ed25519" in low else ("DSA", {"size": 1024}) if "dsa" in low else None
                if guess:
                    out.append(_f("key", value, rel_path, line, m.group(0), [(guess[0], guess[1], "sign")], "ssh-hostkey-file",
                                  extra={"material": "private-key"}))
            elif key == "protocol" and value.strip() == "1":
                out.append(_f("protocol", "SSH-1", rel_path, line, m.group(0), [("TLS", {"version": "SSL 2.0"}, "protocol")], "ssh-protocol-1"))
    elif kind == "openssl":
        for m in re.finditer(r"^[ \t]*(MinProtocol|default_md|CipherString|default_bits|Groups|Curves)[ \t]*=[ \t]*(\S+)", text, re.M):
            key, value, line = m.group(1), m.group(2), _line(text, m.start())
            if key == "MinProtocol":
                out += _versions([value], rel_path, line, m.group(0), "openssl-minprotocol")
            elif key == "default_md":
                n = R.normalize(value)
                if n:
                    out.append(_f("algorithm", value, rel_path, line, m.group(0), [(n[0], n[1], "digest")], "openssl-default-md"))
            elif key == "default_bits" and value.isdigit():
                out.append(_f("algorithm", value, rel_path, line, m.group(0), [("RSA", {"size": int(value)}, "keygen")], "openssl-default-bits"))
            elif key == "CipherString":
                out += _suite_findings(re.split(r"[:,]", value), rel_path, line, m.group(0), "openssl-cipherstring")
            elif key in ("Groups", "Curves"):
                out += _groups(re.split(r"[:,]", value), rel_path, line, m.group(0), "openssl-groups")
    elif kind == "spring":
        for m in re.finditer(r"^[ \t]*(?:server\.ssl\.)?(enabled-protocols|protocol|ciphers)[ \t]*[:=][ \t]*(.+)$", text, re.M):
            key, value, line = m.group(1), m.group(2), _line(text, m.start())
            if key in ("enabled-protocols", "protocol"):
                out += _versions(re.split(r"[,\s\[\]]+", value), rel_path, line, m.group(0), "spring-ssl-protocols")
            else:
                out += _suite_findings(re.split(r"[,\s\[\]]+", value), rel_path, line, m.group(0), "spring-ssl-ciphers")
        for m in re.finditer(r"^[ \t]*(?:server\.ssl\.)?key-store-type[ \t]*[:=][ \t]*(\w+)", text, re.M):
            if m.group(1).upper() == "JKS":
                out.append(RawFinding(scanner="config", kind="library", identifier="JKS keystore", path=rel_path,
                                      line=_line(text, m.start()), snippet=m.group(0).strip(), canonical=None,
                                      params={"name": "JKS keystore", "version": "", "ecosystem": "java"},
                                      usage="storage", confidence=0.9, rule_id="spring-jks", agility="config",
                                      extra={"status": "weak", "note": "JKS uses weak integrity protection; prefer PKCS#12.", "pqc": "n/a"}))
    elif kind == "javasec":
        m = re.search(r"^jdk\.tls\.disabledAlgorithms\s*=\s*(.+?)(?<!\\)$", text, re.M | re.S)
        if m and "TLSv1," not in m.group(1) and "TLSv1 " not in m.group(1):
            out.append(_f("protocol", "TLSv1 enabled", rel_path, _line(text, m.start()), m.group(0)[:200],
                          [("TLS", {"version": "1.0"}, "protocol")], "java-security-tls10"))
    return out
