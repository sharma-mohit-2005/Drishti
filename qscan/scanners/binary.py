"""Compiled artefacts: native binaries (ELF/PE/Mach-O), JAR/WAR/class files.

Three signals, from strongest to weakest:
  1. embedded library version strings (e.g. "OpenSSL 1.1.1k  25 Mar 2021")
  2. crypto API symbol names that survive in import tables (RSA_generate_key_ex,
     BCryptGenerateKeyPair, Go's crypto/rsa.GenerateKey)
  3. algorithm constants that survive stripping (AES S-box, SHA-256 and MD5 round constants)
"""
from __future__ import annotations

import re
import struct
import zipfile
from io import BytesIO
from pathlib import Path

from .. import registry as R
from ..models import RawFinding
from .deps import openssl_finding

BINARY_EXTS = {".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".lib", ".jar", ".war", ".ear", ".class", ".node", ".pyd"}
MAGICS = (b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"PK\x03\x04")

SYMBOLS: list[tuple[bytes, str, dict, str]] = [
    (b"RSA_generate_key_ex", "RSA", {}, "keygen"), (b"RSA_public_encrypt", "RSA", {}, "encrypt"),
    (b"RSA_sign", "RSA", {}, "sign"), (b"EVP_PKEY_CTX_set_rsa_keygen_bits", "RSA", {}, "keygen"),
    (b"ECDSA_do_sign", "ECDSA", {}, "sign"), (b"EC_KEY_generate_key", "EC", {}, "keygen"),
    (b"ECDH_compute_key", "ECDH", {}, "key-agree"), (b"DH_generate_key", "DH", {}, "key-agree"),
    (b"DSA_generate_key", "DSA", {}, "keygen"), (b"MD5_Init", "MD5", {}, "digest"), (b"SHA1_Init", "SHA-1", {}, "digest"),
    (b"DES_ecb_encrypt", "DES", {"mode": "ecb"}, "encrypt"), (b"DES_ede3_cbc_encrypt", "3DES", {"mode": "cbc"}, "encrypt"),
    (b"RC4_set_key", "RC4", {}, "encrypt"), (b"EVP_aes_128_cbc", "AES", {"size": 128, "mode": "cbc"}, "encrypt"),
    (b"EVP_aes_256_gcm", "AES", {"size": 256, "mode": "gcm"}, "encrypt"),
    (b"crypto/rsa.GenerateKey", "RSA", {}, "keygen"), (b"crypto/ecdsa.GenerateKey", "ECDSA", {}, "keygen"),
    (b"crypto/md5.", "MD5", {}, "digest"), (b"crypto/sha1.", "SHA-1", {}, "digest"),
    (b"crypto/des.", "DES", {}, "encrypt"), (b"crypto/rc4.", "RC4", {}, "encrypt"),
    (b"crypto/mlkem.", "ML-KEM", {}, "key-agree"), (b"OQS_KEM_new", "ML-KEM", {}, "key-agree"),
    (b"EVP_PKEY_ML_KEM", "ML-KEM", {}, "key-agree"),
]

# First bytes of well-known algorithm tables.
AES_SBOX = bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76])
SHA256_K = [0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5]
MD5_T = [0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE]
CONSTANTS: list[tuple[bytes, str, str]] = [
    (AES_SBOX, "AES", "AES S-box"),
    (struct.pack(">4I", *SHA256_K), "SHA-256", "SHA-256 round constants (BE)"),
    (struct.pack("<4I", *SHA256_K), "SHA-256", "SHA-256 round constants (LE)"),
    (struct.pack("<4I", *MD5_T), "MD5", "MD5 sine table"),
]

_OPENSSL_VER = re.compile(rb"OpenSSL (\d+\.\d+\.\d+[a-z]?)")
_JCA_STR = re.compile(rb"(RSA/ECB/[A-Za-z0-9]+|AES/(?:ECB|CBC|GCM|CTR)/[A-Za-z0-9]+|DESede/[A-Z]+/[A-Za-z0-9]+|DES/[A-Z]+/[A-Za-z0-9]+|"
                      rb"SHA1withRSA|SHA256withRSA|SHA256withECDSA|SHA1withECDSA|MD5withRSA|HmacSHA1|HmacMD5)")
_JCA_BARE = re.compile(rb"\x01\x00[\x03-\x07](MD5|SHA-1|SHA1|DESede|RC4|DES)(?=[\x00-\x1f])")


def is_binary(name: str, head: bytes) -> bool:
    low = name.lower()
    return any(low.endswith(e) for e in BINARY_EXTS) or head.startswith(MAGICS[:5])


def _f(identifier, canonical, params, usage, path, snippet, rule, conf) -> RawFinding:
    kind = "protocol" if canonical == "TLS" else "algorithm"
    return RawFinding(scanner="binary", kind=kind, identifier=identifier, path=path, line=None, snippet=snippet,
                      canonical=canonical, params=params, usage=usage, confidence=conf, rule_id=rule, agility="hardcoded")


def _scan_class_bytes(data: bytes, path: str) -> list[RawFinding]:
    out = []
    seen = set()
    for m in list(_JCA_STR.finditer(data)) + list(_JCA_BARE.finditer(data)):
        s = m.group(1).decode()
        if s in seen:
            continue
        seen.add(s)
        if "/" in s:
            parts = R.parse_transformation(s)
        elif "with" in s:
            parts = R.parse_jca_signature(s)
        elif s.startswith("Hmac"):
            parts = R.parse_hmac(s)
        else:
            n = R.normalize(s)
            parts = [(n[0], n[1], "digest" if n[0] in ("MD5", "SHA-1") else "encrypt")] if n else []
        if parts:
            c, p, u = parts[0]
            f = _f(s, c, p, u, path, f'JVM constant "{s}"', "jvm-constant-pool", 0.85)
            f.components = parts[1:]
            out.append(f)
    return out


def scan_binary(data: bytes, rel_path: str) -> list[RawFinding]:
    out: list[RawFinding] = []
    low = rel_path.lower()
    if low.endswith((".jar", ".war", ".ear")) or (data.startswith(b"PK\x03\x04") and low.endswith((".jar", ".war", ".ear"))):
        try:
            with zipfile.ZipFile(BytesIO(data)) as z:
                for info in z.infolist():
                    if info.filename.endswith(".class") and info.file_size < 2_000_000:
                        out += _scan_class_bytes(z.read(info), f"{rel_path}!/{info.filename}")
                    elif info.filename.endswith((".so", ".dll")) and info.file_size < 20_000_000:
                        out += scan_binary(z.read(info), f"{rel_path}!/{info.filename}")
        except zipfile.BadZipFile:
            pass
        return out
    if low.endswith(".class") or data.startswith(b"\xca\xfe\xba\xbe") and b"java/" in data[:4096]:
        return _scan_class_bytes(data, rel_path)

    versions = {m.group(1).decode() for m in _OPENSSL_VER.finditer(data)}
    for v in sorted(versions):
        out.append(openssl_finding(v, rel_path, None, f"embedded string 'OpenSSL {v}'", "binary-openssl-version", scanner="binary"))
    # A crypto library contains every algorithm it offers; that is availability, not use.
    is_lib = bool(versions) or bool(_CRYPTO_LIB_NAME.search(Path(rel_path).name))
    seen: set[str] = set()
    for sym, c, p, u in SYMBOLS:
        if sym in data:
            key = R.display_name(c, p) + u
            if key in seen:
                continue
            seen.add(key)
            if is_lib:
                out.append(_f(sym.decode(), c, dict(p), "available", rel_path, f"offered by crypto library (symbol {sym.decode()})", "binary-library-symbol", 0.4))
            else:
                out.append(_f(sym.decode(), c, dict(p), u, rel_path, f"symbol {sym.decode()}", "binary-symbol", 0.7))
    for const, c, label in CONSTANTS:
        if const in data and not any(f.canonical == c for f in out):
            usage = "available" if is_lib else ("digest" if c != "AES" else "encrypt")
            out.append(_f(label, c, {}, usage, rel_path, f"constant table: {label}", "binary-constant", 0.6))
    return out


_CRYPTO_LIB_NAME = re.compile(r"(?i)^(lib)?(crypto|ssl|boringssl|wolfssl|mbedtls|mbedcrypto|sodium|gcrypt|nettle|bcrypt)[-_.\d]")
