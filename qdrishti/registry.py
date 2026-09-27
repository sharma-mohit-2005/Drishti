"""Crypto algorithm registry.

Maps every spelling a scanner can meet (JCA names, OpenSSL names, OIDs, TLS
cipher suites, SSH algorithm names, JWT algs) to one canonical asset, and says
how that asset stands against classical and quantum attacks.
"""
from __future__ import annotations

import re
from typing import Any

# ---- status values -------------------------------------------------------
BROKEN = "broken"                 # classically broken or disallowed today
WEAK = "weak"                     # deprecated / weak classically
QV = "quantum-vulnerable"         # broken by Shor's algorithm
QW = "quantum-weakened"           # strength halved by Grover's algorithm
SAFE = "safe"
PQC = "pqc"                       # NIST post-quantum (or hybrid) algorithm
UNKNOWN = "unknown"

STATUS_ORDER = {BROKEN: 6, QV: 5, WEAK: 4, QW: 3, UNKNOWN: 2, SAFE: 1, PQC: 0}

# ---- canonical algorithms ---------------------------------------------------
# primitive values follow the CycloneDX 1.6 cryptoProperties enum.
ALGORITHMS: dict[str, dict[str, Any]] = {
    "RSA": {"primitive": "pke", "attack": "shor", "oid": "1.2.840.113549.1.1.1"},
    "DSA": {"primitive": "signature", "attack": "shor", "oid": "1.2.840.10040.4.1"},
    "DH": {"primitive": "key-agree", "attack": "shor", "oid": "1.2.840.113549.1.3.1"},
    "EC": {"primitive": "other", "attack": "shor", "oid": "1.2.840.10045.2.1"},
    "ECDSA": {"primitive": "signature", "attack": "shor", "oid": "1.2.840.10045.2.1"},
    "ECDH": {"primitive": "key-agree", "attack": "shor", "oid": "1.3.132.1.12"},
    "Ed25519": {"primitive": "signature", "attack": "shor", "oid": "1.3.101.112"},
    "Ed448": {"primitive": "signature", "attack": "shor", "oid": "1.3.101.113"},
    "X25519": {"primitive": "key-agree", "attack": "shor", "oid": "1.3.101.110"},
    "X448": {"primitive": "key-agree", "attack": "shor", "oid": "1.3.101.111"},
    "AES": {"primitive": "block-cipher", "attack": "grover", "oid": "2.16.840.1.101.3.4.1"},
    "Camellia": {"primitive": "block-cipher", "attack": "grover", "oid": "1.2.392.200011.61.1.1.1"},
    "DES": {"primitive": "block-cipher", "attack": "classical", "oid": "1.3.14.3.2.7"},
    "3DES": {"primitive": "block-cipher", "attack": "classical", "oid": "1.2.840.113549.3.7"},
    "RC2": {"primitive": "block-cipher", "attack": "classical", "oid": "1.2.840.113549.3.2"},
    "RC4": {"primitive": "stream-cipher", "attack": "classical", "oid": "1.2.840.113549.3.4"},
    "Blowfish": {"primitive": "block-cipher", "attack": "classical", "oid": "1.3.6.1.4.1.3029.1.2"},
    "ChaCha20": {"primitive": "stream-cipher", "attack": "grover", "oid": None},
    "ChaCha20-Poly1305": {"primitive": "ae", "attack": "grover", "oid": "1.2.840.113549.1.9.16.3.18"},
    "MD4": {"primitive": "hash", "attack": "classical", "oid": "1.2.840.113549.2.4"},
    "MD5": {"primitive": "hash", "attack": "classical", "oid": "1.2.840.113549.2.5"},
    "SHA-1": {"primitive": "hash", "attack": "classical", "oid": "1.3.14.3.2.26"},
    "RIPEMD-160": {"primitive": "hash", "attack": "classical", "oid": "1.3.36.3.2.1"},
    "SHA-224": {"primitive": "hash", "attack": "grover", "oid": "2.16.840.1.101.3.4.2.4"},
    "SHA-256": {"primitive": "hash", "attack": "grover", "oid": "2.16.840.1.101.3.4.2.1"},
    "SHA-384": {"primitive": "hash", "attack": "grover", "oid": "2.16.840.1.101.3.4.2.2"},
    "SHA-512": {"primitive": "hash", "attack": "grover", "oid": "2.16.840.1.101.3.4.2.3"},
    "SHA3-256": {"primitive": "hash", "attack": "grover", "oid": "2.16.840.1.101.3.4.2.8"},
    "SHA3-384": {"primitive": "hash", "attack": "grover", "oid": "2.16.840.1.101.3.4.2.9"},
    "SHA3-512": {"primitive": "hash", "attack": "grover", "oid": "2.16.840.1.101.3.4.2.10"},
    "BLAKE2b": {"primitive": "hash", "attack": "grover", "oid": None},
    "BLAKE2s": {"primitive": "hash", "attack": "grover", "oid": None},
    "HMAC": {"primitive": "mac", "attack": "grover", "oid": None},
    "PBKDF2": {"primitive": "kdf", "attack": "grover", "oid": "1.2.840.113549.1.5.12"},
    "bcrypt": {"primitive": "kdf", "attack": "grover", "oid": None},
    "scrypt": {"primitive": "kdf", "attack": "grover", "oid": "1.3.6.1.4.1.11591.4.11"},
    "Argon2": {"primitive": "kdf", "attack": "grover", "oid": None},
    "ML-KEM": {"primitive": "kem", "attack": "none", "oid": "2.16.840.1.101.3.4.4"},
    "ML-DSA": {"primitive": "signature", "attack": "none", "oid": "2.16.840.1.101.3.4.3"},
    "SLH-DSA": {"primitive": "signature", "attack": "none", "oid": "2.16.840.1.101.3.4.3"},
    "X25519MLKEM768": {"primitive": "kem", "attack": "none", "oid": None},
    "sntrup761x25519": {"primitive": "kem", "attack": "none", "oid": None},
    "TLS": {"primitive": "other", "attack": "n/a", "oid": None},
}

PQC_OIDS = {
    ("ML-KEM", 512): "2.16.840.1.101.3.4.4.1", ("ML-KEM", 768): "2.16.840.1.101.3.4.4.2",
    ("ML-KEM", 1024): "2.16.840.1.101.3.4.4.3", ("ML-DSA", 44): "2.16.840.1.101.3.4.3.17",
    ("ML-DSA", 65): "2.16.840.1.101.3.4.3.18", ("ML-DSA", 87): "2.16.840.1.101.3.4.3.19",
}

CURVES = {
    "secp256r1": "P-256", "prime256v1": "P-256", "p256": "P-256", "nistp256": "P-256",
    "x962prime256v1": "P-256", "secp384r1": "P-384", "p384": "P-384", "nistp384": "P-384",
    "secp521r1": "P-521", "p521": "P-521", "nistp521": "P-521", "secp256k1": "secp256k1",
    "secp224r1": "P-224", "p224": "P-224", "brainpoolp256r1": "brainpoolP256r1",
    "brainpoolp384r1": "brainpoolP384r1", "curve25519": "Curve25519",
}
CURVE_BITS = {"P-224": 112, "P-256": 128, "P-384": 192, "P-521": 256, "secp256k1": 128,
              "brainpoolP256r1": 128, "brainpoolP384r1": 192, "Curve25519": 128}

# RSA / DH / DSA modulus size -> classical security bits (NIST SP 800-57 Part 1).
FF_BITS = {512: 40, 768: 56, 1024: 80, 2048: 112, 3072: 128, 4096: 152, 7680: 192, 8192: 200, 15360: 256}

ALIASES = {
    "rsa": "RSA", "rsaencryption": "RSA", "evppkeyrsa": "RSA", "rsapss": "RSA", "rsassapss": "RSA",
    "rsaoaep": "RSA", "dsa": "DSA", "dss": "DSA", "dh": "DH", "dhe": "DH", "edh": "DH",
    "diffiehellman": "DH", "ffdhe": "DH", "ec": "EC", "ecc": "EC", "ecdsa": "ECDSA",
    "ecdh": "ECDH", "ecdhe": "ECDH", "ed25519": "Ed25519", "eddsa": "Ed25519", "ed448": "Ed448",
    "x25519": "X25519", "x448": "X448", "aes": "AES", "rijndael": "AES", "des": "DES",
    "desede": "3DES", "tripledes": "3DES", "3des": "3DES", "des3": "3DES", "desede3": "3DES",
    "tdea": "3DES", "cbc3": "3DES", "rc4": "RC4", "arc4": "RC4", "arcfour": "RC4", "rc2": "RC2",
    "blowfish": "Blowfish", "bf": "Blowfish", "chacha20": "ChaCha20",
    "chacha20poly1305": "ChaCha20-Poly1305", "camellia": "Camellia", "md5": "MD5", "md4": "MD4",
    "sha1": "SHA-1", "sha": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256", "sha384": "SHA-384",
    "sha512": "SHA-512", "sha3256": "SHA3-256", "sha3384": "SHA3-384", "sha3512": "SHA3-512",
    "blake2b": "BLAKE2b", "blake2s": "BLAKE2s", "ripemd160": "RIPEMD-160", "pbkdf2": "PBKDF2",
    "bcrypt": "bcrypt", "scrypt": "scrypt", "argon2": "Argon2", "argon2id": "Argon2",
    "mlkem": "ML-KEM", "kyber": "ML-KEM", "mldsa": "ML-DSA", "dilithium": "ML-DSA",
    "slhdsa": "SLH-DSA", "sphincs": "SLH-DSA", "hmac": "HMAC",
}


def _key(raw: str) -> str:
    return re.sub(r"[^a-z0-9]", "", raw.lower())


def normalize(raw: str) -> tuple[str, dict[str, Any]] | None:
    """Turn one algorithm token into (canonical, params); None if unknown."""
    k = _key(raw)
    if not k:
        return None
    if k in ("x25519mlkem768", "x25519kyber768draft00", "x25519kyber768", "mlkem768x25519sha256",
             "mlkem768x25519", "secp256r1mlkem768", "x25519mlkem768sha256"):
        return "X25519MLKEM768", {}
    if k.startswith("sntrup761x25519"):
        return "sntrup761x25519", {}
    m = re.fullmatch(r"(mlkem|kyber)(512|768|1024)", k)
    if m:
        return "ML-KEM", {"size": int(m.group(2))}
    m = re.fullmatch(r"(mldsa|dilithium)(44|65|87|2|3|5)", k)
    if m:
        size = {"2": 44, "3": 65, "5": 87}.get(m.group(2), m.group(2))
        return "ML-DSA", {"size": int(size)}
    m = re.fullmatch(r"slhdsa(sha2|shake)(128|192|256)([sf])", k)
    if m:
        return "SLH-DSA", {"size": int(m.group(2)), "variant": m.group(3)}
    m = re.fullmatch(r"aes(128|192|256)", k)
    if m:
        return "AES", {"size": int(m.group(1))}
    m = re.fullmatch(r"(rsa|dh|dsa)(\d{3,5})", k)
    if m:
        return ALIASES[m.group(1)], {"size": int(m.group(2))}
    if k in CURVES:
        return "EC", {"curve": CURVES[k]}
    if k in ALIASES:
        return ALIASES[k], {}
    return None


def normalize_curve(raw: str) -> str:
    return CURVES.get(_key(raw), raw)


# ---- compound-name parsers ---------------------------------------------------
Parts = list[tuple[str, dict[str, Any], str]]   # (canonical, params, usage)

_MODES = {"ecb", "cbc", "gcm", "ctr", "cfb", "ofb", "ccm", "xts", "siv"}


def parse_transformation(s: str) -> Parts:
    """JCA transformation, e.g. 'AES/ECB/PKCS5Padding', 'RSA/ECB/OAEPWithSHA-256AndMGF1Padding'."""
    bits = s.split("/")
    alg = bits[0]
    params: dict[str, Any] = {}
    m = re.fullmatch(r"(?i)aes[_-]?(128|192|256)", alg)
    if m:
        alg, params["size"] = "AES", int(m.group(1))
    n = normalize(alg)
    if not n:
        return []
    canonical, p = n
    params = {**p, **params}
    if len(bits) > 1 and canonical not in ("RSA",):
        mode = bits[1].lower()
        if mode in _MODES:
            params["mode"] = mode
    if len(bits) > 2:
        pad = bits[2].lower()
        if "oaep" in pad:
            params["padding"] = "oaep"
        elif "pkcs1" in pad:
            params["padding"] = "pkcs1v15"
        elif "pkcs5" in pad or "pkcs7" in pad:
            params["padding"] = "pkcs5"
        elif "nopadding" in pad:
            params["padding"] = "raw"
    elif canonical == "RSA":
        params["padding"] = "pkcs1v15"   # JCA default for bare "RSA"
    if canonical in ("AES", "DES", "3DES", "Blowfish") and "mode" not in params and len(bits) == 1:
        params["mode"] = "ecb"           # JCA default for bare "AES" is AES/ECB/PKCS5Padding
    return [(canonical, params, "encrypt")]


def parse_jca_signature(s: str) -> Parts:
    """'SHA256withRSA', 'SHA1withECDSA', 'SHA256withRSA/PSS', 'Ed25519', 'RSASSA-PSS'."""
    m = re.fullmatch(r"(?i)([a-z0-9-]+)with([a-z0-9]+)(?:/pss|andmgf1)?", s.replace("/PSS", ""))
    if m:
        out: Parts = []
        h = normalize(m.group(1))
        a = normalize(m.group(2))
        if a:
            out.append((a[0] if a[0] != "EC" else "ECDSA", a[1], "sign"))
        if h:
            out.append((h[0], h[1], "digest"))
        return out
    n = normalize(s)
    return [(n[0], n[1], "sign")] if n else []


_OPENSSL_CIPHER = re.compile(r"(?i)^(aes|camellia)[-_]?(128|192|256)(?:[-_](\w+))?$")


def parse_openssl_cipher(s: str) -> Parts:
    """'aes-128-cbc', 'aes-256-gcm', 'des-ede3-cbc', 'rc4', 'bf-cbc', 'chacha20-poly1305'."""
    t = s.strip().lower().replace("_", "-")
    m = _OPENSSL_CIPHER.match(t)
    if m:
        params: dict[str, Any] = {"size": int(m.group(2))}
        if m.group(3) and m.group(3).lower() in _MODES:
            params["mode"] = m.group(3).lower()
        return [("AES" if m.group(1).lower() == "aes" else "Camellia", params, "encrypt")]
    if t.startswith("des-ede3") or t in ("des3", "3des", "des-ede"):
        mode = t.split("-")[-1]
        return [("3DES", {"mode": mode} if mode in _MODES else {}, "encrypt")]
    if t.startswith("des"):
        mode = t.split("-")[-1]
        return [("DES", {"mode": mode} if mode in _MODES else {}, "encrypt")]
    if t.startswith("chacha20"):
        return [("ChaCha20-Poly1305" if "poly" in t else "ChaCha20", {}, "encrypt")]
    if t.startswith("rc4"):
        return [("RC4", {}, "encrypt")]
    if t.startswith("bf") or t.startswith("blowfish"):
        return [("Blowfish", {}, "encrypt")]
    n = normalize(t)
    return [(n[0], n[1], "encrypt")] if n else []


def parse_hmac(s: str) -> Parts:
    """'HmacSHA256', 'hmac-sha1', 'hmac-sha2-256', 'HMAC-MD5'."""
    t = _key(s).replace("hmac", "", 1)
    m = re.fullmatch(r"sha2(224|256|384|512)", t)      # ssh style: hmac-sha2-256
    if m:
        t = "sha" + m.group(1)
    n = normalize(t)
    if not n:
        return [("HMAC", {}, "tag")]
    return [("HMAC", {"hash": n[0]}, "tag")]


_JWT = {
    "RS": ("RSA", {"padding": "pkcs1v15"}), "PS": ("RSA", {"padding": "pss"}),
    "ES": ("ECDSA", {}), "HS": ("HMAC", {}),
}


def parse_jwt(alg: str) -> Parts:
    """JOSE 'alg' values: RS256, PS384, ES256, HS256, EdDSA."""
    if alg.lower() == "eddsa":
        return [("Ed25519", {}, "sign")]
    m = re.fullmatch(r"(RS|PS|ES|HS)(256|384|512)", alg.upper())
    if not m:
        return []
    canonical, params = _JWT[m.group(1)]
    params = dict(params)
    h = f"SHA-{m.group(2)}"
    if canonical == "ECDSA":
        params["curve"] = {"256": "P-256", "384": "P-384", "512": "P-521"}[m.group(2)]
    if canonical == "HMAC":
        params["hash"] = h
        return [("HMAC", params, "tag")]
    return [(canonical, params, "sign"), (h, {}, "digest")]


_TLS = {
    "sslv2": "SSL 2.0", "sslv3": "SSL 3.0", "ssl3": "SSL 3.0", "ssl30": "SSL 3.0",
    "tlsv1": "1.0", "tls1": "1.0", "tls10": "1.0", "tlsv10": "1.0", "tls": None,
    "tlsv11": "1.1", "tls11": "1.1", "tlsv12": "1.2", "tls12": "1.2", "tlsv13": "1.3", "tls13": "1.3",
}


def parse_tls_version(s: str) -> Parts:
    t = _key(s)
    for prefix in ("protocol", "version", "sslprotocols", "tlsversion"):
        if t.startswith(prefix):
            t = t[len(prefix):]
    t = t.replace("method", "")
    if t in ("tls1", "tlsv1", "tls10", "tlsv10"):
        return [("TLS", {"version": "1.0"}, "protocol")]
    v = _TLS.get(t)
    if not v:
        return []
    return [("TLS", {"version": v}, "protocol")]


def parse_cipher_suite(name: str) -> Parts:
    """IANA (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) or OpenSSL (ECDHE-RSA-AES128-GCM-SHA256) names."""
    n = name.strip()
    up = n.upper()
    out: Parts = []
    if up in ("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
              "TLS_AES_128_CCM_SHA256"):
        if "CHACHA" in up:
            return [("ChaCha20-Poly1305", {}, "encrypt")]
        size = 256 if "AES_256" in up else 128
        mode = "ccm" if "CCM" in up else "gcm"
        return [("AES", {"size": size, "mode": mode}, "encrypt")]
    m = re.fullmatch(r"(?:TLS|SSL)_(.+?)_WITH_(.+)_(SHA|SHA256|SHA384|MD5)", up)
    if m:
        kex_auth, cipher, mac = m.group(1).split("_"), m.group(2), m.group(3)
        tokens = kex_auth
    else:
        parts = up.split("-")
        if len(parts) < 2:
            return []
        mac = parts[-1] if parts[-1] in ("SHA", "SHA256", "SHA384", "MD5") else ""
        body = parts[:-1] if mac else parts
        tokens, cipher_tokens = [], []
        for p in body:
            if p in ("ECDHE", "DHE", "EDH", "ECDH", "DH", "RSA", "ECDSA", "DSS", "PSK", "AECDH", "ADH"):
                if cipher_tokens:
                    cipher_tokens.append(p)
                else:
                    tokens.append(p)
            else:
                cipher_tokens.append(p)
        cipher = "_".join(cipher_tokens)
        if not tokens or tokens == ["RSA"]:
            tokens = ["RSA"]
    kex = tokens[0] if tokens else "RSA"
    auth = tokens[1] if len(tokens) > 1 else ("RSA" if kex == "RSA" else None)
    if kex in ("ECDHE", "ECDH", "AECDH"):
        out.append(("ECDH", {}, "key-agree"))
    elif kex in ("DHE", "EDH", "DH", "ADH"):
        out.append(("DH", {}, "key-agree"))
    elif kex == "RSA":
        out.append(("RSA", {"padding": "pkcs1v15"}, "key-agree"))   # static RSA key transport
    if auth == "ECDSA":
        out.append(("ECDSA", {}, "sign"))
    elif auth in ("DSS",):
        out.append(("DSA", {}, "sign"))
    elif auth == "RSA" and kex != "RSA":
        out.append(("RSA", {}, "sign"))
    c = cipher.replace("-", "_")
    aead = False
    mc = re.match(r"AES_?(128|256)_?(GCM|CBC|CCM)?", c)
    if mc:
        mode = (mc.group(2) or "cbc").lower()
        aead = mode in ("gcm", "ccm")
        out.append(("AES", {"size": int(mc.group(1)), "mode": mode}, "encrypt"))
    elif "3DES" in c or "CBC3" in c or "DES_EDE" in c:
        out.append(("3DES", {"mode": "cbc"}, "encrypt"))
    elif c.startswith("DES"):
        out.append(("DES", {"mode": "cbc"}, "encrypt"))
    elif "RC4" in c:
        out.append(("RC4", {}, "encrypt"))
    elif "CHACHA20" in c:
        aead = True
        out.append(("ChaCha20-Poly1305", {}, "encrypt"))
    elif "CAMELLIA" in c:
        size = 256 if "256" in c else 128
        out.append(("Camellia", {"size": size, "mode": "cbc"}, "encrypt"))
    elif c.startswith("NULL"):
        out.append(("TLS", {"version": "NULL cipher"}, "protocol"))
    if mac and not aead:
        h = {"SHA": "SHA-1", "SHA256": "SHA-256", "SHA384": "SHA-384", "MD5": "MD5"}[mac]
        out.append(("HMAC", {"hash": h}, "tag"))
    return out


_SSH_KEX = {
    "diffie-hellman-group1-sha1": [("DH", {"size": 1024}, "key-agree"), ("SHA-1", {}, "digest")],
    "diffie-hellman-group14-sha1": [("DH", {"size": 2048}, "key-agree"), ("SHA-1", {}, "digest")],
    "diffie-hellman-group14-sha256": [("DH", {"size": 2048}, "key-agree")],
    "diffie-hellman-group16-sha512": [("DH", {"size": 4096}, "key-agree")],
    "diffie-hellman-group18-sha512": [("DH", {"size": 8192}, "key-agree")],
    "diffie-hellman-group-exchange-sha1": [("DH", {}, "key-agree"), ("SHA-1", {}, "digest")],
    "diffie-hellman-group-exchange-sha256": [("DH", {}, "key-agree")],
    "ecdh-sha2-nistp256": [("ECDH", {"curve": "P-256"}, "key-agree")],
    "ecdh-sha2-nistp384": [("ECDH", {"curve": "P-384"}, "key-agree")],
    "ecdh-sha2-nistp521": [("ECDH", {"curve": "P-521"}, "key-agree")],
    "curve25519-sha256": [("X25519", {}, "key-agree")],
    "curve25519-sha256@libssh.org": [("X25519", {}, "key-agree")],
    "sntrup761x25519-sha512": [("sntrup761x25519", {}, "key-agree")],
    "sntrup761x25519-sha512@openssh.com": [("sntrup761x25519", {}, "key-agree")],
    "mlkem768x25519-sha256": [("X25519MLKEM768", {}, "key-agree")],
}
_SSH_HOSTKEY = {
    "ssh-rsa": [("RSA", {}, "sign"), ("SHA-1", {}, "digest")],
    "rsa-sha2-256": [("RSA", {}, "sign"), ("SHA-256", {}, "digest")],
    "rsa-sha2-512": [("RSA", {}, "sign"), ("SHA-512", {}, "digest")],
    "ssh-dss": [("DSA", {"size": 1024}, "sign")],
    "ecdsa-sha2-nistp256": [("ECDSA", {"curve": "P-256"}, "sign")],
    "ecdsa-sha2-nistp384": [("ECDSA", {"curve": "P-384"}, "sign")],
    "ecdsa-sha2-nistp521": [("ECDSA", {"curve": "P-521"}, "sign")],
    "ssh-ed25519": [("Ed25519", {}, "sign")],
}


def parse_ssh(name: str, section: str) -> Parts:
    n = name.strip().lower()
    base = n.replace("-cert-v01@openssh.com", "")
    if section == "kex":
        return list(_SSH_KEX.get(n, _SSH_KEX.get(base, [])))
    if section == "hostkey":
        return list(_SSH_HOSTKEY.get(base, []))
    if section == "mac":
        if "umac" in n:
            return []
        return parse_hmac(n.replace("-etm@openssh.com", "").replace("@openssh.com", ""))
    if section == "cipher":
        t = n.split("@")[0]
        return parse_openssl_cipher(t.replace("3des", "des-ede3").replace("arcfour", "rc4"))
    return []


# ---- assessment --------------------------------------------------------------
def assess(canonical: str, params: dict[str, Any]) -> dict[str, Any]:
    """Classical + quantum standing of one canonical algorithm with its parameters."""
    spec = ALGORITHMS.get(canonical, {})
    size = params.get("size")
    curve = params.get("curve")
    res: dict[str, Any] = {"status": UNKNOWN, "attack": spec.get("attack", "unknown"),
                           "classical_bits": None, "nist_level": None, "note": ""}

    if canonical in ("RSA", "DH", "DSA"):
        res["classical_bits"] = FF_BITS.get(size) if size else None
        if size and size < 2048:
            res.update(status=BROKEN, note=f"{canonical}-{size} is below the 2048-bit minimum (NIST SP 800-131A) and is also broken by Shor's algorithm.")
        else:
            res.update(status=QV, nist_level=0, note="Broken by Shor's algorithm on a cryptographically relevant quantum computer.")
        if canonical == "DSA":
            res["note"] += " DSA is no longer approved for signature generation (FIPS 186-5)."
            res["status"] = BROKEN if res["status"] == BROKEN else QV
    elif canonical in ("EC", "ECDSA", "ECDH", "Ed25519", "Ed448", "X25519", "X448"):
        res["classical_bits"] = CURVE_BITS.get(curve) if curve else (128 if canonical in ("Ed25519", "X25519") else None)
        res.update(status=QV, nist_level=0, note="Elliptic-curve cryptography is broken by Shor's algorithm.")
    elif canonical in ("AES", "Camellia"):
        res["classical_bits"] = size
        if params.get("mode") == "ecb":
            res.update(status=WEAK, note="ECB mode leaks patterns in the data. Use an authenticated mode such as GCM.")
        elif size in (192, 256):
            res.update(status=SAFE, nist_level={192: 3, 256: 5}[size], note="256-bit (or 192-bit) keys keep enough margin against Grover's algorithm.")
        else:
            res.update(status=QW, nist_level=1 if size == 128 else None,
                       note="Grover's algorithm roughly halves effective key strength; prefer AES-256 for long-lived data." if size == 128
                       else "Key size not found; assuming 128-bit. Prefer AES-256 for long-lived data.")
    elif canonical in ("DES", "RC2", "RC4", "MD4", "MD5"):
        res.update(status=BROKEN, note=f"{canonical} is broken with classical computers today.")
    elif canonical == "3DES":
        res.update(status=BROKEN, classical_bits=112, note="3DES is disallowed for encryption after 2023 (NIST SP 800-131A Rev. 2); 64-bit blocks enable Sweet32.")
    elif canonical == "SHA-1":
        res.update(status=BROKEN, classical_bits=63, note="Practical SHA-1 collisions exist (SHAttered, 2017). Disallowed for signatures.")
    elif canonical in ("Blowfish", "RIPEMD-160"):
        res.update(status=WEAK, note=f"{canonical} is legacy; 64-bit blocks or short output make it unsuitable for new designs.")
    elif canonical in ("SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512", "BLAKE2b", "BLAKE2s"):
        lvl = {"SHA-256": 2, "SHA3-256": 2, "SHA-384": 4, "SHA3-384": 4, "SHA-512": 4, "SHA3-512": 4}.get(canonical)
        res.update(status=SAFE, nist_level=lvl, note="Hash functions keep adequate strength against quantum attacks at this output size.")
    elif canonical in ("ChaCha20", "ChaCha20-Poly1305"):
        res.update(status=SAFE, classical_bits=256, nist_level=5, note="256-bit key; adequate margin against Grover's algorithm.")
    elif canonical == "HMAC":
        h = params.get("hash")
        if h in ("MD5", "SHA-1"):
            res.update(status=WEAK, note=f"HMAC-{h} is not practically broken but is deprecated; move to HMAC-SHA-256.")
        else:
            res.update(status=SAFE, note="HMAC with a SHA-2/SHA-3 hash is quantum-resistant at 256-bit keys.")
    elif canonical in ("PBKDF2", "bcrypt", "scrypt", "Argon2"):
        res.update(status=SAFE, note="Password hashing/KDF; quantum computers give no significant speed-up beyond Grover.")
    elif canonical == "ML-KEM":
        res.update(status=PQC, nist_level={512: 1, 768: 3, 1024: 5}.get(size), note="NIST FIPS 203 post-quantum key encapsulation.")
    elif canonical == "ML-DSA":
        res.update(status=PQC, nist_level={44: 2, 65: 3, 87: 5}.get(size), note="NIST FIPS 204 post-quantum signature.")
    elif canonical == "SLH-DSA":
        res.update(status=PQC, nist_level={128: 1, 192: 3, 256: 5}.get(size), note="NIST FIPS 205 stateless hash-based signature.")
    elif canonical == "X25519MLKEM768":
        res.update(status=PQC, nist_level=3, note="Hybrid X25519 + ML-KEM-768 key exchange: stays secure if either part holds.")
    elif canonical == "sntrup761x25519":
        res.update(status=PQC, note="Hybrid NTRU Prime + X25519 SSH key exchange (OpenSSH). Not a NIST standard; prefer mlkem768x25519-sha256 where available.")
    elif canonical == "TLS":
        v = params.get("version")
        if v in ("SSL 2.0", "SSL 3.0", "1.0", "1.1", "NULL cipher"):
            res.update(status=BROKEN, note=f"TLS {v} is deprecated (RFC 8996) or insecure." if v not in ("SSL 2.0", "SSL 3.0", "NULL cipher") else f"{v} is insecure.")
        elif v in ("1.2", "1.3"):
            res.update(status=SAFE, note="Protocol version is fine; quantum risk depends on the key exchange it negotiates.")
    return res


def worst(statuses: list[str]) -> str:
    return max(statuses, key=lambda s: STATUS_ORDER.get(s, 0)) if statuses else UNKNOWN


def display_name(canonical: str, params: dict[str, Any]) -> str:
    if canonical == "TLS":
        v = params.get("version", "")
        return v if v.startswith("SSL") or v == "NULL cipher" else f"TLS {v}".strip()
    parts = [canonical]
    if params.get("size"):
        parts.append(str(params["size"]))
    if params.get("curve"):
        parts.append(params["curve"])
    if params.get("hash"):
        parts.append(params["hash"])
    if params.get("mode"):
        parts.append(params["mode"].upper())
    if params.get("padding") and canonical == "RSA" and params["padding"] in ("oaep", "pss"):
        parts.append(params["padding"].upper())
    return "-".join(parts)


def asset_id(canonical: str, params: dict[str, Any]) -> str:
    return "alg:" + re.sub(r"[^a-z0-9.-]+", "-", display_name(canonical, params).lower()).strip("-")


def oid_for(canonical: str, params: dict[str, Any]) -> str | None:
    if (canonical, params.get("size")) in PQC_OIDS:
        return PQC_OIDS[(canonical, params.get("size"))]
    return ALGORITHMS.get(canonical, {}).get("oid")
