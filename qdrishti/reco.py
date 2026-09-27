"""Recommendation engine: what to replace an asset with, and how."""
from __future__ import annotations

from . import registry as R

# Public key / ciphertext / signature sizes in bytes (FIPS 203, 204, 205).
PQC_SIZES = {
    "X25519": {"public_key": 32, "ciphertext": 32, "standard": "RFC 7748"},
    "ML-KEM-512": {"public_key": 800, "ciphertext": 768, "level": 1, "standard": "FIPS 203"},
    "ML-KEM-768": {"public_key": 1184, "ciphertext": 1088, "level": 3, "standard": "FIPS 203"},
    "ML-KEM-1024": {"public_key": 1568, "ciphertext": 1568, "level": 5, "standard": "FIPS 203"},
    "ML-DSA-44": {"public_key": 1312, "signature": 2420, "level": 2, "standard": "FIPS 204"},
    "ML-DSA-65": {"public_key": 1952, "signature": 3309, "level": 3, "standard": "FIPS 204"},
    "ML-DSA-87": {"public_key": 2592, "signature": 4627, "level": 5, "standard": "FIPS 204"},
    "SLH-DSA-SHA2-128s": {"public_key": 32, "signature": 7856, "level": 1, "standard": "FIPS 205"},
    "SLH-DSA-SHA2-128f": {"public_key": 32, "signature": 17088, "level": 1, "standard": "FIPS 205"},
}

HIGH_ASSURANCE = {"identity", "health", "secret"}


def _r(target: str, why: str, change: str, standard: str, priority: int = 1) -> dict:
    return {"target": target, "why": why, "change": change, "standard": standard, "priority": priority}


def recommend(asset: dict, apps: list[dict], surfaces: set[str], languages: set[str], snippets: list[str]) -> list[dict]:
    c = asset.get("canonical")
    p = asset.get("params", {})
    kind = asset["kind"]
    usages = set(asset.get("usages", []))
    data_classes = {a.get("data_class") for a in apps}
    high = bool(data_classes & HIGH_ASSURANCE)
    tls_ctx = bool(surfaces & {"config", "endpoint"}) or kind == "suite"
    joined = " ".join(snippets).lower()
    out: list[dict] = []

    if kind == "library":
        name = p.get("name", "")
        note = asset.get("extra", {}).get("note", "")
        if name == "OpenSSL" and asset["status"] in (R.WEAK, R.QV, "info") and asset.get("extra", {}).get("pqc") != "yes":
            out.append(_r("OpenSSL 3.5 LTS", note, "Upgrade the base image or package to OpenSSL 3.5+, then enable the X25519MLKEM768 group.", "OpenSSL 3.5 release notes"))
        elif asset["status"] == R.WEAK:
            repl = {"pycrypto": "pycryptodome or cryptography", "crypto-js": "Web Crypto API / node:crypto",
                    "bcprov-jdk15on": "bcprov-jdk18on (latest)", "bcpkix-jdk15on": "bcpkix-jdk18on (latest)",
                    "github.com/dgrijalva/jwt-go": "github.com/golang-jwt/jwt/v5", "rsa": "cryptography",
                    "ecdsa": "cryptography", "JKS keystore": "PKCS#12 keystore"}.get(name, "a maintained alternative")
            out.append(_r(repl, note, f"Replace {name} with {repl}.", "Vendor guidance"))
        return out

    if kind == "certificate":
        is_ca = asset.get("extra", {}).get("is_ca")
        if asset.get("extra", {}).get("expired"):
            out.append(_r("Re-issue certificate", "The certificate has expired.", "Re-issue now; use this as the chance to move to a stronger key.", "RFC 5280", 0))
        target = "ML-DSA-87" if is_ca else "ML-DSA-65"
        out.append(_r(f"{target} certificate (composite with ECDSA during transition)",
                      "Certificate keys are broken by Shor's algorithm; CA keys live longest, so they migrate first." if is_ca
                      else "Server certificate signatures are broken by Shor's algorithm.",
                      "Plan PQC PKI: test ML-DSA issuance on a private CA; keep RSA/ECDSA chains in parallel until clients support PQC.",
                      "FIPS 204"))
        return out

    if kind == "suite":
        worst = asset.get("status")
        if worst == R.BROKEN:
            out.append(_r("Remove this cipher suite", "It uses a classically broken component.", "Drop it from the cipher list; keep TLS 1.3 suites and ECDHE+AES-GCM for TLS 1.2.", "RFC 9325", 0))
        if any(x[0] == "RSA" and x[2] == "key-agree" for x in asset.get("components", [])):
            out.append(_r("ECDHE suites, then hybrid PQC", "Static RSA key exchange has no forward secrecy: recorded traffic can be decrypted later.", "Remove TLS_RSA_* suites.", "RFC 9325", 0))
        out.append(_r("TLS 1.3 + X25519MLKEM768", "Protects recorded traffic against a future quantum computer.",
                      "nginx: ssl_protocols TLSv1.3; ssl_ecdh_curve X25519MLKEM768:X25519; (requires nginx built with OpenSSL 3.5+)",
                      "FIPS 203, IETF hybrid TLS draft"))
        return out

    if c == "TLS":
        v = p.get("version")
        if v in ("SSL 2.0", "SSL 3.0", "1.0", "1.1", "NULL cipher"):
            out.append(_r("TLS 1.3 (minimum TLS 1.2)", "TLS 1.0/1.1 are deprecated by RFC 8996.",
                          "nginx: ssl_protocols TLSv1.2 TLSv1.3;  Spring: server.ssl.enabled-protocols=TLSv1.2,TLSv1.3  Go: MinVersion: tls.VersionTLS12", "RFC 8996", 0))
        return out

    key_agree = usages & {"key-agree", "encrypt", "decrypt", "protocol"}
    signing = usages & {"sign", "verify"}
    if c in ("RSA", "DH", "ECDH", "X25519", "X448", "EC", "ECDSA", "Ed25519", "Ed448", "DSA"):
        if p.get("size") and p["size"] < 2048 and c in ("RSA", "DH", "DSA"):
            out.append(_r(f"{c}-3072 now, then PQC", f"{c}-{p['size']} is below today's classical minimum.", "Raise the key size immediately as a stop-gap.", "NIST SP 800-131A", 0))
        if c in ("RSA", "DH", "ECDH", "X25519", "X448") and (key_agree or c in ("DH", "ECDH", "X25519", "X448")):
            if tls_ctx:
                out.append(_r("X25519MLKEM768 (hybrid)", "Key exchange is the harvest-now-decrypt-later target.",
                              "Enable the X25519MLKEM768 group (OpenSSL 3.5+, BoringSSL, Go 1.24+).", "FIPS 203"))
            else:
                t = "ML-KEM-1024" if high else "ML-KEM-768"
                out.append(_r(f"{t} (hybrid with X25519)", "Encryption / key transport is broken by Shor's algorithm and exposed to harvest-now-decrypt-later.",
                              "Replace RSA encryption with a KEM: encapsulate a fresh AES-256-GCM key using ML-KEM (e.g. liboqs, Bouncy Castle, Go crypto/mlkem).", "FIPS 203"))
        if c in ("RSA", "EC", "ECDSA", "Ed25519", "Ed448", "DSA") and (signing or "keygen" in usages or "storage" in usages or not key_agree):
            if "jwt" in joined or "jws" in joined:
                out.append(_r("ML-DSA-65 for JWT (when JOSE PQC specs finalise)", "RS/ES JWT signatures are forgeable once a CRQC exists.",
                              "Short-term: shorten token lifetime and rotate keys; track IETF JOSE/COSE ML-DSA drafts.", "FIPS 204"))
            elif any(k in joined for k in ("firmware", "codesign", "code_sign", "code-sign", "release")):
                out.append(_r("SLH-DSA-SHA2-128s or LMS/XMSS", "Long-lived code/firmware signatures need the most conservative option.",
                              "Sign releases with a hash-based scheme.", "FIPS 205 / NIST SP 800-208"))
            else:
                t = "ML-DSA-87" if high else "ML-DSA-65"
                out.append(_r(f"{t}", "Signatures are forgeable with Shor's algorithm.", "Migrate signing keys to ML-DSA; use composite (ECDSA + ML-DSA) where verifiers are mixed.", "FIPS 204"))
        return out

    if c in ("AES", "Camellia"):
        if p.get("mode") == "ecb":
            out.append(_r("AES-256-GCM", "ECB leaks patterns and has no integrity.", _aes_change(languages), "NIST SP 800-38D", 0))
        elif (p.get("size") or 128) < 256:
            out.append(_r("AES-256-GCM", "Grover's algorithm halves effective key strength; 256-bit keys keep a safe margin.", _aes_change(languages), "NIST SP 800-38D"))
        return out
    if c in ("DES", "3DES", "RC4", "RC2", "Blowfish"):
        out.append(_r("AES-256-GCM or ChaCha20-Poly1305", f"{c} is broken or deprecated today.", _aes_change(languages), "NIST SP 800-131A", 0))
        return out
    if c in ("MD5", "SHA-1", "MD4", "RIPEMD-160"):
        pw = any(k in joined for k in ("password", "passwd", "pwd"))
        if pw:
            out.append(_r("Argon2id (or bcrypt/scrypt)", "Fast hashes must never store passwords.", "Use argon2-cffi / bcrypt with a per-user salt.", "OWASP Password Storage", 0))
        else:
            out.append(_r("SHA-256 (or SHA3-256)", f"{c} collisions are practical.", _hash_change(languages, c), "FIPS 180-4", 0))
        return out
    if c == "HMAC" and p.get("hash") in ("MD5", "SHA-1"):
        out.append(_r("HMAC-SHA-256", "Deprecated hash inside HMAC.", "Switch the MAC to HMAC-SHA-256.", "FIPS 198-1"))
    return out


def _aes_change(langs: set[str]) -> str:
    if "java" in langs:
        return 'Java: Cipher.getInstance("AES/GCM/NoPadding") with a 256-bit key and a unique 12-byte IV.'
    if "python" in langs:
        return "Python: AESGCM(AESGCM.generate_key(bit_length=256)) from cryptography."
    if "go" in langs:
        return "Go: aes.NewCipher(32-byte key) + cipher.NewGCM."
    if "javascript" in langs:
        return "Node: crypto.createCipheriv('aes-256-gcm', key32, iv12)."
    return "Use AES-256-GCM with unique nonces."


def _hash_change(langs: set[str], c: str) -> str:
    if "python" in langs:
        return f"Python: hashlib.sha256(...) instead of hashlib.{c.lower().replace('-', '')}(...)."
    if "java" in langs:
        return 'Java: MessageDigest.getInstance("SHA-256").'
    if "go" in langs:
        return "Go: sha256.Sum256(data)."
    if "javascript" in langs:
        return "Node: crypto.createHash('sha256')."
    return "Use SHA-256 or SHA3-256."
