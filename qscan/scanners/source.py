"""Source-code scanner.

Pattern rules for Java/Kotlin, Python, Go, JavaScript/TypeScript, C/C++, C# and
PHP. Parameters such as key sizes are resolved from literals, from constants
defined in the same file (a light form of constant propagation), or from the
next few lines (e.g. KeyPairGenerator.initialize(2048)).
"""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field

from .. import registry as R
from ..models import RawFinding

JAVA = (".java", ".kt", ".kts", ".scala", ".groovy")
PY = (".py",)
GO = (".go",)
JS = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")
C = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh")
CS = (".cs",)
PHP = (".php",)
SOURCE_EXTS = set(JAVA + PY + GO + JS + C + CS + PHP)

LANG = {**{e: "java" for e in JAVA}, **{e: "python" for e in PY}, **{e: "go" for e in GO},
        **{e: "javascript" for e in JS}, **{e: "c" for e in C}, **{e: "csharp" for e in CS},
        **{e: "php" for e in PHP}}


@dataclass
class Rule:
    id: str
    exts: tuple
    pattern: str
    parser: str
    usage: str
    canonical: str | None = None
    confidence: float = 0.9
    lookahead: tuple = ()
    rx: re.Pattern = field(init=False, repr=False)
    la: list = field(init=False, repr=False)

    def __post_init__(self):
        self.rx = re.compile(self.pattern)
        self.la = [re.compile(p) for p in self.lookahead]


RULES: list[Rule] = [
    # ---- Java / Kotlin (JCA) ----
    Rule("java-cipher", JAVA, r'Cipher\.getInstance\(\s*"(?P<alg>[^"]+)"', "transform", "encrypt"),
    Rule("java-keypairgen", JAVA, r'KeyPairGenerator\.getInstance\(\s*"(?P<alg>[^"]+)"', "plain", "keygen",
         lookahead=(r'\.initialize\(\s*(?P<size>\w+)', r'ECGenParameterSpec\(\s*"(?P<curve>[^"]+)"')),
    Rule("java-keygen", JAVA, r'KeyGenerator\.getInstance\(\s*"(?P<alg>[^"]+)"', "plain", "keygen",
         lookahead=(r'\.init\(\s*(?P<size>\w+)',)),
    Rule("java-signature", JAVA, r'Signature\.getInstance\(\s*"(?P<alg>[^"]+)"', "jca_sig", "sign"),
    Rule("java-digest", JAVA, r'MessageDigest\.getInstance\(\s*"(?P<alg>[^"]+)"', "plain", "digest"),
    Rule("java-mac", JAVA, r'Mac\.getInstance\(\s*"(?P<alg>[^"]+)"', "hmac", "tag"),
    Rule("java-keyagree", JAVA, r'KeyAgreement\.getInstance\(\s*"(?P<alg>[^"]+)"', "plain", "key-agree"),
    Rule("java-secretkeyfactory", JAVA, r'SecretKeyFactory\.getInstance\(\s*"(?P<alg>[^"]+)"', "kdf", "keyderive"),
    Rule("java-sslcontext", JAVA, r'SSLContext\.getInstance\(\s*"(?P<alg>[^"]+)"', "tls", "protocol"),
    Rule("java-protocols", JAVA, r'setEnabledProtocols\(\s*new\s+String\[\]\s*\{(?P<alg>[^}]*)\}', "tls_list", "protocol"),
    Rule("java-getinstance-const", JAVA,
         r'(?P<api>Cipher|Signature|MessageDigest|KeyPairGenerator|KeyGenerator|Mac|KeyAgreement)\.getInstance\(\s*(?P<ident>[A-Z_][A-Z0-9_]*)\s*[,)]',
         "java_const", "unknown", confidence=0.85),
    # ---- Python ----
    Rule("py-rsa-gen", PY, r'rsa\.generate_private_key\((?P<args>[^)]*)\)', "fixed", "keygen", "RSA"),
    Rule("py-ec-gen", PY, r'ec\.generate_private_key\(\s*ec\.(?P<curve>\w+)', "fixed", "keygen", "EC"),
    Rule("py-dsa-gen", PY, r'dsa\.generate_private_key\((?P<args>[^)]*)\)', "fixed", "keygen", "DSA"),
    Rule("py-dh-gen", PY, r'dh\.generate_parameters\((?P<args>[^)]*)\)', "fixed", "key-agree", "DH"),
    Rule("py-edx", PY, r'(?P<alg>Ed25519|X25519|Ed448|X448)PrivateKey\.generate\(', "plain", "keygen"),
    Rule("py-hashlib", PY, r'hashlib\.(?P<alg>md5|sha1|sha224|sha256|sha384|sha512|sha3_256|sha3_384|sha3_512|blake2b|blake2s)\(', "plain", "digest"),
    Rule("py-hashlib-new", PY, r'hashlib\.new\(\s*[\'"](?P<alg>[\w-]+)[\'"]', "plain", "digest"),
    Rule("py-hashes", PY, r'hashes\.(?P<alg>MD5|SHA1|SHA224|SHA256|SHA384|SHA512|SHA3_256|SHA3_512)\(\)', "plain", "digest"),
    Rule("py-pycryptodome-cipher", PY, r'\b(?P<alg>AES|DES3|DES|ARC4|Blowfish|ChaCha20_Poly1305|ChaCha20)\.new\((?P<args>[^)]*)\)', "plain", "encrypt"),
    Rule("py-pycryptodome-rsa", PY, r'\bRSA\.generate\(\s*(?P<size>\w+)', "fixed", "keygen", "RSA"),
    Rule("py-pycryptodome-ecc", PY, r'\bECC\.generate\(\s*curve\s*=\s*[\'"](?P<curve>[\w-]+)', "fixed", "keygen", "EC"),
    Rule("py-pycryptodome-hash", PY, r'\b(?P<alg>MD5|SHA1)\.new\(', "plain", "digest", confidence=0.8),
    Rule("py-cryptography-cipher", PY, r'algorithms\.(?P<alg>AES|AES128|AES256|TripleDES|Blowfish|ARC4|ChaCha20|Camellia)\((?P<args>[^)]*)\)', "plain", "encrypt",
         lookahead=(r'modes\.(?P<mode>[A-Z]{2,4})\(',)),
    Rule("py-ssl-protocol", PY, r'ssl\.PROTOCOL_(?P<alg>TLSv1_2|TLSv1_1|TLSv1|SSLv3|SSLv2)\b', "tls", "protocol"),
    Rule("py-ssl-version", PY, r'TLSVersion\.(?P<alg>TLSv1_3|TLSv1_2|TLSv1_1|TLSv1|SSLv3)\b', "tls", "protocol"),
    Rule("py-pbkdf2", PY, r'hashlib\.pbkdf2_hmac\(\s*[\'"](?P<alg>\w+)[\'"]', "pbkdf2", "keyderive"),
    Rule("py-bcrypt", PY, r'\bbcrypt\.hashpw\(', "fixed", "keyderive", "bcrypt"),
    # ---- JWT (Python + JS) ----
    Rule("jwt-alg", PY + JS, r'algorithms?\s*[=:]\s*\[?\s*[\'"](?P<alg>RS256|RS384|RS512|PS256|PS384|PS512|ES256|ES384|ES512|HS256|HS384|HS512|EdDSA)[\'"]', "jwt", "sign"),
    # ---- Go ----
    Rule("go-rsa-gen", GO, r'rsa\.GenerateKey\(\s*[\w.]+\s*,\s*(?P<size>\w+)', "fixed", "keygen", "RSA"),
    Rule("go-ecdsa-gen", GO, r'ecdsa\.GenerateKey\(\s*elliptic\.(?P<curve>P\d+)\(', "fixed", "keygen", "ECDSA"),
    Rule("go-ecdh", GO, r'ecdh\.(?P<curve>X25519|P256|P384|P521)\(\)', "go_ecdh", "key-agree"),
    Rule("go-ed25519", GO, r'ed25519\.GenerateKey\(', "fixed", "keygen", "Ed25519"),
    Rule("go-hash", GO, r'\b(?P<alg>md5|sha1|sha256|sha512)\.(?:New|Sum|Sum256|Sum512)\(', "plain", "digest"),
    Rule("go-3des", GO, r'des\.NewTripleDESCipher\(', "fixed", "encrypt", "3DES"),
    Rule("go-des", GO, r'des\.NewCipher\(', "fixed", "encrypt", "DES"),
    Rule("go-rc4", GO, r'rc4\.NewCipher\(', "fixed", "encrypt", "RC4"),
    Rule("go-aes", GO, r'aes\.NewCipher\(', "fixed", "encrypt", "AES", confidence=0.75,
         lookahead=(r'cipher\.New(?P<mode>GCM|CBC|CTR|CFB|OFB)',)),
    Rule("go-tls", GO, r'tls\.(?P<alg>VersionTLS10|VersionTLS11|VersionTLS12|VersionTLS13|VersionSSL30)\b', "tls", "protocol"),
    Rule("go-mlkem", GO, r'mlkem\.GenerateKey(?P<size>768|1024)\(', "fixed", "keygen", "ML-KEM"),
    # ---- JavaScript / TypeScript ----
    Rule("js-hash", JS, r'createHash\(\s*[\'"](?P<alg>[\w-]+)[\'"]', "plain", "digest"),
    Rule("js-hmac", JS, r'createHmac\(\s*[\'"](?P<alg>[\w-]+)[\'"]', "hmac", "tag"),
    Rule("js-keypair", JS, r'generateKeyPair(?:Sync)?\(\s*[\'"](?P<alg>rsa-pss|rsa|dsa|ec|ed25519|ed448|x25519|x448|dh)[\'"]\s*(?:,\s*\{(?P<args>[^}]*)\})?', "plain", "keygen"),
    Rule("js-cipher", JS, r'createCipher(?:iv)?\(\s*[\'"](?P<alg>[\w-]+)[\'"]', "openssl_cipher", "encrypt"),
    Rule("js-sign", JS, r'createSign\(\s*[\'"](?P<alg>[\w-]+)[\'"]', "node_sign", "sign"),
    Rule("js-ecdh", JS, r'createECDH\(\s*[\'"](?P<curve>[\w-]+)[\'"]', "fixed", "key-agree", "ECDH"),
    Rule("js-dh", JS, r'createDiffieHellman\(\s*(?P<size>\d+)', "fixed", "key-agree", "DH"),
    Rule("js-cryptojs", JS, r'CryptoJS\.(?P<alg>HmacSHA1|HmacSHA256|HmacMD5|MD5|SHA1|SHA256|SHA512|TripleDES|AES|DES|RC4)\b', "cryptojs", "encrypt", confidence=0.85),
    Rule("js-tls", JS, r'(?:secureProtocol|minVersion)\s*:\s*[\'"](?P<alg>TLSv1_method|TLSv1_1_method|SSLv3_method|TLSv1\.3|TLSv1\.2|TLSv1\.1|TLSv1)[\'"]', "tls", "protocol"),
    Rule("js-webcrypto", JS, r'subtle\.(?:generateKey|importKey)\([^{]*\{\s*name\s*:\s*[\'"](?P<alg>RSA-OAEP|RSASSA-PKCS1-v1_5|RSA-PSS|ECDSA|ECDH|AES-GCM|AES-CBC|AES-CTR|HMAC|Ed25519|X25519)[\'"](?P<args>[^}]*)', "webcrypto", "keygen"),
    # ---- C / C++ (OpenSSL, liboqs) ----
    Rule("c-rsa-gen-ex", C, r'RSA_generate_key_ex\(\s*\w+\s*,\s*(?P<size>\w+)', "fixed", "keygen", "RSA"),
    Rule("c-rsa-gen", C, r'RSA_generate_key\(\s*(?P<size>\w+)', "fixed", "keygen", "RSA"),
    Rule("c-rsa-bits", C, r'EVP_PKEY_CTX_set_rsa_keygen_bits\(\s*\w+\s*,\s*(?P<size>\w+)', "fixed", "keygen", "RSA"),
    Rule("c-ec-curve", C, r'EC_KEY_new_by_curve_name\(\s*NID_(?P<curve>\w+)', "fixed", "keygen", "EC"),
    Rule("c-evp-md", C, r'EVP_(?P<alg>md5|md4|sha1|sha224|sha256|sha384|sha512|sha3_256)\(\)', "plain", "digest"),
    Rule("c-evp-cipher", C, r'EVP_(?P<alg>aes_(?:128|192|256)_[a-z0-9]+|des_ede3_[a-z0-9]+|des_ede3|des_[a-z0-9]+|rc4|bf_[a-z0-9]+|chacha20_poly1305|chacha20)\(\)', "openssl_cipher", "encrypt"),
    Rule("c-lowlevel-hash", C, r'\b(?P<alg>MD5|MD4|SHA1)(?:_Init)?\s*\(', "plain", "digest", confidence=0.6),
    Rule("c-dh", C, r'DH_generate_parameters(?:_ex)?\(\s*(?:\w+\s*,\s*)?(?P<size>\d+)', "fixed", "key-agree", "DH"),
    Rule("c-evp-pkey", C, r'EVP_PKEY_(?P<alg>RSA|DSA|DH|EC|ED25519|X25519|ED448|X448)\b', "plain", "keygen", confidence=0.6),
    Rule("c-ssl-method", C, r'\b(?P<alg>SSLv3_method|TLSv1_method|TLSv1_1_method|TLSv1_2_method)\s*\(', "tls", "protocol"),
    Rule("c-min-proto", C, r'SSL_CTX_set_min_proto_version\(\s*\w+\s*,\s*(?P<alg>SSL3_VERSION|TLS1_VERSION|TLS1_1_VERSION|TLS1_2_VERSION|TLS1_3_VERSION)', "tls_const", "protocol"),
    Rule("c-oqs-kem", C, r'OQS_KEM_new\(\s*OQS_KEM_alg_(?P<alg>\w+)', "plain", "key-agree"),
    # ---- C# (.NET) ----
    Rule("cs-rsa-csp", CS, r'new\s+RSACryptoServiceProvider\(\s*(?P<size>\w*)\s*\)', "fixed", "keygen", "RSA"),
    Rule("cs-rsa-create", CS, r'\bRSA\.Create\(\s*(?P<size>\w*)\s*\)', "fixed", "keygen", "RSA"),
    Rule("cs-hash", CS, r'\b(?P<alg>MD5|SHA1|SHA256|SHA384|SHA512)\.(?:Create|HashData)\(', "plain", "digest"),
    Rule("cs-hash-csp", CS, r'new\s+(?P<alg>MD5|SHA1)CryptoServiceProvider\(', "plain", "digest"),
    Rule("cs-sym", CS, r'\b(?P<alg>TripleDES|DES|RC2|Aes|Rijndael)\.Create\(', "plain", "encrypt"),
    Rule("cs-sym-csp", CS, r'new\s+(?P<alg>TripleDES|DES|RC2)CryptoServiceProvider\(', "plain", "encrypt"),
    Rule("cs-ec", CS, r'\b(?P<alg>ECDsa|ECDiffieHellman)\.Create\(', "plain", "keygen"),
    Rule("cs-tls", CS, r'SslProtocols\.(?P<alg>Ssl2|Ssl3|Tls11|Tls12|Tls13|Tls)\b', "cs_tls", "protocol"),
    # ---- PHP ----
    Rule("php-openssl", PHP, r'openssl_encrypt\([^,]+,\s*[\'"](?P<alg>[\w-]+)[\'"]', "openssl_cipher", "encrypt"),
    Rule("php-hash", PHP, r'(?<![\w>$])(?P<alg>md5|sha1)\s*\(', "plain", "digest", confidence=0.7),
]

_RULES_BY_EXT: dict[str, list[Rule]] = {}
for _r in RULES:
    for _e in _r.exts:
        _RULES_BY_EXT.setdefault(_e, []).append(_r)

_CONFIG_HINT = re.compile(r'getProperty|getenv|environ|process\.env|config\.|settings\.|@Value|viper\.Get|Configuration\[')
_SIZE_ARG = re.compile(r'(?:key_size|keySize|modulusLength|bits|keysize|length)\s*[=:]\s*(\w+)')
_CURVE_ARG = re.compile(r'(?:namedCurve|curve)\s*[=:]\s*[\'"]?([\w-]+)')
_MODE_ARG = re.compile(r'MODE_([A-Z]{2,4})\b|modes\.([A-Z]{2,4})\(')
_KEYBYTES = re.compile(r'(?:urandom|get_random_bytes|token_bytes|randomBytes|secrets\.token_bytes)\(\s*(16|24|32)\s*\)')
_EXTRA_ALIASES = {"ecdiffiehellman": "ECDH", "des3": "3DES", "rijndael": "AES", "rsapss": "RSA"}


def _resolve_int(token: str | None, text: str) -> tuple[int | None, bool]:
    """Resolve a size literal or a constant defined in the same file. Returns (value, via_constant)."""
    if not token:
        return None, False
    if token.isdigit():
        return int(token), False
    m = (re.search(rf'\b{re.escape(token)}\b\s*(?::\s*\w+\s*)?[:=]\s*(\d{{2,5}})\b', text)
         or re.search(rf'#define\s+{re.escape(token)}\s+\(?(\d{{2,5}})\b', text))
    return (int(m.group(1)), True) if m else (None, False)


def _resolve_str(ident: str, text: str) -> str | None:
    m = re.search(rf'\b{re.escape(ident)}\b\s*=\s*"([^"]+)"', text)
    return m.group(1) if m else None


def _plain(alg: str, usage: str) -> R.Parts:
    n = R.normalize(alg)
    if not n:
        k = re.sub(r"[^a-z0-9]", "", alg.lower())
        if k in _EXTRA_ALIASES:
            n = (_EXTRA_ALIASES[k], {"padding": "pss"} if k == "rsapss" else {})
    return [(n[0], n[1], usage)] if n else []


def _parts(rule: Rule, alg: str | None, m: re.Match, text: str) -> R.Parts:
    p = rule.parser
    if p == "fixed":
        return [(rule.canonical, {}, rule.usage)]
    if alg is None:
        alg = ""
    if p == "transform":
        return R.parse_transformation(alg)
    if p == "plain":
        return _plain(alg, rule.usage)
    if p == "jca_sig":
        return R.parse_jca_signature(alg)
    if p == "hmac":
        return R.parse_hmac(alg)
    if p == "jwt":
        return R.parse_jwt(alg)
    if p == "tls":
        return R.parse_tls_version(alg)
    if p == "tls_list":
        out: R.Parts = []
        for v in re.findall(r'"([^"]+)"', alg):
            out += R.parse_tls_version(v)
        return out
    if p == "openssl_cipher":
        return R.parse_openssl_cipher(alg.replace("_", "-"))
    if p == "kdf":
        mm = re.match(r'(?i)PBKDF2WithHmac(\w+)', alg)
        if mm:
            h = R.normalize(mm.group(1))
            return [("PBKDF2", {"hash": h[0]} if h else {}, "keyderive")]
        return _plain(alg, "keyderive")
    if p == "pbkdf2":
        h = R.normalize(alg)
        return [("PBKDF2", {"hash": h[0]} if h else {}, "keyderive")]
    if p == "node_sign":
        up = alg.upper()
        if "-" in alg and up.split("-")[0] in ("RSA", "DSA", "ECDSA"):
            a, h = alg.split("-", 1)
            out = _plain(a, "sign")
            out += [(x[0], x[1], "digest") for x in _plain(h, "digest")]
            return out
        return _plain(alg, "digest")
    if p == "cryptojs":
        if alg.startswith("Hmac"):
            return R.parse_hmac(alg)
        n = _plain(alg, "encrypt")
        if n and R.ALGORITHMS.get(n[0][0], {}).get("primitive") == "hash":
            return [(n[0][0], n[0][1], "digest")]
        if n and n[0][0] == "AES":
            return [("AES", {"mode": "cbc"}, "encrypt")]   # CryptoJS AES default: CBC, key via passphrase KDF
        return n
    if p == "go_ecdh":
        c = m.group("curve")
        return [("X25519", {}, "key-agree")] if c == "X25519" else [("ECDH", {"curve": R.normalize_curve(c)}, "key-agree")]
    if p == "webcrypto":
        name = alg.upper()
        table = {
            "RSA-OAEP": ("RSA", {"padding": "oaep"}, "encrypt"), "RSASSA-PKCS1-V1_5": ("RSA", {"padding": "pkcs1v15"}, "sign"),
            "RSA-PSS": ("RSA", {"padding": "pss"}, "sign"), "ECDSA": ("ECDSA", {}, "sign"), "ECDH": ("ECDH", {}, "key-agree"),
            "AES-GCM": ("AES", {"mode": "gcm"}, "encrypt"), "AES-CBC": ("AES", {"mode": "cbc"}, "encrypt"),
            "AES-CTR": ("AES", {"mode": "ctr"}, "encrypt"), "HMAC": ("HMAC", {}, "tag"),
            "ED25519": ("Ed25519", {}, "sign"), "X25519": ("X25519", {}, "key-agree"),
        }
        t = table.get(name)
        return [(t[0], dict(t[1]), t[2])] if t else []
    if p == "tls_const":
        v = {"SSL3_VERSION": "SSLv3", "TLS1_VERSION": "TLSv1", "TLS1_1_VERSION": "TLSv1.1",
             "TLS1_2_VERSION": "TLSv1.2", "TLS1_3_VERSION": "TLSv1.3"}[alg]
        return R.parse_tls_version(v)
    if p == "cs_tls":
        v = {"Ssl2": "SSLv2", "Ssl3": "SSLv3", "Tls": "TLSv1", "Tls11": "TLSv1.1", "Tls12": "TLSv1.2", "Tls13": "TLSv1.3"}[alg]
        return R.parse_tls_version(v)
    return []


_JAVA_CONST_PARSER = {"Cipher": ("transform", "encrypt"), "Signature": ("jca_sig", "sign"),
                      "MessageDigest": ("plain", "digest"), "KeyPairGenerator": ("plain", "keygen"),
                      "KeyGenerator": ("plain", "keygen"), "Mac": ("hmac", "tag"), "KeyAgreement": ("plain", "key-agree")}


def scan_source(text: str, rel_path: str, ext: str) -> list[RawFinding]:
    rules = _RULES_BY_EXT.get(ext)
    if not rules:
        return []
    lines = text.splitlines()
    starts = [0]
    for ln in lines:
        starts.append(starts[-1] + len(ln) + 1)
    is_py = ext in PY
    findings: list[RawFinding] = []
    seen: set[tuple] = set()

    for rule in rules:
        for m in rule.rx.finditer(text):
            idx = bisect.bisect_right(starts, m.start()) - 1
            line = lines[idx] if idx < len(lines) else ""
            stripped = line.lstrip()
            if stripped.startswith(("//", "/*", "*", "--")) or (is_py and stripped.startswith("#")):
                continue
            gd = m.groupdict()
            alg = gd.get("alg")
            agility = "config" if _CONFIG_HINT.search(line) else "hardcoded"

            if rule.parser == "java_const":
                resolved = _resolve_str(gd["ident"], text)
                if not resolved:
                    continue
                parser, usage = _JAVA_CONST_PARSER[gd["api"]]
                tmp = Rule(rule.id, rule.exts, rule.pattern, parser, usage)
                parts = _parts(tmp, resolved, m, text)
                alg, agility = resolved, "constant"
            else:
                parts = _parts(rule, alg, m, text)
            if not parts:
                continue

            window = "\n".join(lines[idx: idx + 8])
            behind = "\n".join(lines[max(0, idx - 6): idx + 1])
            size_tok = gd.get("size") or None
            curve_tok = gd.get("curve") or None
            mode_tok = gd.get("mode") or None
            args = gd.get("args") or ""
            if args:
                if not size_tok:
                    sm = _SIZE_ARG.search(args)
                    size_tok = sm.group(1) if sm else None
                if not curve_tok:
                    cm = _CURVE_ARG.search(args)
                    curve_tok = cm.group(1) if cm else None
                mm = _MODE_ARG.search(args)
                if mm:
                    mode_tok = mm.group(1) or mm.group(2)
            for la in rule.la:
                lm = la.search(window)
                if lm:
                    lg = lm.groupdict()
                    size_tok = size_tok or lg.get("size")
                    curve_tok = curve_tok or lg.get("curve")
                    mode_tok = mode_tok or lg.get("mode")
            size, via_const = _resolve_int(size_tok, text)
            if via_const and agility == "hardcoded":
                agility = "constant"

            canonical, params, usage = parts[0]
            params = dict(params)
            if size and canonical in ("RSA", "DH", "DSA", "AES", "ML-KEM", "Camellia"):
                params["size"] = size
            if canonical == "AES" and "size" not in params:
                kb = _KEYBYTES.search(behind)
                if kb:
                    params["size"] = int(kb.group(1)) * 8
            if curve_tok and canonical in ("EC", "ECDSA", "ECDH"):
                params["curve"] = R.normalize_curve(curve_tok)
            if mode_tok and canonical in ("AES", "3DES", "DES", "Camellia", "Blowfish"):
                mode = mode_tok.lower()
                if mode in R._MODES:
                    params["mode"] = mode
            parts[0] = (canonical, params, usage)

            key = (rule.id, idx, alg, tuple(sorted(params.items())))
            if key in seen:
                continue
            seen.add(key)
            findings.append(RawFinding(
                scanner="source", kind="protocol" if canonical == "TLS" else "algorithm",
                identifier=alg or m.group(0), path=rel_path, line=idx + 1,
                snippet=stripped[:220], canonical=canonical, params=params, usage=usage,
                confidence=rule.confidence, rule_id=rule.id, agility=agility,
                extra={"language": LANG.get(ext, ext)}, components=parts[1:],
            ))
    return findings
