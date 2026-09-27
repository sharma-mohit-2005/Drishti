"""Copy the demo repo and apply the fixes Q-Scan recommends, for a before/after demo.

  python scripts/apply_demo_fixes.py            # writes demo/bharat-finserve-fixed
  qscan scan demo/bharat-finserve-fixed      # QRI goes up; compare the two scans in the dashboard
"""
from __future__ import annotations

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "demo"
SRC, DST = ROOT / "bharat-finserve", ROOT / "bharat-finserve-fixed"

FIXES = {
    "payments-svc/src/main/java/in/bharatfinserve/pay/KeyService.java": [
        ('Signature.getInstance("SHA1withRSA")', 'Signature.getInstance("SHA256withRSA")'),
        ('MessageDigest.getInstance("MD5")', 'MessageDigest.getInstance("SHA-256")'),
        ("kg.init(128);", "kg.init(256);"),
        ('Cipher.getInstance("AES/ECB/PKCS5Padding")', 'Cipher.getInstance("AES/GCM/NoPadding")'),
        ('SSLContext.getInstance("TLSv1.1")', 'SSLContext.getInstance("TLSv1.3")'),
    ],
    "payments-svc/src/main/resources/application.properties": [
        ("server.ssl.enabled-protocols=TLSv1.1,TLSv1.2", "server.ssl.enabled-protocols=TLSv1.2,TLSv1.3"),
        ("TLS_RSA_WITH_AES_128_CBC_SHA,", ""),
        ("server.ssl.key-store-type=JKS", "server.ssl.key-store-type=PKCS12"),
    ],
    "payments-svc/pom.xml": [("bcprov-jdk15on", "bcprov-jdk18on"), ("<version>1.60</version>", "<version>1.80</version>")],
    "kyc-service/app/crypto_utils.py": [
        ("hashlib.sha1(aadhaar_number", "hashlib.sha256(aadhaar_number"),
        ("DES3.new(key, DES3.MODE_CBC, iv)", "AES.new(key, AES.MODE_GCM, nonce=iv)"),
    ],
    "kyc-service/requirements.txt": [("pycrypto==2.6.1", "pycryptodome==3.20.0")],
    "notification-svc/index.js": [("createHash('md5')", "createHash('sha256')"), ("CryptoJS.SHA1(tpl).toString()", "crypto.createHash('sha256').update(tpl).digest('hex')")],
    "notification-svc/package.json": [('"crypto-js": "^4.1.1",\n    ', "")],
    "legacy-reports/main.go": [
        ("const archiveKeyBits = 1024", "const archiveKeyBits = 3072"),
        ("md5.Sum(data)", "sha256.Sum256(data)"), ('"crypto/md5"', '"crypto/sha256"'),
        ("des.NewTripleDESCipher(key)", "aes.NewCipher(key)"), ('"crypto/des"', '"crypto/aes"'),
        ("tls.VersionTLS10", "tls.VersionTLS13"),
    ],
    "legacy-reports/go.mod": [("github.com/dgrijalva/jwt-go v3.2.0+incompatible", "github.com/golang-jwt/jwt/v5 v5.2.1")],
    "card-gateway/src/hsm_bridge.c": [("EVP_sha1()", "EVP_sha256()"), ("EVP_aes_128_cbc()", "EVP_aes_256_gcm()")],
    "edge/nginx.conf": [
        ("ssl_protocols TLSv1 TLSv1.1 TLSv1.2;", "ssl_protocols TLSv1.3;"),
        ("ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA:DES-CBC3-SHA;", "ssl_ecdh_curve X25519MLKEM768;"),
    ],
    "infra/sshd_config": [
        ("KexAlgorithms diffie-hellman-group14-sha1,ecdh-sha2-nistp256,curve25519-sha256", "KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512"),
        ("Ciphers aes128-cbc,aes256-gcm@openssh.com", "Ciphers aes256-gcm@openssh.com"),
        ("MACs hmac-sha1,hmac-sha2-256", "MACs hmac-sha2-256"),
    ],
    "infra/openssl.cnf": [("default_md = sha1", "default_md = sha256"), ("MinProtocol = TLSv1", "MinProtocol = TLSv1.2"), ("default_bits = 2048", "default_bits = 3072")],
    "infra/Dockerfile": [("FROM ubuntu:18.04", "FROM ubuntu:24.04"), ("openssl libssl1.1", "openssl"), ("pycryptodome==3.9.0", "pycryptodome==3.20.0")],
}


def main():
    if DST.exists():
        shutil.rmtree(DST)
    shutil.copytree(SRC, DST)
    cfg = DST / "qscan.yml"
    cfg.write_text(cfg.read_text(encoding="utf-8").replace("project: Bharat FinServe (demo)", "project: Bharat FinServe (after fixes)"), encoding="utf-8")
    applied = 0
    for rel, subs in FIXES.items():
        p = DST / rel
        text = p.read_text(encoding="utf-8")
        for old, new in subs:
            if old in text:
                text = text.replace(old, new)
                applied += 1
            else:
                print(f"  skipped (not found) {rel}: {old[:50]}")
        p.write_text(text, encoding="utf-8")
    (DST / "payments-svc/src/main/resources/partner-bank.pem").unlink(missing_ok=True)   # expired cert retired
    print(f"applied {applied} fixes -> {DST}")


if __name__ == "__main__":
    main()
