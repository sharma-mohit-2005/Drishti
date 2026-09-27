"""Dependency manifests and Dockerfiles -> crypto libraries, versions and PQC readiness."""
from __future__ import annotations

import json
import re

from ..models import RawFinding

# name -> (ecosystem, status, pqc, note). status: weak = deprecated/unsafe, info = fine.
CRYPTO_LIBS: dict[str, tuple[str, str, str, str]] = {
    # python
    "pycrypto": ("pypi", "weak", "no", "Unmaintained since 2013 with known CVEs. Replace with pycryptodome or cryptography."),
    "pycryptodome": ("pypi", "info", "no", "Maintained; no ML-KEM/ML-DSA yet. Pair with liboqs-python for PQC."),
    "pycryptodomex": ("pypi", "info", "no", "Maintained; no ML-KEM/ML-DSA yet."),
    "cryptography": ("pypi", "info", "unknown", "pyca/cryptography; check the release notes of your version for PQC support."),
    "pyopenssl": ("pypi", "info", "unknown", "Depends on the linked OpenSSL; OpenSSL 3.5+ adds ML-KEM/ML-DSA/SLH-DSA."),
    "rsa": ("pypi", "weak", "no", "python-rsa: pure-Python RSA, historically vulnerable to timing attacks."),
    "ecdsa": ("pypi", "weak", "no", "python-ecdsa is not constant-time; the project advises against it for production."),
    "pyjwt": ("pypi", "info", "no", "JWT signing; RS/ES algorithms are quantum-vulnerable."),
    "python-jose": ("pypi", "info", "no", "JWT/JOSE; RS/ES algorithms are quantum-vulnerable."),
    "paramiko": ("pypi", "info", "unknown", "SSH; check KEX algorithm support."),
    "bcrypt": ("pypi", "info", "n/a", "Password hashing."),
    "passlib": ("pypi", "info", "n/a", "Password hashing."),
    "liboqs-python": ("pypi", "info", "yes", "Open Quantum Safe bindings: ML-KEM, ML-DSA, SLH-DSA."),
    "oqs": ("pypi", "info", "yes", "Open Quantum Safe bindings."),
    # node
    "crypto-js": ("npm", "weak", "no", "Discontinued by its maintainer in 2023. Use Web Crypto or node:crypto."),
    "node-forge": ("npm", "info", "no", "Pure-JS TLS/PKI; RSA/ECC only."),
    "jsonwebtoken": ("npm", "info", "no", "JWT signing; RS/ES algorithms are quantum-vulnerable."),
    "jose": ("npm", "info", "no", "JOSE; RS/ES/EdDSA are quantum-vulnerable."),
    "node-rsa": ("npm", "info", "no", "RSA only."),
    "elliptic": ("npm", "info", "no", "ECC only; several past signature-malleability CVEs."),
    "bcryptjs": ("npm", "info", "n/a", "Password hashing."),
    "tweetnacl": ("npm", "info", "no", "Curve25519/Ed25519 only."),
    "@noble/post-quantum": ("npm", "info", "yes", "ML-KEM, ML-DSA, SLH-DSA in JavaScript."),
    # java
    "bcprov-jdk15on": ("maven", "weak", "no", "Bouncy Castle jdk15on line is end-of-life; move to bcprov-jdk18on."),
    "bcprov-jdk18on": ("maven", "info", "unknown", "Bouncy Castle; recent releases ship ML-KEM/ML-DSA, check your version."),
    "bcpkix-jdk15on": ("maven", "weak", "no", "End-of-life Bouncy Castle line."),
    "jjwt": ("maven", "info", "no", "JWT signing; RS/ES algorithms are quantum-vulnerable."),
    "jjwt-api": ("maven", "info", "no", "JWT signing."),
    "nimbus-jose-jwt": ("maven", "info", "no", "JOSE; RS/ES/EdDSA are quantum-vulnerable."),
    "tink": ("maven", "info", "unknown", "Google Tink."),
    # go
    "golang.org/x/crypto": ("go", "info", "unknown", "Go extended crypto."),
    "github.com/cloudflare/circl": ("go", "info", "yes", "Cloudflare CIRCL: ML-KEM, ML-DSA and hybrids."),
    "github.com/dgrijalva/jwt-go": ("go", "weak", "no", "Unmaintained with a known CVE; use github.com/golang-jwt/jwt."),
    "github.com/golang-jwt/jwt": ("go", "info", "no", "JWT signing."),
}

DEP_FILES = {"requirements.txt", "requirements-dev.txt", "package.json", "pom.xml", "go.mod",
             "build.gradle", "build.gradle.kts", "dockerfile", "pipfile", "pyproject.toml"}


def is_dep_file(name: str) -> bool:
    low = name.lower()
    return low in DEP_FILES or (low.startswith("requirements") and low.endswith(".txt")) or low.startswith("dockerfile") or low.endswith(".dockerfile")


def _lib(name: str, version: str, eco: str, path: str, line: int, snippet: str, rule: str, **extra) -> RawFinding:
    known = CRYPTO_LIBS.get(name.lower())
    status, pqc, note = (known[1], known[2], known[3]) if known else ("info", "unknown", "")
    ex = {"status": status, "pqc": pqc, "note": note}
    ex.update(extra)
    return RawFinding(scanner="dependency", kind="library", identifier=f"{name}@{version}" if version else name,
                      path=path, line=line, snippet=snippet.strip()[:220], canonical=None,
                      params={"name": name, "version": version, "ecosystem": eco}, usage="library",
                      confidence=0.95, rule_id=rule, agility="n/a", extra=ex)


def _openssl_status(version: str) -> tuple[str, str, str]:
    m = re.match(r"(\d+)\.(\d+)", version or "")
    if not m:
        return "info", "unknown", "OpenSSL version not pinned."
    major, minor = int(m.group(1)), int(m.group(2))
    if major < 3:
        return "weak", "no", f"OpenSSL {version} is end-of-life (1.1.1 support ended Sep 2023) and has no PQC."
    if (major, minor) >= (3, 5):
        return "info", "yes", f"OpenSSL {version} includes ML-KEM, ML-DSA and SLH-DSA."
    return "qv", "no", f"OpenSSL {version} has no built-in PQC, so every public-key algorithm it offers is quantum-vulnerable; OpenSSL 3.5+ adds ML-KEM/ML-DSA/SLH-DSA."


def openssl_finding(version: str, path: str, line: int | None, snippet: str, rule: str, scanner: str = "dependency") -> RawFinding:
    status, pqc, note = _openssl_status(version)
    f = _lib("OpenSSL", version, "system", path, line or 0, snippet, rule, status=status, pqc=pqc, note=note)
    f.scanner = scanner
    return f


_DISTRO_OPENSSL = {"ubuntu:18.04": "1.1.1", "ubuntu:20.04": "1.1.1", "ubuntu:22.04": "3.0", "ubuntu:24.04": "3.0",
                   "debian:buster": "1.1.1", "debian:bullseye": "1.1.1", "debian:bookworm": "3.0",
                   "centos:7": "1.0.2", "alpine:3.12": "1.1.1"}


def scan_deps(text: str, rel_path: str, name: str) -> list[RawFinding]:
    low = name.lower()
    out: list[RawFinding] = []
    lines = text.splitlines()
    if low.startswith("requirements") or low == "pipfile":
        for i, ln in enumerate(lines, 1):
            m = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*(?:[=~<>!]=?\s*([\w.\-*]+))?", ln)
            if m and m.group(1).lower() in CRYPTO_LIBS:
                out.append(_lib(m.group(1), m.group(2) or "", "pypi", rel_path, i, ln, "pip-requirement"))
    elif low == "pyproject.toml":
        for i, ln in enumerate(lines, 1):
            for m in re.finditer(r'["\']([A-Za-z0-9_.\-]+)\s*(?:[=~<>!]=?\s*([\w.\-*]+))?', ln):
                if m.group(1).lower() in CRYPTO_LIBS:
                    out.append(_lib(m.group(1), m.group(2) or "", "pypi", rel_path, i, ln, "pyproject-dependency"))
    elif low == "package.json":
        try:
            data = json.loads(text)
        except ValueError:
            return out
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for dep, ver in (data.get(section) or {}).items():
                if dep.lower() in CRYPTO_LIBS:
                    line = next((i for i, ln in enumerate(lines, 1) if f'"{dep}"' in ln), 0)
                    out.append(_lib(dep, str(ver).lstrip("^~"), "npm", rel_path, line, f'"{dep}": "{ver}"', "npm-dependency"))
    elif low == "pom.xml":
        for m in re.finditer(r"<artifactId>\s*([\w.\-]+)\s*</artifactId>\s*(?:<version>\s*([\w.\-${}]+)\s*</version>)?", text):
            if m.group(1).lower() in CRYPTO_LIBS:
                line = text.count("\n", 0, m.start()) + 1
                out.append(_lib(m.group(1), m.group(2) or "", "maven", rel_path, line, m.group(0).replace("\n", " "), "maven-dependency"))
    elif low.startswith("build.gradle"):
        for i, ln in enumerate(lines, 1):
            m = re.search(r"['\"]([\w.\-]+):([\w.\-]+):([\w.\-]+)['\"]", ln)
            if m and m.group(2).lower() in CRYPTO_LIBS:
                out.append(_lib(m.group(2), m.group(3), "maven", rel_path, i, ln, "gradle-dependency"))
    elif low == "go.mod":
        for i, ln in enumerate(lines, 1):
            m = re.match(r"^\s*(?:require\s+)?([\w.\-/]+)\s+(v[\w.\-+]+)", ln)
            if m:
                mod = m.group(1)
                key = next((k for k in CRYPTO_LIBS if mod == k or mod.startswith(k + "/")), None)
                if key:
                    out.append(_lib(key, m.group(2), "go", rel_path, i, ln, "go-module"))
    elif low.startswith("dockerfile") or low.endswith(".dockerfile"):
        for i, ln in enumerate(lines, 1):
            m = re.match(r"^\s*FROM\s+(?:--\S+\s+)?([\w.\-/:]+)", ln, re.I)
            if m:
                img = m.group(1).lower()
                if img in _DISTRO_OPENSSL:
                    out.append(openssl_finding(_DISTRO_OPENSSL[img], rel_path, i, ln, "docker-base-image"))
            for pm in re.finditer(r"\b(openssl|libssl[\w.\-]*)(?:=([\w.\-~+:]+))?", ln):
                if re.search(r"apt-get|apk|yum|dnf", ln):
                    pkg, ver = pm.group(1), pm.group(2) or ""
                    if pkg.startswith("libssl1.0") or pkg.startswith("libssl1.1"):
                        ver = ver or {"1.1": "1.1.1", "1.0": "1.0.2"}.get(pkg[6:9], pkg[6:9])
                    if ver:
                        out.append(openssl_finding(ver.split("-")[0], rel_path, i, ln, "docker-package"))
            pm = re.search(r"pip3? install\s+(.+)", ln)
            if pm:
                for tok in pm.group(1).split():
                    nm = re.match(r"([A-Za-z0-9_.\-]+)(?:==([\w.\-]+))?", tok)
                    if nm and nm.group(1).lower() in CRYPTO_LIBS:
                        out.append(_lib(nm.group(1), nm.group(2) or "", "pypi", rel_path, i, ln, "docker-pip"))
    return out
