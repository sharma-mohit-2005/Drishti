"""PQC benchmark lab: measures algorithms on the machine it runs on.

Classical baselines use pyca/cryptography. PQC timings need liboqs-python
(`pip install liboqs-python`); without it we report the FIPS-defined sizes only.
"""
from __future__ import annotations

import platform
import statistics
import time

from .reco import PQC_SIZES


def _time(fn, n: int) -> float:
    samples = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t) * 1000)
    return round(statistics.median(samples), 4)


def classical(n: int = 50) -> list[dict]:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519

    out = []
    a, b = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
    out.append({"algorithm": "X25519", "operation": "keygen + shared secret",
                "median_ms": _time(lambda: x25519.X25519PrivateKey.generate().exchange(b.public_key()), n),
                "public_key": 32, "ciphertext": 32})
    rk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    msg = b"q-drishti benchmark message"
    out.append({"algorithm": "RSA-2048", "operation": "sign (PKCS#1 v1.5, SHA-256)",
                "median_ms": _time(lambda: rk.sign(msg, padding.PKCS1v15(), hashes.SHA256()), n),
                "public_key": 256, "signature": 256})
    ek = ec.generate_private_key(ec.SECP256R1())
    out.append({"algorithm": "ECDSA-P256", "operation": "sign (SHA-256)",
                "median_ms": _time(lambda: ek.sign(msg, ec.ECDSA(hashes.SHA256())), n),
                "public_key": 65, "signature": 72})
    _ = a
    return out


def pqc(n: int = 50) -> tuple[bool, list[dict]]:
    try:
        import oqs  # type: ignore
    except Exception:
        return False, []
    out = []
    for alg, label in (("ML-KEM-512", "ML-KEM-512"), ("ML-KEM-768", "ML-KEM-768"), ("ML-KEM-1024", "ML-KEM-1024")):
        try:
            with oqs.KeyEncapsulation(alg) as server:
                pk = server.generate_keypair()

                def round_trip():
                    with oqs.KeyEncapsulation(alg) as client:
                        ct, _ = client.encap_secret(pk)
                    server.decap_secret(ct)
                out.append({"algorithm": label, "operation": "encapsulate + decapsulate", "median_ms": _time(round_trip, n),
                            **{k: v for k, v in PQC_SIZES[label].items() if k != "standard"}})
        except Exception:
            continue
    msg = b"q-drishti benchmark message"
    for alg in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"):
        try:
            with oqs.Signature(alg) as s:
                s.generate_keypair()
                out.append({"algorithm": alg, "operation": "sign", "median_ms": _time(lambda: s.sign(msg), n),
                            **{k: v for k, v in PQC_SIZES[alg].items() if k != "standard"}})
        except Exception:
            continue
    return True, out


def run(n: int = 50) -> dict:
    ok, pq = pqc(n)
    return {"machine": f"{platform.system()} {platform.machine()} · Python {platform.python_version()}",
            "iterations": n, "classical": classical(n), "pqc": pq, "liboqs_available": ok,
            "sizes": PQC_SIZES,
            "tls_overhead_bytes": PQC_SIZES["ML-KEM-768"]["public_key"] + PQC_SIZES["ML-KEM-768"]["ciphertext"],
            "note": None if ok else "liboqs-python is not installed; PQC timings unavailable, sizes shown from FIPS 203/204/205."}
