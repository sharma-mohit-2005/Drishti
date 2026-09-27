# Q-Scan

**Enterprise Cryptographic Discovery & Analysis Tool** · Smart India Hackathon 2026 · SIH26164 (NTRO)

Q-Scan finds every cryptographic artefact in a system, tells you which ones a quantum computer will break and when, and recommends the NIST post-quantum replacement. It runs fully offline.

```
scan  →  normalise  →  score quantum risk  →  recommend fix  →  CBOM / SARIF / CSV / dashboard
```

## What it scans

| Surface | What it finds | How |
|---|---|---|
| Source code | Java/Kotlin, Python, Go, JS/TS, C/C++, C#, PHP crypto API calls with key sizes, curves, modes | 80+ pattern rules; key sizes resolved from literals, same-file constants and `#define`s, and follow-up calls |
| Dependencies | Crypto libraries and versions, deprecated/unmaintained libs, OpenSSL version in Dockerfiles | `requirements.txt`, `package.json`, `pom.xml`, `go.mod`, Gradle, Dockerfile |
| Binaries | Embedded OpenSSL versions, crypto symbols, AES/SHA-256/MD5 constant tables, JVM constant-pool strings in JAR/WAR/class | Byte-level signatures; crypto libraries are reported as *available*, not *used* |
| Certificates & keys | X.509 (key, size, curve, signature hash, expiry, CA flag), PEM/PKCS#8/OpenSSH private keys, SSH public keys | `cryptography` parsing |
| Configs | nginx, Apache, HAProxy, sshd, openssl.cnf, Spring Boot, `java.security` | Cipher suites split into key exchange, auth, cipher and MAC |
| Container images | All of the above inside every image layer | `docker save` + safe layer extraction |
| Live TLS endpoints | Accepted TLS versions, negotiated suite, server certificate | Active handshake probes (only scan systems you are authorised to test) |

## Risk model

- **Registry**: ~50 canonical algorithms with OIDs, classical security bits, NIST quantum level, and a status: `broken`, `weak`, `quantum-vulnerable` (Shor), `quantum-weakened` (Grover), `safe`, `pqc`.
- **Probabilistic Mosca**: an asset is at risk when *X + Y > Z*. X is the data shelf life (from the app's data class), Y is the migration time (from where the crypto lives, how hard-coded it is, and how many places use it), and Z is the CRQC arrival time, sampled from a lognormal distribution (default median 2034, σ = 0.45). We report `P(exposure) = P(X + Y > Z)`.
- **Quantum Risk Score** (0–100): `100 × Q × H × P × (0.40·C/5 + 0.35·S + 0.25·E)`, where Q is quantum vulnerability, H is harvest-now-decrypt-later exposure, C is app criticality, S is data sensitivity and E is exposure. Classically broken crypto gets a floor of 90.
- **Quantum Readiness Index**: 100 minus the criticality-weighted mean QRS.
- App context comes from `qscan.yml` in the scanned repo (see `demo/bharat-finserve/qscan.yml`). Without it, names like `payments` or `kyc` are used as hints.

## Quick start

```bash
pip install -r requirements.txt
python -m qscan demo                  # scan the bundled demo repo, write reports to ./qscan-out
python -m qscan serve                 # dashboard on http://127.0.0.1:8765
```

Other commands:

```bash
python -m qscan scan <folder> --out reports          # JSON result, CycloneDX CBOM, SARIF, CSV
python -m qscan scan --image nginx:1.25              # container image (needs Docker, image pulled)
python -m qscan scan --hosts 127.0.0.1:8443          # live TLS endpoint
python -m qscan scan <folder> --crqc-year 2030       # change the CRQC assumption
python -m qscan gate <folder> --baseline reports/qscan-result.json --fail-on critical,classical
python -m qscan bench                                # classical vs PQC timings on this machine
```

Offline deployment with Docker: `docker compose up`, then open http://localhost:8765. Code placed in `./scan-target` is available at `/scan`.

### Hosted demo (free: Render or Hugging Face Spaces)

- **Render** (free web service): in Render choose *New → Blueprint*, pick this GitHub repo, and `render.yaml` sets up a Docker web service that redeploys on every push. The free instance sleeps after about 15 idle minutes; the first request then takes 30–60 s.
- **Hugging Face Spaces**: create a Space with the *Docker* SDK and push this repo to it (the Space's README needs `sdk: docker` and `app_port: 8765` in its front matter).
- `railway.json` is kept for Railway (paid).

Public mode is **on by default on Render, Hugging Face Spaces and Railway** (`QSCAN_PUBLIC=1`). In that mode only the bundled demo repo and `.zip` uploads can be scanned. Folder paths, container images and live TLS probes are disabled, so the public URL cannot read the server's files or probe other hosts. Uploads are capped at 25 MB (`QSCAN_MAX_UPLOAD_MB`), 200 MB unzipped and 20,000 files. Uploaded scans are not listed for other visitors, and only the newest 40 scans are kept (`QSCAN_MAX_SCANS`).

## Dashboard

- **Overview**: Quantum Readiness Index, band counts, harvest-now-decrypt-later count, risk heatmap (criticality × years of margin), asset mix, top risks, and a **what-if slider** for the CRQC year that re-scores everything live.
- **Inventory**: filterable table. Each asset opens a drawer with its risk factors, a Mosca timeline, the recommended fix with the exact code/config change, its components, and every evidence location.
- **Migration roadmap**: three waves ordered by risk, and the QRI after each wave.
- **PQC lab**: benchmarks on the local machine; FIPS 203/204/205 size table; hybrid TLS overhead.
- **Export & CI**: CBOM, SARIF, CSV, JSON downloads, scan-to-scan comparison, and the CI gate command.

## Demo script

```bash
python scripts/make_demo_certs.py        # (re)generate throwaway demo certificates and keys
python -m qscan serve                 # run a demo scan from the dashboard
python scripts/apply_demo_fixes.py       # writes demo/bharat-finserve-fixed with the recommended fixes
                                         # scan that folder, then Export & CI → Compare
python scripts/demo_tls_server.py        # local TLS server on 127.0.0.1:8443 for the live-endpoint demo
```

Bharat FinServe is a fictional company. Its keys exist only to give the scanner real material to parse.

## Measured results (this prototype)

| Measurement | Result |
|---|---|
| Demo repo (22 files, 7 apps) | 54 assets, 97 occurrences, QRI 58, in about 0.4 s |
| After applying recommended fixes | QRI 71; classically broken assets 16 → 0 |
| Synthetic 100,302-line corpus (306 files) | median 0.57 s over 3 warm runs (about 175,000 lines/s); the first run took 14.6 s because Windows Defender scanned the freshly written files |
| Real-world codebase: Python 3.12 standard library + site-packages (35,963 files, 10.2 million lines) | 341 assets, 3,042 occurrences; median 248 s over 3 runs (160–315 s), about 41,000 lines/s |
| Real OpenSSL binary (Git for Windows `libcrypto-3-x64.dll`) | Detects OpenSSL 3.2.3 and flags that it has no PQC |
| Live TLS (local demo server) | Finds accepted versions (TLS 1.2, 1.3), negotiated suite and the RSA-2048 certificate |
| Classical timings on this laptop (`qscan bench`) | X25519 0.15 ms, ECDSA-P256 sign 0.09 ms, RSA-2048 sign 1.5 ms (medians) |
| Tests | `python -m pytest` (21 tests) |

Machine: Windows 11, Python 3.12. Re-run with `python scripts/benchmark.py [folder]`.

## Standards

NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), NIST IR 8547 (draft) transition timeline, NIST SP 800-131A, SP 800-208, RFC 8996 (TLS 1.0/1.1 deprecation), OWASP CycloneDX 1.6 CBOM, SARIF 2.1.0.

## Layout

```
qscan/
  registry.py        canonical algorithms, aliases, parsers, classical + quantum assessment
  scanners/          source, configs, certs, deps, binary, container, network
  engine.py          walk → scan (parallel) → normalise → risk → recommend → summary
  risk.py            probabilistic Mosca, QRS, QRI
  reco.py            recommendation rules
  export.py          CycloneDX 1.6 CBOM, SARIF, CSV
  bench.py           classical/PQC benchmarks
  api.py, web/       FastAPI + offline dashboard
  cli.py             scan | gate | serve | bench | demo
demo/bharat-finserve fictional monorepo with seeded crypto
scripts/             demo certs, demo fixes, TLS server, benchmark
tests/
```

## Limits (prototype)

- Pattern-based source analysis: no inter-file data flow; algorithm names read from runtime config are only resolved when defined as constants in the same file.
- PQC timings need `liboqs-python`; without it the PQC lab shows FIPS sizes and classical timings only.
- HSM (PKCS#11) and cloud KMS inventory are planned, not built.
