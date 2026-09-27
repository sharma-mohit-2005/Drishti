"""Command line: qdrishti scan | gate | serve | bench | demo."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .engine import run_scan
from .export import to_cbom, to_csv, to_sarif
from .risk import RiskConfig

DEMO_DIR = Path(__file__).resolve().parent.parent / "demo" / "bharat-finserve"
BAND_ORDER = ["critical", "high", "medium", "low"]


def _print_summary(r: dict) -> None:
    s, st = r["summary"], r["stats"]
    print(f"\nQ-Drishti {__version__}  |  {r['name']}")
    print(f"  files scanned {st['files_scanned']}  |  source files {st['source_files']}  |  {st['loc']:,} lines of code  |  {st['duration_s']} s")
    print(f"  {st['assets']} crypto assets from {st['occurrences']} occurrences\n")
    print(f"  Quantum Readiness Index  {s['qri']}/100   (CRQC median year {r['risk_config']['crqc_median_year']:.0f})")
    print("  " + "   ".join(f"{b.upper()} {s['bands'][b]}" for b in BAND_ORDER))
    print(f"  harvest-now-decrypt-later exposed {s['hndl']}  |  classically broken/weak {s['classical']}  |  PQC-ready {s['pqc_ready']}\n")
    print("  Top risks")
    for t in s["top"][:10]:
        print(f"    {t['qrs']:>3}  {t['band']:<8}  {t['name']}")
    for e in r.get("errors", []):
        print(f"  note: {e}")


def _write_outputs(r: dict, out: Path, formats: list[str]) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    written = []
    if "json" in formats:
        p = out / "qdrishti-result.json"
        p.write_text(json.dumps(r, indent=1), encoding="utf-8")
        written.append(p)
    if "cbom" in formats:
        p = out / "cbom.cdx.json"
        p.write_text(json.dumps(to_cbom(r), indent=2), encoding="utf-8")
        written.append(p)
    if "sarif" in formats:
        p = out / "qdrishti.sarif"
        p.write_text(json.dumps(to_sarif(r), indent=2), encoding="utf-8")
        written.append(p)
    if "csv" in formats:
        p = out / "inventory.csv"
        p.write_text(to_csv(r), encoding="utf-8")
        written.append(p)
    return written


def cmd_scan(a) -> int:
    hosts = [h for h in (a.hosts or "").split(",") if h.strip()]
    r = run_scan(path=a.target, image=a.image, hosts=hosts, name=a.name,
                 cfg=RiskConfig(crqc_median_year=a.crqc_year), parallel=not a.no_parallel)
    _print_summary(r)
    files = _write_outputs(r, Path(a.out), a.format.split(","))
    print("\n  wrote " + ", ".join(str(f) for f in files))
    return 0


def cmd_gate(a) -> int:
    r = run_scan(path=a.target, cfg=RiskConfig(crqc_median_year=a.crqc_year), parallel=not a.no_parallel)
    baseline = set()
    if a.baseline and Path(a.baseline).exists():
        base = json.loads(Path(a.baseline).read_text(encoding="utf-8"))
        baseline = {o["fingerprint"] for o in base.get("occurrences", [])}
    fail_on = {x.strip() for x in a.fail_on.split(",")}
    assets = {x["id"]: x for x in r["assets"]}
    offending = []
    for o in r["occurrences"]:
        if o["fingerprint"] in baseline or o.get("parent"):
            continue
        risk = assets[o["asset_id"]].get("risk") or {}
        if risk and (risk["band"] in fail_on or ("classical" in fail_on and risk["classical"])):
            offending.append((o, assets[o["asset_id"]]))
    if a.sarif:
        Path(a.sarif).write_text(json.dumps(to_sarif(r), indent=2), encoding="utf-8")
    if not offending:
        print(f"crypto gate: PASS ({len(r['occurrences'])} occurrences checked, none new at {a.fail_on})")
        return 0
    print(f"crypto gate: FAIL  |  {len(offending)} new finding(s) at {a.fail_on}")
    for o, asset in offending[:50]:
        rec = asset["recommendations"][0]["target"] if asset.get("recommendations") else "review"
        print(f"  {o['path']}:{o.get('line') or '-'}  {asset['name']}  [{asset['risk']['band']}]  -> {rec}")
    return 1


def cmd_serve(a) -> int:
    import socket

    import uvicorn
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if s.connect_ex((a.host, a.port)) == 0:
            print(f"Port {a.port} is already in use (maybe Q-Drishti is already running: open http://{a.host}:{a.port}).\n"
                  f"To start another copy, pick a free port: python -m qdrishti serve --port {a.port + 1}")
            return 1
    print(f"Q-Drishti dashboard on http://{a.host}:{a.port}")
    uvicorn.run("qdrishti.api:app", host=a.host, port=a.port, log_level="warning")
    return 0


def cmd_bench(a) -> int:
    from .bench import run
    res = run(a.iterations)
    print(f"Benchmark on {res['machine']} ({res['iterations']} iterations, median)")
    for row in res["classical"] + res["pqc"]:
        print(f"  {row['algorithm']:<12} {row['operation']:<30} {row['median_ms']:>9.4f} ms")
    print(f"  Hybrid TLS overhead with ML-KEM-768: {res['tls_overhead_bytes']} bytes per handshake (FIPS 203 sizes)")
    if res["note"]:
        print("  note: " + res["note"])
    return 0


def cmd_demo(a) -> int:
    a.target, a.image, a.hosts, a.name, a.format = str(DEMO_DIR), None, None, None, "json,cbom,sarif,csv"
    return cmd_scan(a)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="qdrishti", description="Enterprise Cryptographic Discovery & Analysis Tool")
    p.add_argument("--version", action="version", version=f"qdrishti {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--crqc-year", type=float, default=2034.0, help="median year a CRQC is expected (default 2034)")
        sp.add_argument("--no-parallel", action="store_true", help="scan files in one process")

    s = sub.add_parser("scan", help="scan a folder, file, container image and/or TLS hosts")
    s.add_argument("target", nargs="?", help="folder or file to scan")
    s.add_argument("--image", help="local container image, e.g. nginx:1.25")
    s.add_argument("--hosts", help="comma-separated host:port list for live TLS probing")
    s.add_argument("--name")
    s.add_argument("--out", default="qdrishti-out")
    s.add_argument("--format", default="json,cbom,sarif,csv")
    common(s)
    s.set_defaults(fn=cmd_scan)

    g = sub.add_parser("gate", help="CI gate: fail if new risky crypto appears")
    g.add_argument("target")
    g.add_argument("--baseline", help="previous qdrishti-result.json")
    g.add_argument("--fail-on", default="critical,classical")
    g.add_argument("--sarif", help="also write SARIF here")
    common(g)
    g.set_defaults(fn=cmd_gate)

    v = sub.add_parser("serve", help="start the web dashboard")
    v.add_argument("--host", default="127.0.0.1")
    v.add_argument("--port", type=int, default=8765)
    v.set_defaults(fn=cmd_serve)

    b = sub.add_parser("bench", help="benchmark classical vs PQC algorithms on this machine")
    b.add_argument("--iterations", type=int, default=50)
    b.set_defaults(fn=cmd_bench)

    d = sub.add_parser("demo", help="scan the bundled Bharat FinServe demo repository")
    d.add_argument("--out", default="qdrishti-out")
    common(d)
    d.set_defaults(fn=cmd_demo)

    a = p.parse_args(argv)
    if a.cmd == "scan" and not (a.target or a.image or a.hosts):
        p.error("give a folder/file, --image or --hosts")
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
