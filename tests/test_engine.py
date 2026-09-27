from pathlib import Path

from qdrishti import risk as K
from qdrishti.cli import DEMO_DIR, main
from qdrishti.engine import apply_risk, run_scan
from qdrishti.export import to_cbom, to_csv, to_sarif


def test_mosca_probability_is_monotonic():
    lo = K.exposure_probability(2.0, 8.0, 0.45)
    mid = K.exposure_probability(8.0, 8.0, 0.45)
    hi = K.exposure_probability(26.0, 8.0, 0.45)
    assert lo < 0.05 and 0.45 < mid < 0.55 and hi > 0.99


def test_score_bands():
    app = {"criticality": 5, "data_class": "identity", "exposure": "internet"}
    cfg = K.RiskConfig(crqc_median_year=2034, today=2026)
    r = K.score("quantum-vulnerable", "encrypt", "source", "hardcoded", 1, app, cfg)
    assert r["band"] == "critical" and r["hndl"]
    safe = K.score("safe", "encrypt", "source", "hardcoded", 1, app, cfg)
    assert safe["qrs"] == 0
    broken = K.score("broken", "digest", "source", "hardcoded", 1, {"criticality": 1}, cfg)
    assert broken["qrs"] >= 90 and broken["classical"]


def test_demo_scan_end_to_end():
    r = run_scan(path=str(DEMO_DIR), cfg=K.RiskConfig(today=2026), parallel=False)
    names = {a["name"] for a in r["assets"]}
    for expected in ("RSA-2048", "RSA-1024", "RSA-3072", "AES-ECB", "MD5", "SHA-1", "TLS 1.0", "3DES-CBC",
                     "X25519MLKEM768", "DES-CBC3-SHA", "pycrypto 2.6.1", "OpenSSL 1.1.1"):
        assert expected in names, expected
    assert r["summary"]["pqc_ready"] >= 1
    assert r["summary"]["bands"]["critical"] > 0
    assert any(a["kind"] == "certificate" and a["extra"].get("expired") for a in r["assets"])
    # moving the CRQC earlier can only make things worse
    early = apply_risk({**r, "assets": [dict(a) for a in r["assets"]]}, K.RiskConfig(crqc_median_year=2029, today=2026))
    assert early["summary"]["qri"] <= r["summary"]["qri"]


def test_exports_are_well_formed():
    r = run_scan(path=str(DEMO_DIR), parallel=False)
    cbom = to_cbom(r)
    assert cbom["bomFormat"] == "CycloneDX" and cbom["specVersion"] == "1.6"
    refs = {c["bom-ref"] for c in cbom["components"]}
    assert len(refs) == len(cbom["components"])
    for d in cbom["dependencies"]:
        assert d["ref"] in refs and all(x in refs for x in d["dependsOn"])
    types = {c["cryptoProperties"]["assetType"] for c in cbom["components"] if "cryptoProperties" in c}
    assert types == {"algorithm", "protocol", "certificate", "related-crypto-material"}
    sarif = to_sarif(r)
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"]
    assert to_csv(r).startswith("asset,kind,status")


def test_gate_blocks_new_weak_crypto(tmp_path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("import hashlib\nhashlib.sha256(b'x')\n")
    assert main(["scan", str(repo), "--out", str(tmp_path / "base"), "--format", "json", "--no-parallel"]) == 0
    baseline = tmp_path / "base" / "qdrishti-result.json"
    assert main(["gate", str(repo), "--baseline", str(baseline), "--no-parallel"]) == 0
    (repo / "b.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    assert main(["gate", str(repo), "--baseline", str(baseline), "--no-parallel"]) == 1
    assert "b.py:2" in capsys.readouterr().out
