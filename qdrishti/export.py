"""Exports: CycloneDX 1.6 CBOM, SARIF 2.1.0, CSV."""
from __future__ import annotations

import csv
import io
import uuid

from . import registry as R

_FUNCS = {"keygen": "keygen", "encrypt": "encrypt", "decrypt": "decrypt", "sign": "sign", "verify": "verify",
          "key-agree": "keyderive", "digest": "digest", "tag": "tag", "keyderive": "keyderive"}
_MODES = {"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr"}
_PADDING = {"pkcs5": "pkcs5", "pkcs1v15": "pkcs1v15", "oaep": "oaep", "raw": "raw"}


def _props(a: dict) -> list[dict]:
    r = a.get("risk") or {}
    props = [{"name": "qdrishti:status", "value": a["status"]}]
    if r:
        props += [{"name": "qdrishti:qrs", "value": str(r["qrs"])}, {"name": "qdrishti:band", "value": r["band"]},
                  {"name": "qdrishti:hndl", "value": str(r["hndl"]).lower()},
                  {"name": "qdrishti:p_exposure", "value": str(r["p_exposure"])}]
    if a.get("recommendations"):
        props.append({"name": "qdrishti:recommendation", "value": a["recommendations"][0]["target"]})
    return props


def _evidence(a: dict, occ_by_id: dict) -> dict:
    occs = []
    for oid in a["occurrences"][:50]:
        o = occ_by_id[oid]
        e = {"location": o["path"]}
        if o.get("line"):
            e["line"] = o["line"]
        if o.get("snippet"):
            e["additionalContext"] = o["snippet"][:200]
        occs.append(e)
    return {"occurrences": occs}


def to_cbom(result: dict) -> dict:
    occ_by_id = {o["id"]: o for o in result["occurrences"]}
    comps = []
    for a in result["assets"]:
        ref = a["id"]
        base = {"bom-ref": ref, "name": a["name"], "evidence": _evidence(a, occ_by_id), "properties": _props(a)}
        if a["kind"] == "library":
            p = a["params"]
            comp = {"type": "library", **base, "name": p.get("name"), "version": p.get("version") or None}
            eco = {"pypi": "pypi", "npm": "npm", "maven": "maven", "go": "golang"}.get(p.get("ecosystem", ""))
            if eco and p.get("version"):
                comp["purl"] = f"pkg:{eco}/{p['name']}@{p['version']}"
            comps.append({k: v for k, v in comp.items() if v is not None})
            continue
        comp = {"type": "cryptographic-asset", **base}
        if a["kind"] in ("algorithm",):
            p = a["params"]
            ap = {"primitive": a.get("primitive") or "unknown", "executionEnvironment": "software-plain-ram",
                  "implementationPlatform": "unknown",
                  "cryptoFunctions": sorted({_FUNCS[u] for u in a["usages"] if u in _FUNCS}) or ["unknown"]}
            if p.get("size"):
                ap["parameterSetIdentifier"] = str(p["size"])
            if p.get("curve"):
                ap["curve"] = p["curve"]
            if p.get("mode") in _MODES:
                ap["mode"] = p["mode"]
            if p.get("padding") in _PADDING:
                ap["padding"] = _PADDING[p["padding"]]
            if a.get("classical_bits") is not None:
                ap["classicalSecurityLevel"] = a["classical_bits"]
            if a.get("nist_level") is not None:
                ap["nistQuantumSecurityLevel"] = a["nist_level"]
            comp["cryptoProperties"] = {"assetType": "algorithm", "algorithmProperties": ap}
            if a.get("oid"):
                comp["cryptoProperties"]["oid"] = a["oid"]
        elif a["kind"] == "protocol":
            v = a["params"].get("version", "")
            comp["cryptoProperties"] = {"assetType": "protocol",
                                        "protocolProperties": {"type": "tls", "version": v.replace("SSL ", "")}}
        elif a["kind"] == "suite":
            comp["cryptoProperties"] = {"assetType": "protocol", "protocolProperties": {
                "type": "tls", "cipherSuites": [{"name": a["name"], "algorithms": list(a["links"])}]}}
        elif a["kind"] == "certificate":
            ex = a.get("extra", {})
            key_ref = next((l for l in a["links"] if not any(h in l for h in ("sha", "md5"))), None)
            sig_ref = next((l for l in a["links"] if any(h in l for h in ("sha", "md5"))), None)
            cp = {"subjectName": ex.get("subject"), "issuerName": ex.get("issuer"),
                  "notValidBefore": ex.get("not_before"), "notValidAfter": ex.get("not_after"),
                  "certificateFormat": "X.509", "certificateExtension": "pem"}
            if sig_ref:
                cp["signatureAlgorithmRef"] = sig_ref
            if key_ref:
                cp["subjectPublicKeyRef"] = key_ref
            comp["cryptoProperties"] = {"assetType": "certificate", "certificateProperties": {k: v for k, v in cp.items() if v}}
        elif a["kind"] == "key":
            material = a.get("extra", {}).get("material", "key")
            rp = {"type": material if material in ("private-key", "public-key") else "key"}
            if a["params"].get("size"):
                rp["size"] = a["params"]["size"]
            if a.get("canonical") and a["canonical"] != "UNKNOWN":
                rp["algorithmRef"] = R.asset_id(a["canonical"], a["params"])
            comp["cryptoProperties"] = {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": rp}
        comps.append(comp)

    deps = [{"ref": a["id"], "dependsOn": list(a["links"])} for a in result["assets"] if a["links"]]
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": result["created"],
            "tools": {"components": [{"type": "application", "name": "Q-Drishti", "version": result["tool"]["version"]}]},
            "component": {"type": "application", "name": result["name"], "bom-ref": "root"},
            "properties": [{"name": "qdrishti:qri", "value": str(result["summary"]["qri"])},
                           {"name": "qdrishti:crqc_median_year", "value": str(result["risk_config"]["crqc_median_year"])}],
        },
        "components": comps,
        "dependencies": deps,
    }


_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def to_sarif(result: dict) -> dict:
    assets = {a["id"]: a for a in result["assets"]}
    rules, results = {}, []
    for o in result["occurrences"]:
        a = assets[o["asset_id"]]
        r = a.get("risk") or {}
        if o.get("parent") or not r or r["band"] == "low" or o["surface"] in ("endpoint",):
            continue
        rid = o["rule_id"] or "qdrishti"
        rules.setdefault(rid, {"id": rid, "name": rid, "shortDescription": {"text": f"Cryptographic asset ({rid})"}})
        rec = a["recommendations"][0]["target"] if a.get("recommendations") else "review"
        loc = {"physicalLocation": {"artifactLocation": {"uri": o["path"].split("!/")[0]}}}
        if o.get("line"):
            loc["physicalLocation"]["region"] = {"startLine": o["line"]}
        results.append({"ruleId": rid, "level": _LEVEL[r["band"]],
                        "message": {"text": f"{a['name']} ({a['status']}, QRS {r['qrs']}). Recommended: {rec}."},
                        "locations": [loc], "partialFingerprints": {"qdrishti/v1": o["fingerprint"]}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Q-Drishti", "version": result["tool"]["version"],
                                          "rules": list(rules.values())}}, "results": results}]}


def to_csv(result: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["asset", "kind", "status", "band", "qrs", "p_exposure", "hndl", "apps", "occurrences",
                "first_location", "recommendation"])
    occ_by_id = {o["id"]: o for o in result["occurrences"]}
    for a in sorted(result["assets"], key=lambda a: -(a.get("risk") or {}).get("qrs", 0)):
        r = a.get("risk") or {}
        first = occ_by_id[a["occurrences"][0]] if a["occurrences"] else None
        loc = f"{first['path']}:{first['line']}" if first and first.get("line") else (first["path"] if first else "")
        w.writerow([a["name"], a["kind"], a["status"], r.get("band", ""), r.get("qrs", ""), r.get("p_exposure", ""),
                    r.get("hndl", ""), ";".join(a["apps"]), len(a["occurrences"]), loc,
                    a["recommendations"][0]["target"] if a.get("recommendations") else ""])
    return buf.getvalue()
