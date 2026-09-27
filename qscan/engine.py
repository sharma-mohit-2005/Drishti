"""Scan orchestration: walk -> scan -> normalise -> score -> recommend -> summarise."""
from __future__ import annotations

import hashlib
import os
import re
import time
import uuid
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import yaml

from . import __version__
from . import registry as R
from . import reco
from . import risk as K
from .models import RawFinding
from .scanners import binary, certs, configs, deps
from .scanners.source import LANG, SOURCE_EXTS, scan_source

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", "env", ".tox", ".idea",
             ".vscode", ".mypy_cache", ".pytest_cache", ".gradle", ".next", ".cache", "qscan-out", ".qscan"}
MAX_TEXT = 5 * 1024 * 1024
MAX_BIN = 64 * 1024 * 1024
PARALLEL_THRESHOLD = 400

Progress = Callable[[str, float, str], None]


# ---- per-file scanning (module level so it can run in worker processes) -------
def scan_file(path: str, rel: str) -> tuple[list[dict], int, bool]:
    """Returns (findings as dicts, lines of source code, is_source_file)."""
    p = Path(path)
    try:
        size = p.stat().st_size
    except OSError:
        return [], 0, False
    if size == 0 or size > MAX_BIN:
        return [], 0, False
    name, ext = p.name, p.suffix.lower()
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096)
            if binary.is_binary(name, head):
                data = head + fh.read()
                return [f.to_dict() for f in binary.scan_binary(data, rel)], 0, False
            if size > MAX_TEXT or b"\x00" in head:
                return [], 0, False
            data = head + fh.read()
    except OSError:
        return [], 0, False
    text = data.decode("utf-8", errors="replace")
    out: list[RawFinding] = []
    is_src = ext in SOURCE_EXTS
    if is_src:
        out += scan_source(text, rel, ext)
    ck = configs.is_config(name, text[:20000])
    if ck:
        out += configs.scan_config(text, rel, ck)
    if deps.is_dep_file(name):
        out += deps.scan_deps(text, rel, name)
    if certs.looks_like_cert_file(name, head):
        out += certs.scan_cert_file(data, rel)
    return [f.to_dict() for f in out], (text.count("\n") + 1) if is_src else 0, is_src


def _scan_file_star(args):
    return scan_file(*args)


def walk(root: Path) -> list[tuple[str, str]]:
    if root.is_file():
        return [(str(root), root.name)]
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info")]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            files.append((full, os.path.relpath(full, root).replace("\\", "/")))
    return files


# ---- application context -----------------------------------------------------
_KEYWORDS = [
    (("payment", "pay", "bank", "card", "upi", "wallet", "ledger", "finance"), "financial", 5),
    (("kyc", "aadhaar", "identity", "auth", "login", "passport", "pan"), "identity", 5),
    (("health", "patient", "medical"), "health", 5),
    (("secret", "classified", "defence", "defense"), "secret", 5),
    (("report", "analytics", "legacy"), "confidential", 3),
]


def guess_app(name: str) -> dict:
    low = name.lower()
    data_class, crit = "internal", 3
    for words, dc, c in _KEYWORDS:
        if any(w in low for w in words):
            data_class, crit = dc, c
            break
    exposure = "internet" if any(w in low for w in ("gateway", "edge", "web", "api", "nginx", "frontend", "portal")) else "internal"
    return {"name": name, "path": name, "criticality": crit, "data_class": data_class, "exposure": exposure, "source": "auto"}


class AppMap:
    def __init__(self, root: Path | None, default: dict | None = None):
        self.apps: list[dict] = []
        self.project = None
        self.default = {"criticality": 3, "data_class": "internal", "exposure": "internal", **(default or {})}
        cfg_file = None
        if root and root.is_dir():
            for n in ("qscan.yml", "qscan.yaml", ".qscan.yml", "qdrishti.yml", "qdrishti.yaml", ".qdrishti.yml"):  # qdrishti.* = pre-rename name
                if (root / n).exists():
                    cfg_file = root / n
                    break
        if cfg_file:
            data = yaml.safe_load(cfg_file.read_text(encoding="utf-8")) or {}
            self.project = data.get("project")
            self.default.update(data.get("default_app") or {})
            for a in data.get("apps") or []:
                self.apps.append({"criticality": 3, "data_class": "internal", "exposure": "internal", **a,
                                  "path": str(a.get("path", a["name"])).strip("/"), "source": cfg_file.name})
        self._auto: dict[str, dict] = {}

    def for_path(self, rel: str) -> dict:
        best = None
        for a in self.apps:
            if rel == a["path"] or rel.startswith(a["path"] + "/"):
                if best is None or len(a["path"]) > len(best["path"]):
                    best = a
        if best:
            return best
        top = rel.split("/")[0] if "/" in rel else "(root)"
        if top not in self._auto:
            self._auto[top] = guess_app(top) if top != "(root)" else {"name": "(root)", "path": "", **self.default, "source": "default"}
        return self._auto[top]

    def all(self) -> list[dict]:
        return self.apps + list(self._auto.values())


# ---- normalisation -----------------------------------------------------------
SURFACE_OF = {"source": "source", "config": "config", "certificate": "certificate", "dependency": "dependency",
              "binary": "binary", "endpoint": "endpoint"}


class Builder:
    def __init__(self):
        self.assets: dict[str, dict] = {}
        self.occ: list[dict] = []

    def _asset(self, aid: str, **fields) -> dict:
        a = self.assets.get(aid)
        if a is None:
            a = {"id": aid, "occurrences": [], "links": [], "usages": [], "apps": [], "surfaces": [], **fields}
            self.assets[aid] = a
        return a

    def _alg_asset(self, canonical: str, params: dict) -> dict:
        aid = R.asset_id(canonical, params)
        if aid in self.assets:
            return self.assets[aid]
        ass = R.assess(canonical, params)
        spec = R.ALGORITHMS.get(canonical, {})
        return self._asset(aid, name=R.display_name(canonical, params), kind="protocol" if canonical == "TLS" else "algorithm",
                           canonical=canonical, params=params, primitive=spec.get("primitive", "unknown"),
                           oid=R.oid_for(canonical, params), status=ass["status"], attack=ass["attack"],
                           classical_bits=ass["classical_bits"], nist_level=ass["nist_level"], note=ass["note"], extra={})

    def _link(self, parent: dict, child: dict):
        if child["id"] not in parent["links"]:
            parent["links"].append(child["id"])

    def _add_occ(self, asset: dict, f: RawFinding, surface: str, usage: str, app: dict, parent: str | None = None):
        oid = f"o{len(self.occ) + 1}"
        fp = hashlib.sha1(f"{asset['id']}|{f.path}|{f.rule_id}|{f.snippet.strip()}".encode()).hexdigest()[:16]
        self.occ.append({"id": oid, "asset_id": asset["id"], "surface": surface, "path": f.path, "line": f.line,
                         "snippet": f.snippet, "usage": usage, "agility": f.agility, "confidence": f.confidence,
                         "rule_id": f.rule_id, "app": app["name"], "language": f.extra.get("language"),
                         "parent": parent, "fingerprint": fp})
        asset["occurrences"].append(oid)
        for key, val in (("usages", usage), ("apps", app["name"]), ("surfaces", surface)):
            if val not in asset[key]:
                asset[key].append(val)

    def add(self, f: RawFinding, app: dict, surface_override: str | None = None):
        surface = surface_override or SURFACE_OF.get(f.scanner, f.scanner)
        if f.kind == "key" and surface == "certificate":
            surface = "key"
        if f.kind in ("algorithm", "protocol"):
            if not f.canonical or f.canonical == "UNKNOWN":
                return
            a = self._alg_asset(f.canonical, f.params)
            self._add_occ(a, f, surface, f.usage, app)
            for c, p, u in f.components:
                ca = self._alg_asset(c, p)
                self._add_occ(ca, f, surface, u, app, parent=a["id"])
                self._link(a, ca)
        elif f.kind == "suite":
            name = f.params.get("suite", f.identifier)
            children = [self._alg_asset(c, p) for c, p, _ in f.components]
            status = R.worst([ch["status"] for ch in children])
            a = self._asset("suite:" + name.upper(), name=name, kind="suite", canonical=None, params={"suite": name},
                            primitive="other", oid=None, status=status, attack="n/a", classical_bits=None,
                            nist_level=None, note="Cipher suite; risk comes from its weakest component.",
                            extra={"components": [ch["name"] for ch in children]},
                            components=[list(x) for x in f.components])
            self._add_occ(a, f, surface, "protocol", app)
            for ch, (c, p, u) in zip(children, f.components):
                self._add_occ(ch, f, surface, u, app, parent=a["id"])
                self._link(a, ch)
        elif f.kind == "certificate":
            fp = f.extra.get("fingerprint", hashlib.sha1(f.snippet.encode()).hexdigest())
            children = [self._alg_asset(c, p) for c, p, _ in f.components]
            key_status = R.assess(f.canonical, f.params)["status"] if f.canonical else R.UNKNOWN
            status = R.worst([key_status] + [ch["status"] for ch in children])
            cn = re.search(r"CN=([^,]+)", f.extra.get("subject", ""))
            label = cn.group(1) if cn else f.extra.get("subject", "certificate")
            a = self._asset("cert:" + fp[:16], name=f"{label} ({R.display_name(f.canonical, f.params)})", kind="certificate",
                            canonical=f.canonical, params=f.params, primitive="signature", oid=None, status=status,
                            attack="shor", classical_bits=None, nist_level=0,
                            note="X.509 certificate; its key and signature are quantum-vulnerable." if status in (R.QV,) else
                            "X.509 certificate with a classically weak component.", extra=dict(f.extra))
            self._add_occ(a, f, surface, "sign", app)
            for ch, (c, p, u) in zip(children, f.components):
                self._add_occ(ch, f, surface, u, app, parent=a["id"])
                self._link(a, ch)
        elif f.kind == "key":
            material = f.extra.get("material", "key")
            fp = f.extra.get("fingerprint") or hashlib.sha1(f"{f.path}:{f.line}:{f.identifier}".encode()).hexdigest()
            if f.canonical and f.canonical != "UNKNOWN":
                ass = R.assess(f.canonical, f.params)
                disp = R.display_name(f.canonical, f.params)
            else:
                ass, disp = {"status": R.UNKNOWN, "note": "Encrypted key; algorithm not visible without the password."}, "encrypted"
            a = self._asset("key:" + fp[:16], name=f"{material} {disp} @ {Path(f.path).name}", kind="key",
                            canonical=f.canonical, params=f.params, primitive="other", oid=R.oid_for(f.canonical or "", f.params),
                            status=ass["status"], attack=R.ALGORITHMS.get(f.canonical or "", {}).get("attack", "unknown"),
                            classical_bits=ass.get("classical_bits"), nist_level=ass.get("nist_level"),
                            note=ass.get("note", ""), extra=dict(f.extra))
            self._add_occ(a, f, surface, "storage" if material == "private-key" else "sign", app)
            for c, p, u in f.components:
                ca = self._alg_asset(c, p)
                self._add_occ(ca, f, surface, u, app, parent=a["id"])
                self._link(a, ca)
        elif f.kind == "library":
            name, ver, eco = f.params.get("name"), f.params.get("version", ""), f.params.get("ecosystem", "")
            st = f.extra.get("status", "info")
            a = self._asset(f"lib:{eco}:{name}@{ver}".lower(), name=f"{name} {ver}".strip(), kind="library", canonical=None,
                            params=dict(f.params), primitive="other", oid=None, status={"weak": R.WEAK, "qv": R.QV}.get(st, "info"),
                            attack="n/a", classical_bits=None, nist_level=None, note=f.extra.get("note", ""),
                            extra={"pqc": f.extra.get("pqc", "unknown"), "ecosystem": eco})
            self._add_occ(a, f, surface, "library", app)


# ---- risk + summary ------------------------------------------------------------
_AGILITY_RANK = {"hardcoded": 3, "constant": 2, "n/a": 1, "config": 0}


def build_risk_inputs(assets: dict, occ_by_id: dict, apps_by_name: dict):
    for a in assets.values():
        groups: dict[str, list[dict]] = defaultdict(list)
        for oid in a["occurrences"]:
            o = occ_by_id[oid]
            groups[o["app"]].append(o)
        inputs = []
        extra = a.get("extra", {})
        is_ca = bool(extra.get("is_ca"))
        for app_name, occs in groups.items():
            usages = [o["usage"] for o in occs]
            usage = max(usages, key=lambda u: K.h_factor(u, False))
            surface = Counter(o["surface"] for o in occs).most_common(1)[0][0]
            agility = max((o["agility"] for o in occs), key=lambda g: _AGILITY_RANK.get(g, 1))
            snippets = " ".join(o["snippet"].lower() for o in occs)
            long_lived = is_ca or any(k in snippets for k in ("firmware", "codesign", "code_sign", "release"))
            status = a["status"] if a["status"] != "info" else R.SAFE
            inputs.append({"app": app_name, "status": status, "usage": usage, "surface": surface, "agility": agility,
                           "n": len(occs), "long_lived": long_lived, "is_ca": is_ca})
        a["risk_inputs"] = inputs


def apply_risk(result: dict, cfg: K.RiskConfig) -> dict:
    apps_by_name = {a["name"]: a for a in result["apps"]}
    for a in result["assets"]:
        per_app = []
        for inp in a.get("risk_inputs", []):
            app = apps_by_name.get(inp["app"], {"criticality": 3, "data_class": "internal", "exposure": "internal"})
            r = K.score(inp["status"], inp["usage"], inp["surface"], inp["agility"], inp["n"], app, cfg,
                        long_lived=inp["long_lived"], is_ca=inp["is_ca"])
            r["app"] = inp["app"]
            per_app.append(r)
        if per_app:
            best = max(per_app, key=lambda r: (r["qrs"], r["factors"]["C"]))
            a["risk"] = {**best, "per_app": [{"app": r["app"], "qrs": r["qrs"], "band": r["band"]} for r in per_app]}
        else:
            a["risk"] = None
    result["risk_config"] = {"crqc_median_year": cfg.crqc_median_year, "sigma": cfg.sigma, "today": cfg.today}
    result["summary"] = summarise(result)
    return result


def summarise(result: dict) -> dict:
    assets = result["assets"]
    bands = Counter(a["risk"]["band"] for a in assets if a.get("risk"))
    heat = [[0] * 5 for _ in range(5)]   # rows: criticality 5..1, cols: heat_column
    for a in assets:
        r = a.get("risk")
        if not r or a["kind"] == "library":
            continue
        heat[5 - r["factors"]["C"]][K.heat_column(r)] += 1
    waves = []
    for i, band in enumerate(("critical", "high", "medium"), 1):
        items = [a for a in assets if a.get("risk") and a["risk"]["band"] == band]
        waves.append({"wave": i, "band": band, "assets": len(items),
                      "migration_years_total": round(sum(a["risk"]["y_years"] for a in items), 2),
                      "top": [a["name"] for a in sorted(items, key=lambda a: -a["risk"]["qrs"])[:5]]})
    top = sorted((a for a in assets if a.get("risk")), key=lambda a: (-a["risk"]["qrs"], a["name"]))[:10]
    return {
        "qri": K.qri(assets),
        "bands": {b: bands.get(b, 0) for b in ("critical", "high", "medium", "low")},
        "by_kind": dict(Counter(a["kind"] for a in assets)),
        "by_status": dict(Counter(a["status"] for a in assets)),
        "by_surface": dict(Counter(o["surface"] for o in result["occurrences"])),
        "hndl": sum(1 for a in assets if a.get("risk") and a["risk"]["hndl"]),
        "classical": sum(1 for a in assets if a.get("risk") and a["risk"]["classical"]),
        "quantum_vulnerable": sum(1 for a in assets if a["status"] == R.QV),
        "pqc_ready": sum(1 for a in assets if a["status"] == R.PQC),
        "heatmap": heat, "waves": waves,
        "top": [{"id": a["id"], "name": a["name"], "qrs": a["risk"]["qrs"], "band": a["risk"]["band"]} for a in top],
    }


# ---- main entry --------------------------------------------------------------
def run_scan(path: str | None = None, image: str | None = None, hosts: list[str] | None = None,
             name: str | None = None, cfg: K.RiskConfig | None = None, progress: Progress | None = None,
             parallel: bool = True) -> dict:
    cfg = cfg or K.RiskConfig()
    progress = progress or (lambda *_: None)
    t0 = time.perf_counter()
    errors: list[str] = []
    raw: list[tuple[dict, str | None]] = []   # (finding, surface override)
    files_scanned = src_files = loc = 0
    root = Path(path).resolve() if path else None
    appmap = AppMap(root)
    targets = []
    workdir = None

    def scan_tree(tree_root: Path, prefix: str, surface: str | None):
        nonlocal files_scanned, src_files, loc
        files = walk(tree_root)
        progress("scan", 0.05, f"Scanning {len(files)} files")
        jobs = [(full, prefix + rel) for full, rel in files]
        results = None
        if parallel and len(jobs) >= PARALLEL_THRESHOLD:
            try:
                workers = min(8, (os.cpu_count() or 2))
                with ProcessPoolExecutor(max_workers=workers) as ex:
                    results = list(ex.map(_scan_file_star, jobs, chunksize=64))
            except Exception as e:   # fall back to sequential on any pool problem
                errors.append(f"parallel scan unavailable ({e.__class__.__name__}); ran sequentially")
                results = None
        if results is None:
            results = []
            for i, j in enumerate(jobs):
                results.append(scan_file(*j))
                if i % 200 == 0:
                    progress("scan", 0.05 + 0.6 * i / max(1, len(jobs)), f"Scanned {i}/{len(jobs)} files")
        for fds, n_loc, is_src in results:
            files_scanned += 1
            src_files += int(is_src)
            loc += n_loc
            raw.extend((fd, surface) for fd in fds)

    if root:
        if not root.exists():
            raise FileNotFoundError(f"Path not found: {path}")
        targets.append({"type": "path", "value": str(root)})
        scan_tree(root, "", None)
    if image:
        from .scanners import container
        targets.append({"type": "image", "value": image})
        progress("image", 0.1, f"Exporting image {image}")
        workdir = container.temp_workdir()
        try:
            rootfs = container.export_image(image, workdir)
            scan_tree(rootfs, f"{image}:/", "container")
        except container.ContainerError as e:
            errors.append(str(e))
        finally:
            import shutil
            shutil.rmtree(workdir, ignore_errors=True)
    if hosts:
        from .scanners import network
        for h in hosts:
            h = h.strip()
            if not h:
                continue
            targets.append({"type": "endpoint", "value": h})
            progress("network", 0.7, f"Probing {h}")
            try:
                raw.extend((f.to_dict(), None) for f in network.scan_endpoint(h))
            except Exception as e:
                errors.append(f"{h}: {e}")

    progress("analyse", 0.8, "Normalising findings")
    b = Builder()
    for fd, surface in raw:
        f = RawFinding.from_dict(fd)
        if f.scanner == "endpoint":
            host = f.path.split(":")[0]
            app = next((a for a in appmap.apps if host in (a.get("hosts") or [])), None)
            if app is None:
                app = appmap._auto.setdefault(f"endpoint {host}", {"name": f"endpoint {host}", "path": "", "criticality": 4,
                                                                   "data_class": "confidential", "exposure": "internet", "source": "auto"})
        elif surface == "container":
            app = appmap._auto.setdefault(f"image {image}", {**guess_app(image or "image"), "name": f"image {image}"})
        else:
            app = appmap.for_path(f.path)
        b.add(f, app, surface)

    occ_by_id = {o["id"]: o for o in b.occ}
    apps = [a for a in appmap.all() if any(o["app"] == a["name"] for o in b.occ)]
    build_risk_inputs(b.assets, occ_by_id, {a["name"]: a for a in apps})

    for a in b.assets.values():
        occs = [occ_by_id[o] for o in a["occurrences"]]
        app_objs = [x for x in apps if x["name"] in a["apps"]]
        langs = {o["language"] for o in occs if o.get("language")}
        a["recommendations"] = reco.recommend(a, app_objs, set(a["surfaces"]), langs, [f'{o["snippet"]} {o["path"]}' for o in occs])

    result = {
        "id": uuid.uuid4().hex[:12],
        "name": name or appmap.project or (root.name if root else image or (f"TLS {hosts[0]}" if hosts else "scan")),
        "tool": {"name": "Q-Scan", "version": __version__},
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "targets": targets, "apps": apps,
        "assets": sorted(b.assets.values(), key=lambda a: a["id"]), "occurrences": b.occ,
        "stats": {"files_scanned": files_scanned, "source_files": src_files, "loc": loc,
                  "raw_findings": len(raw), "assets": len(b.assets), "occurrences": len(b.occ)},
        "errors": errors,
    }
    progress("risk", 0.9, "Scoring quantum risk")
    apply_risk(result, cfg)
    result["stats"]["duration_s"] = round(time.perf_counter() - t0, 3)
    progress("done", 1.0, "Scan complete")
    return result
