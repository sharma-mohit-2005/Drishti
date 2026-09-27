"""REST API + static dashboard (FastAPI). Binds to localhost by default; everything runs offline."""
from __future__ import annotations

import copy
import json
import os
import shutil
import threading
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import __version__
from .engine import apply_risk, run_scan
from .export import to_cbom, to_csv, to_sarif
from .risk import RiskConfig

ROOT = Path(__file__).resolve().parent.parent
WEB = Path(__file__).resolve().parent / "web"
DEMO = ROOT / "demo" / "bharat-finserve"
DATA = Path(os.environ.get("QDRISHTI_DATA", ROOT / ".qdrishti"))
SCANS = DATA / "scans"
UPLOADS = DATA / "uploads"
SCANS.mkdir(parents=True, exist_ok=True)
UPLOADS.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="Q-Drishti", version=__version__)
_pool = ThreadPoolExecutor(max_workers=2)
_jobs: dict[str, dict] = {}
_lock = threading.Lock()
_cache: dict[str, dict] = {}


class ScanRequest(BaseModel):
    path: str | None = None
    image: str | None = None
    hosts: list[str] | None = None
    name: str | None = None
    crqc_year: float = 2034.0


class SimRequest(BaseModel):
    crqc_year: float = 2034.0
    sigma: float = 0.45


def _load(scan_id: str) -> dict:
    if scan_id in _cache:
        return _cache[scan_id]
    p = SCANS / f"{scan_id}.json"
    if not p.exists() or not scan_id.isalnum():
        raise HTTPException(404, "Scan not found")
    r = json.loads(p.read_text(encoding="utf-8"))
    _cache[scan_id] = r
    return r


def _start(req: ScanRequest, cleanup: Path | None = None) -> str:
    job_id = uuid.uuid4().hex[:10]
    _jobs[job_id] = {"id": job_id, "status": "running", "progress": 0.0, "message": "Queued", "scan_id": None, "error": None}

    def progress(stage, pct, msg):
        with _lock:
            _jobs[job_id].update(progress=round(pct, 3), message=msg)

    def work():
        try:
            r = run_scan(path=req.path, image=req.image, hosts=req.hosts, name=req.name,
                         cfg=RiskConfig(crqc_median_year=req.crqc_year), progress=progress)
            (SCANS / f"{r['id']}.json").write_text(json.dumps(r), encoding="utf-8")
            _cache[r["id"]] = r
            with _lock:
                _jobs[job_id].update(status="done", progress=1.0, message="Scan complete", scan_id=r["id"])
        except Exception as e:
            with _lock:
                _jobs[job_id].update(status="error", error=str(e), message="Scan failed")
        finally:
            if cleanup:
                shutil.rmtree(cleanup, ignore_errors=True)

    _pool.submit(work)
    return job_id


@app.get("/api/health")
def health():
    return {"ok": True, "version": __version__}


@app.post("/api/scans")
def create_scan(req: ScanRequest):
    if not (req.path or req.image or req.hosts):
        raise HTTPException(400, "Give a folder path, a container image, or TLS hosts to scan.")
    if req.path and not Path(req.path).exists():
        raise HTTPException(400, f"Folder not found: {req.path}")
    return {"job_id": _start(req)}


@app.post("/api/scans/demo")
def demo_scan():
    return {"job_id": _start(ScanRequest(path=str(DEMO), name="Bharat FinServe (demo)"))}


@app.post("/api/scans/upload")
async def upload_scan(file: UploadFile = File(...)):
    if not (file.filename or "").lower().endswith(".zip"):
        raise HTTPException(400, "Upload a .zip of the repository.")
    dest = UPLOADS / uuid.uuid4().hex[:10]
    dest.mkdir(parents=True)
    zpath = dest / "upload.zip"
    with open(zpath, "wb") as fh:
        shutil.copyfileobj(file.file, fh)
    root = dest / "src"
    try:
        with zipfile.ZipFile(zpath) as z:
            for m in z.infolist():
                target = (root / m.filename).resolve()
                if not str(target).startswith(str(root.resolve())):
                    raise HTTPException(400, "Zip contains unsafe paths.")
            z.extractall(root)
    except zipfile.BadZipFile:
        shutil.rmtree(dest, ignore_errors=True)
        raise HTTPException(400, "Not a valid zip file.")
    zpath.unlink()
    return {"job_id": _start(ScanRequest(path=str(root), name=Path(file.filename).stem), cleanup=dest)}


@app.get("/api/jobs/{job_id}")
def job(job_id: str):
    if job_id not in _jobs:
        raise HTTPException(404, "Job not found")
    return _jobs[job_id]


@app.get("/api/scans")
def list_scans():
    items = []
    for p in sorted(SCANS.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            r = _load(p.stem)
        except Exception:
            continue
        items.append({"id": r["id"], "name": r["name"], "created": r["created"], "qri": r["summary"]["qri"],
                      "assets": r["stats"]["assets"], "bands": r["summary"]["bands"]})
    return items


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    return _load(scan_id)


@app.post("/api/scans/{scan_id}/simulate")
def simulate(scan_id: str, req: SimRequest):
    r = copy.deepcopy(_load(scan_id))
    apply_risk(r, RiskConfig(crqc_median_year=req.crqc_year, sigma=req.sigma))
    return {"summary": r["summary"], "risk_config": r["risk_config"], "risks": {a["id"]: a["risk"] for a in r["assets"]}}


@app.get("/api/scans/{scan_id}/export/{fmt}")
def export(scan_id: str, fmt: str):
    r = _load(scan_id)
    safe = "".join(c if c.isalnum() else "-" for c in r["name"]).strip("-").lower() or "scan"
    if fmt == "cbom":
        body, mt, fn = json.dumps(to_cbom(r), indent=2), "application/vnd.cyclonedx+json", f"{safe}.cdx.json"
    elif fmt == "sarif":
        body, mt, fn = json.dumps(to_sarif(r), indent=2), "application/sarif+json", f"{safe}.sarif"
    elif fmt == "csv":
        body, mt, fn = to_csv(r), "text/csv", f"{safe}-inventory.csv"
    elif fmt == "json":
        body, mt, fn = json.dumps(r, indent=1), "application/json", f"{safe}-qdrishti.json"
    else:
        raise HTTPException(400, "Format must be cbom, sarif, csv or json.")
    return Response(body, media_type=mt, headers={"Content-Disposition": f'attachment; filename="{fn}"'})


@app.get("/api/scans/{a}/diff/{b}")
def diff(a: str, b: str):
    ra, rb = _load(a), _load(b)
    ia = {x["id"]: x for x in ra["assets"]}
    ib = {x["id"]: x for x in rb["assets"]}
    risky = lambda x: (x.get("risk") or {}).get("band") in ("critical", "high")
    return {"qri_before": ra["summary"]["qri"], "qri_after": rb["summary"]["qri"],
            "added": [ib[k]["name"] for k in ib.keys() - ia.keys()],
            "removed": [ia[k]["name"] for k in ia.keys() - ib.keys()],
            "fixed_risky": [ia[k]["name"] for k in ia.keys() - ib.keys() if risky(ia[k])],
            "bands_before": ra["summary"]["bands"], "bands_after": rb["summary"]["bands"]}


@app.get("/api/bench")
def bench(iterations: int = 30):
    from .bench import run
    return JSONResponse(run(max(5, min(iterations, 500))))


app.mount("/", StaticFiles(directory=WEB, html=True), name="web")
