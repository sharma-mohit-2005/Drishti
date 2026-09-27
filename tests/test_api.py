import io
import time
import zipfile

import pytest


def _client(tmp_path, monkeypatch, public):
    monkeypatch.setenv("QSCAN_DATA", str(tmp_path / "data"))
    for v in ("RENDER", "SPACE_ID", "RAILWAY_ENVIRONMENT"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("QSCAN_PUBLIC", "1" if public else "0")
    import importlib

    import qscan.api as api
    importlib.reload(api)
    from fastapi.testclient import TestClient
    return TestClient(api.app)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    return _client(tmp_path, monkeypatch, public=False)


@pytest.fixture()
def public_client(tmp_path, monkeypatch):
    return _client(tmp_path, monkeypatch, public=True)


def wait(client, job_id):
    for _ in range(200):
        j = client.get(f"/api/jobs/{job_id}").json()
        if j["status"] != "running":
            return j
        time.sleep(0.05)
    raise AssertionError("scan did not finish")


def test_upload_scan_simulate_export(client):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("svc/app.py", "import hashlib\nhashlib.md5(b'x')\nrsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    r = client.post("/api/scans/upload", files={"file": ("repo.zip", buf.getvalue(), "application/zip")})
    assert r.status_code == 200
    job = wait(client, r.json()["job_id"])
    assert job["status"] == "done", job
    sid = job["scan_id"]
    scan = client.get(f"/api/scans/{sid}").json()
    assert {"MD5", "RSA-2048"} <= {a["name"] for a in scan["assets"]}
    sim = client.post(f"/api/scans/{sid}/simulate", json={"crqc_year": 2029}).json()
    assert sim["summary"]["qri"] <= scan["summary"]["qri"]
    cbom = client.get(f"/api/scans/{sid}/export/cbom")
    assert cbom.status_code == 200 and cbom.json()["specVersion"] == "1.6"
    assert client.get(f"/api/scans/{sid}/export/nope").status_code == 400
    assert any(s["id"] == sid for s in client.get("/api/scans").json())


def test_rejects_unsafe_zip_and_bad_path(client):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../evil.py", "x = 1\n")
    r = client.post("/api/scans/upload", files={"file": ("evil.zip", buf.getvalue(), "application/zip")})
    assert r.status_code == 400
    assert client.post("/api/scans", json={"path": "Z:/does/not/exist"}).status_code == 400
    assert client.get("/api/scans/doesnotexist").status_code == 404


def _zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, body in files.items():
            z.writestr(name, body)
    return buf.getvalue()


def test_public_mode_blocks_paths_images_and_hosts(public_client, tmp_path):
    h = public_client.get("/api/health").json()
    assert h["public"] is True and h["sources"] == ["demo", "upload"]
    for body in ({"path": str(tmp_path)}, {"image": "nginx:1.25"}, {"hosts": ["127.0.0.1:443"]}):
        assert public_client.post("/api/scans", json=body).status_code == 403


def test_public_mode_hides_uploads_from_the_list(public_client):
    r = public_client.post("/api/scans/upload", files={"file": ("mine.zip", _zip({"a.py": "import hashlib\nhashlib.md5(b'x')\n"}), "application/zip")})
    job = wait(public_client, r.json()["job_id"])
    assert job["status"] == "done", job
    assert public_client.get(f"/api/scans/{job['scan_id']}").status_code == 200
    assert all(s["id"] != job["scan_id"] for s in public_client.get("/api/scans").json())
    demo = wait(public_client, public_client.post("/api/scans/demo").json()["job_id"])
    assert any(s["id"] == demo["scan_id"] for s in public_client.get("/api/scans").json())


def test_public_mode_rejects_oversized_upload(tmp_path, monkeypatch):
    monkeypatch.setenv("QSCAN_MAX_UPLOAD_MB", "0.01")
    c = _client(tmp_path, monkeypatch, public=True)
    big_stored = io.BytesIO()
    with zipfile.ZipFile(big_stored, "w", compression=zipfile.ZIP_STORED) as z:
        z.writestr("big.txt", "x" * 50_000)
    assert c.post("/api/scans/upload", files={"file": ("big.zip", big_stored.getvalue(), "application/zip")}).status_code == 413
