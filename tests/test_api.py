import io
import time
import zipfile

import pytest


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("QSCAN_DATA", str(tmp_path / "data"))
    import importlib

    import qscan.api as api
    importlib.reload(api)
    from fastapi.testclient import TestClient
    return TestClient(api.app)


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
