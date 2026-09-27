"""Container images: export with `docker save`, unpack every layer into a root filesystem."""
from __future__ import annotations

import json
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

MAX_MEMBER = 64 * 1024 * 1024


class ContainerError(RuntimeError):
    pass


def export_image(image: str, workdir: Path) -> Path:
    """Save a local image and unpack its layers in order. Returns the rootfs directory."""
    if not shutil.which("docker"):
        raise ContainerError("Docker CLI not found on PATH.")
    tar_path = workdir / "image.tar"
    r = subprocess.run(["docker", "image", "inspect", image], capture_output=True, text=True)
    if r.returncode != 0:
        raise ContainerError(f"Image '{image}' is not available locally. Run `docker pull {image}` first.")
    r = subprocess.run(["docker", "save", "-o", str(tar_path), image], capture_output=True, text=True)
    if r.returncode != 0:
        raise ContainerError(r.stderr.strip() or "docker save failed")
    return unpack_saved_image(tar_path, workdir)


def unpack_saved_image(tar_path: Path, workdir: Path) -> Path:
    """Unpack a `docker save` archive: apply its layers in order into workdir/rootfs."""
    extract = workdir / "image"
    extract.mkdir()
    with tarfile.open(tar_path) as t:
        t.extractall(extract, filter="data")
    manifest = json.loads((extract / "manifest.json").read_text())
    layers = manifest[0]["Layers"]
    rootfs = workdir / "rootfs"
    rootfs.mkdir()
    for layer in layers:
        with tarfile.open(extract / layer) as lt:
            members = []
            for m in lt.getmembers():
                name = Path(m.name).name
                if name.startswith(".wh.") or not m.isreg() or m.size > MAX_MEMBER:
                    continue
                members.append(m)
            try:
                lt.extractall(rootfs, members=members, filter="data")
            except (tarfile.TarError, OSError):
                for m in members:
                    try:
                        lt.extract(m, rootfs, filter="data")
                    except (tarfile.TarError, OSError):
                        continue
    return rootfs


def temp_workdir() -> Path:
    return Path(tempfile.mkdtemp(prefix="qdrishti-img-"))
