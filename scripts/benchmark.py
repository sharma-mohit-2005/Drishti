"""Measure scan speed.

  python scripts/benchmark.py                 # synthetic ~100k-line corpus built from the demo repo
  python scripts/benchmark.py <folder> ...    # any real codebase(s)

Reports files, lines of code, wall time and throughput. Run 3 times and quote the median.
"""
from __future__ import annotations

import random
import shutil
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from qscan.cli import DEMO_DIR  # noqa: E402
from qscan.engine import run_scan  # noqa: E402

FILLER = {
    ".py": "def handler_{i}(request):\n    total = sum(x * 2 for x in range({i} % 50))\n    return {{'ok': True, 'n': total}}\n\n",
    ".java": "    public int handler{i}(int x) {{\n        int total = 0;\n        for (int k = 0; k < x; k++) total += k;\n        return total;\n    }}\n",
    ".go": "func handler{i}(x int) int {{\n\ttotal := 0\n\tfor k := 0; k < x; k++ {{ total += k }}\n\treturn total\n}}\n",
    ".js": "function handler{i}(x) {{\n  let total = 0;\n  for (let k = 0; k < x; k++) total += k;\n  return total;\n}}\n",
}


def synthetic(target_loc: int = 100_000) -> Path:
    root = Path(tempfile.mkdtemp(prefix="qd-bench-"))
    sources = [p for p in DEMO_DIR.rglob("*") if p.suffix in FILLER]
    rnd = random.Random(7)
    loc, n = 0, 0
    while loc < target_loc:
        src = sources[n % len(sources)]
        body = src.read_text(encoding="utf-8")
        filler = "".join(FILLER[src.suffix].format(i=rnd.randint(1, 10_000)) for _ in range(60))
        if src.suffix == ".java":
            body = body.rstrip().rstrip("}") + filler + "}\n"
        else:
            body = body + "\n" + filler
        out = root / f"svc{n // 40}" / f"{src.stem}_{n}{src.suffix}"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(body, encoding="utf-8")
        loc += body.count("\n") + 1
        n += 1
    return root


def measure(path: str, runs: int = 3) -> dict:
    times, r = [], None
    for _ in range(runs):
        t = time.perf_counter()
        r = run_scan(path=path)
        times.append(time.perf_counter() - t)
    st = r["stats"]
    med = statistics.median(times)
    return {"path": path, "files": st["files_scanned"], "source_files": st["source_files"], "loc": st["loc"],
            "assets": st["assets"], "occurrences": st["occurrences"], "median_s": round(med, 2),
            "runs_s": [round(x, 2) for x in times], "loc_per_s": int(st["loc"] / med) if med else 0}


def main():
    paths = sys.argv[1:]
    tmp = None
    if not paths:
        tmp = synthetic()
        paths = [str(tmp)]
    try:
        for p in paths:
            m = measure(p)
            print(f"{m['path']}\n  files {m['files']:,} | source files {m['source_files']:,} | {m['loc']:,} lines of code\n"
                  f"  {m['assets']} assets, {m['occurrences']} occurrences\n"
                  f"  median {m['median_s']} s over 3 runs {m['runs_s']} | {m['loc_per_s']:,} lines/s")
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
