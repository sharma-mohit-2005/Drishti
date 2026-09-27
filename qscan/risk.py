"""Quantum risk engine.

Mosca's inequality says data is at risk when X + Y > Z:
  X = years the data must stay secret, Y = years the migration takes,
  Z = years until a cryptographically relevant quantum computer (CRQC).
Z is uncertain, so we sample it from a lognormal distribution and report
P(exposure) = P(X + Y > Z) instead of a yes/no answer.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import date
from functools import lru_cache

import numpy as np

from . import registry as R

DATA_CLASS = {   # name -> (shelf life X in years, sensitivity 0..1)
    "public": (0, 0.1), "internal": (2, 0.3), "confidential": (7, 0.6), "pii": (10, 0.8),
    "financial": (10, 0.8), "identity": (25, 1.0), "health": (25, 1.0), "secret": (25, 1.0),
}
EXPOSURE = {"internet": 1.0, "internal": 0.6, "offline": 0.3}
SURFACE_EFFORT = {   # base migration years by where the crypto lives
    "config": 0.25, "endpoint": 0.25, "dependency": 0.5, "source": 1.0, "certificate": 1.0,
    "key": 1.0, "binary": 1.5, "container": 0.75,
}
AGILITY = {"config": 0.6, "constant": 1.0, "hardcoded": 1.2, "n/a": 1.0}
BANDS = [(70, "critical"), (40, "high"), (20, "medium"), (0, "low")]


@dataclass
class RiskConfig:
    crqc_median_year: float = 2034.0
    sigma: float = 0.45
    samples: int = 20_000
    today: float = float(date.today().year)

    @property
    def median_years(self) -> float:
        return max(0.5, self.crqc_median_year - self.today)


@lru_cache(maxsize=4096)
def exposure_probability(x_plus_y: float, median_years: float, sigma: float, samples: int = 20_000) -> float:
    """P(X + Y > Z) with Z ~ LogNormal(ln(median_years), sigma). Seeded so results are repeatable."""
    rng = np.random.default_rng(7)
    z = rng.lognormal(mean=math.log(median_years), sigma=sigma, size=samples)
    return float(np.mean(x_plus_y > z))


def q_factor(status: str) -> float:
    return {R.QV: 1.0, R.QW: 0.4}.get(status, 0.0)


def h_factor(usage: str, long_lived: bool) -> float:
    """Harvest-now-decrypt-later exposure: confidentiality uses are exposed today."""
    if usage in ("encrypt", "decrypt", "key-agree", "protocol", "storage"):
        return 1.0
    if usage in ("sign", "verify"):
        return 0.9 if long_lived else 0.5
    if usage == "keygen":
        return 0.8
    if usage == "available":
        return 0.3
    return 0.5


def migration_years(surface: str, agility: str, occurrences: int, is_ca: bool = False) -> float:
    base = SURFACE_EFFORT.get(surface, 1.0) * (2.0 if is_ca else 1.0)
    return round(base * AGILITY.get(agility, 1.0) * (1 + 0.15 * math.log(max(1, occurrences))), 2)


def band_for(score: int) -> str:
    for threshold, name in BANDS:
        if score >= threshold:
            return name
    return "low"


def score(status: str, usage: str, surface: str, agility: str, occurrences: int, app: dict,
          cfg: RiskConfig, long_lived: bool = False, is_ca: bool = False) -> dict:
    x, sens = DATA_CLASS.get(app.get("data_class", "internal"), DATA_CLASS["internal"])
    crit = max(1, min(5, int(app.get("criticality", 3))))
    expo = EXPOSURE.get(app.get("exposure", "internal"), 0.6)
    y = migration_years(surface, agility, occurrences, is_ca)
    q = q_factor(status)
    h = h_factor(usage, long_lived)
    p = exposure_probability(round(x + y, 2), cfg.median_years, cfg.sigma, cfg.samples) if q else 0.0
    context = 0.40 * (crit / 5) + 0.35 * sens + 0.25 * expo
    qrs = round(100 * q * h * p * context)
    classical = status in (R.BROKEN, R.WEAK)
    if usage == "available":
        # Offered by a crypto library but not shown to be used: informational only.
        qrs, classical = min(qrs, 15), False
    elif status == R.BROKEN:
        qrs = max(qrs, 90)
    elif status == R.WEAK:
        qrs = max(qrs, 30)
    return {
        "qrs": int(qrs), "band": band_for(int(qrs)), "x_years": x, "y_years": y,
        "margin_years": round(cfg.median_years - (x + y), 2), "p_exposure": round(p, 3),
        "factors": {"Q": q, "H": h, "P": round(p, 3), "C": crit, "S": sens, "E": expo, "context": round(context, 3)},
        "hndl": bool(q and h >= 1.0 and p > 0), "classical": classical,
    }


def qri(assets: list[dict]) -> int:
    """Quantum Readiness Index: 100 minus the criticality-weighted mean risk score."""
    scored = [a for a in assets if a.get("risk")]
    if not scored:
        return 100
    num = sum(a["risk"]["qrs"] * a["risk"]["factors"]["C"] for a in scored)
    den = sum(a["risk"]["factors"]["C"] for a in scored)
    return int(round(100 - num / den))


def heat_column(risk: dict) -> int:
    """0: exposed (X+Y beyond the median CRQC year), 1: <3y margin, 2: 3-6y, 3: >6y, 4: not quantum-exposed."""
    if not risk["factors"]["Q"]:
        return 4
    m = risk["margin_years"]
    return 0 if m <= 0 else 1 if m < 3 else 2 if m < 6 else 3
