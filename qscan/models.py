"""Data shapes shared by every scanner and the analysis core."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class RawFinding:
    """One thing a scanner saw. The engine turns these into assets."""

    scanner: str            # source | config | certificate | dependency | binary | endpoint
    kind: str               # algorithm | protocol | certificate | key | library
    identifier: str         # the literal token that was matched
    path: str
    line: int | None = None
    snippet: str = ""
    canonical: str | None = None          # set when the scanner already knows the canonical name
    params: dict[str, Any] = field(default_factory=dict)
    usage: str = "unknown"                # keygen | encrypt | sign | key-agree | digest | tag | protocol | ...
    confidence: float = 0.8
    rule_id: str = ""
    agility: str = "hardcoded"            # hardcoded | constant | config | n/a
    extra: dict[str, Any] = field(default_factory=dict)
    # Parts a compound finding breaks into, e.g. a TLS cipher suite or a certificate.
    components: list[tuple[str, dict, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RawFinding":
        d = dict(d)
        d["components"] = [tuple(c) for c in d.get("components", [])]
        return cls(**d)
