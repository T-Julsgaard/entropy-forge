"""Entropy pool with per-source and per-domain accounting (plan §4 stage 4).

Rules enforced here:
- Health-failing samples are absorbed but credited ZERO entropy.
- Domain haircut: no single domain's credited entropy may exceed
  ``domain_cap`` (default 40%) of the total (plan §3.4).
- ``ready(n_bits)`` requires estimated input entropy >= 2x the requested
  output AND at least ``min_domains`` distinct domains contributing.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from ..sources.base import SourceSample
from .health import SourceHealth


@dataclass
class EntropyPool:
    min_domains: int = 5
    domain_cap: float = 0.40
    safety_margin: float = 2.0

    _buf: bytearray = field(default_factory=bytearray, repr=False)
    _domain_bits: dict[str, float] = field(default_factory=dict)
    _source_bits: dict[str, float] = field(default_factory=dict)
    _health: dict[str, SourceHealth] = field(default_factory=dict)
    events: list[str] = field(default_factory=list)

    def add(self, sample: SourceSample) -> bool:
        """Absorb a sample. Returns True if it was credited entropy."""
        health = self._health.setdefault(sample.source_name, SourceHealth())
        verdict = health.check(sample.entropy_bytes)

        # Always absorb the bytes (can't hurt after conditioning)...
        self._buf += hashlib.sha256(
            sample.source_name.encode() + b"\x00" + sample.entropy_bytes
        ).digest()

        # ...but only credit entropy if healthy.
        if not verdict.ok:
            self.events.append(f"{sample.source_name}: {verdict.reason} (0 bits)")
            return False
        bits = max(0.0, sample.est_min_entropy_bits)
        self._domain_bits[sample.domain] = self._domain_bits.get(sample.domain, 0.0) + bits
        self._source_bits[sample.source_name] = (
            self._source_bits.get(sample.source_name, 0.0) + bits
        )
        return True

    @property
    def credited_bits(self) -> float:
        """Total credited entropy with the per-domain haircut applied."""
        total_raw = sum(self._domain_bits.values())
        if total_raw <= 0:
            return 0.0
        cap = self.domain_cap * total_raw
        return sum(min(v, cap) for v in self._domain_bits.values())

    @property
    def domains(self) -> set[str]:
        return {d for d, v in self._domain_bits.items() if v > 0}

    def ready(self, n_bits: int) -> tuple[bool, str]:
        if len(self.domains) < self.min_domains:
            return False, (
                f"need >= {self.min_domains} domains, have {len(self.domains)}"
            )
        if self.credited_bits < self.safety_margin * n_bits:
            return False, (
                f"need >= {self.safety_margin * n_bits:.0f} credited bits, "
                f"have {self.credited_bits:.0f}"
            )
        return True, "ok"

    def snapshot(self) -> bytes:
        return bytes(self._buf)
