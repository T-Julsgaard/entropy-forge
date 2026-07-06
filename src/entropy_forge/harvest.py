"""Harvest orchestration: run sources, apply health/pool rules, emit output.

Failure model (plan §3.3): a failing source NEVER crashes the pipeline —
timeouts/retries live in the HTTP client, circuit breakers live here, and
the pool simply receives fewer inputs. Output metadata records who
contributed.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .core.pool import EntropyPool
from .core.whitener import condition
from .sources.base import REGISTRY, CircuitBreaker, EntropySource


@dataclass
class Harvester:
    pool: EntropyPool = field(default_factory=EntropyPool)
    breakers: dict[str, CircuitBreaker] = field(default_factory=dict)
    contributed: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)

    def round(self, sources: list[EntropySource]) -> None:
        for src in sources:
            breaker = self.breakers.setdefault(src.name, CircuitBreaker())
            if breaker.is_open:
                self.failed.append(f"{src.name} (circuit open)")
                continue
            try:
                sample = src.fetch()
            except Exception as exc:  # noqa: BLE001 — isolation by design
                breaker.record_failure()
                self.failed.append(f"{src.name} ({type(exc).__name__})")
                continue
            breaker.record_success()
            credited = self.pool.add(sample)
            self.contributed.append(
                f"{src.name}[{sample.domain}]" + ("" if credited else " (0 bits)")
            )

    def emit(self, n_bytes: int) -> bytes:
        ok, why = self.pool.ready(n_bytes * 8)
        if not ok:
            raise RuntimeError(f"pool not ready: {why}")
        return condition(self.pool.snapshot(), n_bytes)


def default_sources(client, offline: bool = False) -> list[EntropySource]:
    out: list[EntropySource] = [REGISTRY["system_jitter"]()]
    if offline:
        return out
    for name, cls in REGISTRY.items():
        if name == "system_jitter":
            continue
        out.append(cls(client=client))
    return out
