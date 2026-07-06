"""Entropy source contracts, registry and circuit breaker.

Every source lives in its own module, implements :class:`EntropySource`,
and registers itself with :func:`register`. Core code never imports a
concrete source directly (plan §3.3).
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

# Independent physical/social domains (plan §3.1). The pool enforces a
# minimum number of *domains*, not sources.
DOMAINS = (
    "atmosphere", "geophysics", "orbital", "markets", "blockchain",
    "space_weather", "human", "local",
)


@dataclass
class SourceSample:
    source_name: str
    domain: str
    fetched_at: float
    raw_fields: dict
    entropy_bytes: bytes
    est_min_entropy_bits: float  # deliberately pessimistic (plan §5.4)


class CircuitBreaker:
    """Skip a source for a cooldown after repeated failures."""

    def __init__(self, max_failures: int = 3, cooldown_s: float = 300.0):
        self.max_failures = max_failures
        self.cooldown_s = cooldown_s
        self.failures = 0
        self.opened_at: float | None = None

    @property
    def is_open(self) -> bool:
        if self.opened_at is None:
            return False
        if time.monotonic() - self.opened_at >= self.cooldown_s:
            self.opened_at = None  # half-open: allow one try
            self.failures = 0
            return False
        return True

    def record_failure(self) -> None:
        self.failures += 1
        if self.failures >= self.max_failures:
            self.opened_at = time.monotonic()

    def record_success(self) -> None:
        self.failures = 0
        self.opened_at = None


@dataclass
class EntropySource(ABC):
    """A single harvestable source. Subclasses set ``name`` and ``domain``."""

    name: str = field(init=False)
    domain: str = field(init=False)

    @abstractmethod
    def fetch(self) -> SourceSample:
        """Fetch one sample. May raise; callers handle failure (plan §3.3)."""


REGISTRY: dict[str, type[EntropySource]] = {}


def register(cls: type[EntropySource]) -> type[EntropySource]:
    REGISTRY[cls.name] = cls
    return cls
