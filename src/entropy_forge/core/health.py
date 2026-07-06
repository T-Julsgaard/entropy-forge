"""Continuous health tests, inspired by NIST SP 800-90B (plan §4 stage 2).

A lying source is worse than a dead one. Samples that fail are credited
zero entropy and the source can be quarantined by the caller.
"""
from __future__ import annotations

import hashlib
from collections import Counter, deque
from dataclasses import dataclass, field


@dataclass
class HealthVerdict:
    ok: bool
    reason: str = ""


@dataclass
class SourceHealth:
    """Per-source rolling health state."""

    repetition_limit: int = 3
    window: int = 64
    proportion_limit: float = 0.5

    _last_hash: bytes | None = field(default=None, repr=False)
    _repeat_count: int = 0
    _recent: deque = field(default_factory=lambda: deque(maxlen=64), repr=False)

    def check(self, entropy_bytes: bytes) -> HealthVerdict:
        digest = hashlib.sha256(entropy_bytes).digest()

        # Freshness / duplicate test: identical to previous fetch => CDN
        # cache hit or stale feed. Most common real-world failure (plan §4).
        if digest == self._last_hash:
            self._repeat_count += 1
            self._last_hash = digest
            if self._repeat_count >= self.repetition_limit:
                return HealthVerdict(False, "repetition_count")
            return HealthVerdict(False, "stale_duplicate")
        self._repeat_count = 0
        self._last_hash = digest

        # Adaptive proportion: one value dominating the recent window.
        self._recent.append(digest)
        if len(self._recent) >= 8:
            most_common = Counter(self._recent).most_common(1)[0][1]
            if most_common / len(self._recent) > self.proportion_limit:
                return HealthVerdict(False, "adaptive_proportion")

        return HealthVerdict(True)
