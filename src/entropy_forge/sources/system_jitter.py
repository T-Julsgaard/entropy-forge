"""Local timing-jitter source (domain: local). Always available."""
from __future__ import annotations

import os
import time
from dataclasses import dataclass

from .base import EntropySource, SourceSample, register


@dataclass
class SystemJitter(EntropySource):
    name = "system_jitter"
    domain = "local"
    n_samples: int = 512

    def fetch(self) -> SourceSample:
        deltas = bytearray()
        prev = time.perf_counter_ns()
        for _ in range(self.n_samples):
            os.stat(".")  # tiny syscall whose latency jitters
            now = time.perf_counter_ns()
            deltas.append((now - prev) & 0xFF)
            prev = now
        return SourceSample(
            source_name=self.name,
            domain=self.domain,
            fetched_at=time.time(),
            raw_fields={"n_samples": self.n_samples},
            entropy_bytes=bytes(deltas),
            # ~0.5 bit/sample is a deliberately pessimistic cap (plan §5.4)
            est_min_entropy_bits=self.n_samples * 0.5,
        )


register(SystemJitter)
