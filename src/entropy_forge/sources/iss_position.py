"""ISS live position (domain: orbital). Position is computable from public\nTLEs, so estimated entropy is deliberately near zero \u2014 kept for domain diversity."""
from __future__ import annotations

import time
from dataclasses import dataclass

from ..core.extractor import digits_to_bytes, trailing_digits
from .base import EntropySource, SourceSample, register


@dataclass
class IssPosition(EntropySource):
    name = "iss_position"
    domain = "orbital"
    client: object = None

    def fetch(self) -> SourceSample:
        data = self.client.get_json("https://api.wheretheiss.at/v1/satellites/25544")
        digits: list[int] = []
        for k in ("latitude", "longitude", "velocity", "altitude"):
            if k in data:
                digits += trailing_digits(data[k], 3)
        return SourceSample(
            source_name=self.name, domain=self.domain, fetched_at=time.time(),
            raw_fields={k: data.get(k) for k in ("latitude", "longitude", "velocity")},
            entropy_bytes=digits_to_bytes(digits),
            est_min_entropy_bits=0.5,  # near-zero by design (public TLEs)
        )


register(IssPosition)
