"""NOAA SWPC real-time solar wind (domain: space_weather). Genuinely\nchaotic plasma physics."""
from __future__ import annotations

import time
from dataclasses import dataclass

from ..core.extractor import digits_to_bytes, trailing_digits
from .base import EntropySource, SourceSample, register


@dataclass
class SpaceWeather(EntropySource):
    name = "space_weather"
    domain = "space_weather"
    client: object = None

    def fetch(self) -> SourceSample:
        data = self.client.get_json(
            "https://services.swpc.noaa.gov/products/solar-wind/plasma-7-day.json"
        )
        digits: list[int] = []
        rows = data[1:] if data else []
        for row in rows[-10:]:  # last 10 measurements: density, speed, temp
            for v in row[1:4]:
                if v is not None:
                    digits += trailing_digits(float(v), 2)
        return SourceSample(
            source_name=self.name, domain=self.domain, fetched_at=time.time(),
            raw_fields={"latest": rows[-1] if rows else None},
            entropy_bytes=digits_to_bytes(digits),
            est_min_entropy_bits=min(1.5 * len(rows[-10:]) * 3 / 3, 15.0),
        )


register(SpaceWeather)
