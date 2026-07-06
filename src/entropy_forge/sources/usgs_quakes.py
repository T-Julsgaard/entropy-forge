"""USGS earthquake feed (domain: geophysics). DESIGNATED timestamp source:\nthis is the ONE source allowed to extract clock digits (plan \u00a73.4)."""
from __future__ import annotations

import time
from dataclasses import dataclass

from ..core.extractor import digits_to_bytes, trailing_digits
from .base import EntropySource, SourceSample, register


@dataclass
class UsgsQuakes(EntropySource):
    name = "usgs_quakes"
    domain = "geophysics"
    client: object = None

    def fetch(self) -> SourceSample:
        data = self.client.get_json(
            "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_hour.geojson"
        )
        feats = data.get("features", [])
        digits: list[int] = []
        quakes = []
        for f in feats[:25]:
            p, g = f["properties"], f["geometry"]["coordinates"]
            quakes.append({"mag": p.get("mag"), "depth": g[2], "time": p.get("time")})
            for v in (p.get("mag"), g[0], g[1], g[2]):
                if v is not None:
                    digits += trailing_digits(v, 2)
            if p.get("time"):
                digits += trailing_digits(p["time"], 3)  # ms digits — designated source
        return SourceSample(
            source_name=self.name, domain=self.domain, fetched_at=time.time(),
            raw_fields={"count": len(feats), "quakes": quakes[:5]},
            entropy_bytes=digits_to_bytes(digits),
            est_min_entropy_bits=min(3.0 * len(quakes), 45.0),
        )


register(UsgsQuakes)
