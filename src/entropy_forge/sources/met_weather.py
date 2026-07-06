"""MET Norway weather source (domain: atmosphere).

Requires a proper User-Agent (set by the shared client). Honors caching:
we sample a randomized subset of cities each round (plan §3.5), and the
freshness health test zero-credits any cached repeats.
Attribution: data from MET Norway, NLOD/CC-BY 4.0.
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass, field

from ..core.extractor import digits_to_bytes, trailing_digits
from .base import EntropySource, SourceSample, register

URL = "https://api.met.no/weatherapi/locationforecast/2.0/compact"

# A large parameter space so the randomized harvest plan multiplies the
# attacker's search space (plan §3.5). lat/lon rounded per MET ToS.
CITIES = {
    "oslo": (59.91, 10.75), "bergen": (60.39, 5.32), "tokyo": (35.68, 139.69),
    "nairobi": (-1.29, 36.82), "sydney": (-33.87, 151.21), "lima": (-12.05, -77.04),
    "reykjavik": (64.15, -21.94), "mumbai": (19.08, 72.88), "anchorage": (61.22, -149.90),
    "capetown": (-33.92, 18.42), "honolulu": (21.31, -157.86), "ushuaia": (-54.80, -68.30),
    "singapore": (1.35, 103.82), "nuuk": (64.18, -51.72), "perth": (-31.95, 115.86),
    "stpetersburg": (59.93, 30.36), "mexicocity": (19.43, -99.13), "auckland": (-36.85, 174.76),
}


@dataclass
class MetWeather(EntropySource):
    name = "met_weather"
    domain = "atmosphere"
    client: object = None
    n_cities: int = 6
    rng: random.Random = field(default_factory=random.SystemRandom)

    def fetch(self) -> SourceSample:
        chosen = self.rng.sample(sorted(CITIES), k=min(self.n_cities, len(CITIES)))
        digits: list[int] = []
        raw: dict = {"cities": chosen, "values": {}}
        for city in chosen:
            lat, lon = CITIES[city]
            data = self.client.get_json(URL, params={"lat": lat, "lon": lon})
            details = data["properties"]["timeseries"][0]["data"]["instant"]["details"]
            vals = {
                k: details[k]
                for k in (
                    "air_temperature", "air_pressure_at_sea_level",
                    "wind_speed", "wind_from_direction", "relative_humidity",
                )
                if k in details
            }
            raw["values"][city] = vals
            for v in vals.values():
                digits += trailing_digits(v, 2)  # NOTE: no timestamps (plan §3.4)
        return SourceSample(
            source_name=self.name, domain=self.domain, fetched_at=time.time(),
            raw_fields=raw, entropy_bytes=digits_to_bytes(digits),
            est_min_entropy_bits=min(2.0 * len(digits) / 2, 40.0),  # <=2 bits/field, capped
        )


register(MetWeather)
