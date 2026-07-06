"""Crypto spot prices via CoinGecko keyless tier (domain: markets)."""
from __future__ import annotations

import time
from dataclasses import dataclass

from ..core.extractor import digits_to_bytes, trailing_digits
from .base import EntropySource, SourceSample, register


@dataclass
class CryptoPrices(EntropySource):
    name = "crypto_prices"
    domain = "markets"
    client: object = None

    def fetch(self) -> SourceSample:
        data = self.client.get_json(
            "https://api.coingecko.com/api/v3/simple/price",
            params={"ids": "bitcoin,ethereum,solana,monero,dogecoin",
                    "vs_currencies": "usd", "precision": "8"},
        )
        digits: list[int] = []
        for coin, quote in sorted(data.items()):
            digits += trailing_digits(quote.get("usd", 0), 3)
        return SourceSample(
            source_name=self.name, domain=self.domain, fetched_at=time.time(),
            raw_fields=data, entropy_bytes=digits_to_bytes(digits),
            est_min_entropy_bits=min(2.0 * len(data), 10.0),
        )


register(CryptoPrices)
