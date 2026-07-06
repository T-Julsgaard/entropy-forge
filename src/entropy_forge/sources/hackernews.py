"""Hacker News item-ID drift (domain: human). Global human posting\nbehavior \u2014 uncorrelated with geophysics."""
from __future__ import annotations

import time
from dataclasses import dataclass

from ..core.extractor import digits_to_bytes, trailing_digits
from .base import EntropySource, SourceSample, register


@dataclass
class HackerNews(EntropySource):
    name = "hackernews"
    domain = "human"
    client: object = None

    def fetch(self) -> SourceSample:
        max_item = self.client.get_json("https://hacker-news.firebaseio.com/v0/maxitem.json")
        updates = self.client.get_json("https://hacker-news.firebaseio.com/v0/updates.json")
        digits: list[int] = trailing_digits(int(max_item), 4)
        for item_id in (updates.get("items") or [])[:20]:
            digits += trailing_digits(int(item_id), 3)
        return SourceSample(
            source_name=self.name, domain=self.domain, fetched_at=time.time(),
            raw_fields={"max_item": max_item, "updated": len(updates.get("items") or [])},
            entropy_bytes=digits_to_bytes(digits),
            est_min_entropy_bits=min(1.0 * len(digits) / 3, 12.0),
        )


register(HackerNews)
