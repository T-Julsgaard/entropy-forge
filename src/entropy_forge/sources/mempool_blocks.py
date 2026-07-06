"""Bitcoin tip block hash + mempool stats via mempool.space (domain:\nblockchain). Block hashes are high-quality unpredictable bits (miners can\nbias slightly \u2014 fine for mixing)."""
from __future__ import annotations

import time
from dataclasses import dataclass

from ..core.extractor import digits_to_bytes, trailing_digits
from .base import EntropySource, SourceSample, register


@dataclass
class MempoolBlocks(EntropySource):
    name = "mempool_blocks"
    domain = "blockchain"
    client: object = None

    def fetch(self) -> SourceSample:
        tip = self.client.get_json("https://mempool.space/api/blocks")
        mp = self.client.get_json("https://mempool.space/api/mempool")
        digits: list[int] = []
        block_hash = b""
        if tip:
            block_hash = bytes.fromhex(tip[0]["id"])
            digits += trailing_digits(tip[0].get("tx_count", 0), 3)
        digits += trailing_digits(mp.get("count", 0), 4)
        digits += trailing_digits(mp.get("vsize", 0), 4)
        return SourceSample(
            source_name=self.name, domain=self.domain, fetched_at=time.time(),
            raw_fields={"tip": tip[0]["id"] if tip else None, "mempool_count": mp.get("count")},
            entropy_bytes=block_hash + digits_to_bytes(digits),
            est_min_entropy_bits=20.0 if block_hash else 5.0,
        )


register(MempoolBlocks)
