"""One shared HTTP client for all sources (plan §3.3).

Sources accept a ``client`` object exposing ``get_json(url, params=None)``
so unit tests can inject fakes without network or monkeypatching.
"""
from __future__ import annotations

import random
import time

import os

import httpx

_CONTACT = os.environ.get("ENTROPY_FORGE_CONTACT")
# MET Norway ToS requires an identifiable User-Agent with a contact.
USER_AGENT = (
    f"entropy-forge/0.1 ({_CONTACT})"
    if _CONTACT
    else "entropy-forge/0.1 (contact-unset: export ENTROPY_FORGE_CONTACT, see README)"
)


class HttpClient:
    def __init__(self, timeout_s: float = 5.0, max_retries: int = 3):
        self._client = httpx.Client(
            timeout=timeout_s, headers={"User-Agent": USER_AGENT}
        )
        self.max_retries = max_retries

    def get_json(self, url: str, params: dict | None = None):
        last_exc: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                resp = self._client.get(url, params=params)
                resp.raise_for_status()
                return resp.json()
            except Exception as exc:  # noqa: BLE001 - sources isolate failures
                last_exc = exc
                # jittered exponential backoff: ~0.5s, ~1s, give up
                if attempt < self.max_retries - 1:
                    time.sleep((2**attempt) * 0.5 * (0.5 + random.random()))
        raise last_exc  # type: ignore[misc]

    def close(self) -> None:
        self._client.close()
