import json
import pathlib

import pytest


@pytest.fixture(scope="session")
def vectors():
    return json.loads((pathlib.Path(__file__).parent / "vectors.json").read_text(encoding="utf-8"))["english"]


class FakeClient:
    """Injectable fake for the shared HTTP client (plan §3.3: no network in unit tests)."""

    def __init__(self, responses):
        self.responses = responses  # url-substring -> payload (or Exception)
        self.calls = []

    def get_json(self, url, params=None):
        self.calls.append((url, params))
        for key, payload in self.responses.items():
            if key in url:
                if isinstance(payload, Exception):
                    raise payload
                return payload
        raise KeyError(f"no fake response for {url}")


@pytest.fixture
def fake_client():
    return FakeClient
