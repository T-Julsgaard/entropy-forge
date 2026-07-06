"""Sources against fake HTTP clients; failure isolation in the harvester."""
from entropy_forge.harvest import Harvester
from entropy_forge.sources.base import REGISTRY
from entropy_forge.sources.system_jitter import SystemJitter


def test_registry_has_all_tier1():
    assert set(REGISTRY) >= {
        "system_jitter", "met_weather", "usgs_quakes", "iss_position",
        "crypto_prices", "mempool_blocks", "space_weather", "hackernews",
    }


def test_system_jitter_produces_bytes():
    s = SystemJitter(n_samples=64).fetch()
    assert len(s.entropy_bytes) == 64 and s.est_min_entropy_bits > 0


def test_met_weather_parses_and_strips_timestamps(fake_client):
    payload = {"properties": {"timeseries": [{"data": {"instant": {"details": {
        "air_temperature": 17.3, "air_pressure_at_sea_level": 1002.4,
        "wind_speed": 4.7, "wind_from_direction": 210.0, "relative_humidity": 61.0,
    }}}}]}}
    client = fake_client({"api.met.no": payload})
    src = REGISTRY["met_weather"](client=client, n_cities=2)
    s = src.fetch()
    assert s.entropy_bytes and s.domain == "atmosphere"
    assert "time" not in str(s.raw_fields)  # timestamps stripped (plan §3.4)


def test_usgs_is_designated_timestamp_source(fake_client):
    payload = {"features": [{"properties": {"mag": 2.31, "time": 1751468400483},
                             "geometry": {"coordinates": [12.3456, -45.678, 12.44]}}]}
    client = fake_client({"earthquake.usgs.gov": payload})
    s = REGISTRY["usgs_quakes"](client=client).fetch()
    assert s.entropy_bytes and s.domain == "geophysics"


def test_failing_source_never_crashes_harvest(fake_client):
    class Boom(Exception):
        pass

    client = fake_client({
        "api.met.no": Boom("down"),
        "earthquake.usgs.gov": {"features": []},
    })
    h = Harvester()
    h.round([REGISTRY["met_weather"](client=client),
             REGISTRY["usgs_quakes"](client=client),
             SystemJitter(n_samples=32)])
    assert any("met_weather" in f for f in h.failed)
    assert any("usgs_quakes" in c for c in h.contributed)


def test_circuit_breaker_opens_after_repeated_failures(fake_client):
    client = fake_client({"api.met.no": RuntimeError("down")})
    h = Harvester()
    src = REGISTRY["met_weather"](client=client)
    for _ in range(3):
        h.round([src])
    h.round([src])
    assert any("circuit open" in f for f in h.failed)
