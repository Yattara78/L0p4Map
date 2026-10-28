"""EPSS / KEV enrichment: parsing, cache TTL, ranking. No real network."""

import json

from core import risks


class FakeResponse:
    def __init__(self, payload: dict):
        self._payload = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._payload


class FakeOpener:
    def __init__(self, payloads):
        self.payloads = payloads
        self.calls = []

    def __call__(self, url, timeout=None):
        self.calls.append(url)
        for needle, payload in self.payloads.items():
            if needle in url:
                if isinstance(payload, Exception):
                    raise payload
                return FakeResponse(payload)
        raise AssertionError(f"unexpected url {url}")


EPSS_PAYLOAD = {
    "data": [
        {"cve": "CVE-2021-44228", "epss": "0.97", "percentile": "0.999"},
        {"cve": "CVE-2019-0708", "epss": "0.94", "percentile": "0.99"},
    ]
}
KEV_PAYLOAD = {"vulnerabilities": [{"cveID": "CVE-2019-0708"}]}


def test_normalise_dedupes_and_uppercases():
    assert risks.normalise(["cve-2021-44228", "CVE-2021-44228", ""]) == ["CVE-2021-44228"]


def test_fetch_epss_parses_scores(tmp_path):
    opener = FakeOpener({"epss": EPSS_PAYLOAD})
    scores = risks.fetch_epss(["CVE-2021-44228"], opener=opener, cache_dir=tmp_path)
    assert scores["CVE-2021-44228"]["epss"] == 0.97
    assert "CVE-2021-44228" in opener.calls[0]


def test_fetch_epss_uses_cache_within_ttl(tmp_path):
    opener = FakeOpener({"epss": EPSS_PAYLOAD})
    risks.fetch_epss(["CVE-2021-44228"], opener=opener, cache_dir=tmp_path, now=1000)
    offline = FakeOpener({})
    scores = risks.fetch_epss(["CVE-2021-44228"], opener=offline, cache_dir=tmp_path, now=1000 + 60)
    assert scores["CVE-2021-44228"]["epss"] == 0.97
    assert offline.calls == []


def test_fetch_epss_refetches_after_ttl(tmp_path):
    opener = FakeOpener({"epss": EPSS_PAYLOAD})
    risks.fetch_epss(["CVE-2021-44228"], opener=opener, cache_dir=tmp_path, now=1000)
    again = FakeOpener({"epss": EPSS_PAYLOAD})
    risks.fetch_epss(
        ["CVE-2021-44228"], opener=again, cache_dir=tmp_path, now=1000 + risks.EPSS_TTL + 1
    )
    assert len(again.calls) == 1


def test_fetch_epss_offline_returns_empty(tmp_path):
    opener = FakeOpener({"epss": OSError("offline")})
    assert risks.fetch_epss(["CVE-2021-44228"], opener=opener, cache_dir=tmp_path) == {}


def test_fetch_kev_parses_catalogue(tmp_path):
    opener = FakeOpener({"known_exploited": KEV_PAYLOAD})
    assert risks.fetch_kev(opener=opener, cache_dir=tmp_path) == {"CVE-2019-0708"}


def test_fetch_kev_falls_back_to_stale_cache(tmp_path):
    good = FakeOpener({"known_exploited": KEV_PAYLOAD})
    risks.fetch_kev(opener=good, cache_dir=tmp_path, now=1000)

    offline = FakeOpener({"known_exploited": OSError("offline")})
    kev = risks.fetch_kev(
        opener=offline, cache_dir=tmp_path, now=1000 + risks.KEV_TTL + 1
    )
    assert "CVE-2019-0708" in kev


def test_priority_prefers_kev_over_raw_cvss():
    rows = risks.prioritise(
        [
            {"id": "CVE-2020-1111", "cvss": 10.0},
            {"id": "CVE-2019-0708", "cvss": 9.8},
        ],
        epss={"CVE-2019-0708": {"epss": 0.9, "percentile": 0.99}},
        kev={"CVE-2019-0708"},
    )
    assert rows[0]["id"] == "CVE-2019-0708"
    assert rows[0]["kev"] is True
    assert rows[0]["priority"] >= rows[1]["priority"]


def test_priority_is_bounded():
    assert risks.priority_score(10, 1.0, True) <= 1.0
    assert risks.priority_score(0, 0.0, False) == 0.0


def test_enrich_annotates_and_sorts(tmp_path):
    opener = FakeOpener({"epss": EPSS_PAYLOAD, "known_exploited": KEV_PAYLOAD})
    rows = risks.enrich(
        [{"id": "CVE-2021-44228", "cvss": 10.0}, {"id": "CVE-2019-0708", "cvss": 9.8}],
        opener=opener,
        cache_dir=tmp_path,
    )
    assert rows[0]["id"] == "CVE-2019-0708"  # KEV first
    assert rows[0]["epss"] > 0
    assert all("priority" in row for row in rows)
