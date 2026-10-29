"""Enricher registry: predicates, selection by entity type, ipinfo parsing."""

import json

import pytest

from core import enrichers


class FakeResponse:
    def __init__(self, payload):
        self._payload = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._payload


def test_predicates():
    assert enrichers.is_ip("10.0.0.1") and not enrichers.is_ip("example.com")
    assert enrichers.is_public_ip("8.8.8.8")
    assert not enrichers.is_public_ip("192.168.1.10")
    assert enrichers.looks_like_domain("nas.local")
    assert not enrichers.looks_like_domain("mac-mini")
    assert not enrichers.looks_like_domain("192.168.1.10")
    assert not enrichers.looks_like_domain("")


def test_private_ip_gets_reverse_dns_and_fingerprint():
    keys = {e.key for e in enrichers.for_value("ip", "192.168.1.10")}
    assert keys == {"reverse_dns", "http_fingerprint"}


def test_public_ip_gets_asn_enricher():
    keys = {e.key for e in enrichers.for_value("ip", "8.8.8.8")}
    assert keys == {"reverse_dns", "http_fingerprint", "ip_asn"}


def test_slow_enrichers_are_opt_in():
    fast = enrichers.run_all("ip", "192.168.1.10", only=["reverse_dns"])
    assert set(fast) == {"reverse_dns"}
    assert enrichers.get("http_fingerprint").slow is True
    assert enrichers.get("whois").slow is False


def test_domain_gets_four_enrichers():
    keys = {e.key for e in enrichers.for_value("domain", "example.com")}
    assert keys == {"dns", "whois", "cert_transparency", "zone_transfer"}


def test_no_enricher_for_unknown_kind():
    assert enrichers.for_value("device", "10.0.0.1") == ()
    assert enrichers.for_value("ip", "") == ()


def test_registry_lookup():
    assert enrichers.get("whois") is not None
    assert enrichers.get("does-not-exist") is None
    assert {e.key for e in enrichers.all_enrichers()} >= {
        "reverse_dns", "ip_asn", "dns", "whois", "cert_transparency", "zone_transfer",
        "http_fingerprint",
    }


class FakeHTTPResponse:
    def __init__(self, body: bytes, headers=None, status=200, url="http://10.0.0.9/"):
        self._body = body
        self.headers = headers or {}
        self.status = status
        self._url = url

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, size=None):
        return self._body

    def geturl(self):
        return self._url


CAMERA_HTML = (
    b"<html><head><title>Camera IP</title>"
    b"<meta name='generator' content='Hikvision'>"
    b"<script src='https://www.google-analytics.com/ga.js'></script>"
    b"</head><body><a href='/a'>a</a><a href='/b'>b</a></body></html>"
)


def test_http_fingerprint_parses_page():
    def opener(request, timeout=None, context=None):
        if request.full_url.startswith("http://"):
            return FakeHTTPResponse(
                CAMERA_HTML, {"Server": "nginx", "X-Powered-By": "PHP/8.1"}
            )
        raise OSError("connection refused")

    data = enrichers.http_fingerprint("10.0.0.9", opener=opener)
    endpoint = data["endpoints"][0]
    assert endpoint["title"] == "Camera IP"
    assert endpoint["server"] == "nginx"
    assert endpoint["powered_by"] == "PHP/8.1"
    assert endpoint["generator"] == "Hikvision"
    assert "google-analytics" in endpoint["trackers"]
    assert endpoint["links"] == 2
    assert "connection refused" in data["endpoints"][1]["error"]


def test_http_fingerprint_survives_both_ports_closed():
    def opener(request, timeout=None, context=None):
        raise TimeoutError("timed out")

    data = enrichers.http_fingerprint("10.0.0.9", opener=opener)
    assert len(data["endpoints"]) == 2
    assert all("timed out" in ep["error"] for ep in data["endpoints"])


def test_http_fingerprint_registered_for_ips():
    keys = {e.key for e in enrichers.for_value("ip", "192.168.1.10")}
    assert "http_fingerprint" in keys


def test_ip_asn_parses_ipinfo_payload():
    def opener(request, timeout=None):
        assert "8.8.8.8" in request.full_url
        return FakeResponse({
            "ip": "8.8.8.8", "org": "AS15169 Google LLC", "city": "Mountain View",
            "region": "California", "country": "US", "timezone": "America/Los_Angeles",
            "hostname": "dns.google",
        })

    data = enrichers.ip_asn("8.8.8.8", opener=opener)
    assert data["asn"] == "AS15169"
    assert data["organisation"] == "Google LLC"
    assert data["country"] == "US"
    assert data["hostname"] == "dns.google"


def test_ip_asn_reports_failure():
    def opener(request, timeout=None):
        raise OSError("offline")

    assert "offline" in enrichers.ip_asn("8.8.8.8", opener=opener)["error"]


def test_reverse_dns_wraps_passive_recon(monkeypatch):
    from core.scanners import passive_recon

    monkeypatch.setattr(
        passive_recon, "reverse_dns_lookup", lambda ip: "mac-mini.local"
    )
    assert enrichers.reverse_dns("192.168.1.10")["hostname"] == "mac-mini.local"


def test_enricher_failure_is_captured(monkeypatch):
    from core.scanners import passive_recon

    def boom(ip):
        raise RuntimeError("resolver down")

    monkeypatch.setattr(passive_recon, "reverse_dns_lookup", boom)
    assert "resolver down" in enrichers.reverse_dns("192.168.1.10")["error"]


def test_run_all_respects_only(monkeypatch):
    from core.scanners import passive_recon

    monkeypatch.setattr(passive_recon, "reverse_dns_lookup", lambda ip: "x.local")
    results = enrichers.run_all("ip", "192.168.1.10", only=["reverse_dns"])
    assert list(results) == ["reverse_dns"]


def test_run_all_skips_when_nothing_applies():
    assert enrichers.run_all("device", "mac-mini") == {}


def test_enricher_is_hashable_and_immutable():
    enricher = enrichers.get("whois")
    assert enricher in {enricher}
    with pytest.raises(Exception):
        enricher.key = "other"  # type: ignore[misc]
