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


def test_private_ip_gets_reverse_dns_only():
    keys = {e.key for e in enrichers.for_value("ip", "192.168.1.10")}
    assert keys == {"reverse_dns"}


def test_public_ip_gets_asn_enricher():
    keys = {e.key for e in enrichers.for_value("ip", "8.8.8.8")}
    assert keys == {"reverse_dns", "ip_asn"}


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
        "reverse_dns", "ip_asn", "dns", "whois", "cert_transparency", "zone_transfer"
    }


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
