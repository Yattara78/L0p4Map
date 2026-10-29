"""Enricher registry: one entity value in, one structured result out.

This mirrors the model that makes Flowsint useful — the UI does not know what an
"action" is, it only lists the enrichers that declare they can handle the value
under the cursor. Adding a capability means registering it here, not editing
`ui/app.py`.
"""

from __future__ import annotations

import ipaddress
import json
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Optional

IP_KIND = "ip"
DOMAIN_KIND = "domain"

IPINFO_URL = "https://ipinfo.io/{ip}/json"


# -- type predicates ---------------------------------------------------
def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(str(value).strip()).is_global
    except ValueError:
        return False


def looks_like_domain(value: str) -> bool:
    candidate = (value or "").strip().rstrip(".")
    if not candidate or is_ip(candidate) or "." not in candidate:
        return False
    return all(
        part and part.replace("-", "").isalnum() for part in candidate.split(".")
    )


# -- registry ----------------------------------------------------------
@dataclass(frozen=True)
class Enricher:
    key: str
    label: str
    kinds: tuple[str, ...]
    run: Callable[[str], Any]
    description: str = ""
    match: Optional[Callable[[str], bool]] = None

    def applies(self, kind: str, value: str) -> bool:
        if kind not in self.kinds or not (value or "").strip():
            return False
        return self.match(value) if self.match else True


_REGISTRY: dict[str, Enricher] = {}


def register(enricher: Enricher) -> Enricher:
    _REGISTRY[enricher.key] = enricher
    return enricher


def get(key: str) -> Optional[Enricher]:
    return _REGISTRY.get(key)


def all_enrichers() -> tuple[Enricher, ...]:
    return tuple(_REGISTRY.values())


def for_value(kind: str, value: str) -> tuple[Enricher, ...]:
    return tuple(e for e in _REGISTRY.values() if e.applies(kind, value))


def run_all(kind: str, value: str, only: Optional[list[str]] = None) -> dict[str, Any]:
    """Run every applicable enricher, returning {key: result}."""
    results: dict[str, Any] = {}
    for enricher in for_value(kind, value):
        if only and enricher.key not in only:
            continue
        results[enricher.key] = enricher.run(value)
    return results


# -- built-in enrichers ------------------------------------------------
def _passive_recon():
    from core.scanners import passive_recon

    return passive_recon


def reverse_dns(value: str) -> dict:
    try:
        return {"ip": value, "hostname": _passive_recon().reverse_dns_lookup(value)}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def dns_records(value: str) -> dict:
    try:
        return _passive_recon().dns_lookup(value)
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def whois(value: str) -> dict:
    try:
        return _passive_recon().whois_lookup(value)
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def cert_transparency(value: str) -> dict:
    try:
        return {"entries": _passive_recon().ssl_cert_transparency(value)}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def zone_transfer(value: str) -> dict:
    try:
        return _passive_recon().dns_zone_transfer(value)
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def ip_asn(value: str, opener: Optional[Callable] = None) -> dict:
    """Owner/ASN and geolocation for a public IP (ipinfo.io, no key needed)."""
    request = urllib.request.Request(
        IPINFO_URL.format(ip=value), headers={"User-Agent": "L0p4Map/1.0"}
    )
    try:
        with (opener or urllib.request.urlopen)(request, timeout=8) as response:
            payload = json.loads(response.read() or b"{}")
    except Exception as exc:  # noqa: BLE001 - offline / rate limited
        return {"error": str(exc)}

    org = str(payload.get("org") or "")
    asn, _, as_name = org.partition(" ")
    return {
        "ip": payload.get("ip", value),
        "asn": asn if asn.upper().startswith("AS") else "",
        "organisation": as_name or org,
        "hostname": payload.get("hostname", ""),
        "city": payload.get("city", ""),
        "region": payload.get("region", ""),
        "country": payload.get("country", ""),
        "timezone": payload.get("timezone", ""),
    }


def register_builtins() -> None:
    register(Enricher(
        "reverse_dns", "Reverse DNS", (IP_KIND,), reverse_dns,
        "Nom DNS associé à l'adresse IP", match=is_ip,
    ))
    register(Enricher(
        "ip_asn", "ASN / géolocalisation", (IP_KIND,), ip_asn,
        "Propriétaire du réseau, ville, pays (ipinfo.io)", match=is_public_ip,
    ))
    register(Enricher(
        "dns", "Enregistrements DNS", (DOMAIN_KIND,), dns_records,
        "A / AAAA / MX / TXT / NS / SOA",
    ))
    register(Enricher(
        "whois", "WHOIS", (DOMAIN_KIND,), whois,
        "Registraire, dates et contacts du domaine",
    ))
    register(Enricher(
        "cert_transparency", "Certificate Transparency", (DOMAIN_KIND,), cert_transparency,
        "Certificats émis pour le domaine (crt.sh)",
    ))
    register(Enricher(
        "zone_transfer", "Transfert de zone (AXFR)", (DOMAIN_KIND,), zone_transfer,
        "Tente un AXFR sur les serveurs NS — à réserver aux domaines autorisés",
    ))


register_builtins()
