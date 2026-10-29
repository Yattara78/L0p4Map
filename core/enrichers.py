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
    slow: bool = False  # network-heavy: opt-in for batch runs (UI still lists it)

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


def run_all(
    kind: str,
    value: str,
    only: Optional[list[str]] = None,
    include_slow: bool = False,
) -> dict[str, Any]:
    """Run applicable enrichers, returning {key: result}.

    Slow ones (HTTP fingerprint, AXFR, Certificate Transparency) are skipped
    unless `include_slow` or explicitly named in `only`.
    """
    results: dict[str, Any] = {}
    for enricher in for_value(kind, value):
        if only and enricher.key not in only:
            continue
        if enricher.slow and not include_slow and not (only and enricher.key in only):
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


TRACKER_PATTERNS = (
    "google-analytics", "googletagmanager", "gtag/js", "facebook.net",
    "hotjar", "matomo", "plausible.io", "segment.com", "mixpanel",
)


def http_fingerprint(value: str, opener: Optional[Callable] = None,
                     timeout: float = 6.0) -> dict:
    """Grab title / Server / tech hints and trackers from http(s) on 80 and 443."""
    import re
    import ssl

    endpoints: list[dict] = []
    for scheme, port in (("http", 80), ("https", 443)):
        url = f"{scheme}://{value}/"
        request = urllib.request.Request(
            url, headers={"User-Agent": "L0p4Map/1.0"}
        )
        kwargs: dict = {"timeout": timeout}
        if scheme == "https":
            kwargs["context"] = ssl._create_unverified_context()  # noqa: S323 - LAN appliances
        try:
            try:
                response = (opener or urllib.request.urlopen)(request, **kwargs)
            except TypeError:  # injected opener with a narrower signature
                response = (opener or urllib.request.urlopen)(request, timeout=timeout)
            with response:
                body = response.read(65536) or b""
                text = body.decode("utf-8", errors="ignore")
                headers = dict(response.headers.items())
                final_url = response.geturl() if hasattr(response, "geturl") else url
        except Exception as exc:  # noqa: BLE001 - closed port, TLS error, timeout
            endpoints.append({"url": url, "error": str(exc)})
            continue

        title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        generator = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', text, re.I
        )
        endpoints.append({
            "url": final_url,
            "status": int(getattr(response, "status", 0) or 0),
            "server": headers.get("Server", ""),
            "powered_by": headers.get("X-Powered-By", ""),
            "title": (title_match.group(1).strip()[:120] if title_match else ""),
            "generator": generator.group(1) if generator else "",
            "trackers": sorted({p for p in TRACKER_PATTERNS if p in text.lower()}),
            "links": len(re.findall(r"<a\s[^>]*href=", text, re.I)),
        })
    return {"ip": value, "endpoints": endpoints}


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
        "http_fingerprint", "Empreinte web", (IP_KIND,), http_fingerprint,
        "Titre, serveur, techno et trackers des pages 80/443", match=is_ip, slow=True,
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
        "Certificats émis pour le domaine (crt.sh)", slow=True,
    ))
    register(Enricher(
        "zone_transfer", "Transfert de zone (AXFR)", (DOMAIN_KIND,), zone_transfer,
        "Tente un AXFR sur les serveurs NS — à réserver aux domaines autorisés", slow=True,
    ))


register_builtins()
