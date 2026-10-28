"""CVE prioritisation: FIRST EPSS scores and the CISA KEV catalogue.

Both sources are public JSON over HTTPS and are cached in the user config dir
(EPSS 12 h, KEV 24 h). Everything degrades to "no data" instead of raising, so a
scan or a report never fails because an API is unreachable.
"""

from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable, Iterable, Optional

from core import settings

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
EPSS_TTL = 12 * 3600
KEV_TTL = 24 * 3600
BATCH_SIZE = 50


def _cache_path(name: str, cache_dir: Optional[str | Path]) -> Path:
    base = Path(cache_dir) if cache_dir else settings.CONFIG_DIR
    return base / f"{name}-cache.json"


def _read_cache(path: Path, ttl: float, now: float) -> Optional[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if now - float(data.get("fetched") or 0) > ttl:
        return None
    return data


def _write_cache(path: Path, payload: dict, now: float) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
        settings.fix_ownership(path)
        settings.fix_ownership(path.parent)
    except OSError:
        pass


def normalise(cve_ids: Iterable[str]) -> list[str]:
    return sorted({str(c).strip().upper() for c in cve_ids if str(c).strip()})


def fetch_epss(
    cve_ids: Iterable[str],
    opener: Optional[Callable] = None,
    cache_dir: Optional[str | Path] = None,
    now: Optional[float] = None,
) -> dict[str, dict]:
    """Return {CVE: {"epss": float, "percentile": float}} for the requested ids."""
    ids = normalise(cve_ids)
    if not ids:
        return {}
    now = time.time() if now is None else now
    path = _cache_path("epss", cache_dir)
    cached = _read_cache(path, EPSS_TTL, now) or {}
    scores: dict[str, dict] = dict(cached.get("scores") or {})

    missing = [cve for cve in ids if cve not in scores]
    if missing:
        open_fn = opener or urllib.request.urlopen
        for start in range(0, len(missing), BATCH_SIZE):
            chunk = missing[start:start + BATCH_SIZE]
            query = urllib.parse.urlencode({"cve": ",".join(chunk)})
            try:
                with open_fn(f"{EPSS_URL}?{query}", timeout=15) as response:
                    payload = json.loads(response.read() or b"{}")
            except Exception:  # noqa: BLE001 - offline / API change: keep going
                break
            for row in payload.get("data") or []:
                cve = str(row.get("cve", "")).upper()
                if not cve:
                    continue
                scores[cve] = {
                    "epss": float(row.get("epss") or 0.0),
                    "percentile": float(row.get("percentile") or 0.0),
                }
        _write_cache(path, {"fetched": now, "scores": scores}, now)

    return {cve: scores[cve] for cve in ids if cve in scores}


def fetch_kev(
    opener: Optional[Callable] = None,
    cache_dir: Optional[str | Path] = None,
    now: Optional[float] = None,
) -> set[str]:
    """Return the set of CVEs in CISA's Known Exploited Vulnerabilities list."""
    now = time.time() if now is None else now
    path = _cache_path("kev", cache_dir)
    cached = _read_cache(path, KEV_TTL, now)
    if cached is not None:
        return {str(c).upper() for c in cached.get("ids") or []}

    open_fn = opener or urllib.request.urlopen
    try:
        with open_fn(KEV_URL, timeout=20) as response:
            payload = json.loads(response.read() or b"{}")
    except Exception:  # noqa: BLE001
        try:  # stale cache is better than nothing
            stale = json.loads(path.read_text(encoding="utf-8"))
            return {str(c).upper() for c in stale.get("ids") or []}
        except (OSError, json.JSONDecodeError):
            return set()

    ids = {
        str(item.get("cveID", "")).upper()
        for item in payload.get("vulnerabilities") or []
        if item.get("cveID")
    }
    _write_cache(path, {"fetched": now, "ids": sorted(ids)}, now)
    return ids


def priority_score(cvss: float, epss: float, kev: bool) -> float:
    """0..1 blend: exploitation likelihood, severity, and known exploitation."""
    severity = min(max(float(cvss), 0.0), 10.0) / 10.0
    score = 0.5 * max(min(float(epss), 1.0), 0.0) + 0.3 * severity
    if kev:
        score += 0.2
    return round(min(score, 1.0), 3)


def prioritise(
    cves: Iterable[dict],
    epss: Optional[dict[str, dict]] = None,
    kev: Optional[set[str]] = None,
) -> list[dict]:
    """Annotate CVE dicts with epss/percentile/kev/priority, best first."""
    epss = epss or {}
    kev = kev or set()
    rows: list[dict] = []
    for cve in cves:
        cve_id = str(cve.get("id") or cve.get("cve") or "").upper()
        score = epss.get(cve_id, {})
        value = float(score.get("epss") or 0.0)
        is_kev = cve_id in kev
        row = dict(cve)
        row.update({
            "id": cve_id,
            "epss": value,
            "percentile": float(score.get("percentile") or 0.0),
            "kev": is_kev,
            "priority": priority_score(float(cve.get("cvss") or 0), value, is_kev),
        })
        rows.append(row)
    rows.sort(key=lambda r: (r["kev"], r["priority"]), reverse=True)
    return rows


def enrich(
    cves: Iterable[dict],
    opener: Optional[Callable] = None,
    cache_dir: Optional[str | Path] = None,
    now: Optional[float] = None,
) -> list[dict]:
    """Fetch both sources (best effort) then annotate the CVE list."""
    items = list(cves)
    ids = [str(c.get("id") or c.get("cve") or "") for c in items]
    scores = fetch_epss(ids, opener=opener, cache_dir=cache_dir, now=now)
    kev = fetch_kev(opener=opener, cache_dir=cache_dir, now=now)
    return prioritise(items, scores, kev)
