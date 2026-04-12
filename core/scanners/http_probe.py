"""HTTP probe utilities using requests.

Probe an HTTP(S) endpoint and return basic metadata (status, headers).
"""
import requests
from typing import Dict, Optional


def http_probe(host: str, port: int = 80, timeout: float = 2.0) -> Dict[str, Optional[str]]:
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}/"
    result = {"url": url, "status_code": None, "server": None, "error": None}
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
        result["status_code"] = str(resp.status_code)
        result["server"] = resp.headers.get("Server")
    except Exception as e:
        result["error"] = str(e)
    return result
