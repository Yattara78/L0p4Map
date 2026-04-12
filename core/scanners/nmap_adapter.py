"""Optional adapter for python-nmap.

Provides a thin wrapper around nmap.PortScanner if installed.
"""
from typing import Dict, Any, Optional

try:
    import nmap
except Exception:
    nmap = None


def run_nmap(target: str, options: str = "-sV -O") -> Dict[str, Any]:
    if nmap is None:
        return {"error": "python-nmap not installed"}
    scanner = nmap.PortScanner()
    try:
        res = scanner.scan(hosts=target, arguments=options)
        return res
    except Exception as e:
        return {"error": str(e)}
