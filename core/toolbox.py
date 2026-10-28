"""Small network utilities shared by the GUI dialog and the CLI.

Pure functions with optional injection points (`opener`, `resolver`) so they can
be tested without touching the network.
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.error
import urllib.request
from typing import Any, Callable, Iterable, Optional


def subnet_info(cidr: str) -> dict[str, Any]:
    """Network/broadcast/usable hosts for a CIDR block."""
    net = ipaddress.ip_network(str(cidr).strip(), strict=False)
    if net.version == 4:
        if net.prefixlen <= 30:
            first = str(net.network_address + 1)
            last = str(net.broadcast_address - 1)
            usable = net.num_addresses - 2
        else:  # /31 point-to-point and /32 single host
            first = str(net.network_address)
            last = str(net.broadcast_address)
            usable = net.num_addresses
        broadcast = str(net.broadcast_address)
    else:
        first = str(net.network_address + 1)
        last = str(net.network_address + net.num_addresses - 1)
        usable = net.num_addresses
        broadcast = ""

    return {
        "cidr": str(net),
        "version": net.version,
        "prefix": net.prefixlen,
        "netmask": str(net.netmask),
        "network": str(net.network_address),
        "broadcast": broadcast,
        "first_host": first,
        "last_host": last,
        "total_addresses": net.num_addresses,
        "usable_hosts": usable,
        "private": net.is_private,
    }


class _Answer:
    def __init__(self, text: str) -> None:
        self._text = text

    def to_text(self) -> str:
        return self._text


def dns_lookup(
    name: str,
    record_types: Iterable[str] = ("A", "AAAA", "MX", "NS", "TXT"),
    timeout: float = 5.0,
    resolver: Optional[Any] = None,
) -> dict[str, Any]:
    """Query DNS records, falling back to getaddrinfo when dnspython is absent."""
    result: dict[str, Any] = {"name": name, "records": {}, "error": ""}

    if resolver is None:
        try:
            import dns.resolver as dns_resolver

            resolver = dns_resolver.Resolver()
            resolver.lifetime = timeout
        except Exception:  # noqa: BLE001 - no dnspython: fall back below
            resolver = None

    if resolver is not None:
        errors: list[str] = []
        for record_type in record_types:
            try:
                answers = resolver.resolve(name, record_type)
                values = []
                for answer in answers:
                    text = answer.to_text() if hasattr(answer, "to_text") else str(answer)
                    values.append(text.strip('"').rstrip("."))
                result["records"][record_type] = values
            except Exception as exc:  # noqa: BLE001 - NXDOMAIN / NoAnswer / timeout
                result["records"][record_type] = []
                errors.append(str(exc))
        if errors and not any(result["records"].values()):
            # every type failed: surface the reason instead of a wall of dashes
            result["error"] = errors[0]
        return result

    try:
        addresses = socket.getaddrinfo(name, None, socket.AF_INET)
        result["records"]["A"] = sorted({info[4][0] for info in addresses})
    except OSError as exc:
        result["error"] = str(exc)
    return result


def http_headers(
    url: str,
    timeout: float = 5.0,
    opener: Optional[Callable] = None,
) -> dict[str, Any]:
    """Fetch a URL and return status + headers (no body kept in memory)."""
    target = url.strip()
    if not target.lower().startswith(("http://", "https://")):
        target = "https://" + target
    request = urllib.request.Request(
        target, method="GET", headers={"User-Agent": "L0p4Map/1.0"}
    )
    open_fn = opener or urllib.request.urlopen
    try:
        with open_fn(request, timeout=timeout) as response:
            headers = dict(response.headers.items())
            return {
                "url": response.geturl(),
                "status": int(response.status),
                "server": headers.get("Server", ""),
                "headers": headers,
                "error": "",
            }
    except urllib.error.HTTPError as exc:
        headers = dict((exc.headers or {}).items())
        return {
            "url": target,
            "status": int(exc.code),
            "server": headers.get("Server", ""),
            "headers": headers,
            "error": "",
        }
    except Exception as exc:  # noqa: BLE001 - surface the reason to the UI
        return {"url": target, "status": 0, "server": "", "headers": {}, "error": str(exc)}


def quick_port_check(host: str, ports: Iterable[int], timeout: float = 0.5) -> list[int]:
    """TCP connect scan of a few ports (no raw sockets needed)."""
    open_ports: list[int] = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((host, int(port))) == 0:
                open_ports.append(int(port))
    return open_ports
