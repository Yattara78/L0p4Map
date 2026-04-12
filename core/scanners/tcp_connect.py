"""Simple TCP connect scanner (pure Python).

Provides a fast, threads-based TCP connect scan which can be used
when nmap is not available. Returns a list of open ports.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
from typing import Iterable, List


def _check_port(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def tcp_connect_scan(host: str, ports: Iterable[int], workers: int = 100, timeout: float = 0.5) -> List[int]:
    """Scan a list/iterable of ports on host using TCP connect.

    Returns a list of open ports (ints). This intentionally avoids
    external dependencies so it's usable in most environments.
    """
    open_ports: List[int] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_check_port, host, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            port = futures[fut]
            try:
                if fut.result():
                    open_ports.append(port)
            except Exception:
                # ignore per-port errors
                pass
    open_ports.sort()
    return open_ports
