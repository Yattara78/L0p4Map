import socket

from core.scanners.tcp_connect import tcp_connect_scan
from core.scanners.http_probe import http_probe
from core.scanners.ssl_info import get_ssl_info


def test_tcp_connect_scan_runs():
    # Just ensure the function runs and returns a list (may be empty)
    ports = [22, 80, 443]
    result = tcp_connect_scan("127.0.0.1", ports, workers=10, timeout=0.2)
    assert isinstance(result, list)


def test_http_probe_runs():
    # Probe localhost on a port unlikely to respond; just ensure no crash
    info = http_probe("127.0.0.1", 8080, timeout=0.5)
    assert isinstance(info, dict)


def test_ssl_info_runs():
    # Attempt to fetch ssl info from localhost:443 (may return error) but must be dict
    info = get_ssl_info("127.0.0.1", 443, timeout=0.5)
    assert isinstance(info, dict)
