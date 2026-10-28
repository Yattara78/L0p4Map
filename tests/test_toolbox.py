"""Network toolbox helpers: subnet math, DNS parsing, HTTP headers, port check."""

import socket

import pytest

from core import toolbox


# -- subnet ------------------------------------------------------------
def test_subnet_24():
    info = toolbox.subnet_info("192.168.1.0/24")
    assert info["usable_hosts"] == 254
    assert info["network"] == "192.168.1.0"
    assert info["broadcast"] == "192.168.1.255"
    assert info["first_host"] == "192.168.1.1"
    assert info["last_host"] == "192.168.1.254"
    assert info["private"] is True
    assert info["netmask"] == "255.255.255.0"


def test_subnet_single_host():
    info = toolbox.subnet_info("10.0.0.5/32")
    assert info["first_host"] == info["last_host"] == "10.0.0.5"
    assert info["usable_hosts"] == 1


def test_subnet_point_to_point():
    info = toolbox.subnet_info("10.0.0.0/31")
    assert info["usable_hosts"] == 2
    assert info["first_host"] == "10.0.0.0" and info["last_host"] == "10.0.0.1"


def test_subnet_ipv6():
    info = toolbox.subnet_info("2001:db8::/64")
    assert info["version"] == 6
    assert info["broadcast"] == ""
    assert info["first_host"] == "2001:db8::1"


def test_subnet_invalid_raises():
    with pytest.raises(ValueError):
        toolbox.subnet_info("not-a-network")


# -- DNS ---------------------------------------------------------------
class FakeAnswer:
    def __init__(self, text):
        self._text = text

    def to_text(self):
        return self._text


class FakeResolver:
    def __init__(self, mapping, explode=False):
        self.mapping = mapping
        self.explode = explode
        self.queries = []

    def resolve(self, name, record_type):
        self.queries.append((name, record_type))
        if self.explode:
            raise TimeoutError("no answer")
        return [FakeAnswer(v) for v in self.mapping.get(record_type, [])]


def test_dns_lookup_parses_records():
    resolver = FakeResolver({"A": ["93.184.216.34"], "MX": ["10 mail.example.com."]})
    result = toolbox.dns_lookup("example.com", resolver=resolver)
    assert result["records"]["A"] == ["93.184.216.34"]
    assert result["records"]["MX"] == ["10 mail.example.com"]
    assert result["records"]["TXT"] == []


def test_dns_lookup_handles_errors_per_type():
    resolver = FakeResolver({}, explode=True)
    result = toolbox.dns_lookup("nxdomain.test", resolver=resolver)
    assert all(values == [] for values in result["records"].values())
    assert result["error"], "the failure reason must be surfaced"


def test_dns_lookup_falls_back_to_getaddrinfo(monkeypatch):
    import dns.resolver  # noqa: F401  (ensure the module exists, then break it)

    def boom(*args, **kwargs):
        raise RuntimeError("no resolver")

    monkeypatch.setattr("dns.resolver.Resolver", boom)
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda host, port, family=0: [(None, None, None, None, ("127.0.0.1", 0))],
    )
    result = toolbox.dns_lookup("localhost")
    assert result["records"]["A"] == ["127.0.0.1"]


# -- HTTP --------------------------------------------------------------
class FakeHeaders(dict):
    def items(self):
        return super().items()


class FakeHTTPResponse:
    def __init__(self, status=200, headers=None, url="https://example.com/"):
        self.status = status
        self.headers = FakeHeaders(headers or {"Server": "nginx", "Content-Type": "text/html"})
        self._url = url

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def geturl(self):
        return self._url


def test_http_headers_adds_scheme_and_parses():
    seen = {}

    def opener(request, timeout=None):
        seen["url"] = request.full_url
        return FakeHTTPResponse()

    result = toolbox.http_headers("example.com", opener=opener)
    assert seen["url"] == "https://example.com"
    assert result["status"] == 200
    assert result["server"] == "nginx"
    assert result["headers"]["Content-Type"] == "text/html"


def test_http_headers_reports_failure():
    def opener(request, timeout=None):
        raise OSError("dns failure")

    result = toolbox.http_headers("http://nope.invalid", opener=opener)
    assert result["status"] == 0
    assert "dns failure" in result["error"]


# -- ports -------------------------------------------------------------
def test_quick_port_check_finds_listening_port():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        assert toolbox.quick_port_check("127.0.0.1", [port], timeout=0.5) == [port]
    finally:
        server.close()


def test_quick_port_check_skips_closed_port():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    server.close()  # now closed
    assert toolbox.quick_port_check("127.0.0.1", [port], timeout=0.2) == []
