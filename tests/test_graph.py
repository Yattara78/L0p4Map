"""Graph payload: devices plus service nodes (Qt-free)."""

import pytest

from core import graph
from core.inventory import Inventory


@pytest.fixture()
def inventory(tmp_path):
    inv = Inventory(db_path=tmp_path / "graph.db")
    inv.record_scan([
        {"ip": "10.0.0.5", "mac": "aa:bb:cc:00:00:01", "vendor": "Apple", "hostname": "mac"},
        {"ip": "10.0.0.9", "mac": "aa:bb:cc:00:00:02", "vendor": "HP", "hostname": "printer"},
    ])
    inv.record_ports("aa:bb:cc:00:00:01", [22, 80, 443])
    inv.record_ports("aa:bb:cc:00:00:02", [9100])
    yield inv
    inv.close()


HOSTS = [
    {"ip": "10.0.0.5", "mac": "aa:bb:cc:00:00:01", "vendor": "Apple", "hostname": "mac"},
    {"ip": "10.0.0.9", "mac": "aa:bb:cc:00:00:02", "vendor": "HP", "hostname": "printer"},
]


def test_service_nodes_per_device(inventory):
    services = graph.service_nodes(HOSTS, inventory)
    assert len(services) == 4
    assert {s["port"] for s in services} == {22, 80, 443, 9100}
    assert all(s["mac"].startswith("AA:BB:CC") for s in services)


def test_service_nodes_cap(inventory):
    services = graph.service_nodes(HOSTS, inventory, max_per_device=2)
    assert len(services) == 3  # 2 for the mac + 1 for the printer


def test_service_nodes_without_inventory():
    assert graph.service_nodes(HOSTS, None) == []


def test_service_nodes_skips_devices_without_mac(inventory):
    services = graph.service_nodes([{"ip": "10.0.0.7", "mac": ""}], inventory)
    assert services == []


def test_build_payload_shape(inventory):
    payload = graph.build_payload(HOSTS, inventory)
    assert len(payload["devices"]) == 2
    assert len(payload["services"]) == 4
    assert {"devices", "services"} == set(payload)


def test_summarise():
    assert graph.summarise({"devices": [], "services": []}) == "0 appareils"
    assert graph.summarise({"devices": [1], "services": []}) == "1 appareil"
    assert graph.summarise({"devices": [1], "services": [1, 2]}) == "1 appareil · 2 services"
