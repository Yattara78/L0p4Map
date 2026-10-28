"""Inventory: diff between scans, ports history, labels (P1 core feature)."""

import pytest

from core.inventory import (
    EVENT_MISSING_DEVICE,
    EVENT_NEW_DEVICE,
    EVENT_NEW_PORT,
    Inventory,
)


@pytest.fixture()
def inv(tmp_path):
    inventory = Inventory(db_path=tmp_path / "inv.db", clock=lambda: 1000.0)
    yield inventory
    inventory.close()


HOSTS = [
    {"ip": "192.168.1.10", "mac": "aa:bb:cc:00:00:01", "vendor": "Apple", "hostname": "mac-mini"},
    {"ip": "192.168.1.20", "mac": "AA:BB:CC:00:00:02", "vendor": "Ubiquiti", "hostname": "ap"},
]


def test_first_scan_reports_everything_as_new(inv):
    diff = inv.record_scan(HOSTS, subnet="192.168.1.0/24")
    assert len(diff.seen) == 2
    assert {d["mac"] for d in diff.new} == {"AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"}
    assert diff.missing == []
    assert diff.has_changes
    assert inv.stats()["devices"] == 2
    assert any(e["kind"] == EVENT_NEW_DEVICE for e in inv.events())


def test_second_scan_with_same_hosts_has_no_changes(inv):
    inv.record_scan(HOSTS)
    diff = inv.record_scan(HOSTS)
    assert diff.new == [] and diff.missing == [] and diff.changed == []
    assert not diff.has_changes
    assert inv.stats()["scans"] == 2


def test_disappearing_device_is_reported_once(inv):
    inv.record_scan(HOSTS)
    diff = inv.record_scan(HOSTS[:1])
    assert [d["mac"] for d in diff.missing] == ["AA:BB:CC:00:00:02"]
    kinds = [e["kind"] for e in inv.events()]
    assert EVENT_MISSING_DEVICE in kinds

    # still absent on the next scan: no duplicate alert
    diff2 = inv.record_scan(HOSTS[:1])
    assert diff2.missing == []


def test_ip_change_is_flagged(inv):
    inv.record_scan(HOSTS)
    moved = [dict(HOSTS[0], ip="192.168.1.99"), HOSTS[1]]
    diff = inv.record_scan(moved)
    assert diff.changed and diff.changed[0]["field"] == "ip"
    assert diff.changed[0]["old"] == "192.168.1.10"
    assert inv.get("aa:bb:cc:00:00:01")["ip"] == "192.168.1.99"


def test_mac_is_normalised_to_uppercase(inv):
    inv.record_scan(HOSTS)
    assert inv.get("aa:bb:cc:00:00:01") is not None
    assert inv.get("AA:BB:CC:00:00:01") is not None


def test_ports_history_reports_new_ports_once(inv):
    inv.record_scan(HOSTS)
    assert inv.record_ports("aa:bb:cc:00:00:01", [22, 80]) == [22, 80]
    assert inv.record_ports("aa:bb:cc:00:00:01", [80, 443]) == [443]
    assert [p["port"] for p in inv.ports("aa:bb:cc:00:00:01")] == [22, 80, 443]
    assert sum(1 for e in inv.events() if e["kind"] == EVENT_NEW_PORT) == 3


def test_ports_recorded_within_scan_update_diff(inv):
    diff = inv.record_scan(HOSTS, ports_by_mac={"aa:bb:cc:00:00:02": [23]})
    assert diff.new_ports == [{"mac": "AA:BB:CC:00:00:02", "port": 23, "proto": "tcp"}]


def test_labels_and_groups(inv):
    inv.record_scan(HOSTS)
    assert inv.set_meta("aa:bb:cc:00:00:01", label="Serveur salon", group="Maison")
    device = inv.get("aa:bb:cc:00:00:01")
    assert device["label"] == "Serveur salon"
    assert device["name"] == "Serveur salon"
    assert device["group"] == "Maison"
    assert [d["mac"] for d in inv.devices(group="maison")] == ["AA:BB:CC:00:00:01"]


def test_set_meta_only_touches_given_fields(inv):
    inv.record_scan(HOSTS)
    inv.set_meta("aa:bb:cc:00:00:01", label="A", notes="note")
    inv.set_meta("aa:bb:cc:00:00:01", group="IoT")
    device = inv.get("aa:bb:cc:00:00:01")
    assert device["label"] == "A" and device["notes"] == "note"
    assert device["group"] == "IoT"


def test_set_meta_unknown_mac_returns_false(inv):
    assert inv.set_meta("ff:ff:ff:ff:ff:ff", label="x") is False


def test_empty_scan_keeps_inventory(inv):
    inv.record_scan(HOSTS)
    diff = inv.record_scan([])
    assert diff.seen == []
    assert len(diff.missing) == 2
    assert inv.stats()["devices"] == 2
