"""CLI smoke tests: no Qt, no network, no privileged calls."""

import json

import pytest

import l0p4map
from core import settings
from core.inventory import Inventory


def _seed(db_path):
    inv = Inventory(db_path=db_path)
    inv.record_scan(
        [{"ip": "10.0.0.5", "mac": "aa:bb:cc:00:00:01", "vendor": "Apple",
          "hostname": "mac-mini"}],
        subnet="10.0.0.0/24",
    )
    inv.close()


def test_inventory_empty(tmp_path, capsys):
    code = l0p4map.main(["--db", str(tmp_path / "i.db"), "inventory"])
    assert code == 0
    assert "inventaire vide" in capsys.readouterr().out


def test_inventory_json(tmp_path, capsys):
    _seed(tmp_path / "i.db")
    code = l0p4map.main(["--db", str(tmp_path / "i.db"), "inventory", "--json"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["ip"] == "10.0.0.5"
    assert payload[0]["name"] == "mac-mini"


def test_label_unknown_mac_exits_2(tmp_path):
    code = l0p4map.main(
        ["--db", str(tmp_path / "i.db"), "label", "ff:ff:ff:ff:ff:ff", "--label", "x"]
    )
    assert code == 2


def test_label_known_mac(tmp_path, capsys):
    _seed(tmp_path / "i.db")
    code = l0p4map.main(
        ["--db", str(tmp_path / "i.db"), "label", "aa:bb:cc:00:00:01",
         "--label", "Serveur", "--group", "Bureau"]
    )
    assert code == 0
    inv = Inventory(db_path=tmp_path / "i.db")
    assert inv.get("aa:bb:cc:00:00:01")["label"] == "Serveur"
    inv.close()


def test_events_command(tmp_path, capsys):
    _seed(tmp_path / "i.db")
    code = l0p4map.main(["--db", str(tmp_path / "i.db"), "events", "--json"])
    assert code == 0
    events = json.loads(capsys.readouterr().out)
    assert any(e["kind"] == "new_device" for e in events)


def test_report_html(tmp_path, capsys):
    _seed(tmp_path / "i.db")
    out = tmp_path / "rapport.html"
    code = l0p4map.main(
        ["--db", str(tmp_path / "i.db"), "report", "--format", "html", "--out", str(out)]
    )
    assert code == 0
    assert out.exists() and out.stat().st_size > 500
    body = out.read_text(encoding="utf-8")
    assert "mac-mini" in body


def test_schedule_writes_config(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(settings, "CONFIG_PATH", tmp_path / "config.json")
    code = l0p4map.main(["schedule", "--every", "30"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["enabled"] is True
    assert payload["interval_minutes"] == 30
    assert (tmp_path / "config.json").exists()


def test_scan_refuses_without_raw_sockets(tmp_path, capsys, monkeypatch):
    import core.scanner as scanner

    monkeypatch.setattr(scanner, "has_raw_socket_access", lambda: False)
    code = l0p4map.main(["--db", str(tmp_path / "i.db"), "scan", "--subnet", "10.0.0.0/30"])
    captured = capsys.readouterr()
    assert code == 2
    assert "sudo" in captured.err.lower() or "cap_net_raw" in captured.err.lower()


def test_unknown_command_fails():
    with pytest.raises(SystemExit):
        l0p4map.main(["nope"])
