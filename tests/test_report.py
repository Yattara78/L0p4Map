"""Report generation: HTML always, PDF when reportlab is available."""

import pytest

from core import report
from core.inventory import Inventory


@pytest.fixture()
def inventory(tmp_path):
    inv = Inventory(db_path=tmp_path / "inv.db")
    inv.record_scan(
        [
            {"ip": "10.0.0.5", "mac": "aa:bb:cc:00:00:01", "vendor": "Apple",
             "hostname": "mac-mini"},
            {"ip": "10.0.0.9", "mac": "aa:bb:cc:00:00:02", "vendor": "HP",
             "hostname": "printer"},
        ],
        subnet="10.0.0.0/24",
    )
    inv.set_meta("aa:bb:cc:00:00:01", label="Poste direction", group="Bureau")
    inv.record_ports("aa:bb:cc:00:00:02", [23, 80, 9100], service="printer")
    yield inv
    inv.close()


def test_collect_data_flags_risky_ports(inventory):
    data = report.collect_data(inventory, subnet="10.0.0.0/24", hostname="test-host")
    assert data["device_count"] == 2
    severities = {f["port"]: f["severity"] for f in data["findings"]}
    assert severities[23] == "HIGH"      # telnet
    assert severities[80] == "MEDIUM"    # http
    assert 9100 not in severities        # not in the risk lists
    # HIGH findings must be sorted before MEDIUM
    assert data["findings"][0]["severity"] == "HIGH"


def test_html_report_contains_inventory(inventory):
    data = report.collect_data(inventory, subnet="10.0.0.0/24")
    html = report.render_html(data)
    assert "Rapport d'audit réseau" in html
    assert "Poste direction" in html
    assert "10.0.0.9" in html
    assert "<table" in html
    # device fields are escaped
    assert "<script>" not in html


def test_html_report_escapes_device_names(tmp_path):
    inv = Inventory(db_path=tmp_path / "x.db")
    inv.record_scan([{"ip": "10.0.0.7", "mac": "aa:bb:cc:00:00:03",
                      "vendor": "<b>evil</b>", "hostname": "<script>x</script>"}])
    data = report.collect_data(inv)
    html = report.render_html(data)
    inv.close()
    assert "<script>x</script>" not in html
    assert "&lt;script&gt;" in html


def test_write_html_creates_file(inventory, tmp_path):
    data = report.collect_data(inventory)
    target = report.write_html(data, tmp_path / "out" / "rapport.html")
    assert target.exists()
    assert target.stat().st_size > 500


def test_write_pdf_creates_valid_file(inventory, tmp_path):
    pytest.importorskip("reportlab")
    data = report.collect_data(inventory, subnet="10.0.0.0/24")
    target = report.write_pdf(data, tmp_path / "rapport.pdf")
    assert target.exists()
    blob = target.read_bytes()
    assert blob.startswith(b"%PDF")
    assert len(blob) > 1500


def test_pdf_without_reportlab_raises_clear_error(inventory, tmp_path, monkeypatch):
    import builtins

    real_import = builtins.__import__

    def guarded(name, *args, **kwargs):
        if name.startswith("reportlab"):
            raise ImportError("no reportlab")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded)
    data = report.collect_data(inventory)
    with pytest.raises(report.ReportError):
        report.write_pdf(data, tmp_path / "x.pdf")
