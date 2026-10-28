"""Client-facing report: HTML (always) and PDF (when reportlab is installed).

Data comes from the inventory; the PDF layout is deliberately simple so it stays
readable when printed and never depends on the GUI.
"""

from __future__ import annotations

import html
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Optional

from core.inventory import Inventory

HIGH_RISK_PORTS = {
    21: "FTP", 23: "Telnet", 25: "SMTP", 110: "POP3", 135: "RPC",
    139: "NetBIOS", 445: "SMB", 512: "rexec", 513: "rlogin", 514: "rsh",
    3389: "RDP", 5900: "VNC", 6379: "Redis", 27017: "MongoDB",
}
MEDIUM_RISK_PORTS = {
    22: "SSH", 80: "HTTP", 8080: "HTTP-alt", 3306: "MySQL", 5432: "PostgreSQL",
    1433: "MSSQL", 2375: "Docker", 2376: "Docker TLS", 4444: "Metasploit",
}


class ReportError(RuntimeError):
    """Raised when the PDF backend is unavailable."""


def _fmt_ts(value: Optional[float]) -> str:
    if not value:
        return "—"
    return datetime.fromtimestamp(float(value)).strftime("%Y-%m-%d %H:%M")


def collect_data(
    inventory: Inventory,
    subnet: str = "",
    cves: Optional[Iterable[dict]] = None,
    hostname: Optional[str] = None,
) -> dict[str, Any]:
    """Snapshot of the inventory plus derived risk findings."""
    devices = inventory.devices()
    findings: list[dict] = []

    for device in devices:
        for entry in inventory.ports(device["mac"]):
            port = int(entry["port"])
            if port in HIGH_RISK_PORTS:
                severity, label = "HIGH", HIGH_RISK_PORTS[port]
            elif port in MEDIUM_RISK_PORTS:
                severity, label = "MEDIUM", MEDIUM_RISK_PORTS[port]
            else:
                continue
            findings.append({
                "severity": severity,
                "mac": device["mac"],
                "ip": device["ip"],
                "name": device["name"],
                "port": port,
                "service": entry.get("service") or label,
                "detail": f"{port}/{entry.get('proto', 'tcp')} {label} exposé",
            })

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda f: (order.get(f["severity"], 3), f["ip"]))

    stats = inventory.stats()
    import socket

    return {
        "generated_at": _fmt_ts(time.time()),
        "hostname": hostname or socket.gethostname(),
        "subnet": subnet or "—",
        "scans": stats["scans"],
        "device_count": stats["devices"],
        "groups": stats["groups"],
        "devices": devices,
        "findings": findings,
        "cves": list(cves or []),
    }


def _count(count: int, word: str, plural: Optional[str] = None) -> str:
    plural = plural or f"{word}s"
    return f"{count} {word if count in (0, 1) else plural}"


def _severity_counts(findings: Iterable[dict]) -> dict[str, int]:
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    return counts


# -- HTML -------------------------------------------------------------
HTML_STYLE = """
body { font-family: -apple-system, "Helvetica Neue", Arial, sans-serif;
       margin: 32px; color: #1a1a1a; }
h1 { font-size: 26px; margin-bottom: 4px; }
h2 { font-size: 16px; margin-top: 28px; border-bottom: 1px solid #ddd;
     padding-bottom: 4px; text-transform: uppercase; letter-spacing: 1px; }
.meta { color: #666; font-size: 12px; }
.kpis { display: flex; gap: 16px; margin-top: 18px; }
.kpi { border: 1px solid #ddd; border-radius: 6px; padding: 10px 16px; min-width: 120px; }
.kpi .n { font-size: 22px; font-weight: bold; }
.kpi .l { color: #666; font-size: 11px; text-transform: uppercase; }
table { border-collapse: collapse; width: 100%; font-size: 11px; margin-top: 10px; }
th, td { border-bottom: 1px solid #eee; padding: 6px 8px; text-align: left; }
th { background: #f6f6f6; font-size: 10px; text-transform: uppercase; letter-spacing: .5px; }
.HIGH { color: #b00020; font-weight: bold; }
.MEDIUM { color: #b26a00; font-weight: bold; }
.LOW { color: #555; }
footer { margin-top: 36px; color: #888; font-size: 10px; }
"""


def render_html(data: dict) -> str:
    esc = html.escape
    counts = _severity_counts(data["findings"])

    rows = "".join(
        f"<tr><td>{esc(d['ip'] or '—')}</td><td>{esc(d['mac'])}</td>"
        f"<td>{esc(d['name'])}</td><td>{esc(d['vendor'] or '—')}</td>"
        f"<td>{esc(d['group'] or '—')}</td><td>{_fmt_ts(d['first_seen'])}</td>"
        f"<td>{_fmt_ts(d['last_seen'])}</td></tr>"
        for d in data["devices"]
    )

    finding_rows = "".join(
        f"<tr><td class='{esc(f['severity'])}'>{esc(f['severity'])}</td>"
        f"<td>{esc(f['ip'] or '—')}</td><td>{esc(f['name'])}</td>"
        f"<td>{esc(f['detail'])}</td></tr>"
        for f in data["findings"]
    ) or "<tr><td colspan='4'>Aucun port à risque détecté.</td></tr>"

    cve_rows = "".join(
        f"<tr><td>{esc(str(c.get('id', c.get('cve', ''))))}</td>"
        f"<td>{esc(str(c.get('host', '')))}</td>"
        f"<td>{esc(str(c.get('port', '')))}</td>"
        f"<td>{esc(str(c.get('cvss', '')))}</td>"
        f"<td>{esc(str(c.get('severity', '')))}</td></tr>"
        for c in data["cves"]
    )

    cve_section = ""
    if cve_rows:
        cve_section = f"""
  <h2>Vulnérabilités connues</h2>
  <table><tr><th>CVE</th><th>Hôte</th><th>Port</th><th>CVSS</th><th>Sévérité</th></tr>
  {cve_rows}</table>"""

    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<title>Rapport L0p4Map — {esc(data['hostname'])}</title>
<style>{HTML_STYLE}</style></head>
<body>
  <h1>Rapport d'audit réseau</h1>
  <div class="meta">Généré le {esc(data['generated_at'])} par L0p4Map ·
    machine {esc(data['hostname'])} · réseau {esc(data['subnet'])}</div>

  <div class="kpis">
    <div class="kpi"><div class="n">{data['device_count']}</div><div class="l">appareils</div></div>
    <div class="kpi"><div class="n">{data['scans']}</div><div class="l">scans</div></div>
    <div class="kpi"><div class="n">{counts['HIGH']}</div><div class="l">risques élevés</div></div>
    <div class="kpi"><div class="n">{counts['MEDIUM']}</div><div class="l">risques moyens</div></div>
  </div>

  <h2>Appareils</h2>
  <table>
    <tr><th>IP</th><th>MAC</th><th>Nom</th><th>Constructeur</th><th>Groupe</th>
        <th>Vu le</th><th>Dernière activité</th></tr>
    {rows or "<tr><td colspan='7'>Aucun appareil enregistré.</td></tr>"}
  </table>

  <h2>Exposition</h2>
  <table><tr><th>Sévérité</th><th>Hôte</th><th>Nom</th><th>Détail</th></tr>
    {finding_rows}</table>
  {cve_section}

  <footer>L0p4Map — rapport généré automatiquement. Les ports et CVE listés
  reflètent les scans enregistrés dans l'inventaire local ; à vérifier avant
  remise au client.</footer>
</body></html>"""


def write_html(data: dict, path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_html(data), encoding="utf-8")
    return target


# -- PDF --------------------------------------------------------------
def write_pdf(data: dict, path: str | Path) -> Path:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
        )
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise ReportError(
            "reportlab est requis pour le PDF : pip install reportlab"
        ) from exc

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("L0H1", parent=styles["Title"], fontSize=22, spaceAfter=6)
    h2 = ParagraphStyle("L0H2", parent=styles["Heading2"], fontSize=13, spaceBefore=14,
                        spaceAfter=6, textColor=colors.HexColor("#222222"))
    small = ParagraphStyle("L0Small", parent=styles["Normal"], fontSize=8.5, leading=11)
    body = ParagraphStyle("L0Body", parent=styles["Normal"], fontSize=9.5, leading=13)

    def table(header, rows, widths, severity_col=None):
        payload = [header] + rows
        tbl = Table(payload, colWidths=widths, repeatRows=1)
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f0f0")),
            ("FONT SIZE", (0, 0), (-1, -1), 7.8),
            ("FONT NAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#dddddd")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafafa")]),
        ]
        if severity_col is not None:
            for index, row in enumerate(rows, start=1):
                value = str(row[severity_col])
                if value == "HIGH":
                    style.append(("TEXTCOLOR", (severity_col, index),
                                  (severity_col, index), colors.HexColor("#b00020")))
                elif value == "MEDIUM":
                    style.append(("TEXTCOLOR", (severity_col, index),
                                  (severity_col, index), colors.HexColor("#b26a00")))
        tbl.setStyle(TableStyle(style))
        return tbl

    counts = _severity_counts(data["findings"])
    doc = SimpleDocTemplate(
        str(target), pagesize=A4,
        leftMargin=15 * mm, rightMargin=15 * mm,
        topMargin=15 * mm, bottomMargin=15 * mm,
        title="Rapport L0p4Map", author="L0p4Map",
    )

    story: list[Any] = [
        Paragraph("Rapport d'audit réseau", h1),
        Paragraph(
            f"Généré le {html.escape(data['generated_at'])} · machine "
            f"{html.escape(data['hostname'])} · réseau {html.escape(data['subnet'])}",
            small,
        ),
        Spacer(1, 8 * mm),
        Paragraph(
            f"{_count(data['device_count'], 'appareil')} inventoriés · "
            f"{_count(data['scans'], 'scan')} · "
            f"{_count(counts['HIGH'], 'risque élevé', 'risques élevés')} · "
            f"{_count(counts['MEDIUM'], 'risque moyen', 'risques moyens')}",
            body,
        ),
        Paragraph("Appareils", h2),
    ]

    device_rows = [
        [
            html.escape(d["ip"] or "—"),
            html.escape(d["mac"]),
            html.escape(d["name"])[:38],
            html.escape(d["vendor"] or "—")[:28],
            html.escape(d["group"] or "—"),
            _fmt_ts(d["last_seen"]),
        ]
        for d in data["devices"]
    ]
    if device_rows:
        story.append(table(
            ["IP", "MAC", "Nom", "Constructeur", "Groupe", "Vu le"],
            device_rows,
            [30 * mm, 34 * mm, 40 * mm, 36 * mm, 20 * mm, 26 * mm],
        ))
    else:
        story.append(Paragraph("Aucun appareil enregistré.", body))

    story.append(Paragraph("Exposition", h2))
    finding_rows = [
        [f["severity"], html.escape(f["ip"] or "—"), html.escape(f["name"])[:34],
         html.escape(f["detail"])]
        for f in data["findings"]
    ]
    if finding_rows:
        story.append(table(
            ["Sév.", "Hôte", "Nom", "Détail"],
            finding_rows,
            [16 * mm, 32 * mm, 52 * mm, 86 * mm],
            severity_col=0,
        ))
    else:
        story.append(Paragraph("Aucun port à risque détecté.", body))

    if data["cves"]:
        story.append(Paragraph("Vulnérabilités connues", h2))
        cve_rows = [
            [
                html.escape(str(c.get("id", c.get("cve", "")))),
                html.escape(str(c.get("host", ""))),
                html.escape(str(c.get("port", ""))),
                html.escape(str(c.get("cvss", ""))),
                html.escape(str(c.get("severity", ""))),
            ]
            for c in data["cves"]
        ]
        story.append(table(
            ["CVE", "Hôte", "Port", "CVSS", "Sévérité"],
            cve_rows,
            [36 * mm, 40 * mm, 20 * mm, 20 * mm, 26 * mm],
            severity_col=4,
        ))

    story.append(Spacer(1, 10 * mm))
    story.append(Paragraph(
        "Rapport généré automatiquement par L0p4Map. Les ports et CVE listés "
        "reflètent les scans enregistrés dans l'inventaire local ; à vérifier "
        "avant remise au client.", small,
    ))

    doc.build(story)
    return target
