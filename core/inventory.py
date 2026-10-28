"""Persistent device inventory backed by SQLite.

Turns one-shot scans into a history: which devices are known, which are new,
which disappeared, when each port was first seen, plus user labels and notes.
Qt-free so it can be unit-tested and reused by the CLI.
"""

from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

DEFAULT_DB_PATH = Path(
    os.environ.get("L0P4MAP_DB") or (Path.home() / ".l0p4map" / "inventory.db")
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started REAL NOT NULL,
    subnet TEXT,
    device_count INTEGER NOT NULL DEFAULT 0,
    source TEXT
);
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY,
    ip TEXT,
    vendor TEXT,
    hostname TEXT,
    label TEXT,
    grp TEXT,
    notes TEXT,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    last_scan_id INTEGER,
    seen_count INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS ports (
    mac TEXT NOT NULL,
    port INTEGER NOT NULL,
    proto TEXT NOT NULL DEFAULT 'tcp',
    service TEXT,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    PRIMARY KEY (mac, port, proto)
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,
    mac TEXT,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_devices_last_scan ON devices(last_scan_id);
"""

EVENT_NEW_DEVICE = "new_device"
EVENT_MISSING_DEVICE = "missing_device"
EVENT_IP_CHANGE = "ip_change"
EVENT_NEW_PORT = "new_port"


@dataclass
class Device:
    mac: str
    ip: str = ""
    vendor: str = ""
    hostname: str = ""
    label: str = ""
    group: str = ""
    notes: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    seen_count: int = 1

    @property
    def display_name(self) -> str:
        return self.label or self.hostname or self.ip or self.mac

    def as_dict(self) -> dict[str, Any]:
        return {
            "mac": self.mac,
            "ip": self.ip,
            "vendor": self.vendor,
            "hostname": self.hostname,
            "label": self.label,
            "group": self.group,
            "notes": self.notes,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "seen_count": self.seen_count,
            "name": self.display_name,
        }


@dataclass
class ScanDiff:
    """What changed during the scan that was just recorded."""

    scan_id: int
    seen: list[dict] = field(default_factory=list)
    new: list[dict] = field(default_factory=list)
    missing: list[dict] = field(default_factory=list)
    changed: list[dict] = field(default_factory=list)
    new_ports: list[dict] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.new or self.missing or self.changed or self.new_ports)

    def summary(self) -> str:
        parts = [f"{len(self.seen)} appareil(s)"]
        if self.new:
            parts.append(f"{len(self.new)} nouveau(x)")
        if self.missing:
            parts.append(f"{len(self.missing)} absent(s)")
        if self.new_ports:
            parts.append(f"{len(self.new_ports)} port(s) ouvert(s)")
        return ", ".join(parts)


class Inventory:
    """SQLite-backed inventory. Safe to construct per scan, cheap to keep open."""

    def __init__(
        self,
        db_path: Optional[str | Path] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # -- lifecycle -----------------------------------------------------
    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Inventory":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- helpers -------------------------------------------------------
    def _event(self, kind: str, mac: str, detail: str = "") -> None:
        self.conn.execute(
            "INSERT INTO events (ts, kind, mac, detail) VALUES (?,?,?,?)",
            (self._clock(), kind, mac, detail),
        )

    def _previous_scan_id(self) -> Optional[int]:
        row = self.conn.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        return row["id"] if row else None

    # -- writes --------------------------------------------------------
    def record_scan(
        self,
        hosts: Iterable[dict],
        subnet: str = "",
        source: str = "arp",
        ports_by_mac: Optional[dict[str, Iterable[int]]] = None,
    ) -> ScanDiff:
        now = self._clock()
        conn = self.conn
        prev_scan = self._previous_scan_id()
        cur = conn.execute(
            "INSERT INTO scans (started, subnet, device_count, source) VALUES (?,?,?,?)",
            (now, subnet, 0, source),
        )
        scan_id = int(cur.lastrowid or 0)
        diff = ScanDiff(scan_id=scan_id)

        seen_macs: set[str] = set()
        for host in hosts:
            mac = str(host.get("mac") or "").strip().upper()
            if not mac or mac in seen_macs:
                continue
            seen_macs.add(mac)
            ip = str(host.get("ip") or "").strip()
            vendor = str(host.get("vendor") or "").strip()
            hostname = str(host.get("hostname") or "").strip()

            row = conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO devices (mac, ip, vendor, hostname, first_seen,"
                    " last_seen, last_scan_id, seen_count) VALUES (?,?,?,?,?,?,?,1)",
                    (mac, ip, vendor, hostname, now, now, scan_id),
                )
                entry = {
                    "mac": mac, "ip": ip, "vendor": vendor,
                    "hostname": hostname, "name": hostname or ip or mac,
                }
                diff.new.append(entry)
                self._event(EVENT_NEW_DEVICE, mac, f"{ip} {hostname}".strip())
            else:
                old_ip = row["ip"] or ""
                old_vendor = row["vendor"] or ""
                conn.execute(
                    "UPDATE devices SET ip = ?,"
                    " vendor = COALESCE(NULLIF(?, ''), vendor),"
                    " hostname = COALESCE(NULLIF(?, ''), hostname),"
                    " last_seen = ?, last_scan_id = ?,"
                    " seen_count = seen_count + 1 WHERE mac = ?",
                    (ip or old_ip, vendor, hostname, now, scan_id, mac),
                )
                if ip and old_ip and ip != old_ip:
                    diff.changed.append(
                        {"mac": mac, "field": "ip", "old": old_ip, "new": ip}
                    )
                    self._event(EVENT_IP_CHANGE, mac, f"{old_ip} -> {ip}")
                if vendor and old_vendor and vendor != old_vendor:
                    diff.changed.append(
                        {"mac": mac, "field": "vendor", "old": old_vendor, "new": vendor}
                    )
                entry = {
                    "mac": mac, "ip": ip or old_ip, "vendor": vendor or old_vendor,
                    "hostname": hostname or (row["hostname"] or ""),
                    "name": row["label"] or hostname or ip or mac,
                }
            diff.seen.append(entry)

        if prev_scan is not None:
            for row in conn.execute(
                "SELECT * FROM devices WHERE last_scan_id = ?", (prev_scan,)
            ):
                if row["mac"] not in seen_macs:
                    missing = dict(row)
                    diff.missing.append(missing)
                    self._event(
                        EVENT_MISSING_DEVICE, row["mac"], row["ip"] or ""
                    )

        if ports_by_mac:
            for mac, ports in ports_by_mac.items():
                for port in self.record_ports(mac, ports, scan_id=scan_id):
                    diff.new_ports.append(
                        {"mac": mac.upper(), "port": port, "proto": "tcp"}
                    )

        conn.execute(
            "UPDATE scans SET device_count = ? WHERE id = ?", (len(seen_macs), scan_id)
        )
        conn.commit()
        return diff

    def record_ports(
        self,
        mac: str,
        ports: Iterable[int],
        proto: str = "tcp",
        service: str = "",
        scan_id: Optional[int] = None,
    ) -> list[int]:
        """Store open ports, returning the ones never seen on this device."""
        now = self._clock()
        mac = mac.strip().upper()
        fresh: list[int] = []
        for port in sorted({int(p) for p in ports if 0 < int(p) < 65536}):
            row = self.conn.execute(
                "SELECT first_seen FROM ports WHERE mac=? AND port=? AND proto=?",
                (mac, port, proto),
            ).fetchone()
            if row is None:
                self.conn.execute(
                    "INSERT INTO ports (mac, port, proto, service, first_seen, last_seen)"
                    " VALUES (?,?,?,?,?,?)",
                    (mac, port, proto, service, now, now),
                )
                fresh.append(port)
                self._event(EVENT_NEW_PORT, mac, f"{port}/{proto}")
            else:
                self.conn.execute(
                    "UPDATE ports SET last_seen = ?, service = COALESCE(NULLIF(?, ''), service)"
                    " WHERE mac=? AND port=? AND proto=?",
                    (now, service, mac, port, proto),
                )
        self.conn.commit()
        return fresh

    def set_meta(
        self,
        mac: str,
        label: Optional[str] = None,
        group: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> bool:
        """Update user metadata. None leaves the field untouched, '' clears it."""
        mac = mac.strip().upper()
        row = self.conn.execute("SELECT mac FROM devices WHERE mac=?", (mac,)).fetchone()
        if row is None:
            return False
        updates = {"label": label, "grp": group, "notes": notes}
        for column, value in updates.items():
            if value is not None:
                self.conn.execute(
                    f"UPDATE devices SET {column} = ? WHERE mac = ?", (value, mac)
                )
        self.conn.commit()
        return True

    # -- reads ---------------------------------------------------------
    def devices(self, group: Optional[str] = None) -> list[dict]:
        query = "SELECT * FROM devices ORDER BY last_seen DESC"
        rows = self.conn.execute(query).fetchall()
        out = [
            Device(
                mac=r["mac"], ip=r["ip"] or "", vendor=r["vendor"] or "",
                hostname=r["hostname"] or "", label=r["label"] or "",
                group=r["grp"] or "", notes=r["notes"] or "",
                first_seen=r["first_seen"], last_seen=r["last_seen"],
                seen_count=r["seen_count"],
            ).as_dict()
            for r in rows
        ]
        if group:
            out = [d for d in out if d["group"].lower() == group.lower()]
        return out

    def get(self, mac: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM devices WHERE mac=?", (mac.strip().upper(),)
        ).fetchone()
        if row is None:
            return None
        return Device(
            mac=row["mac"], ip=row["ip"] or "", vendor=row["vendor"] or "",
            hostname=row["hostname"] or "", label=row["label"] or "",
            group=row["grp"] or "", notes=row["notes"] or "",
            first_seen=row["first_seen"], last_seen=row["last_seen"],
            seen_count=row["seen_count"],
        ).as_dict()

    def ports(self, mac: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT port, proto, service, first_seen, last_seen FROM ports"
            " WHERE mac=? ORDER BY port",
            (mac.strip().upper(),),
        ).fetchall()
        return [dict(r) for r in rows]

    def events(self, limit: int = 100) -> list[dict]:
        rows = self.conn.execute(
            "SELECT ts, kind, mac, detail FROM events ORDER BY id DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> dict:
        count = self.conn.execute("SELECT COUNT(*) AS n FROM devices").fetchone()["n"]
        scans = self.conn.execute("SELECT COUNT(*) AS n FROM scans").fetchone()["n"]
        groups = self.conn.execute(
            "SELECT grp, COUNT(*) AS n FROM devices WHERE grp IS NOT NULL AND grp != ''"
            " GROUP BY grp ORDER BY n DESC"
        ).fetchall()
        return {
            "devices": count,
            "scans": scans,
            "groups": {r["grp"]: r["n"] for r in groups},
        }
