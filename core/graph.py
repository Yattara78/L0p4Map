"""Graph payload for vis.js: devices plus the services they expose.

Qt-free so the shape can be unit-tested; the web view only renders what it gets.
"""

from __future__ import annotations

from typing import Iterable, Optional

from core.inventory import Inventory

MAX_SERVICES_PER_DEVICE = 12


def service_nodes(
    hosts: Iterable[dict],
    inventory: Optional[Inventory],
    max_per_device: int = MAX_SERVICES_PER_DEVICE,
) -> list[dict]:
    """One entry per open port, tagged with the owning device MAC."""
    if inventory is None:
        return []

    services: list[dict] = []
    for device in hosts:
        mac = (device.get("mac") or "").strip().upper()
        if not mac:
            continue
        try:
            ports = inventory.ports(mac)
        except Exception:  # noqa: BLE001 - a broken DB must not kill the graph
            continue
        for entry in ports[:max_per_device]:
            services.append({
                "mac": mac,
                "ip": device.get("ip", ""),
                "port": int(entry["port"]),
                "proto": entry.get("proto") or "tcp",
                "service": entry.get("service") or "",
            })
    return services


def build_payload(
    hosts: Iterable[dict],
    inventory: Optional[Inventory],
    max_per_device: int = MAX_SERVICES_PER_DEVICE,
) -> dict:
    devices = list(hosts)
    return {
        "devices": devices,
        "services": service_nodes(devices, inventory, max_per_device),
    }


def summarise(payload: dict) -> str:
    devices = len(payload.get("devices") or [])
    services = len(payload.get("services") or [])
    text = f"{devices} appareil{'s' if devices != 1 else ''}"
    if services:
        text += f" · {services} service{'s' if services != 1 else ''}"
    return text
