#!/usr/bin/env python3
"""L0p4Map command line — scan, inventory, labels, events, schedule, report.

Headless on purpose: no Qt import, so it runs from cron, over SSH or on a
server. Raw sockets (ARP scan) still need root or CAP_NET_RAW.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core import alerts, report, settings  # noqa: E402
from core.inventory import DEFAULT_DB_PATH, Inventory  # noqa: E402
from core.scheduler import Schedule  # noqa: E402

EXIT_OK = 0
EXIT_ERROR = 2


def _print_table(rows: list[list[str]], headers: list[str]) -> None:
    widths = [len(h) for h in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(str(cell)))
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(line)
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print("  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row)))


def _fmt_ts(value: float | None) -> str:
    if not value:
        return "-"
    return datetime.fromtimestamp(float(value)).strftime("%Y-%m-%d %H:%M")


# -- commands ---------------------------------------------------------
def cmd_scan(args: argparse.Namespace) -> int:
    from core.scanner import (
        get_local_subnet,
        get_network_interfaces,
        has_raw_socket_access,
        scan_network,
    )

    subnet = args.subnet
    iface_name = args.iface
    if not subnet:
        interfaces = get_network_interfaces()
        if not interfaces:
            print("aucune interface réseau active", file=sys.stderr)
            return EXIT_ERROR
        if iface_name is None:
            iface_name = interfaces[0]["name"]
        subnet = get_local_subnet(iface_name)

    if not has_raw_socket_access():
        print(
            "ARP scan impossible : droits insuffisants. Relance avec sudo "
            "ou accorde CAP_NET_RAW (Linux).",
            file=sys.stderr,
        )
        return EXIT_ERROR

    started = time.time()
    hosts = scan_network(subnet)
    elapsed = time.time() - started
    print(f"scan {subnet} : {len(hosts)} appareil(s) en {elapsed:.1f}s", file=sys.stderr)

    with Inventory(args.db) as inventory:
        diff = inventory.record_scan(hosts, subnet=subnet, source="cli")
        title, body = alerts.format_scan_diff(diff, subnet=subnet)

        if not args.no_alerts and diff.has_changes:
            cfg = alerts.AlertConfig.load()
            if cfg.is_configured() or cfg.desktop:
                results = alerts.dispatch(
                    cfg, title, body,
                    notifier=lambda t, b: print(f"{t}\n{b}", file=sys.stderr),
                )
                for channel, error in results.items():
                    if error:
                        print(f"alerte {channel} en échec: {error}", file=sys.stderr)

        devices = diff.seen
        if args.json:
            print(json.dumps(
                {
                    "subnet": subnet,
                    "count": len(devices),
                    "devices": devices,
                    "new": diff.new,
                    "missing": diff.missing,
                    "changed": diff.changed,
                    "new_ports": diff.new_ports,
                },
                indent=2,
                ensure_ascii=False,
            ))
        else:
            rows = [
                [d["ip"], d["mac"], d["vendor"][:24], d["hostname"][:28]]
                for d in devices
            ]
            _print_table(rows, ["IP", "MAC", "CONSTRUCTEUR", "HOSTNAME"])
            new_macs = {d["mac"] for d in diff.new}
            if new_macs:
                print(f"\n{len(new_macs)} nouveau(x) : {', '.join(sorted(new_macs))}")
            if diff.missing:
                print(f"{len(diff.missing)} absent(s) depuis le scan précédent")
    return EXIT_OK


def cmd_inventory(args: argparse.Namespace) -> int:
    with Inventory(args.db) as inventory:
        devices = inventory.devices(group=args.group)
        if args.json:
            print(json.dumps(devices, indent=2, ensure_ascii=False))
            return EXIT_OK
        if not devices:
            print("inventaire vide — lance `l0p4map.py scan` d'abord")
            return EXIT_OK
        rows = [
            [d["ip"], d["mac"], d["name"][:30], d["vendor"][:22],
             d["group"] or "-", _fmt_ts(d["last_seen"])]
            for d in devices
        ]
        _print_table(rows, ["IP", "MAC", "NOM", "CONSTRUCTEUR", "GROUPE", "VU LE"])
        stats = inventory.stats()
        print(f"\n{stats['devices']} appareil(s), {stats['scans']} scan(s)")
    return EXIT_OK


def cmd_label(args: argparse.Namespace) -> int:
    with Inventory(args.db) as inventory:
        found = inventory.set_meta(
            args.mac, label=args.label, group=args.group, notes=args.notes
        )
    if not found:
        print(f"MAC inconnue: {args.mac}", file=sys.stderr)
        return EXIT_ERROR
    print(f"{args.mac} mis à jour")
    return EXIT_OK


def cmd_events(args: argparse.Namespace) -> int:
    with Inventory(args.db) as inventory:
        events = inventory.events(limit=args.limit)
    if args.json:
        print(json.dumps(events, indent=2, ensure_ascii=False))
        return EXIT_OK
    if not events:
        print("aucun événement")
        return EXIT_OK
    rows = [[_fmt_ts(e["ts"]), e["kind"], e["mac"] or "", (e["detail"] or "")[:40]]
            for e in events]
    _print_table(rows, ["QUAND", "TYPE", "MAC", "DETAIL"])
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    with Inventory(args.db) as inventory:
        data = report.collect_data(inventory, subnet=args.subnet or "")
    stamp = datetime.now().strftime("%Y%m%d-%H%M")
    target = Path(args.out) if args.out else Path(f"rapport-l0p4map-{stamp}.{args.format}")
    try:
        if args.format == "html":
            path = report.write_html(data, target)
        else:
            path = report.write_pdf(data, target)
    except report.ReportError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_ERROR
    print(path)
    return EXIT_OK


def cmd_schedule(args: argparse.Namespace) -> int:
    schedule = Schedule.load()
    if args.every:
        schedule.mode = "interval"
        schedule.interval_minutes = args.every
        schedule.enabled = True
    if args.daily:
        schedule.mode = "daily"
        schedule.at_time = args.daily
        schedule.enabled = True
    if args.enable:
        schedule.enabled = True
    if args.disable:
        schedule.enabled = False
    if any([args.every, args.daily, args.enable, args.disable]):
        schedule.save()
    upcoming = schedule.next_run()
    print(json.dumps(
        {
            "enabled": schedule.enabled,
            "mode": schedule.mode,
            "interval_minutes": schedule.interval_minutes,
            "at_time": schedule.at_time,
            "next_run": _fmt_ts(upcoming),
            "config": str(settings.CONFIG_PATH),
        },
        indent=2,
    ))
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="l0p4map",
        description="L0p4Map en ligne de commande : scan, inventaire, rapport.",
    )
    parser.add_argument("--db", default=None, help=f"base SQLite (défaut: {DEFAULT_DB_PATH})")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan ARP + mise à jour de l'inventaire")
    scan.add_argument("--iface", help="interface réseau (défaut: première active)")
    scan.add_argument("--subnet", help="sous-réseau CIDR (défaut: celui de l'interface)")
    scan.add_argument("--json", action="store_true", help="sortie JSON")
    scan.add_argument("--no-alerts", action="store_true", help="ne pas notifier")
    scan.set_defaults(func=cmd_scan)

    inv = sub.add_parser("inventory", help="lister les appareils connus")
    inv.add_argument("--group", help="filtrer par groupe")
    inv.add_argument("--json", action="store_true")
    inv.set_defaults(func=cmd_inventory)

    label = sub.add_parser("label", help="nommer / grouper un appareil")
    label.add_argument("mac")
    label.add_argument("--label")
    label.add_argument("--group")
    label.add_argument("--notes")
    label.set_defaults(func=cmd_label)

    events = sub.add_parser("events", help="derniers événements")
    events.add_argument("--limit", type=int, default=30)
    events.add_argument("--json", action="store_true")
    events.set_defaults(func=cmd_events)

    report_cmd = sub.add_parser("report", help="générer le rapport HTML ou PDF")
    report_cmd.add_argument("--out", help="chemin de sortie")
    report_cmd.add_argument("--format", choices=["pdf", "html"], default="pdf")
    report_cmd.add_argument("--subnet", help="libellé du réseau dans le rapport")
    report_cmd.set_defaults(func=cmd_report)

    sched = sub.add_parser("schedule", help="planifier les scans")
    sched.add_argument("--every", type=int, metavar="MIN", help="toutes les N minutes")
    sched.add_argument("--daily", metavar="HH:MM", help="tous les jours à HH:MM")
    sched.add_argument("--enable", action="store_true")
    sched.add_argument("--disable", action="store_true")
    sched.set_defaults(func=cmd_schedule)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(f"erreur: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
