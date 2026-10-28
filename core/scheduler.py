"""Scan scheduling: interval or daily, persisted in the user config.

Pure time arithmetic on purpose (no Qt, no threads) so it can be tested and
reused by the CLI.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timedelta
from typing import Optional

from core import settings

MODES = ("interval", "daily")
MIN_INTERVAL_MINUTES = 1


def parse_hhmm(value: str) -> tuple[int, int]:
    try:
        hour_str, minute_str = value.strip().split(":", 1)
        hour, minute = int(hour_str), int(minute_str)
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"heure invalide: {value!r} (attendu HH:MM)") from exc
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise ValueError(f"heure invalide: {value!r} (attendu 00:00–23:59)")
    return hour, minute


@dataclass
class Schedule:
    enabled: bool = False
    mode: str = "interval"
    interval_minutes: int = 60
    at_time: str = "08:00"
    last_run: float = 0.0

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            raise ValueError(f"mode inconnu: {self.mode}")
        parse_hhmm(self.at_time)
        if int(self.interval_minutes) < MIN_INTERVAL_MINUTES:
            raise ValueError(
                f"intervalle minimum: {MIN_INTERVAL_MINUTES} minute(s)"
            )

    # -- (de)serialisation --------------------------------------------
    @classmethod
    def from_dict(cls, data: dict) -> "Schedule":
        known = {f.name for f in fields(cls)}
        clean = {k: v for k, v in (data or {}).items() if k in known and v is not None}
        try:
            return cls(**clean)
        except (TypeError, ValueError):
            return cls()

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Schedule":
        return cls.from_dict(settings.section("schedule", path))

    def save(self, path: Optional[str] = None) -> None:
        settings.update_section("schedule", self.to_dict(), path)

    def mark_run(self, now: Optional[float] = None, path: Optional[str] = None) -> None:
        self.last_run = float(now if now is not None else time.time())
        self.save(path)

    # -- scheduling ----------------------------------------------------
    def next_run(self, now: Optional[float] = None) -> Optional[float]:
        """Epoch seconds of the next due run, or None when disabled."""
        if not self.enabled:
            return None
        now = float(now if now is not None else time.time())

        if self.mode == "interval":
            interval = int(self.interval_minutes) * 60
            base = self.last_run or now
            return base + interval

        hour, minute = parse_hhmm(self.at_time)
        current = datetime.fromtimestamp(now)
        slot = current.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if self.last_run:
            last = datetime.fromtimestamp(self.last_run)
            if last >= slot:
                slot = slot + timedelta(days=1)
        elif slot < current:
            # never ran and today's slot is already past: run at the next start
            slot = current.replace(second=0, microsecond=0)
        return slot.timestamp()

    def due(self, now: Optional[float] = None) -> bool:
        if not self.enabled:
            return False
        now = float(now if now is not None else time.time())
        if self.mode == "interval":
            # An interval starts counting from the last run; without one there
            # is no reference point, so the caller must mark a run first.
            if not self.last_run:
                return False
            return now >= self.last_run + int(self.interval_minutes) * 60
        upcoming = self.next_run(now)
        return upcoming is not None and now >= upcoming
