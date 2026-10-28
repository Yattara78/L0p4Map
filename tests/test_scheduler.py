"""Scheduling arithmetic (interval + daily), no clock mocking needed."""

from datetime import datetime

import pytest

from core.scheduler import Schedule, parse_hhmm


def ts(year, month, day, hour, minute=0):
    return datetime(year, month, day, hour, minute).timestamp()


def test_parse_hhmm():
    assert parse_hhmm("08:00") == (8, 0)
    assert parse_hhmm("23:59") == (23, 59)
    for bad in ("24:00", "8", "08:60", "", "aa:bb"):
        with pytest.raises(ValueError):
            parse_hhmm(bad)


def test_disabled_schedule_never_runs():
    schedule = Schedule(enabled=False)
    assert schedule.next_run(now=1000) is None
    assert schedule.due(now=10**9) is False


def test_interval_from_last_run():
    schedule = Schedule(enabled=True, mode="interval", interval_minutes=60, last_run=1000)
    assert schedule.next_run(now=1100) == 1000 + 3600
    assert schedule.due(now=1000 + 3599) is False
    assert schedule.due(now=1000 + 3600) is True


def test_interval_never_run_counts_from_now():
    schedule = Schedule(enabled=True, mode="interval", interval_minutes=15)
    assert schedule.next_run(now=5000) == 5000 + 15 * 60
    # without a recorded run there is no anchor, so nothing fires yet
    assert schedule.due(now=5000) is False


def test_interval_due_after_mark_run():
    schedule = Schedule(enabled=True, mode="interval", interval_minutes=15)
    schedule.last_run = 5000
    assert schedule.due(now=5000 + 15 * 60 - 1) is False
    assert schedule.due(now=5000 + 15 * 60) is True


def test_daily_before_slot_is_today():
    schedule = Schedule(enabled=True, mode="daily", at_time="08:00")
    now = ts(2026, 3, 1, 7, 30)
    assert schedule.next_run(now=now) == ts(2026, 3, 1, 8, 0)
    assert schedule.due(now=now) is False


def test_daily_after_slot_without_run_fires_now():
    schedule = Schedule(enabled=True, mode="daily", at_time="08:00")
    now = ts(2026, 3, 1, 9, 0)
    assert schedule.next_run(now=now) == ts(2026, 3, 1, 9, 0)
    assert schedule.due(now=now) is True


def test_daily_after_run_moves_to_tomorrow():
    schedule = Schedule(
        enabled=True, mode="daily", at_time="08:00", last_run=ts(2026, 3, 1, 8, 0)
    )
    now = ts(2026, 3, 1, 9, 0)
    assert schedule.next_run(now=now) == ts(2026, 3, 2, 8, 0)
    assert schedule.due(now=now) is False


def test_invalid_mode_rejected():
    with pytest.raises(ValueError):
        Schedule(mode="hourly")


def test_interval_minimum():
    with pytest.raises(ValueError):
        Schedule(interval_minutes=0)


def test_roundtrip_dict():
    schedule = Schedule(enabled=True, mode="daily", at_time="21:15")
    clone = Schedule.from_dict(schedule.to_dict())
    assert clone == schedule


def test_from_dict_ignores_garbage():
    schedule = Schedule.from_dict({"mode": "nope", "at_time": "99:99"})
    assert schedule.enabled is False and schedule.mode == "interval"
