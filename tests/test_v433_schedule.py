"""
v4.33 - schedules, and the promise they change.

`due_at()` is pure so the behaviour that matters can be tested without waiting a
day. Three things it must never do, each of which is a real failure mode:

    run twice in one window     the loop ticks every 60s; a schedule that
                                fires again 60 seconds later is a schedule that
                                hammers the Management Server all morning
    run three times after
    three days off              catching up must mean "run once", not "run the
                                backlog"
    start running because
    it was created              a new schedule is off until somebody enables
                                it, because this is the feature that makes the
                                application call out on its own
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest

from app.jobs import schedule as S

MON, TUE, WED = "mon", "tue", "wed"


def at(y, m, d, hh, mm=0) -> datetime:
    return datetime(y, m, d, hh, mm)


def sched(**over):
    base = {"id": "daily", "enabled": True, "package": "P", "at": "09:00",
            "days": list(S.DAYS), "catch_up": True}
    base.update(over)
    return S.normalise(base)


# 2026-09-07 is a Monday.
MONDAY = at(2026, 9, 7, 0, 0)


class TestWhenItIsDue:
    def test_not_due_before_the_time_arrives(self):
        assert S.due_at(sched(), at(2026, 9, 7, 8, 59)) is None

    def test_due_once_the_time_has_passed(self):
        moment = S.due_at(sched(), at(2026, 9, 7, 9, 0))
        assert moment == at(2026, 9, 7, 9, 0)

    def test_a_disabled_schedule_is_never_due(self):
        assert S.due_at(sched(enabled=False), at(2026, 9, 7, 12, 0)) is None

    def test_a_day_it_does_not_run_on_is_not_due(self):
        weekdays = sched(days=["sat", "sun"])
        assert S.due_at(weekdays, at(2026, 9, 7, 12, 0)) is None    # Monday

    def test_it_is_due_on_a_day_it_does_run_on(self):
        weekend = sched(days=["sat", "sun"])
        assert S.due_at(weekend, at(2026, 9, 12, 12, 0)) is not None  # Saturday


class TestItRunsOncePerWindow:
    """The loop ticks every 60 seconds. This is what stops it re-firing."""

    def test_a_completed_window_is_not_due_again(self):
        s = sched(last_run_at=at(2026, 9, 7, 9, 0).isoformat())
        assert S.due_at(s, at(2026, 9, 7, 9, 1)) is None
        assert S.due_at(s, at(2026, 9, 7, 17, 0)) is None

    def test_the_next_day_is_a_new_window(self):
        s = sched(last_run_at=at(2026, 9, 7, 9, 0).isoformat())
        assert S.due_at(s, at(2026, 9, 8, 9, 0)) == at(2026, 9, 8, 9, 0)

    def test_a_run_before_the_window_does_not_cover_it(self):
        """Somebody pressing Run at 08:00 is not the 09:00 review."""
        s = sched(last_run_at=at(2026, 9, 7, 8, 0).isoformat())
        assert S.due_at(s, at(2026, 9, 7, 9, 30)) == at(2026, 9, 7, 9, 0)


class TestCatchingUp:
    def test_a_window_missed_while_the_machine_was_off_still_runs(self):
        """The laptop was asleep at nine. It is now two in the afternoon."""
        assert S.due_at(sched(), at(2026, 9, 7, 14, 0)) == at(2026, 9, 7, 9, 0)

    def test_three_days_away_produces_one_run_not_three(self):
        s = sched(last_run_at=at(2026, 9, 4, 9, 0).isoformat())
        moment = S.due_at(s, at(2026, 9, 7, 14, 0))
        assert moment == at(2026, 9, 7, 9, 0), "caught up to the wrong window"

    def test_without_catch_up_a_missed_window_is_gone(self):
        s = sched(catch_up=False)
        assert S.due_at(s, at(2026, 9, 7, 9, 0)) == at(2026, 9, 7, 9, 0)
        # ...but once the day has moved on, that window is not resurrected
        assert S.due_at(sched(catch_up=False), at(2026, 9, 8, 8, 0)) is None

    def test_catch_up_does_not_reach_back_forever(self):
        s = sched(last_run_at=at(2025, 1, 1, 9, 0).isoformat())
        moment = S.due_at(s, at(2026, 9, 7, 14, 0))
        assert moment == at(2026, 9, 7, 9, 0)


class TestNextDueIsForReading:
    def test_it_reports_the_upcoming_moment(self):
        assert S.next_due(sched(), at(2026, 9, 7, 8, 0)) == at(2026, 9, 7, 9, 0)

    def test_after_today_it_rolls_to_the_next_matching_day(self):
        weekend = sched(days=["sat"])
        assert S.next_due(weekend, at(2026, 9, 7, 8, 0)) == at(2026, 9, 12, 9, 0)

    def test_a_disabled_schedule_has_no_next(self):
        assert S.next_due(sched(enabled=False), at(2026, 9, 7, 8, 0)) is None


class TestNewSchedulesDoNotStartRunning:
    def test_enabled_defaults_to_false(self):
        assert S.normalise({"package": "P", "at": "09:00"})["enabled"] is False

    def test_any_enabled_reports_whether_the_app_calls_out_on_its_own(self, tmp_path):
        f = tmp_path / "s.json"
        S.save_all([{"package": "P", "at": "09:00"}], base=f)
        assert S.any_enabled(base=f) is False
        S.save_all([{"package": "P", "at": "09:00", "enabled": True}], base=f)
        assert S.any_enabled(base=f) is True


class TestABadDefinitionIsRefusedWithAReason:
    @pytest.mark.parametrize("entry,message", [
        ({"at": "09:00"}, "needs a policy package"),
        ({"package": "P", "at": "9am"}, "not a time of day"),
        ({"package": "P", "at": "24:00"}, "not a time of day"),
        ({"package": "P", "at": "09:60"}, "not a time of day"),
        ({"package": "P", "at": "09:00", "days": ["funday"]}, "Unknown day"),
        ({"package": "P", "at": "09:00", "pdf_detail": "everything"}, "pdf_detail"),
    ])
    def test_it_says_what_is_wrong(self, entry, message):
        with pytest.raises(ValueError, match=message):
            S.normalise(entry)

    def test_one_bad_entry_does_not_disable_the_good_ones(self, tmp_path):
        f = tmp_path / "s.json"
        f.write_text(json.dumps([
            {"id": "good", "package": "P", "at": "09:00", "enabled": True},
            {"id": "bad", "package": "P", "at": "not a time"},
        ]), encoding="utf-8")
        rows = S.load_all(base=f)
        assert [r["id"] for r in rows] == ["good"]

    def test_an_unreadable_file_runs_nothing_rather_than_guessing(self, tmp_path):
        f = tmp_path / "s.json"
        f.write_text("{ not json", encoding="utf-8")
        assert S.load_all(base=f) == []


class TestTheStore:
    def test_upsert_replaces_by_id(self, tmp_path):
        f = tmp_path / "s.json"
        S.upsert({"id": "x", "package": "P", "at": "09:00"}, base=f)
        S.upsert({"id": "x", "package": "P", "at": "10:00"}, base=f)
        rows = S.load_all(base=f)
        assert len(rows) == 1 and rows[0]["at"] == "10:00"

    def test_remove_reports_whether_anything_went(self, tmp_path):
        f = tmp_path / "s.json"
        S.upsert({"id": "x", "package": "P", "at": "09:00"}, base=f)
        assert S.remove("x", base=f) is True
        assert S.remove("x", base=f) is False

    def test_recording_a_result_closes_the_window(self, tmp_path):
        f = tmp_path / "s.json"
        S.upsert({"id": "x", "package": "P", "at": "09:00", "enabled": True}, base=f)
        assert S.due_at(S.load_all(base=f)[0], at(2026, 9, 7, 10, 0)) is not None
        S.record_result("x", run_id="R1", result="complete",
                        when=at(2026, 9, 7, 9, 1), base=f)
        assert S.due_at(S.load_all(base=f)[0], at(2026, 9, 7, 10, 0)) is None

    def test_a_failure_also_closes_the_window(self, tmp_path):
        """Otherwise a broken schedule retries every 60 seconds, all day."""
        f = tmp_path / "s.json"
        S.upsert({"id": "x", "package": "P", "at": "09:00", "enabled": True}, base=f)
        S.record_result("x", run_id=None, result="failed: boom",
                        when=at(2026, 9, 7, 9, 1), base=f)
        row = S.load_all(base=f)[0]
        assert S.due_at(row, at(2026, 9, 7, 10, 0)) is None
        assert row["last_result"].startswith("failed")


def test_a_schedule_cannot_ask_for_a_write():
    """It composes the read-only runner; it must not grow a verb of its own."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent
           / "app" / "jobs" / "schedule.py").read_text(encoding="utf-8")
    for forbidden in ("add-", "set-", "delete-", "publish", "install-policy"):
        assert f'"{forbidden}' not in src, forbidden
