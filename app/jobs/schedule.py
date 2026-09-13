"""
Schedules: the application calling itself, on purpose and in the open.

This is the change that alters what the application promises. Until now the
status line said *"No API calls are made automatically"* and it was exactly
true - nothing reached the Management Server unless somebody pressed something.
A schedule breaks that sentence, so the sentence changes with it rather than
being quietly left to rot: the promise becomes "no calls except the schedules
you can see, and you can turn them off from the same page".

Three things follow from that, and they are the design:

    off by default      A fresh install schedules nothing. Enabling is an act.
    visible             Every schedule, its next due time, and its last result
                        are readable over the API, so "what is this thing doing
                        to my Management Server" has an answer.
    stoppable           Disabling takes effect on the next tick, and the loop is
                        a task the lifespan cancels on shutdown.

TIME
Schedules run on the machine's local clock, because "every morning at nine" is
a local statement - a firewall team means nine where they are, not 09:00 UTC.
Everything *recorded* stays UTC, like the rest of the application.

MISSED RUNS
A laptop asleep at 09:00 is the normal case, not an edge case. `catch_up`
(default on) runs the job when the application next comes up, and marks the run
late so nobody reads a 14:00 review as a 09:00 one. With it off, a missed
window is skipped and recorded as skipped - which is a different fact from
never having been scheduled.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
from datetime import date, datetime, time as dtime, timedelta
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

SCHEDULE_FILE = Path(__file__).resolve().parent.parent.parent / "schedules.json"

# Checked once a minute. A schedule is a daily or weekly thing; a tighter tick
# would buy nothing and would be one more timer waking a laptop up.
TICK_SECONDS = 60

DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_TIME_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


# ---- the definition --------------------------------------------------------

def normalise(entry: dict[str, Any]) -> dict[str, Any]:
    """Validate and fill in one schedule. Raises ValueError with a usable message."""
    package = str(entry.get("package") or "").strip()
    if not package:
        raise ValueError("A schedule needs a policy package.")

    at = str(entry.get("at") or "").strip()
    if not _TIME_RE.match(at):
        raise ValueError(f"'{at}' is not a time of day. Use HH:MM, 24-hour, "
                         "in this machine's local time.")

    days = [str(d).lower()[:3] for d in (entry.get("days") or list(DAYS))]
    unknown = [d for d in days if d not in DAYS]
    if unknown:
        raise ValueError(f"Unknown day(s): {', '.join(unknown)}. "
                         f"Use any of: {', '.join(DAYS)}.")
    if not days:
        raise ValueError("A schedule that runs on no days would never run.")

    detail = str(entry.get("pdf_detail") or "summary")
    if detail not in ("summary", "findings", "full"):
        raise ValueError(f"Unknown pdf_detail '{detail}'.")

    return {
        "id": _SAFE.sub("-", str(entry.get("id") or f"{package}-{at}")),
        # Off unless somebody says otherwise. A schedule that starts running
        # because it was created is a schedule that ran without being decided.
        "enabled": bool(entry.get("enabled", False)),
        "package": package,
        "profile": (str(entry["profile"]).strip() or None) if entry.get("profile") else None,
        "at": at,
        "days": sorted(set(days), key=DAYS.index),
        "include_health": bool(entry.get("include_health", True)),
        "catch_up": bool(entry.get("catch_up", True)),
        "pdf": bool(entry.get("pdf", False)),
        "pdf_detail": detail,
        "pdf_dir": str(entry.get("pdf_dir") or "reports"),
        "last_run_at": entry.get("last_run_at"),
        "last_run_id": entry.get("last_run_id"),
        "last_result": entry.get("last_result"),
    }


# ---- when it is due --------------------------------------------------------

def _scheduled_for(day: date, at: str) -> datetime:
    h, m = (int(x) for x in at.split(":"))
    return datetime.combine(day, dtime(hour=h, minute=m))


def due_at(schedule: dict[str, Any], now: datetime) -> datetime | None:
    """The moment this schedule *should already have run* by `now`, or None.

    Pure, so the behaviour that matters can be tested without waiting a day:

      * not enabled, or not a day it runs on   -> None
      * today's time has not arrived yet       -> None
      * it arrived and no run has happened for it today -> that moment
      * a run already covered it               -> None

    `catch_up` decides only whether a window missed while the application was
    down still counts. It never invents a second run inside one window.
    """
    if not schedule.get("enabled"):
        return None

    last = _parse(schedule.get("last_run_at"))

    # How far back a missed window still counts.
    #
    # Never past the last recorded run: a schedule enabled this morning must not
    # fire for yesterday, which it was not part of. With nothing recorded there
    # is no evidence any window was missed, so only today's counts - otherwise
    # creating a schedule at 08:59 makes it run immediately for a window from
    # days ago.
    if not schedule.get("catch_up", True) or last is None:
        horizon = 0
    else:
        horizon = max(0, min(7, (now.date() - last.date()).days))

    # Today first, then backwards, so a machine that was off for three days
    # runs once, not three times.
    for back in range(0, horizon + 1):
        day = (now - timedelta(days=back)).date()
        if DAYS[day.weekday()] not in schedule["days"]:
            continue
        moment = _scheduled_for(day, schedule["at"])
        if moment > now:
            continue                       # not yet
        if last is not None and last >= moment:
            return None                    # this window is already covered
        return moment
    return None


def next_due(schedule: dict[str, Any], now: datetime) -> datetime | None:
    """The next moment this will fire, for display. None when disabled."""
    if not schedule.get("enabled"):
        return None
    for ahead in range(0, 8):
        day = (now + timedelta(days=ahead)).date()
        if DAYS[day.weekday()] not in schedule["days"]:
            continue
        moment = _scheduled_for(day, schedule["at"])
        if moment > now:
            return moment
    return None


def _parse(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    # Stored UTC, compared against a local `now`.
    return parsed.astimezone().replace(tzinfo=None) if parsed.tzinfo else parsed


# ---- the file --------------------------------------------------------------

def load_all(base: Path | None = None) -> list[dict[str, Any]]:
    path = base or SCHEDULE_FILE
    if not path.is_file():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("schedules.json could not be read (%s); no schedule will run", exc)
        return []
    out = []
    for entry in raw if isinstance(raw, list) else []:
        try:
            out.append(normalise(entry))
        except ValueError as exc:
            # A bad entry must not silently disable the good ones, and must not
            # be silently dropped either.
            log.warning("Ignoring an unusable schedule (%s): %s", exc, entry)
    return out


def save_all(schedules: list[dict[str, Any]], base: Path | None = None) -> None:
    path = base or SCHEDULE_FILE
    path.write_text(json.dumps([normalise(s) for s in schedules], indent=2,
                               ensure_ascii=False), encoding="utf-8")


def upsert(entry: dict[str, Any], base: Path | None = None) -> dict[str, Any]:
    entry = normalise(entry)
    rows = [s for s in load_all(base) if s["id"] != entry["id"]]
    rows.append(entry)
    save_all(rows, base)
    return entry


def remove(sid: str, base: Path | None = None) -> bool:
    rows = load_all(base)
    kept = [s for s in rows if s["id"] != sid]
    if len(kept) == len(rows):
        return False
    save_all(kept, base)
    return True


def record_result(sid: str, *, run_id: str | None, result: str,
                  when: datetime | None = None, base: Path | None = None) -> None:
    """Remember that this window was handled, so it is not handled twice."""
    rows = load_all(base)
    for s in rows:
        if s["id"] == sid:
            s["last_run_at"] = (when or datetime.now()).isoformat(timespec="seconds")
            s["last_run_id"] = run_id
            s["last_result"] = result
    save_all(rows, base)


# ---- the loop --------------------------------------------------------------

async def _fire(schedule: dict[str, Any], moment: datetime) -> None:
    """Run one due schedule. Never raises: a failure is a recorded result."""
    from ..runtime import cp
    from .report import build_report
    from .runner import run_review
    from .store import save_run

    sid = schedule["id"]
    late = (datetime.now() - moment) > timedelta(minutes=5)
    log.info("Schedule %s firing for the %s window%s",
             sid, moment.isoformat(timespec="minutes"), " (late)" if late else "")
    try:
        run = await run_review(cp, schedule["package"],
                               profile=schedule.get("profile"),
                               include_health=schedule.get("include_health", True))
        run["triggered_by"] = {"kind": "schedule", "id": sid,
                               "window": moment.isoformat(timespec="minutes"),
                               "late": late}
        run_id = save_run(run)

        if schedule.get("pdf"):
            out = Path(schedule.get("pdf_dir") or "reports")
            out.mkdir(parents=True, exist_ok=True)
            (out / f"{run_id}.pdf").write_bytes(
                build_report(run, schedule.get("pdf_detail", "summary")))

        # Alerts go out after the run is saved, so a delivery failure cannot
        # cost the review, and the outcome of each delivery is written back
        # onto the run where the Reviews page shows it.
        from .alerts import dispatch
        run["id"] = run_id
        run["alerts"] = await dispatch(run)
        if run["alerts"]:
            save_run(run)

        result = "complete" if run.get("complete") else "incomplete"
        record_result(sid, run_id=run_id, result=result)
    except Exception as exc:                                      # noqa: BLE001
        log.exception("Schedule %s failed", sid)
        # Recorded, so the window is not retried in a loop, and so the failure
        # is visible rather than being a run that never appears.
        record_result(sid, run_id=None, result=f"failed: {exc}")


async def loop(stop: asyncio.Event | None = None) -> None:
    """Check every minute for a due schedule and run it. One at a time."""
    log.info("Schedule loop started (tick %ss)", TICK_SECONDS)
    while not (stop and stop.is_set()):
        try:
            now = datetime.now()
            for schedule in load_all():
                moment = due_at(schedule, now)
                if moment is not None:
                    await _fire(schedule, moment)
        except asyncio.CancelledError:
            raise
        except Exception:                                         # noqa: BLE001
            log.exception("Schedule tick failed; the loop continues")
        try:
            if stop:
                await asyncio.wait_for(stop.wait(), timeout=TICK_SECONDS)
            else:
                await asyncio.sleep(TICK_SECONDS)
        except asyncio.TimeoutError:
            pass
    log.info("Schedule loop stopped")


def any_enabled(base: Path | None = None) -> bool:
    """Whether the application currently calls out on its own. The UI says so."""
    return any(s.get("enabled") for s in load_all(base))


@contextlib.asynccontextmanager
async def running():
    """Start the loop for the life of the application, and cancel it after.

    Lives here rather than in main.py so the application factory stays a
    factory: `app/main.py` should say what the application is made of, not how
    one of its parts is started and stopped.

    Starting the loop is not the same as the application deciding to call out.
    Every schedule is off until somebody enables it, so on a fresh install this
    ticks once a minute over an empty list and does nothing.
    """
    stop = asyncio.Event()
    task = asyncio.create_task(loop(stop), name="schedule-loop")
    try:
        yield
    finally:
        stop.set()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
