"""
Run one review from the command line, with no browser and no server.

This is what makes the trigger movable. Windows Task Scheduler, cron, a Docker
sidecar or a person in a terminal all call the same `run_review()` the UI
button calls; deciding later that the schedule should live outside the
application means pointing the scheduler here and turning the in-app one off.
Nothing in the runner changes.

    python -m tools.run_review --package External-FW
    python -m tools.run_review --package External-FW --profile nist-800-41-baseline
    python -m tools.run_review --package External-FW --no-health --quiet

Credentials come from the same place the server takes them: the encrypted
store if one exists, otherwise `.env`. Nothing is written to the Management
Server - this issues the same read-only show-* calls the pages issue.

Exit codes, so a scheduler can act on the result:

    0   the run completed, nothing changed, nothing was left undecided
    1   something changed, or a compliance check failed - look at it
    2   the run could not answer part of what it was asked: a section failed to
        read, or the comparison contains scope it could not verify. "I could
        not tell" is not "nothing changed", and a scheduler that treats them
        the same will be ignored by the second week.
    3   the run could not start at all (no credentials, server unreachable)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.api.credentials import load_credentials_on_startup   # noqa: E402
from app.checkpoint import CheckPointAPIError                  # noqa: E402
from app.config import settings                                # noqa: E402
from app.jobs import store                                     # noqa: E402
from app.jobs.runner import run_review                         # noqa: E402
from app.runtime import cp                                     # noqa: E402

EXIT_UNCHANGED, EXIT_CHANGED, EXIT_UNDECIDED, EXIT_FAILED = 0, 1, 2, 3


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m tools.run_review",
        description="Run one read-only review of a policy package and store it.")
    p.add_argument("--package", required=True, help="policy package name")
    p.add_argument("--profile", default=None,
                   help="compliance profile id to evaluate (optional)")
    p.add_argument("--no-health", action="store_true",
                   help="skip the Gaia gateway reading even if GAIA_ENABLED is set")
    p.add_argument("--no-compare", action="store_true",
                   help="do not diff against the previous snapshot")
    p.add_argument("--json", action="store_true",
                   help="print the whole run as JSON instead of a summary")
    p.add_argument("--quiet", action="store_true", help="print nothing on success")
    p.add_argument("--pdf", metavar="PATH", default=None,
                   help="also write a PDF report to PATH")
    p.add_argument("--pdf-detail", default="summary",
                   choices=("summary", "findings", "full"),
                   help="how much of the policy the PDF may contain "
                        "(default: summary - counts and severities, no rule "
                        "identifiers, because this is the file that gets emailed)")
    return p


def _summarise(run: dict) -> list[str]:
    s = run["sections"]
    lines = [f"package        {run['package']}",
             f"started        {run['started_at']}",
             f"duration       {run['duration_seconds']}s",
             f"stored as      {run.get('id')}"]

    access = (s["access"].get("data") or {}).get("summary") or {}
    if s["access"]["ok"]:
        lines.append(f"access         {access.get('analyzed_rules', '?')} rule(s) analysed, "
                     f"score {access.get('optimization_score', '?')}")
    else:
        lines.append(f"access         NOT READ - {s['access']['error']}")

    if s["snapshot"]["ok"]:
        lines.append(f"snapshot       {s['snapshot']['data']['snapshot_id']}")

    changed = s["changed"].get("data") or {}
    if not s["changed"]["requested"]:
        lines.append("changed        not compared")
    elif not s["changed"]["ok"]:
        lines.append(f"changed        NOT READ - {s['changed']['error']}")
    elif changed.get("first_run"):
        lines.append("changed        first run - nothing to compare against yet")
    elif changed.get("identical"):
        lines.append(f"changed        no change since {changed.get('compared_with')}")
    else:
        # `identical` is false when ANY of nine counters is non-zero, and only
        # four of them used to be printed. A run that reported "CHANGED - 0
        # added, 0 removed, 0 modified, 0 moved" was telling the truth and
        # hiding the reason, which is the worst of both.
        cs = changed.get("summary") or {}
        real = {k: cs.get(k, 0) for k in REAL_CHANGE_KEYS if cs.get(k)}
        undecided = cs.get("scope_unverifiable", 0)
        if real:
            lines.append(f"changed        CHANGED since {changed.get('compared_with')} - "
                         + ", ".join(f"{v} {k.replace('_', ' ')}" for k, v in real.items()))
        if undecided:
            lines.append(f"undecided      {undecided} rule(s) whose reach could not be "
                         "verified in one of the two snapshots, so this comparison "
                         "cannot say they are unchanged")
        if not real and not undecided:
            lines.append(f"changed        differs from {changed.get('compared_with')}, "
                         "reason not in the summary counters")

    for w in changed.get("warnings") or []:
        lines.append(f"warning        {w}")

    if s["compliance"]["requested"]:
        if not s["compliance"]["ok"]:
            lines.append(f"compliance     NOT READ - {s['compliance']['error']}")
        else:
            c = s["compliance"]["data"]
            cs = c.get("summary") or {}
            lines.append(f"compliance     {'CONFORMANT' if c.get('conformant') else 'NOT CONFORMANT'}"
                         f" - {cs.get('failed', 0)} failed, {cs.get('unverifiable', 0)} unverifiable")

    if s["gateways"]["requested"]:
        if not s["gateways"]["ok"]:
            lines.append(f"gateways       NOT READ - {s['gateways']['error']}")
        else:
            g = s["gateways"]["data"]
            lines.append(f"gateways       {len(g.get('gateways') or [])} read, "
                         f"{len(g.get('findings') or [])} finding(s)")

    if run["incomplete_sections"]:
        lines.append("")
        lines.append("INCOMPLETE: " + ", ".join(run["incomplete_sections"])
                     + " - this run is not evidence that those are clean.")
    return lines


# The counters that mean the policy actually moved. `scope_unverifiable` is
# deliberately not among them: it means one rule's reach could not be decided
# in one of the two snapshots, which is a reason to look, not a change.
REAL_CHANGE_KEYS = ("added", "removed", "modified", "moved", "scope_changed",
                    "nat_added", "nat_removed", "nat_modified")


def _exit_code(run: dict) -> int:
    """A mapping of store.outcome(), which is where the meaning lives.

    The order of the checks is the order the previous body had, and
    tests/test_v432_review_runner.py pins every case it distinguished.
    """
    from app.jobs.store import outcome
    o = outcome(run)
    if o["incomplete"]:
        return EXIT_UNDECIDED
    if o["changed"] or o["compliance"] == "not-conformant":
        return EXIT_CHANGED
    if o["could_not_compare"]:
        return EXIT_UNDECIDED
    return EXIT_UNCHANGED


async def _run(args) -> int:
    load_credentials_on_startup()
    if not settings.checkpoint_user:
        print("No Management API credentials. Save them in Settings, or set "
              "CHECKPOINT_USER and CHECKPOINT_PASSWORD in .env.", file=sys.stderr)
        return EXIT_FAILED

    def on_step(i, total, label):
        if not args.quiet:
            print(f"[{i + 1}/{total}] {label}", file=sys.stderr)

    try:
        run = await run_review(
            cp, args.package,
            profile=args.profile,
            include_health=not args.no_health,
            compare_previous=not args.no_compare,
            on_step=on_step,
        )
    except CheckPointAPIError as exc:
        print(f"Management API: {exc}", file=sys.stderr)
        return EXIT_FAILED
    finally:
        await cp.close()

    run["id"] = store.save_run(run)

    if args.pdf:
        from app.jobs.report import build_report
        out = Path(args.pdf)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(build_report(run, args.pdf_detail))
        if not args.quiet:
            print(f"pdf            {out} ({args.pdf_detail})")

    if args.json:
        print(json.dumps(run, indent=2, ensure_ascii=False))
    elif not args.quiet:
        print("\n".join(_summarise(run)))

    return _exit_code(run)


def main() -> int:
    return asyncio.run(_run(_parser().parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
