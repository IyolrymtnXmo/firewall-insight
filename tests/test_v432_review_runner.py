"""
v4.32 - one review run, triggered by anything.

The runner exists so a review can happen without somebody clicking through
five pages and waiting out a cold 47-second analysis. It composes service
functions that already have tests; what needs testing here is the composition,
and one property in particular:

    a section that could not be read is reported as not read,
    never as having found nothing.

That is the same distinction the tracer makes between no-match and unknown, and
it matters more here than anywhere else in the application, because nobody is
watching when this runs. A run that quietly records "no gateway findings"
because Gaia was unreachable is worse than no run at all.

The exit codes get their own tests because a scheduler acts on them, and
because "the policy changed" and "I could not tell whether the policy changed"
must not be the same signal - a daily job that cries "changed" every morning is
ignored by the second week.
"""

from __future__ import annotations

import asyncio

import pytest

from app.jobs import runner as R
from app.jobs import store
from tools.run_review import (EXIT_CHANGED, EXIT_UNCHANGED, EXIT_UNDECIDED,
                              _exit_code)


# ---- helpers ---------------------------------------------------------------

def _tree():
    return {"root_layers": ["L"], "layers": [{"name": "L", "path": "L", "depth": 0,
                                              "parent_layer": None, "parent_rule": None,
                                              "display_prefix": "", "payload": {}}]}


def _snapshot(package="P", taken_at="2026-01-02T00:00:00+00:00"):
    return {"package": package, "taken_at": taken_at, "app_version": "test",
            "summary": {"access_rules": 3}, "access": {"rules": []}, "nat": {"rules": []},
            "notes": []}


class _Client:
    """Only the one call the runner makes on the client directly."""

    def __init__(self, nat=None, nat_error=None):
        self._nat, self._nat_error = nat or {"rulebase": []}, nat_error

    async def show_nat_rulebase(self, package):
        if self._nat_error:
            raise RuntimeError(self._nat_error)
        return self._nat


@pytest.fixture
def wired(monkeypatch, tmp_path):
    """Every service the runner composes, replaced with something predictable."""
    async def tree(c, package, hydrate=True, rid=None):
        return _tree()

    async def access(c, package, rid=None):
        return {"summary": {"analyzed_rules": 3, "optimization_score": 100}}

    async def nat(c, package):
        return {"summary": {"total_nat_rules": 2}}

    monkeypatch.setattr(R, "package_access_tree", tree)
    monkeypatch.setattr(R, "analyze_package", access)
    monkeypatch.setattr(R, "analyze_nat", nat)
    monkeypatch.setattr(R, "cache_get", lambda k: None)
    monkeypatch.setattr(R, "cache_set", lambda k, v: None)
    monkeypatch.setattr(R.snapshot_store, "SNAPSHOT_DIR", tmp_path / "snapshots")
    monkeypatch.setattr(R, "diff_snapshots",
                        lambda a, b: {"identical": True, "summary": {}, "warnings": []})
    monkeypatch.setattr(R.snapshot_store, "build_snapshot",
                        lambda tree, nat, package: _snapshot(package))
    monkeypatch.setattr(R.snapshot_store, "save_snapshot", lambda snap: "SNAP-1")
    monkeypatch.setattr(R.snapshot_store, "list_snapshots", lambda: [])
    monkeypatch.setattr(R.settings, "gaia_enabled", False)
    return monkeypatch


# ---- the composition -------------------------------------------------------

class TestARunRecordsWhatItDid:
    def test_a_clean_run_is_complete(self, wired):
        run = asyncio.run(R.run_review(_Client(), "P"))
        assert run["complete"] is True
        assert run["incomplete_sections"] == []
        assert run["sections"]["access"]["ok"]
        assert run["sections"]["snapshot"]["data"]["snapshot_id"] == "SNAP-1"

    def test_it_reports_the_steps_it_is_on(self, wired):
        seen = []
        asyncio.run(R.run_review(_Client(), "P",
                                 on_step=lambda i, n, label: seen.append((i, label))))
        assert [i for i, _ in seen] == list(range(6))
        assert all(label for _, label in seen)

    def test_a_section_nobody_asked_for_is_not_a_failure(self, wired):
        run = asyncio.run(R.run_review(_Client(), "P",
                                       profile=None, include_health=False))
        assert run["complete"] is True
        assert run["sections"]["compliance"]["requested"] is False
        assert run["sections"]["gateways"]["requested"] is False


class TestAFailureIsNeverRecordedAsNothingFound:
    """The property the whole design turns on."""

    def test_an_unreadable_nat_rulebase_is_reported_not_swallowed(self, wired):
        run = asyncio.run(R.run_review(_Client(nat_error="NAT unavailable"), "P"))
        assert run["sections"]["nat"]["ok"] is False
        assert "NAT unavailable" in run["sections"]["nat"]["error"]
        assert "nat" in run["incomplete_sections"]
        assert run["complete"] is False

    def test_the_access_analysis_still_runs_when_nat_fails(self, wired):
        run = asyncio.run(R.run_review(_Client(nat_error="boom"), "P"))
        assert run["sections"]["access"]["ok"], "one failure took the whole run down"

    def test_unreachable_gateways_do_not_become_zero_findings(self, wired, monkeypatch):
        monkeypatch.setattr(R.settings, "gaia_enabled", True)

        async def unreachable():
            raise OSError("gateway did not answer")

        monkeypatch.setattr("app.gaia.read_all_state", unreachable)
        run = asyncio.run(R.run_review(_Client(), "P", include_health=True))

        gw = run["sections"]["gateways"]
        assert gw["requested"] is True
        assert gw["ok"] is False
        assert gw["data"] is None, "an unreachable gateway produced a data section"
        assert "gateway did not answer" in gw["error"]
        assert run["complete"] is False

    def test_a_broken_profile_does_not_pass_silently(self, wired, monkeypatch):
        monkeypatch.setattr(R.compliance_engine, "load_profile_by_id",
                            lambda pid: (_ for _ in ()).throw(FileNotFoundError("no such profile")))
        run = asyncio.run(R.run_review(_Client(), "P", profile="ghost"))
        assert run["sections"]["compliance"]["ok"] is False
        assert "compliance" in run["incomplete_sections"]


class TestComparingWithThePreviousRun:
    def test_the_first_run_says_so_instead_of_no_change(self, wired):
        run = asyncio.run(R.run_review(_Client(), "P"))
        assert run["sections"]["changed"]["data"]["first_run"] is True

    def test_it_compares_against_the_newest_earlier_snapshot(self, wired, monkeypatch):
        monkeypatch.setattr(R.snapshot_store, "list_snapshots", lambda: [
            {"id": "OLD", "package": "P", "taken_at": "2026-01-01T00:00:00+00:00"},
            {"id": "NEWER", "package": "P", "taken_at": "2026-01-02T00:00:00+00:00"},
            {"id": "OTHER", "package": "Q", "taken_at": "2026-01-03T00:00:00+00:00"},
        ])
        monkeypatch.setattr(R.snapshot_store, "load_snapshot", lambda sid: _snapshot("P"))
        run = asyncio.run(R.run_review(_Client(), "P"))
        data = run["sections"]["changed"]["data"]
        assert data["compared_with"] == "NEWER", "compared against the wrong snapshot"

    def test_a_snapshot_of_another_package_is_not_a_comparison(self, wired, monkeypatch):
        monkeypatch.setattr(R.snapshot_store, "list_snapshots", lambda: [
            {"id": "OTHER", "package": "Q", "taken_at": "2026-01-03T00:00:00+00:00"}])
        run = asyncio.run(R.run_review(_Client(), "P"))
        assert run["sections"]["changed"]["data"]["first_run"] is True


# ---- what a scheduler acts on ---------------------------------------------

class TestExitCodesSeparateChangedFromUndecided:
    """A daily job that reports "changed" every morning gets ignored."""

    def _run(self, counters, *, conformant=True, incomplete=()):
        return {
            "incomplete_sections": list(incomplete),
            "sections": {
                "changed": {"ok": True, "requested": True,
                            "data": {"first_run": False, "summary": counters}},
                "compliance": {"ok": True, "requested": True,
                               "data": {"conformant": conformant}},
            },
        }

    def test_nothing_moved_is_zero(self):
        assert _exit_code(self._run({"unchanged": 12})) == EXIT_UNCHANGED

    def test_a_real_change_is_one(self):
        for key in ("added", "removed", "modified", "moved", "scope_changed",
                    "nat_added", "nat_removed", "nat_modified"):
            assert _exit_code(self._run({key: 1})) == EXIT_CHANGED, key

    def test_unverifiable_scope_is_undecided_not_changed(self):
        """The live lab produces exactly this: 0 of everything, 1 unverifiable."""
        code = _exit_code(self._run({"unchanged": 12, "scope_unverifiable": 1}))
        assert code == EXIT_UNDECIDED, (
            "one rule whose reach could not be verified was reported as a change")

    def test_a_failed_compliance_check_is_worth_looking_at(self):
        assert _exit_code(self._run({}, conformant=False)) == EXIT_CHANGED

    def test_a_section_that_did_not_read_outranks_everything(self):
        code = _exit_code(self._run({"added": 5}, incomplete=["gateways"]))
        assert code == EXIT_UNDECIDED


# ---- the store -------------------------------------------------------------

class TestTheRunStore:
    def test_a_run_round_trips(self, tmp_path):
        rid = store.save_run({"package": "P", "started_at": "2026-01-01T09:00:00+00:00",
                              "sections": {}}, base=tmp_path)
        assert store.load_run(rid, base=tmp_path)["package"] == "P"

    def test_runs_are_listed_newest_first(self, tmp_path):
        for stamp in ("2026-01-01T09:00:00+00:00", "2026-01-03T09:00:00+00:00",
                      "2026-01-02T09:00:00+00:00"):
            store.save_run({"package": "P", "started_at": stamp, "sections": {}},
                           base=tmp_path)
        order = [r["started_at"] for r in store.list_runs(base=tmp_path)]
        assert order == sorted(order, reverse=True)

    def test_an_unreadable_run_is_named_not_skipped(self, tmp_path):
        (tmp_path / "broken.json").write_text("{not json", encoding="utf-8")
        rows = store.list_runs(base=tmp_path)
        assert len(rows) == 1 and rows[0]["id"] == "broken"
        assert "unreadable" in rows[0]

    def test_the_index_carries_whether_the_policy_moved(self, tmp_path):
        store.save_run({
            "package": "P", "started_at": "2026-01-01T09:00:00+00:00",
            # A change means a counter moved. `identical: False` alone is not
            # one - it is also false when a rule merely could not be compared.
            "sections": {"changed": {"data": {"first_run": False, "identical": False,
                                              "summary": {"modified": 1}}},
                         "snapshot": {"data": {"snapshot_id": "SNAP-9"}}},
        }, base=tmp_path)
        row = store.list_runs(base=tmp_path)[0]
        assert row["policy_changed"] is True
        assert row["snapshot_id"] == "SNAP-9"

    def test_a_first_run_is_not_reported_as_changed(self, tmp_path):
        store.save_run({"package": "P", "started_at": "2026-01-01T09:00:00+00:00",
                        "sections": {"changed": {"data": {"first_run": True}}}},
                       base=tmp_path)
        assert store.list_runs(base=tmp_path)[0]["policy_changed"] is None


def test_the_runner_issues_no_write_command():
    """It composes read-only services; it must not grow a write of its own."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent
           / "app" / "jobs" / "runner.py").read_text(encoding="utf-8")
    for forbidden in ("add-", "set-", "delete-", "publish", "install-policy"):
        assert f'"{forbidden}' not in src, forbidden


class TestOnlyOneDefinitionOfChanged:
    """Three places consume the diff summary. They must agree on what a change is.

    `identical` is false when any of nine counters moves, and one of them -
    `scope_unverifiable` - means "could not be compared". Reading that as a
    change produced a wrong answer three separate times: in the CLI summary, in
    the PDF headline, and in the run index behind the Reviews table. Each was
    found only by looking at real output.
    """

    def test_the_two_key_lists_are_identical(self):
        from tools.run_review import REAL_CHANGE_KEYS as cli
        assert store.REAL_CHANGE_KEYS == cli, (
            "the run index and the CLI disagree about what counts as a change")

    def test_scope_unverifiable_is_in_neither(self):
        assert "scope_unverifiable" not in store.REAL_CHANGE_KEYS

    def test_the_index_reports_unverifiable_separately(self, tmp_path):
        store.save_run({
            "package": "P", "started_at": "2026-01-01T09:00:00+00:00",
            "sections": {"changed": {"data": {
                "first_run": False, "identical": False,
                "summary": {"added": 0, "removed": 0, "modified": 0, "moved": 0,
                            "unchanged": 12, "scope_unverifiable": 1}}}},
        }, base=tmp_path)
        row = store.list_runs(base=tmp_path)[0]
        assert row["policy_changed"] is False, (
            "one rule that could not be compared was counted as a change")
        assert row["undecided_rules"] == 1

    def test_a_real_change_still_reads_as_changed(self, tmp_path):
        store.save_run({
            "package": "P", "started_at": "2026-01-01T09:00:00+00:00",
            "sections": {"changed": {"data": {
                "first_run": False, "identical": False,
                "summary": {"modified": 2, "scope_unverifiable": 1}}}},
        }, base=tmp_path)
        row = store.list_runs(base=tmp_path)[0]
        assert row["policy_changed"] is True
        assert row["undecided_rules"] == 1
