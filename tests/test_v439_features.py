"""
v4.39 - cleanup scripts, object hygiene, rule usage from logs, and trends.

Each feature is held here to the property that makes it safe to show someone,
not only to its output:

    the script generator cannot reach a network, refuses an incomplete read,
      and never proposes a command where the finding calls for a decision
    object hygiene never widens a group when it suggests a merge
    rule usage never calls a rule unused when the logs could not show it
    a trend never draws "could not read" as zero
    the new reads are reads, and the set of them is written down
"""

from __future__ import annotations

import ast
import asyncio
from pathlib import Path

import pytest

from app import estate_reads, log_usage, object_hygiene, remediation, trends

APP = Path(__file__).resolve().parent.parent / "app"


# ============================================================================
# the cleanup script
# ============================================================================

def _rules():
    rows = []
    spec = [  # layer, number, name, uid, extra
        ("Net", 1, "Admin", "u1", {}),
        ("Net", 2, "Admin-copy", "u2", {}),
        ("Net", 3, "", "u3", {}),                       # unnamed
        ("Net", 4, "Outbound", "u4", {"inline_layer": "Inner"}),
        ("Net", 5, "Cleanup rule", "u5", {"action": "Drop"}),
        ("Net", 6, "Old", "u6", {"enabled": False}),
        ("Inner", 1, "Web", "u7", {}),
    ]
    for layer, n, name, uid, extra in spec:
        row = {"uid": uid, "layer": layer, "rule_number": n, "name": name,
               "display_rule": f"4.{n}" if layer == "Inner" else str(n),
               "enabled": True, "action": "Accept", "hits": 10, "track": "Log",
               "inline_layer": ""}
        row.update(extra)
        rows.append(row)
    return rows


def _analysis(**findings):
    base = {"shadowing": [], "duplicates": [], "any_any_any_rules": [],
            "zero_hit_rules": [], "disabled_rules": [],
            "cleanup_rules": [{"layer": "Net", "rule": 5, "display_rule": "5"}]}
    base.update(findings)
    return {"findings": base, "data_quality": {"complete": True}}


class TestTheGeneratorCannotRunAnything:
    def test_it_imports_nothing_that_reaches_a_network(self):
        tree = ast.parse((APP / "remediation.py").read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add(("." * node.level) + (node.module or ""))
        assert imported <= {"__future__", "json", "datetime", "typing", ".version"}, (
            f"remediation.py imports {sorted(imported)}. It holds mutating commands as "
            "text; the reason that is safe is that it cannot send anything.")

    def test_only_the_script_route_uses_it(self):
        def imports_it(text):
            return ("import remediation" in text or "from .remediation" in text
                    or "from ..remediation" in text)
        # Compared by path: api/remediation.py shares the module's file name.
        users = sorted(p.relative_to(APP).as_posix() for p in APP.rglob("*.py")
                       if p != APP / "remediation.py"
                       and imports_it(p.read_text(encoding="utf-8")))
        assert users == ["api/remediation.py"], users

    def test_the_script_route_is_a_get_that_returns_text(self):
        src = (APP / "api" / "remediation.py").read_text(encoding="utf-8")
        assert "@router.get(" in src
        for verb in ("router.post", "router.put", "router.delete", "router.patch"):
            assert verb not in src
        # The script is returned to the caller, never handed to the client.
        assert "c.call(" not in src

    def test_no_other_module_writes_cli(self):
        for p in APP.rglob("*.py"):
            if p.name == "remediation.py":
                continue
            assert "mgmt_cli" not in p.read_text(encoding="utf-8"), p.name


class TestWhatItProposes:
    def test_a_redundant_rule_is_disabled_not_deleted(self):
        plan = remediation.build_plan(_analysis(shadowing=[{
            "layer": "Net", "rule": 2, "display_rule": "2", "covered_by": 1,
            "classification": "Redundant", "earlier_action": "Accept", "later_action": "Accept"}]),
            _rules(), package="P")
        assert [(a["command"], a["uid"]) for a in plan["actions"]] == [("disable_rule", "u2")]

    def test_an_action_conflict_is_a_decision_with_no_command(self):
        plan = remediation.build_plan(_analysis(shadowing=[{
            "layer": "Net", "rule": 2, "display_rule": "2", "covered_by": 1,
            "classification": "Shadowed / action conflict",
            "earlier_action": "Accept", "later_action": "Drop"}]), _rules(), package="P")
        assert not plan["actions"]
        assert len(plan["decisions"]) == 1 and "Drop" in plan["decisions"][0]["why"]

    def test_the_cleanup_rule_and_an_inline_holder_are_never_touched(self):
        plan = remediation.build_plan(_analysis(
            zero_hit_rules=[{"layer": "Net", "rule": 5}, {"layer": "Net", "rule": 4}]),
            _rules(), package="P", include_zero_hit=True)
        assert not plan["actions"]
        whys = " ".join(s["why"] for s in plan["skipped"])
        assert "cleanup rule" in whys and "sub-policy" in whys

    def test_zero_hit_and_disabled_are_opt_in(self):
        a = _analysis(zero_hit_rules=[{"layer": "Net", "rule": 3}],
                      disabled_rules=[{"layer": "Net", "rule": 6}])
        assert not remediation.build_plan(a, _rules(), package="P")["actions"]
        plan = remediation.build_plan(a, _rules(), package="P",
                                      include_zero_hit=True, include_disabled=True)
        assert {(x["command"], x["uid"]) for x in plan["actions"]} == {
            ("disable_rule", "u3"), ("delete_rule", "u6")}

    def test_an_incomplete_read_produces_no_script(self):
        a = _analysis()
        a["data_quality"] = {"complete": False, "failed_inline_layers": 1}
        with pytest.raises(remediation.RefusedIncomplete):
            remediation.build_plan(a, _rules(), package="P")

    def test_a_rule_missing_from_the_snapshot_is_skipped_not_guessed(self):
        plan = remediation.build_plan(_analysis(zero_hit_rules=[{"layer": "Net", "rule": 99}]),
                                      _rules(), package="P", include_zero_hit=True)
        assert not plan["actions"] and "no uid" in plan["skipped"][0]["why"]

    def test_predefined_objects_are_never_deleted(self):
        plan = remediation.build_plan(_analysis(), _rules(), package="P", unused_objects=[
            {"uid": "o1", "name": "Mine", "type": "host", "domain": {"domain-type": "domain"}},
            {"uid": "o2", "name": "Builtin", "type": "host", "domain": {"domain-type": "data domain"}},
        ])
        assert [o["uid"] for o in plan["objects"]] == ["o1"]


class TestTheScriptText:
    def _plan(self):
        return remediation.build_plan(_analysis(zero_hit_rules=[{"layer": "Net", "rule": 3}],
                                                duplicates=[{"layer": "Net", "members": [
                                                    {"rule": 1, "layer": "Net", "action": "Accept", "display_rule": "1"},
                                                    {"rule": 2, "layer": "Net", "action": "Accept", "display_rule": "2"}]}]),
                                      _rules(), package="P", include_zero_hit=True)

    def test_mgmt_cli_publishes_only_on_typed_confirmation(self):
        text = remediation.render(self._plan(), "mgmt_cli")
        assert 'if [ "$ANSWER" = "PUBLISH" ]' in text
        assert "discard" in text
        assert "install-policy" not in text and "install policy" not in text.replace(
            "until you install policy", "")
        # The commands come before the prompt, not after it (the header also
        # mentions PUBLISH, so the prompt line itself is the anchor).
        assert text.index("run set access-rule") < text.index("read -r -p")

    def test_mgmt_cli_discards_if_it_stops_half_way(self):
        text = remediation.render(self._plan(), "mgmt_cli")
        assert "trap on_exit EXIT" in text and "set -euo pipefail" in text

    def test_names_cannot_break_out_of_the_shell_string(self):
        rules = _rules()
        rules[1]["layer"] = 'Net"; rm -rf / #$(whoami)`id`'
        plan = remediation.build_plan(_analysis(zero_hit_rules=[{"layer": rules[1]["layer"], "rule": 2}]),
                                      rules, package="P", include_zero_hit=True)
        line = next(l for l in remediation.render(plan, "mgmt_cli").splitlines()
                    if l.startswith("run set access-rule"))
        assert '\\"' in line and "\\$(" in line and "\\`" in line

    def test_ansible_never_auto_publishes_and_skips_unnamed_rules(self):
        text = remediation.render(self._plan(), "ansible")
        assert "auto_publish_session: false" in text
        assert "auto_publish_session: true" not in text
        assert "tags: [publish]" in text
        # rule 3 has no name, and the collection addresses rules by name
        assert "addresses rules by name" in text and "uid u3" in text

    def test_decisions_are_listed_at_the_end_as_comments(self):
        plan = remediation.build_plan(_analysis(any_any_any_rules=[{"layer": "Net", "rule": 1}]),
                                      _rules(), package="P")
        text = remediation.render(plan, "mgmt_cli")
        tail = text.split("# ---- Left to you", 1)[1].splitlines()[1:]
        assert tail and all(l.startswith("#") for l in tail if l.strip())


# ============================================================================
# object hygiene
# ============================================================================

def _defs(hosts=(), networks=(), ranges=(), groups=()):
    wrap = lambda xs: {"objects": list(xs), "total": len(xs), "capped": False}
    return {"host": wrap(hosts), "network": wrap(networks),
            "address-range": wrap(ranges), "group": wrap(groups)}


class TestObjectHygiene:
    def test_two_names_for_one_address_is_a_duplicate(self):
        d = object_hygiene.duplicates(_defs(hosts=[
            {"uid": "a", "name": "web1", "type": "host", "ipv4-address": "192.0.2.10"},
            {"uid": "b", "name": "WEB-01", "type": "host", "ipv4-address": "192.0.2.10"},
            {"uid": "c", "name": "db", "type": "host", "ipv4-address": "192.0.2.11"}]))
        assert len(d) == 1 and {o["name"] for o in d[0]["objects"]} == {"web1", "WEB-01"}

    def test_predefined_objects_are_not_duplicates(self):
        d = object_hygiene.duplicates(_defs(hosts=[
            {"uid": "a", "name": "x", "type": "host", "ipv4-address": "192.0.2.1", "read-only": True},
            {"uid": "b", "name": "y", "type": "host", "ipv4-address": "192.0.2.1"}]))
        assert d == []

    def test_contiguous_hosts_merge_exactly(self):
        hosts = [{"uid": f"h{i}", "name": f"h{i}", "type": "host", "ipv4-address": f"192.0.2.{i}"}
                 for i in range(4)]
        g = {"uid": "g", "name": "G", "members": [{"uid": h["uid"]} for h in hosts]}
        m = object_hygiene.merge_suggestions(_defs(hosts=hosts, groups=[g]))
        assert m and m[0]["equivalent_to"] == ["192.0.2.0/30"] and m[0]["addresses"] == 4

    def test_a_merge_is_never_wider_than_its_members(self):
        """Three of four addresses do not become a /30."""
        hosts = [{"uid": f"h{i}", "name": f"h{i}", "type": "host", "ipv4-address": f"192.0.2.{i}"}
                 for i in (0, 1, 3)]
        g = {"uid": "g", "name": "G", "members": [{"uid": h["uid"]} for h in hosts]}
        m = object_hygiene.merge_suggestions(_defs(hosts=hosts, groups=[g]))
        for s in m:
            assert "192.0.2.0/30" not in s["equivalent_to"]
            assert s["addresses"] == 3

    def test_a_member_inside_another_member_is_named_as_redundant(self):
        """The lab case: a /16 next to three networks already inside it."""
        nets = [{"uid": "big", "name": "Corp", "type": "network", "subnet4": "198.51.100.0", "mask-length4": 24},
                {"uid": "a", "name": "A", "type": "network", "subnet4": "198.51.100.0", "mask-length4": 26},
                {"uid": "b", "name": "B", "type": "network", "subnet4": "198.51.100.64", "mask-length4": 26}]
        g = {"uid": "g", "name": "Admin", "members": [{"uid": n["uid"]} for n in nets]}
        m = object_hygiene.merge_suggestions(_defs(networks=nets, groups=[g]))
        assert m, "a group holding redundant members produced no finding"
        red = {r["member"]: r["inside"] for r in m[0]["redundant_members"]}
        assert red == {"A": "Corp", "B": "Corp"}
        assert m[0]["merge_reduces"] is False, (
            "removing the redundant members is the whole finding; there is nothing to merge")

    def test_non_address_members_are_left_alone_and_counted(self):
        hosts = [{"uid": f"h{i}", "name": f"h{i}", "type": "host", "ipv4-address": f"192.0.2.{i}"}
                 for i in range(2)]
        g = {"uid": "g", "name": "G", "members": [{"uid": "h0"}, {"uid": "h1"},
                                                  {"uid": "svc", "type": "group"}]}
        m = object_hygiene.merge_suggestions(_defs(hosts=hosts, groups=[g]))
        assert m[0]["other_members_unchanged"] == 1


# ============================================================================
# rule usage from logs
# ============================================================================

RULES = [
    {"uid": "seen", "display_rule": "1", "track": "Log", "hits": 5},
    {"uid": "quiet", "display_rule": "2", "track": "Log", "hits": 0},
    {"uid": "nolog", "display_rule": "3", "track": "None", "hits": 0},
    {"uid": "unk", "display_rule": "4", "track": "unresolved", "hits": 0},
    {"uid": "parent", "display_rule": "5", "track": "Log", "hits": 9, "inline_layer": "Inner"},
]
RECORDS = [
    {"rule_uid": "seen", "policy_name": "P", "time": "2026-09-13T10:00:00Z", "action": "Accept"},
    {"rule_uid": "seen", "policy_name": "P", "time": "2026-09-13T11:00:00Z", "action": "Accept"},
    {"rule_uid": "quiet", "policy_name": "OTHER", "time": "2026-09-13T11:30:00Z"},
    {"rule_uid": None, "policy_name": "P", "time": "2026-09-13T09:00:00Z"},
]


class TestRuleUsage:
    def _usage(self, capped):
        return log_usage.usage(RULES, log_usage.aggregate(RECORDS, "P"),
                               capped=capped, time_frame="last-7-days")

    def test_each_rule_gets_the_verdict_the_logs_can_support(self):
        v = {r["uid"]: r["verdict"] for r in self._usage(capped=False)["rules"]}
        assert v == {"seen": "seen", "quiet": "no-traffic", "nolog": "not-logged",
                     "unk": "track-unknown", "parent": "via-inline"}

    def test_a_capped_scan_never_says_no_traffic(self):
        u = self._usage(capped=True)
        assert u["counts"]["no-traffic"] == 0
        assert {r["uid"]: r["verdict"] for r in u["rules"]}["quiet"] == "not-in-sample"

    def test_another_packages_records_are_not_counted(self):
        agg = log_usage.aggregate(RECORDS, "P")
        assert "quiet" not in agg["per_rule"] and agg["other_policy"] == 1 and agg["no_uid"] == 1

    def test_first_and_last_seen_are_the_window_edges(self):
        row = next(r for r in self._usage(False)["rules"] if r["uid"] == "seen")
        assert row["logs"] == 2
        assert row["first_seen"] == "2026-09-13T10:00:00Z" and row["last_seen"] == "2026-09-13T11:00:00Z"


# ============================================================================
# trends
# ============================================================================

class TestTrends:
    def _run(self, at, compliance):
        return {"id": at, "package": "P", "started_at": at, "complete": True,
                "sections": {
                    "access": {"requested": True, "ok": True, "data": {
                        "summary": {"optimization_score": 90, "analyzed_rules": 10},
                        "data_quality": {"complete": True}}},
                    "compliance": compliance,
                    "gateways": {"requested": True, "ok": False, "error": "timeout", "data": None},
                    "changed": {"requested": True, "ok": True, "data": {
                        "first_run": False, "summary": {"added": 1, "scope_unverifiable": 2}}}}}

    def test_a_failed_section_is_marked_failed_not_zero(self):
        p = trends.review_points([self._run("2026-09-01", {"requested": True, "ok": False})])[0]
        assert p["compliance"] == "failed"
        assert p["gateways"] == "failed"

    def test_a_section_nobody_asked_for_has_no_point(self):
        p = trends.review_points([self._run("2026-09-01", {"requested": False, "ok": False})])[0]
        assert p["compliance"] == "not-requested"

    def test_could_not_compare_is_not_counted_as_changed(self):
        p = trends.review_points([self._run("2026-09-01", {"requested": False, "ok": False})])[0]
        assert p["changes"] == {"changed": 1, "could_not_compare": 2}

    def test_points_are_in_time_order(self):
        pts = trends.review_points([self._run("2026-09-03", {}), self._run("2026-09-01", {})])
        assert [p["at"] for p in pts] == ["2026-09-01", "2026-09-03"]

    def test_a_snapshot_with_no_counted_hits_is_none_not_zero(self):
        pts = trends.snapshot_points([{"id": "s", "package": "P", "taken_at": "t", "total_hits": None}])
        assert pts[0]["total_hits"] is None


# ============================================================================
# the new reads
# ============================================================================

class _FakeClient:
    def __init__(self, pages):
        self.pages, self.calls = pages, []

    async def call(self, command, payload=None):
        self.calls.append((command, payload))
        return self.pages.pop(0)


class TestTheNewReads:
    def test_every_new_command_is_a_read(self):
        for command in estate_reads.READ_COMMANDS:
            assert command.startswith("show-") or command == "where-used", command

    def test_nothing_else_is_issued(self):
        src = (APP / "estate_reads.py").read_text(encoding="utf-8")
        called = set()
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "call" \
                    and node.args and isinstance(node.args[0], ast.Constant):
                called.add(node.args[0].value)
        assert called <= estate_reads.READ_COMMANDS, called - estate_reads.READ_COMMANDS

    def test_a_list_cut_short_says_so(self):
        c = _FakeClient([{"objects": [{"uid": str(i)} for i in range(3)], "total": 10, "to": 3}])
        items, total, capped = asyncio.run(estate_reads._paged(c, "show-hosts", cap=3))
        assert len(items) == 3 and total == 10 and capped is True

    def test_log_records_keep_no_addresses(self):
        c = _FakeClient([{"logs": [{"rule_uid": "u", "src": "192.0.2.1", "dst": "192.0.2.2",
                                    "time": "t", "policy_name": "P"}], "query-id": "q"}])
        records, capped = asyncio.run(estate_reads.log_records(c, "last-7-days", cap=10, per_page=100))
        assert records and "src" not in records[0] and "dst" not in records[0]
        assert capped is False

    def test_a_long_scan_does_not_hold_the_lock_between_pages(self):
        """3,000 records under one lock kept every other read waiting 3.5 minutes.

        A second reader asks for the lock while the scan is running. With the
        lock taken per page it gets in between two pages; with the lock held
        for the whole scan it only gets in after the last one.
        """
        events: list[str] = []
        pages = [{"logs": [{"rule_uid": "u", "time": "t"}] * 100, "query-id": "q"}
                 for _ in range(4)] + [{"logs": [], "query-id": "q"}]

        class Slow(_FakeClient):
            async def call(self, command, payload=None):
                events.append("page")
                await asyncio.sleep(0.01)
                return await super().call(command, payload)

        async def other_reader():
            await asyncio.sleep(0.015)        # after the scan has begun
            async with estate_reads.heavy_lock:
                events.append("other")

        async def both():
            await asyncio.gather(
                estate_reads.log_records(Slow(pages), "last-7-days", cap=10_000),
                other_reader())

        asyncio.run(both())
        last_page = len(events) - 1 - events[::-1].index("page")
        assert events.index("other") < last_page, (
            f"another read could not start until the scan finished: {events}")

    def test_an_unknown_time_frame_is_refused_before_any_call(self):
        c = _FakeClient([])
        with pytest.raises(AssertionError):
            asyncio.run(estate_reads.log_records(c, "last-10-years"))
        assert c.calls == []
