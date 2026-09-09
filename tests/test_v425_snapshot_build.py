"""
v4.25 - what goes into a snapshot, and what deliberately does not.

The diff engine is only as good as what the snapshot recorded. Two things it
must get right: the rule uid (identity across time) and the resolved intervals
(the reason a group change is visible at all). Two things it must NOT record:
the object dictionary, which would make a snapshot enormous, and anything that
makes the file unsafe to name.
"""

import json

import pytest

from app.snapshot import (SAFE_ID, build_snapshot, list_snapshots, load_snapshot,
                          save_snapshot, snapshot_id)

OBJECTS = [
    {"uid": "any", "name": "Any", "type": "CpmiAnyObject"},
    {"uid": "acc", "name": "Accept", "type": "RulebaseAction"},
    {"uid": "log", "name": "Log", "type": "Track"},
    {"uid": "lab", "name": "LAB-VLAN10", "type": "network",
     "subnet4": "192.168.10.0", "mask-length4": 24},
    {"uid": "https", "name": "https", "type": "service-tcp", "port": "443"},
    {"uid": "zone", "name": "InternalZone", "type": "security-zone"},
]


def access_rule(uid, number, name, source="lab", service="https"):
    return {"type": "access-rule", "uid": uid, "rule-number": number, "name": name,
            "enabled": True, "source": [source], "destination": ["any"],
            "service": [service], "vpn": ["any"], "action": "acc", "track": "log",
            "install-on": ["any"], "comments": "",
            "hits": {"value": 42, "last-date": "2026-09-01"}}


def tree(rules, prefix="", layer="Network"):
    return {"layers": [{"name": layer, "depth": 0, "path": layer,
                        "display_prefix": prefix,
                        "payload": {"layer": layer, "rulebase": rules,
                                    "objects-dictionary": OBJECTS}}]}


class TestWhatIsRecorded:
    def test_the_rule_uid_is_carried_through(self):
        snap = build_snapshot(tree([access_rule("u-1", 1, "Web")]), None, "External-FW")
        assert snap["access"]["rules"][0]["uid"] == "u-1"

    def test_resolved_intervals_are_recorded_per_dimension(self):
        snap = build_snapshot(tree([access_rule("u-1", 1, "Web")]), None, "External-FW")
        row = snap["access"]["rules"][0]
        assert row["source"]["atoms"] == [[4, 3232238080, 3232238335]]
        assert row["source"]["complete"] is True
        assert row["service"]["atoms"] == [["tcp", 443, 443]]

    def test_an_unmodellable_object_is_recorded_as_incomplete(self):
        snap = build_snapshot(tree([access_rule("u-1", 1, "Zoned", source="zone")]),
                              None, "External-FW")
        source = snap["access"]["rules"][0]["source"]
        assert source["complete"] is False
        assert source["atoms"] == []

    def test_vpn_and_install_on_are_compared_on_names_not_intervals(self):
        row = build_snapshot(tree([access_rule("u-1", 1, "Web")]), None,
                             "External-FW")["access"]["rules"][0]
        for name in ("vpn", "install_on"):
            assert row[name]["atoms"] == []
            assert row[name]["complete"] is True, (
                "no intervals to resolve is not the same as failing to resolve them")

    def test_position_is_a_running_ordinal_across_layers(self):
        snap = build_snapshot(
            {"layers": [
                tree([access_rule("a", 1, "A"), access_rule("b", 2, "B")])["layers"][0],
                tree([access_rule("c", 1, "C")], prefix="8", layer="Inline")["layers"][0],
            ]}, None, "External-FW")
        rows = snap["access"]["rules"]
        assert [r["position"] for r in rows] == [1, 2, 3]
        assert [r["display_rule"] for r in rows] == ["1", "2", "8.1"]

    def test_hits_are_recorded_even_though_the_diff_ignores_them(self):
        """Kept for the record; excluded from the comparison. Both on purpose."""
        row = build_snapshot(tree([access_rule("u-1", 1, "Web")]), None,
                             "External-FW")["access"]["rules"][0]
        assert row["hits"] == 42

    def test_the_object_dictionary_is_not_copied_into_the_snapshot(self):
        snap = build_snapshot(tree([access_rule("u-1", 1, "Web")]), None, "External-FW")
        assert "objects-dictionary" not in json.dumps(snap)

    def test_the_app_version_is_stamped_so_a_diff_can_warn_about_it(self):
        from app.version import APP_VERSION
        assert build_snapshot(tree([]), None, "X")["app_version"] == APP_VERSION


class TestNatIsCaptured:
    def test_nat_rules_are_recorded_with_their_uid(self):
        nat = {"objects-dictionary": OBJECTS, "rulebase": [{
            "type": "nat-rule", "uid": "n-1", "rule-number": 1, "name": "Hide",
            "enabled": True, "original-source": "lab", "original-destination": "any",
            "original-service": "any", "translated-source": "any",
            "translated-destination": "Original", "translated-service": "Original",
            "method": "hide", "install-on": ["any"]}]}
        snap = build_snapshot(tree([]), nat, "External-FW")
        row = snap["nat"]["rules"][0]
        assert row["uid"] == "n-1"
        assert row["translated_destination"] == "Original"
        assert row["method"] == "hide"

    def test_no_nat_payload_is_an_empty_list_not_a_crash(self):
        assert build_snapshot(tree([]), None, "X")["nat"]["rules"] == []


class TestTheStore:
    def test_a_snapshot_round_trips(self, tmp_path):
        snap = build_snapshot(tree([access_rule("u-1", 1, "Web")]), None, "External-FW")
        sid = save_snapshot(snap, base=tmp_path)
        again = load_snapshot(sid, base=tmp_path)
        assert again["access"]["rules"][0]["uid"] == "u-1"
        assert again["id"] == sid

    def test_two_snapshots_in_the_same_second_do_not_overwrite_each_other(self, tmp_path):
        snap = build_snapshot(tree([]), None, "P", )
        first = save_snapshot(dict(snap), base=tmp_path)
        second = save_snapshot(dict(snap), base=tmp_path)
        assert first != second
        assert len(list_snapshots(base=tmp_path)) == 2

    def test_listing_is_newest_first_and_carries_the_counts(self, tmp_path):
        save_snapshot(build_snapshot(tree([access_rule("a", 1, "A")]), None, "P",
                                     taken_at="2026-08-01T00:00:00"), base=tmp_path)
        save_snapshot(build_snapshot(tree([]), None, "P",
                                     taken_at="2026-09-01T00:00:00"), base=tmp_path)
        rows = list_snapshots(base=tmp_path)
        assert rows[0]["taken_at"] > rows[1]["taken_at"]
        assert rows[1]["access_rules"] == 1

    def test_the_listing_carries_hit_totals_and_says_what_they_cover(self, tmp_path):
        """A trend can only be drawn from readings that happened.

        The Management API reports a running total and a last-hit date, never a
        time series, so the only honest source for "hits over time" is the
        snapshots the user took. The listing therefore carries the total, and
        `hit_counted_rules` says how many rules that total actually covers - a
        rule that reports no count is left out rather than counted as zero,
        which would silently drag every trend downwards.
        """
        rules = [access_rule("a", 1, "A"), access_rule("b", 2, "B"),
                 access_rule("c", 3, "C")]
        rules[0]["hits"] = {"value": 500}
        rules[1]["hits"] = {"value": 0}
        rules[2].pop("hits")            # this rule reports no count at all
        save_snapshot(build_snapshot(tree(rules), None, "P",
                                     taken_at="2026-09-01T00:00:00"), base=tmp_path)
        row = list_snapshots(base=tmp_path)[0]
        assert row["total_hits"] == 500
        assert row["hit_counted_rules"] == 2, "the uncounted rule must not be a zero"
        assert row["zero_hit_rules"] == 1

    def test_a_snapshot_with_no_hit_data_reports_no_total_rather_than_zero(self, tmp_path):
        """Zero hits and "this rulebase does not report hits" are different
        claims, and a chart that draws the second as the first invents a
        collapse in traffic that never happened."""
        mute = access_rule("a", 1, "A")
        mute.pop("hits")
        save_snapshot(build_snapshot(tree([mute]), None, "P",
                                     taken_at="2026-09-02T00:00:00"), base=tmp_path)
        row = list_snapshots(base=tmp_path)[0]
        assert row["total_hits"] is None
        assert row["hit_counted_rules"] == 0

    @pytest.mark.parametrize("bad", ["../secrets", "a/b", "..", "", "x" * 200, "a\\b"])
    def test_a_path_is_refused_not_sanitised(self, bad, tmp_path):
        assert not SAFE_ID.match(bad)
        with pytest.raises(ValueError):
            load_snapshot(bad, base=tmp_path)

    def test_a_missing_snapshot_is_a_clear_error(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_snapshot("nope", base=tmp_path)

    def test_the_id_is_derived_from_package_and_time(self):
        assert snapshot_id("External-FW", "2026-09-08T11:22:33+00:00").startswith(
            "External-FW-20260908")


def test_build_and_diff_fit_together():
    """The two halves are tested apart; this proves they meet."""
    from app.snapshot_diff import diff_snapshots
    before = build_snapshot(tree([access_rule("u-1", 1, "Web")]), None, "External-FW")
    after = build_snapshot(
        tree([access_rule("u-1", 1, "Web"), access_rule("u-2", 2, "New")]),
        None, "External-FW")
    d = diff_snapshots(before, after)
    assert d["summary"]["added"] == 1
    assert d["summary"]["unchanged"] == 1
    assert d["identical"] is False


# ---- routes and UI ----------------------------------------------------

class TestTheRoutesAreWiredAndStillReadOnly:
    def setup_method(self):
        from pathlib import Path
        self.api = Path(__file__).resolve().parent.parent / "app" / "api"

    def test_every_snapshot_route_is_a_get(self):
        src = (self.api / "snapshot.py").read_text(encoding="utf-8")
        for verb in ("router.post", "router.put", "router.patch", "router.delete"):
            assert verb not in src
        assert src.count("@router.get") == 3

    def test_the_router_includes_the_new_module(self):
        src = (self.api / "__init__.py").read_text(encoding="utf-8")
        assert "snapshot" in src

    def test_capturing_says_that_it_wrote_to_disk(self):
        """The only write in the codebase must not be a surprise."""
        src = (self.api / "snapshot.py").read_text(encoding="utf-8")
        assert "saved_to" in src
        assert "writes to disk" in src or "writes to" in src

    def test_a_bad_snapshot_id_is_a_400_and_a_missing_one_a_404(self):
        src = (self.api / "snapshot.py").read_text(encoding="utf-8")
        assert "status_code=404" in src and "status_code=400" in src


class TestTheUiKeepsTheCategoriesApart:
    def setup_method(self):
        from conftest import ui_source
        self.ui = ui_source()

    def test_the_page_exists_and_is_reachable(self):
        assert 'id="diff"' in self.ui
        assert "showPage('diff',this)" in self.ui

    def test_moved_is_presented_separately_from_modified(self):
        assert "diffSection('Modified'" in self.ui
        assert "diffSection('Moved'" in self.ui

    def test_a_scope_change_is_explained_as_a_rule_that_did_not_change(self):
        assert "Scope changed without the rule changing" in self.ui
        assert "A textual diff cannot see this" in self.ui

    def test_unverifiable_is_shown_not_folded_into_unchanged(self):
        assert "Could not be compared" in self.ui
        assert "rather than counted as unchanged" in self.ui

    def test_the_warnings_are_rendered_above_the_findings(self):
        assert "Read this before acting on the result" in self.ui
        head = self.ui.index("Read this before acting on the result")
        assert head < self.ui.index("diffSection('Added'")

    def test_comparing_a_snapshot_with_itself_is_refused(self):
        assert "Same snapshot twice" in self.ui
