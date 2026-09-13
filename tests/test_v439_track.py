"""
v4.39 - a rule's tracking was never recorded.

`track` is the one rule column that is not a reference. The Management API
returns it as an object whose `type` points at a Track object:

    "track": {"type": "598ead32-...", "per-connection": true, "alert": "none"}
    objects-dictionary: {"uid": "598ead32-...", "name": "Log", "type": "Track"}

It went through `_single_name()`, which looks for `name` or `uid` on the outer
object, finds neither, and returns "". Confirmed on the lab: all 13 rules of
External-FW were stored with `track: ""`, while the rulebase holds both Log and
None rules. Consequences, all silent:

    a profile check `all_rules_have: track` (shipped in nist-800-41-baseline)
      failed every rule in the estate
    `cleanup_rule_present` with `require_log` reported every cleanup rule as
      not logged
    a rule switched from Log to None never appeared in a snapshot diff
    the Access Policy page's Track column was blank

The fix resolves the type. A type uid this read could not resolve becomes
"unresolved" - neither logged nor not logged - so a check asking the question
answers "cannot tell". Snapshots taken before the fix hold "", and comparing
one of those with a current snapshot must not report the whole estate edited.
"""

from __future__ import annotations

from app.compliance import FAIL, PASS, UNVERIFIABLE, _check_all_rules_have, _check_cleanup_rule_present
from app.policy_browser import TRACK_UNRESOLVED, browse_access_rulebase, track_name
from app.resolver import ObjectResolver
from app.snapshot import build_snapshot
from app.snapshot_diff import diff_snapshots

LOG, NONE = "uid-track-log", "uid-track-none"
ANY = "97aeb369-9aea-11d5-bd16-0090272ccb30"

DICTIONARY = [
    {"uid": LOG, "name": "Log", "type": "Track"},
    {"uid": NONE, "name": "None", "type": "Track"},
    {"uid": ANY, "name": "Any", "type": "CpmiAnyObject"},
    {"uid": "uid-drop", "name": "Drop", "type": "RulebaseAction"},
    {"uid": "uid-accept", "name": "Accept", "type": "RulebaseAction"},
]


def _rule(n, track_uid, action="uid-accept", uid=None):
    return {"type": "access-rule", "uid": uid or f"rule-{n}", "rule-number": n,
            "name": f"R{n}", "enabled": True, "action": action,
            "source": [ANY], "destination": [ANY], "service": [ANY],
            "track": {"type": track_uid, "per-connection": True, "alert": "none"}}


def _tree(*rules):
    return {"layers": [{"name": "L", "display_prefix": "", "path": "L", "depth": 0,
                        "payload": {"rulebase": list(rules),
                                    "objects-dictionary": DICTIONARY}}]}


class TestTheTrackTypeIsResolved:
    def test_the_real_api_shape_yields_the_track_name(self):
        res = ObjectResolver({o["uid"]: o for o in DICTIONARY})
        assert track_name({"type": LOG, "per-connection": True}, res) == "Log"
        assert track_name({"type": NONE}, res) == "None"

    def test_an_expanded_type_object_is_read_directly(self):
        res = ObjectResolver({})
        assert track_name({"type": {"uid": LOG, "name": "Detailed Log"}}, res) == "Detailed Log"

    def test_a_type_this_read_cannot_resolve_is_not_guessed(self):
        res = ObjectResolver({})
        assert track_name({"type": "some-uid-not-in-the-dictionary"}, res) == TRACK_UNRESOLVED

    def test_the_snapshot_records_it(self):
        snap = build_snapshot(_tree(_rule(1, LOG), _rule(2, NONE)), None, "P")
        tracks = [r["track"] for r in snap["access"]["rules"]]
        assert tracks == ["Log", "None"], (
            f"snapshot recorded {tracks}; before v4.39 this was ['', ''] for every rule")

    def test_the_access_policy_page_shows_it(self):
        rows = browse_access_rulebase(_tree(_rule(1, LOG))["layers"][0]["payload"])["rules"]
        assert rows[0]["track"] == "Log"


class TestComplianceStopsFailingEveryRule:
    def _rules(self, *tracks):
        rules = build_snapshot(_tree(*[_rule(i + 1, t) for i, t in enumerate(tracks)]),
                               None, "P")["access"]["rules"]
        return rules

    def test_logged_rules_pass_every_rule_has_a_track(self):
        """The false positive, reproduced: this failed every rule before the fix."""
        status, _, offenders, _ = _check_all_rules_have({"field": "track"}, self._rules(LOG, LOG), {})
        assert status == PASS, f"logged rules were reported as untracked: {offenders}"

    def test_a_rule_with_tracking_off_still_fails(self):
        status, _, offenders, _ = _check_all_rules_have({"field": "track"}, self._rules(LOG, NONE), {})
        assert status == FAIL
        assert [o["display_rule"] for o in offenders] == ["2"]
        assert offenders[0]["reason"] == "track is None"

    def test_an_unresolved_track_is_undecided_not_passed(self):
        rules = self._rules(LOG)
        rules[0]["track"] = TRACK_UNRESOLVED
        status, _, offenders, undecided = _check_all_rules_have({"field": "track"}, rules, {})
        assert status == UNVERIFIABLE and not offenders and len(undecided) == 1

    def test_a_logged_cleanup_rule_is_logged(self):
        rules = build_snapshot(_tree(_rule(1, LOG), _rule(2, LOG, action="uid-drop")),
                               None, "P")["access"]["rules"]
        status, detail, offenders, _ = _check_cleanup_rule_present({"require_log": True}, rules, {})
        assert status == PASS, f"{detail} {offenders}"

    def test_an_unlogged_cleanup_rule_still_fails(self):
        rules = build_snapshot(_tree(_rule(1, LOG), _rule(2, NONE, action="uid-drop")),
                               None, "P")["access"]["rules"]
        status, _, _, _ = _check_cleanup_rule_present({"require_log": True}, rules, {})
        assert status == FAIL


class TestTheDiffSeesTrackingChange:
    def _snap(self, track_uid):
        return build_snapshot(_tree(_rule(1, track_uid, uid="same-rule")), None, "P")

    def test_log_to_none_is_an_edit(self):
        d = diff_snapshots(self._snap(LOG), self._snap(NONE))
        mods = d["access"]["modified"]
        assert mods and mods[0]["changes"] == [{"field": "track", "from": "Log", "to": "None"}], (
            "switching a rule's logging off is invisible to the diff")

    def test_a_pre_fix_snapshot_does_not_make_the_estate_look_edited(self):
        """Snapshots before v4.39 hold track "" for every rule."""
        old = self._snap(LOG)
        old["access"]["rules"][0]["track"] = ""
        d = diff_snapshots(old, self._snap(LOG))
        assert d["summary"]["modified"] == 0, (
            "comparing an old snapshot with a current one reported tracking edits "
            "that are only the bug being fixed")
        assert any("does not record rule tracking" in w for w in d["warnings"]), (
            "the reader is not told that a Log/None change cannot be seen here")
