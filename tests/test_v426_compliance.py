"""
v4.26 - compliance as code: the customer writes the standard, not us.

The question that shaped this feature is "why would anyone believe our
baseline?" The answer is that they should not have to, so the tool does not
ship one as authority. A profile is a file the customer writes, and the engine
reports conformance against *their* rules.

Three properties the tests below hold in place:

1. **Every check declares where its requirement came from.** A check with no
   `source` is not rejected - house rules are legitimate - but it is labelled
   as uncited, visibly, in the result. Making an uncited rule look identical to
   one backed by NIST is how a report stops being evidence.

2. **The result is tri-state, like everything else here.** A check whose input
   cannot be resolved is `unverifiable`. It is never a pass. A compliance
   report that quietly upgrades "we could not tell" to "compliant" is worse
   than no report, because somebody signs it.

3. **There is no compliance percentage.** Counts only. A percentage has to
   decide what an unverifiable check is worth, and every possible answer to
   that is a lie - so the engine refuses to pick one.
"""

import pytest

from app.compliance import evaluate_profile, load_profile

# ---- fixtures: snapshot-shaped rules ---------------------------------

def dim(uids, text, atoms=None, complete=True):
    return {"uids": list(uids), "text": text,
            "atoms": list(atoms or []), "complete": complete}


ANY_ADDR = dim(["any"], "Any", [[4, 0, 4294967295]])
LAB = dim(["lab"], "LAB-VLAN10", [[4, 3232238080, 3232238335]])
ANY_SVC = dim(["any"], "Any", [["any", 0, 65535]])
HTTPS = dim(["https"], "https", [["tcp", 443, 443]])
TELNET = dim(["telnet"], "telnet", [["tcp", 23, 23]])
OPAQUE = dim(["zone"], "InternalZone", [], complete=False)


def rule(uid, position, action="Accept", source=LAB, destination=ANY_ADDR,
         service=HTTPS, enabled=True, track="Log", name="R", layer="Network",
         comments="documented"):
    return {"uid": uid, "display_rule": str(position), "position": position,
            "layer": layer, "section": "", "name": name, "enabled": enabled,
            "action": action, "track": track, "comments": comments,
            "inline_layer": "", "hits": 5,
            "source": source, "destination": destination, "service": service,
            "vpn": dim(["vany"], "Any"), "install_on": dim(["pt"], "Policy Targets")}


def snap(rules):
    return {"schema": 1, "package": "External-FW", "app_version": "4.26.0",
            "taken_at": "2026-09-08T12:00:00", "access": {"rules": rules},
            "nat": {"rules": []},
            "summary": {"access_rules": len(rules), "nat_rules": 0}}


def profile(checks, name="Test profile"):
    return {"version": 1, "name": name, "checks": checks}


def status_of(result, check_id):
    return next(r["status"] for r in result["results"] if r["id"] == check_id)


# ---- no_rule_matches --------------------------------------------------

class TestNoRuleMatches:
    CHECK = {"id": "NO-ANY", "title": "No Any/Any/Any permit rule",
             "severity": "high", "type": "no_rule_matches",
             "where": {"action": "accept", "source_is_any": True,
                       "destination_is_any": True, "service_is_any": True}}

    def test_a_clean_policy_passes(self):
        out = evaluate_profile(profile([self.CHECK]), snap([rule("a", 1)]))
        assert status_of(out, "NO-ANY") == "pass"

    def test_a_violating_rule_fails_and_is_named(self):
        bad = rule("b", 2, source=ANY_ADDR, destination=ANY_ADDR, service=ANY_SVC,
                   name="Allow-Any")
        out = evaluate_profile(profile([self.CHECK]), snap([rule("a", 1), bad]))
        assert status_of(out, "NO-ANY") == "fail"
        offenders = out["results"][0]["offenders"]
        assert [o["uid"] for o in offenders] == ["b"]
        assert offenders[0]["name"] == "Allow-Any"

    def test_a_drop_rule_of_the_same_shape_is_not_a_violation(self):
        """Any/Any/Any Drop is a cleanup rule, which is the opposite problem."""
        cleanup = rule("c", 2, action="Drop", source=ANY_ADDR,
                       destination=ANY_ADDR, service=ANY_SVC, name="Cleanup rule")
        out = evaluate_profile(profile([self.CHECK]), snap([rule("a", 1), cleanup]))
        assert status_of(out, "NO-ANY") == "pass"

    def test_a_disabled_rule_can_be_excluded(self):
        check = dict(self.CHECK, where=dict(self.CHECK["where"], enabled=True))
        bad = rule("b", 2, source=ANY_ADDR, destination=ANY_ADDR, service=ANY_SVC,
                   enabled=False)
        assert status_of(evaluate_profile(profile([check]), snap([bad])), "NO-ANY") == "pass"

    def test_an_empty_policy_is_not_applicable_not_a_pass(self):
        out = evaluate_profile(profile([self.CHECK]), snap([]))
        assert status_of(out, "NO-ANY") == "not_applicable"


class TestServiceCoverageIsTriState:
    CHECK = {"id": "NO-TELNET", "title": "Telnet is never permitted",
             "severity": "high", "type": "no_rule_matches",
             "where": {"action": "accept", "service_covers": {"protocol": "tcp", "port": 23}}}

    def test_a_rule_permitting_telnet_fails(self):
        out = evaluate_profile(profile([self.CHECK]), snap([rule("a", 1, service=TELNET)]))
        assert status_of(out, "NO-TELNET") == "fail"

    def test_a_rule_on_another_port_passes(self):
        out = evaluate_profile(profile([self.CHECK]), snap([rule("a", 1, service=HTTPS)]))
        assert status_of(out, "NO-TELNET") == "pass"

    def test_any_service_covers_telnet_and_therefore_fails(self):
        out = evaluate_profile(profile([self.CHECK]), snap([rule("a", 1, service=ANY_SVC)]))
        assert status_of(out, "NO-TELNET") == "fail"

    def test_an_unresolvable_service_is_unverifiable_never_a_pass(self):
        """The whole point. 'We could not tell' must not be signed off as clean."""
        out = evaluate_profile(profile([self.CHECK]),
                               snap([rule("a", 1, service=OPAQUE)]))
        assert status_of(out, "NO-TELNET") == "unverifiable"
        result = out["results"][0]
        assert result["unverifiable_rules"][0]["uid"] == "a"
        assert "InternalZone" in result["unverifiable_rules"][0]["reason"]

    def test_a_proven_violation_outranks_an_unverifiable_rule(self):
        """One proven failure is a failure, whatever else could not be read."""
        out = evaluate_profile(profile([self.CHECK]),
                               snap([rule("a", 1, service=OPAQUE),
                                     rule("b", 2, service=TELNET)]))
        assert status_of(out, "NO-TELNET") == "fail"
        assert out["results"][0]["unverifiable_rules"], "and it still says what it could not read"


class TestAddressCoverage:
    CHECK = {"id": "NO-INBOUND", "title": "Nothing from the internet reaches the lab",
             "severity": "high", "type": "no_rule_matches",
             "where": {"action": "accept", "source_is_any": True,
                       "destination_covers": "192.168.10.0/24"}}

    def test_an_inbound_any_rule_fails(self):
        out = evaluate_profile(profile([self.CHECK]),
                               snap([rule("a", 1, source=ANY_ADDR, destination=LAB)]))
        assert status_of(out, "NO-INBOUND") == "fail"

    def test_an_unrelated_destination_passes(self):
        other = dim(["o"], "Other", [[4, 167772160, 167772415]])
        out = evaluate_profile(profile([self.CHECK]),
                               snap([rule("a", 1, source=ANY_ADDR, destination=other)]))
        assert status_of(out, "NO-INBOUND") == "pass"


# ---- hygiene checks ---------------------------------------------------

class TestFieldChecks:
    def test_every_rule_must_be_logged(self):
        check = {"id": "LOG-ALL", "title": "Every rule is tracked",
                 "type": "all_rules_have", "field": "track"}
        ok = evaluate_profile(profile([check]), snap([rule("a", 1, track="Log")]))
        assert status_of(ok, "LOG-ALL") == "pass"
        bad = evaluate_profile(profile([check]), snap([rule("a", 1, track="None")]))
        assert status_of(bad, "LOG-ALL") == "fail"

    def test_every_rule_must_carry_a_comment(self):
        check = {"id": "DOC-ALL", "title": "Every rule has a business justification",
                 "type": "all_rules_have", "field": "comments"}
        bad = evaluate_profile(profile([check]), snap([rule("a", 1, comments="")]))
        assert status_of(bad, "DOC-ALL") == "fail"
        assert bad["results"][0]["offenders"][0]["uid"] == "a"

    def test_disabled_rules_check(self):
        check = {"id": "NO-DISABLED", "title": "No disabled rules left behind",
                 "type": "no_disabled_rules"}
        assert status_of(evaluate_profile(profile([check]), snap([rule("a", 1)])),
                         "NO-DISABLED") == "pass"
        assert status_of(evaluate_profile(profile([check]),
                                          snap([rule("a", 1, enabled=False)])),
                         "NO-DISABLED") == "fail"

    def test_cleanup_rule_must_be_present_and_logged(self):
        check = {"id": "CLEANUP", "title": "Explicit logged cleanup rule",
                 "type": "cleanup_rule_present", "require_log": True}
        cleanup = rule("z", 9, action="Drop", source=ANY_ADDR, destination=ANY_ADDR,
                       service=ANY_SVC, name="Cleanup rule")
        assert status_of(evaluate_profile(profile([check]),
                                          snap([rule("a", 1), cleanup])),
                         "CLEANUP") == "pass"
        assert status_of(evaluate_profile(profile([check]), snap([rule("a", 1)])),
                         "CLEANUP") == "fail"
        unlogged = dict(cleanup, track="None")
        assert status_of(evaluate_profile(profile([check]),
                                          snap([rule("a", 1), unlogged])),
                         "CLEANUP") == "fail"

    def test_a_rule_count_ceiling(self):
        check = {"id": "SIZE", "title": "At most 2 rules", "type": "max_rules", "limit": 2}
        assert status_of(evaluate_profile(profile([check]),
                                          snap([rule("a", 1), rule("b", 2)])), "SIZE") == "pass"
        assert status_of(evaluate_profile(profile([check]),
                                          snap([rule("a", 1), rule("b", 2), rule("c", 3)])),
                         "SIZE") == "fail"


class TestChecksThatNeedTheAnalyzer:
    CHECK = {"id": "NO-SHADOW", "title": "No shadowed rules",
             "type": "no_findings", "kind": "shadowed"}

    def test_it_uses_the_analysis_when_given_one(self):
        analysis = {"summary": {"potential_shadowed_or_redundant": 0}}
        assert status_of(evaluate_profile(profile([self.CHECK]), snap([rule("a", 1)]),
                                          analysis=analysis), "NO-SHADOW") == "pass"
        analysis = {"summary": {"potential_shadowed_or_redundant": 3}}
        assert status_of(evaluate_profile(profile([self.CHECK]), snap([rule("a", 1)]),
                                          analysis=analysis), "NO-SHADOW") == "fail"

    def test_without_an_analysis_it_is_unverifiable_not_a_pass(self):
        out = evaluate_profile(profile([self.CHECK]), snap([rule("a", 1)]))
        assert status_of(out, "NO-SHADOW") == "unverifiable"
        assert "analysis" in out["results"][0]["detail"].lower()


# ---- provenance and scoring ------------------------------------------

class TestProvenance:
    def test_a_cited_check_carries_its_citation_through(self):
        check = {"id": "DENY", "title": "Deny by default", "type": "no_disabled_rules",
                 "source": {"standard": "NIST SP 800-41 Rev. 1", "clause": "Section 4",
                            "url": "https://example.invalid/nist"}}
        out = evaluate_profile(profile([check]), snap([rule("a", 1)]))
        result = out["results"][0]
        assert result["source"]["standard"] == "NIST SP 800-41 Rev. 1"
        assert result["cited"] is True

    def test_an_uncited_check_runs_but_is_labelled_uncited(self):
        check = {"id": "HOUSE", "title": "House rule", "type": "no_disabled_rules"}
        result = evaluate_profile(profile([check]), snap([rule("a", 1)]))["results"][0]
        assert result["status"] == "pass"
        assert result["cited"] is False
        assert "no external" in result["source"]["note"].lower()

    def test_the_summary_counts_uncited_checks(self):
        out = evaluate_profile(profile([
            {"id": "A", "title": "a", "type": "no_disabled_rules",
             "source": {"standard": "X", "clause": "1"}},
            {"id": "B", "title": "b", "type": "no_disabled_rules"},
        ]), snap([rule("a", 1)]))
        assert out["summary"]["uncited_checks"] == 1


class TestItRefusesToScore:
    def test_there_is_no_percentage_anywhere_in_the_result(self):
        out = evaluate_profile(profile([
            {"id": "A", "title": "a", "type": "no_disabled_rules"},
            {"id": "B", "title": "b", "type": "no_findings", "kind": "shadowed"},
        ]), snap([rule("a", 1)]))
        assert "score" not in out["summary"]
        assert "percent" not in str(out["summary"]).lower()

    def test_the_counts_add_up_and_keep_unverifiable_separate(self):
        out = evaluate_profile(profile([
            {"id": "A", "title": "a", "type": "no_disabled_rules"},
            {"id": "B", "title": "b", "type": "no_findings", "kind": "shadowed"},
        ]), snap([rule("a", 1)]))
        s = out["summary"]
        assert s["total"] == 2
        assert s["passed"] == 1
        assert s["unverifiable"] == 1
        assert s["failed"] == 0
        assert s["passed"] + s["failed"] + s["unverifiable"] + s["not_applicable"] == s["total"]

    def test_compliant_requires_zero_failures_and_zero_unverifiable(self):
        clean = evaluate_profile(profile([{"id": "A", "title": "a",
                                           "type": "no_disabled_rules"}]),
                                 snap([rule("a", 1)]))
        assert clean["conformant"] is True
        murky = evaluate_profile(profile([{"id": "B", "title": "b",
                                           "type": "no_findings", "kind": "shadowed"}]),
                                 snap([rule("a", 1)]))
        assert murky["conformant"] is False, (
            "an unverifiable check is not a clean bill of health")


# ---- profile loading --------------------------------------------------

class TestLoadProfile:
    def test_a_yaml_profile_loads(self, tmp_path):
        path = tmp_path / "p.yaml"
        path.write_text(
            "version: 1\nname: Demo\nchecks:\n"
            "  - id: A\n    title: No disabled rules\n    type: no_disabled_rules\n",
            encoding="utf-8")
        p = load_profile(path)
        assert p["name"] == "Demo"
        assert p["checks"][0]["type"] == "no_disabled_rules"

    def test_a_json_profile_loads_too(self, tmp_path):
        path = tmp_path / "p.json"
        path.write_text('{"version":1,"name":"J","checks":[]}', encoding="utf-8")
        assert load_profile(path)["name"] == "J"

    def test_an_unknown_check_type_is_reported_not_skipped(self):
        out = evaluate_profile(profile([{"id": "X", "title": "x", "type": "wat"}]),
                               snap([rule("a", 1)]))
        assert status_of(out, "X") == "unverifiable"
        assert "wat" in out["results"][0]["detail"]

    def test_a_check_without_an_id_is_rejected_loudly(self):
        with pytest.raises(ValueError):
            evaluate_profile(profile([{"title": "no id", "type": "no_disabled_rules"}]),
                             snap([]))


# ---- profiles that ship with the application --------------------------

class TestStarterProfiles:
    def test_both_starter_profiles_parse(self):
        from app.compliance import list_profiles
        ids = {p["id"] for p in list_profiles()}
        assert {"nist-800-41-baseline", "house-hygiene"} <= ids

    def test_every_check_in_the_nist_profile_cites_a_clause(self):
        from app.compliance import load_profile_by_id
        for check in load_profile_by_id("nist-800-41-baseline")["checks"]:
            source = check.get("source")
            assert source, check["id"]
            assert source.get("standard") and source.get("clause"), check["id"]
            assert source.get("url"), check["id"]

    def test_the_nist_profile_says_what_it_cannot_check(self):
        """A clean run must not read as 'the standard is satisfied'."""
        from app.compliance import load_profile_by_id
        not_checkable = load_profile_by_id("nist-800-41-baseline")["not_checkable"]
        assert len(not_checkable) >= 3
        for item in not_checkable:
            assert item.get("requirement") and item.get("why")

    def test_the_house_profile_cites_nothing_and_is_honest_about_it(self):
        from app.compliance import load_profile_by_id
        profile = load_profile_by_id("house-hygiene")
        assert all(not c.get("source") for c in profile["checks"])
        assert "uncited" in profile["name"].lower()

    def test_a_run_carries_not_checkable_through_to_the_result(self):
        from app.compliance import evaluate_profile, load_profile_by_id
        out = evaluate_profile(load_profile_by_id("nist-800-41-baseline"), snap([rule("a", 1)]))
        assert len(out["not_checkable"]) >= 3

    def test_the_house_profile_marks_every_result_uncited(self):
        from app.compliance import evaluate_profile, load_profile_by_id
        out = evaluate_profile(load_profile_by_id("house-hygiene"), snap([rule("a", 1)]))
        assert out["summary"]["uncited_checks"] == out["summary"]["total"]
        assert all(r["cited"] is False for r in out["results"])

    def test_a_bad_profile_id_is_refused(self):
        from app.compliance import load_profile_by_id
        with pytest.raises(ValueError):
            load_profile_by_id("../../.env")


class TestRoutesAndUi:
    def setup_method(self):
        from pathlib import Path
        from conftest import ui_source
        self.src = (Path(__file__).resolve().parent.parent / "app" / "api"
                    / "compliance.py").read_text(encoding="utf-8")
        self.ui = ui_source()

    def test_the_routes_are_gets(self):
        for verb in ("router.post", "router.put", "router.patch", "router.delete"):
            assert verb not in self.src
        assert self.src.count("@router.get") == 2

    def test_a_snapshot_run_says_why_some_checks_cannot_be_decided(self):
        assert "does not \n" not in self.src
        assert "unverifiable here" in self.src

    def test_the_ui_never_folds_unverifiable_into_pass(self):
        assert "COMPLIANCE_TONE" in self.ui
        assert "unverifiable:'warn'" in self.ui
        assert "not counted as passes" in self.ui

    def test_the_ui_shows_whether_a_check_is_cited(self):
        assert "HOUSE RULE" in self.ui
        assert "complianceSource_cite" in self.ui

    def test_the_ui_states_there_is_no_percentage(self):
        assert "no compliance percentage" in self.ui.lower()

    def test_not_checked_is_rendered_below_the_results(self):
        assert "Not checked by this tool" in self.ui
        assert self.ui.index("Not checked by this tool") > self.ui.index("COMPLIANCE_TONE")
