"""
v4.25 - comparing a policy with itself, a month apart.

The question this answers is the one periodic audit work always asks and no
screen in SmartConsole answers: *what changed since last time?* Not "what does
the policy say now", which every other page here already tells you.

Four decisions the tests below pin down, because getting any of them wrong
makes the feature actively misleading:

1. **Rules are tracked by uid, never by rule number.** Insert one rule at the
   top and every number below it shifts. A diff keyed on numbers would report
   the whole rulebase as rewritten, which is how a person learns to skip the
   report.

2. **"Moved" is its own category, not a kind of "modified".** A rule whose
   text is byte-identical but which now sits above a rule it used to sit
   below is a behaviour change - first-match-wins makes position part of the
   meaning. Filing it under "unchanged" hides a real event; filing it under
   "modified" says fields changed when none did.

3. **A rule can change without the rule changing.** If `LAB-Internal-Nets`
   gains a member, every rule referencing it now permits more traffic while
   its text, its uids and its rule number all stay identical. A textual diff
   sees nothing. This is the finding an auditor actually needs, so the
   snapshot stores each dimension's resolved address/port intervals and
   compares those too.

4. **An unresolvable object makes the comparison unavailable, not equal.**
   Same discipline as everywhere else in this codebase: if either side could
   not be fully modelled, the answer is "cannot compare", never "no change".
   And if the two snapshots were taken by different versions of this
   application, a scope difference may be OUR change rather than the
   policy's - so it is reported as a warning on the whole diff.
"""

from app.snapshot_diff import diff_snapshots


def dim(uids, text, atoms=None, complete=True):
    return {"uids": list(uids), "text": text,
            "atoms": list(atoms if atoms is not None else []), "complete": complete}


def rule(uid, position, name="R", action="Accept", enabled=True, display=None,
         source=None, service=None, layer="Network", comments=""):
    return {
        "uid": uid,
        "display_rule": display or str(position),
        "position": position,
        "layer": layer,
        "section": "",
        "name": name,
        "enabled": enabled,
        "action": action,
        "track": "Log",
        "comments": comments,
        "inline_layer": "",
        "source": source or dim(["lab"], "LAB-VLAN10", [[4, 3232238080, 3232238335]]),
        "destination": dim(["any"], "Any", [[4, 0, 4294967295]]),
        "service": service or dim(["https"], "https", [["tcp", 443, 443]]),
        "vpn": dim(["vany"], "Any"),
        "install_on": dim(["pt"], "Policy Targets"),
        "hits": 10,
    }


def snap(rules, nat=None, package="External-FW", version="4.25.0", taken="2026-09-01T09:00:00"):
    return {
        "schema": 1,
        "package": package,
        "app_version": version,
        "taken_at": taken,
        "access": {"rules": rules},
        "nat": {"rules": nat or []},
        "summary": {"access_rules": len(rules), "nat_rules": len(nat or [])},
    }


# ---- identity ---------------------------------------------------------

def test_an_unchanged_policy_reports_nothing():
    a = snap([rule("r1", 1), rule("r2", 2)])
    d = diff_snapshots(a, snap([rule("r1", 1), rule("r2", 2)]))
    s = d["summary"]
    assert (s["added"], s["removed"], s["modified"], s["moved"]) == (0, 0, 0, 0)
    assert s["unchanged"] == 2
    assert d["identical"] is True


def test_inserting_a_rule_at_the_top_is_one_addition_not_a_rewrite():
    """The reason identity is the uid and not the rule number."""
    before = snap([rule("r1", 1), rule("r2", 2)])
    after = snap([rule("new", 1, name="New-Rule"), rule("r1", 2), rule("r2", 3)])
    d = diff_snapshots(before, after)
    assert d["summary"]["added"] == 1
    assert d["summary"]["modified"] == 0
    assert d["access"]["added"][0]["name"] == "New-Rule"
    # The two survivors moved down, and that IS reported - just not as edits.
    assert d["summary"]["moved"] == 2


def test_a_removed_rule_is_named():
    d = diff_snapshots(snap([rule("r1", 1), rule("r2", 2, name="Gone")]),
                       snap([rule("r1", 1)]))
    assert d["summary"]["removed"] == 1
    assert d["access"]["removed"][0]["name"] == "Gone"


# ---- modified vs moved ------------------------------------------------

def test_a_changed_field_is_reported_field_by_field():
    d = diff_snapshots(snap([rule("r1", 1, action="Accept", name="Web")]),
                       snap([rule("r1", 1, action="Drop", name="Web")]))
    assert d["summary"]["modified"] == 1
    change = d["access"]["modified"][0]
    assert change["uid"] == "r1"
    fields = {c["field"]: (c["from"], c["to"]) for c in change["changes"]}
    assert fields["action"] == ("Accept", "Drop")
    assert "name" not in fields


def test_disabling_a_rule_is_a_modification():
    d = diff_snapshots(snap([rule("r1", 1)]), snap([rule("r1", 1, enabled=False)]))
    fields = [c["field"] for c in d["access"]["modified"][0]["changes"]]
    assert "enabled" in fields


def test_reordering_two_rules_is_a_move_not_a_modification():
    before = snap([rule("r1", 1, name="A"), rule("r2", 2, name="B")])
    after = snap([rule("r2", 1, name="B"), rule("r1", 2, name="A")])
    d = diff_snapshots(before, after)
    assert d["summary"]["modified"] == 0
    assert d["summary"]["moved"] == 2
    moved = {m["uid"]: (m["from_position"], m["to_position"]) for m in d["access"]["moved"]}
    assert moved["r1"] == (1, 2)
    assert moved["r2"] == (2, 1)
    assert d["identical"] is False, "order is part of the meaning of a rulebase"


def test_hit_counts_alone_are_not_a_policy_change():
    """Hits move every day. Reporting them would drown the real changes."""
    a = snap([rule("r1", 1)])
    b = snap([rule("r1", 1)])
    b["access"]["rules"][0]["hits"] = 99999
    d = diff_snapshots(a, b)
    assert d["summary"]["modified"] == 0
    assert d["identical"] is True


# ---- the finding a text diff cannot make ------------------------------

def test_a_group_gaining_a_member_changes_a_rule_that_did_not_change():
    before = snap([rule("r1", 1, source=dim(["grp"], "LAB-Internal-Nets",
                                            [[4, 3232238080, 3232238335]]))])
    after = snap([rule("r1", 1, source=dim(["grp"], "LAB-Internal-Nets",
                                           [[4, 3232238080, 3232238335],
                                            [4, 3232243200, 3232243455]]))])
    d = diff_snapshots(before, after)
    assert d["summary"]["modified"] == 0, "no field of the rule changed"
    assert d["summary"]["scope_changed"] == 1
    finding = d["access"]["scope_changed"][0]
    assert finding["uid"] == "r1"
    assert finding["dimension"] == "source"
    assert finding["direction"] == "widened"
    assert "LAB-Internal-Nets" in finding["text"]


def test_a_group_losing_a_member_is_reported_as_narrowed():
    before = snap([rule("r1", 1, source=dim(["grp"], "G",
                                            [[4, 10, 20], [4, 100, 200]]))])
    after = snap([rule("r1", 1, source=dim(["grp"], "G", [[4, 10, 20]]))])
    d = diff_snapshots(before, after)
    assert d["access"]["scope_changed"][0]["direction"] == "narrowed"


def test_a_service_group_change_is_caught_on_the_service_dimension():
    before = snap([rule("r1", 1, service=dim(["sg"], "Web", [["tcp", 443, 443]]))])
    after = snap([rule("r1", 1, service=dim(["sg"], "Web",
                                            [["tcp", 443, 443], ["tcp", 8080, 8080]]))])
    d = diff_snapshots(before, after)
    assert d["access"]["scope_changed"][0]["dimension"] == "service"


def test_changing_the_referenced_object_is_a_modification_not_a_scope_change():
    """Different uids means the RULE was edited; that is the ordinary case."""
    before = snap([rule("r1", 1, source=dim(["a"], "Net-A", [[4, 10, 20]]))])
    after = snap([rule("r1", 1, source=dim(["b"], "Net-B", [[4, 30, 40]]))])
    d = diff_snapshots(before, after)
    assert d["summary"]["modified"] == 1
    assert d["summary"]["scope_changed"] == 0


# ---- what it refuses to claim -----------------------------------------

def test_an_incomplete_side_makes_the_comparison_unavailable_not_equal():
    before = snap([rule("r1", 1, source=dim(["z"], "Zone", [], complete=False))])
    after = snap([rule("r1", 1, source=dim(["z"], "Zone", [], complete=False))])
    d = diff_snapshots(before, after)
    assert d["summary"]["scope_changed"] == 0
    assert d["summary"]["scope_unverifiable"] == 1
    entry = d["access"]["scope_unverifiable"][0]
    assert entry["dimension"] == "source"
    assert "Zone" in entry["text"]
    assert d["identical"] is False, "an unverifiable comparison is not a clean bill of health"


def test_different_app_versions_warn_that_a_scope_change_may_be_ours():
    before = snap([rule("r1", 1, source=dim(["g"], "G", [[4, 10, 20]]))], version="4.24.0")
    after = snap([rule("r1", 1, source=dim(["g"], "G", [[4, 10, 30]]))], version="4.25.0")
    d = diff_snapshots(before, after)
    assert d["summary"]["scope_changed"] == 1
    joined = " ".join(d["warnings"])
    assert "4.24.0" in joined and "4.25.0" in joined
    assert "this application" in joined.lower()


def test_a_rule_with_no_uid_is_counted_and_warned_about_not_dropped():
    a = snap([rule("r1", 1)])
    b = snap([rule("r1", 1), dict(rule("x", 2), uid="")])
    d = diff_snapshots(a, b)
    assert d["summary"]["untracked_rules"] == 1
    assert any("uid" in w for w in d["warnings"])


def test_comparing_two_different_packages_is_allowed_but_flagged():
    d = diff_snapshots(snap([rule("r1", 1)], package="External-FW"),
                       snap([rule("r1", 1)], package="Internal-FW"))
    joined = " ".join(d["warnings"])
    assert "External-FW" in joined and "Internal-FW" in joined


# ---- NAT --------------------------------------------------------------

def nat(uid, position, name="N", translated="Hide-GW", enabled=True):
    return {"uid": uid, "position": position, "rule": position, "name": name,
            "enabled": enabled,
            "original_source": "LAB-VLAN10", "original_destination": "Any",
            "original_service": "Any", "translated_source": translated,
            "translated_destination": "Original", "translated_service": "Original",
            "method": "hide", "install_on": "Policy Targets"}


def test_nat_rules_are_diffed_on_the_same_terms():
    d = diff_snapshots(snap([], nat=[nat("n1", 1), nat("n2", 2)]),
                       snap([], nat=[nat("n1", 1), nat("n2", 2, translated="Other")]))
    assert d["summary"]["nat_modified"] == 1
    assert d["nat"]["modified"][0]["changes"][0]["field"] == "translated_source"


def test_a_new_nat_rule_is_an_addition():
    d = diff_snapshots(snap([], nat=[nat("n1", 1)]),
                       snap([], nat=[nat("n1", 1), nat("n2", 2, name="New-Hide")]))
    assert d["summary"]["nat_added"] == 1
    assert d["nat"]["added"][0]["name"] == "New-Hide"


# ---- shape ------------------------------------------------------------

def test_the_diff_reports_both_snapshots_it_compared():
    d = diff_snapshots(snap([rule("r1", 1)], taken="2026-08-01T10:00:00"),
                       snap([rule("r1", 1)], taken="2026-09-01T10:00:00"))
    assert d["a"]["taken_at"] == "2026-08-01T10:00:00"
    assert d["b"]["taken_at"] == "2026-09-01T10:00:00"
    assert d["a"]["package"] == "External-FW"
