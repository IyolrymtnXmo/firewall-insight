"""
v4.20 - correlate_nat() is tri-state, and reads NAT fields in both shapes.

Three defects motivated this file, all reproduced before anything was fixed:

1. Singular NAT fields were dropped. Access rules always send `source` as a
   list; a NAT rule may send `"original-source": "uid"`. `ObjectResolver.uids()`
   returns [] for a non-list, so the rule matched nothing and was skipped in
   silence - the Chapter 5 `_as_list()` lesson, in the one file that had not
   learned it.
2. Matching was boolean. A NAT rule whose objects this static simulator cannot
   model was reported as "does not match", so a LATER rule became the answer.
   NAT is first-match-wins, so that answer is not merely incomplete, it is the
   wrong rule presented with no warning at all.
3. The literal string "Original" in a translated field rendered as "-",
   because describe_list() also expects a list. "no translation configured"
   and "translate back to the original" are different statements.

The tri-state upgrade must not change a verdict that was already provable:
where every object resolves, the finding keys and values stay as they were.
"""

from app.traffic import correlate_nat


def obj(uid, name, typ, **kw):
    d = {"uid": uid, "name": name, "type": typ}
    d.update(kw)
    return d


def objects():
    return [
        obj("any", "Any", "CpmiAnyObject"),
        obj("lab", "LAB-VLAN10", "network", subnet4="192.168.10.0", **{"mask-length4": 24}),
        obj("srv", "RDP-Server", "host", **{"ipv4-address": "192.168.20.100"}),
        obj("gw", "External-Cluster-VIP", "host", **{"ipv4-address": "172.23.31.179"}),
        # No address fields and not a group: the resolver cannot model it, and
        # says so rather than treating it as an empty set.
        obj("zone", "InternalZone", "security-zone"),
    ]


def payload(rules):
    return {"objects-dictionary": objects(), "rulebase": rules}


def hide_rule(number, source, **over):
    rule = {
        "type": "nat-rule", "rule-number": number, "name": f"Hide-{number}",
        "enabled": True,
        "original-source": source,
        "original-destination": "any",
        "original-service": "any",
        "translated-source": "gw",
        "translated-destination": "Original",
        "translated-service": "Original",
    }
    rule.update(over)
    return rule


SRC, DST = "192.168.10.50", "192.168.20.100"


# ---- defect 1: singular fields ---------------------------------------

def test_singular_nat_fields_are_read_like_list_fields():
    singular = correlate_nat(payload([hide_rule(1, "lab")]), SRC, DST)
    listed = correlate_nat(
        payload([hide_rule(1, ["lab"], **{"original-destination": ["any"]})]), SRC, DST
    )
    assert len(singular) == 1, "a NAT rule sent in singular form must still be found"
    assert singular[0]["rule"] == 1
    assert singular[0]["original_source"] == listed[0]["original_source"]


def test_original_literal_is_not_rendered_as_no_value():
    found = correlate_nat(payload([hide_rule(1, "lab")]), SRC, DST)
    assert found[0]["translated_destination"] == "Original"
    assert found[0]["translated_source"] == "External-Cluster-VIP (172.23.31.179)"


# ---- defect 2: tri-state ---------------------------------------------

def test_provable_match_is_unchanged_and_marked_exact():
    found = correlate_nat(payload([hide_rule(1, "lab")]), SRC, DST)
    assert len(found) == 1
    assert found[0]["rule"] == 1
    assert found[0]["state"] == "match"
    assert found[0]["confidence"] == "exact"
    assert found[0]["original_source"] == "LAB-VLAN10 (192.168.10.0/24)"


def test_proven_non_match_is_still_skipped_silently():
    other = obj("other", "Net-Other", "network", subnet4="10.9.9.0", **{"mask-length4": 24})
    data = payload([hide_rule(1, ["other"]), hide_rule(2, "lab")])
    data["objects-dictionary"].append(other)
    found = correlate_nat(data, SRC, DST)
    assert [f["rule"] for f in found] == [2]
    assert found[0]["confidence"] == "exact"


def test_unmodellable_earlier_rule_is_reported_not_dropped():
    """The whole point: an earlier rule we cannot evaluate must be visible."""
    found = correlate_nat(payload([hide_rule(1, "zone"), hide_rule(2, "lab")]), SRC, DST)
    assert [f["rule"] for f in found] == [1, 2], (
        "the unevaluated earlier rule must lead, because NAT is first-match-wins"
    )
    assert found[0]["state"] == "unknown"
    assert found[0]["confidence"] == "unverified"
    assert "InternalZone" in found[0]["original_source"]

    # The later rule still matches - but cannot be called the one that runs.
    assert found[1]["state"] == "match"
    assert found[1]["confidence"] == "unverified"
    assert found[1]["blocked_by"] == 1


def test_unmodellable_rule_with_no_later_match_is_still_reported():
    found = correlate_nat(payload([hide_rule(1, "zone")]), SRC, DST)
    assert len(found) == 1
    assert found[0]["rule"] == 1
    assert found[0]["state"] == "unknown"
    assert found[0]["confidence"] == "unverified"


def test_disabled_rules_take_no_part():
    found = correlate_nat(
        payload([hide_rule(1, "zone", enabled=False), hide_rule(2, "lab")]), SRC, DST
    )
    assert [f["rule"] for f in found] == [2]
    assert found[0]["confidence"] == "exact"


def test_no_nat_rule_matches_returns_empty():
    other = obj("other", "Net-Other", "network", subnet4="10.9.9.0", **{"mask-length4": 24})
    data = payload([hide_rule(1, ["other"])])
    data["objects-dictionary"].append(other)
    assert correlate_nat(data, SRC, DST) == []


# ---- the UI must say so, not just the payload -------------------------

def test_ui_shows_the_nat_confidence_and_the_blocked_rule():
    from conftest import ui_source
    ui = ui_source()
    assert "natLead.confidence==='exact'?'good':'warn'" in ui, (
        "an unverified NAT result must not be painted like a settled one"
    )
    assert "NAT correlation unverified" in ui
    assert "cannot be declared the rule that runs" in ui


def test_route_states_the_service_gap_rather_than_hiding_it():
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "app" / "api" / "traffic.py").read_text(
        encoding="utf-8")
    assert "original-service is not evaluated" in src
    assert "never as a non-match" in src
