"""
v4.21 - Chapter 5 homework (d): a NAT rule installed on a gateway that is not
there.

A NAT rule carries `install-on`. Nothing in the Management API stops that field
pointing at an object that no longer exists as a gateway - a decommissioned
box, a rename, a copied policy package. The rule then sits in the rulebase
looking completely normal and never runs anywhere.

Two traps this test file pins down:

1. `Policy Targets` is not a gateway name. It is the "all gateways in this
   package" marker, and flagging it would produce a finding on almost every
   rule in almost every policy - the fastest way to teach someone to ignore
   the report.
2. Without the gateway list there is nothing to check against. The analyzer
   must then say the check did not run, NOT report zero problems. Zero
   findings and no data look identical in a summary, and only one of them
   means the policy is clean.
"""

from app.nat_analyzer import analyze_nat_rulebase


def obj(uid, name, typ="host", **kw):
    d = {"uid": uid, "name": name, "type": typ}
    d.update(kw)
    return d


OBJECTS = [
    obj("any", "Any", "CpmiAnyObject"),
    obj("pt", "Policy Targets", "Global"),
    obj("gw1", "External-GW01", "simple-gateway"),
    obj("cluster", "External-Cluster", "CpmiGatewayCluster"),
    obj("ghost", "Retired-GW09", "simple-gateway"),
    obj("lab", "LAB-VLAN10", "network", subnet4="192.168.10.0", **{"mask-length4": 24}),
]

LIVE_GATEWAYS = [
    {"uid": "gw1", "name": "External-GW01", "type": "simple-gateway"},
    {"uid": "cluster", "name": "External-Cluster", "type": "CpmiGatewayCluster"},
]


def rule(number, install_on, name=None):
    return {
        "type": "nat-rule", "rule-number": number, "name": name or f"NAT-{number}",
        "enabled": True,
        "original-source": "lab", "original-destination": "any",
        "original-service": "any",
        "translated-source": "gw1", "translated-destination": "Original",
        "translated-service": "Original",
        "install-on": install_on,
    }


def analyze(rules, gateways=LIVE_GATEWAYS):
    return analyze_nat_rulebase(
        {"objects-dictionary": OBJECTS, "rulebase": rules}, gateways=gateways
    )


def test_install_on_a_live_gateway_is_not_a_finding():
    out = analyze([rule(1, ["gw1"]), rule(2, "cluster")])
    assert out["findings"]["install_on_unknown_rule_numbers"] == []
    assert out["summary"]["install_on_unknown_rules"] == 0
    assert out["summary"]["install_on_checked"] is True


def test_policy_targets_means_every_gateway_not_a_missing_one():
    out = analyze([rule(1, ["pt"]), rule(2, ["any"])])
    assert out["findings"]["install_on_unknown_rule_numbers"] == []


def test_missing_gateway_is_found_and_named():
    out = analyze([rule(1, ["gw1"]), rule(2, ["ghost"], name="Legacy hide")])
    assert out["findings"]["install_on_unknown_rule_numbers"] == [2]
    assert out["summary"]["install_on_unknown_rules"] == 1
    detail = out["findings"]["install_on_findings"][0]
    assert detail["rule"] == 2
    assert "Retired-GW09" in detail["target"]
    assert "show-gateways-and-servers" in detail["reason"]


def test_singular_install_on_is_read_too():
    out = analyze([rule(1, "ghost")])
    assert out["findings"]["install_on_unknown_rule_numbers"] == [1]


def test_target_matched_by_uid_when_the_dictionary_is_thin():
    """A thin objects-dictionary gives a uid and no name; the uid still counts."""
    payload = {"objects-dictionary": [], "rulebase": [rule(1, ["gw1"])]}
    out = analyze_nat_rulebase(payload, gateways=LIVE_GATEWAYS)
    assert out["findings"]["install_on_unknown_rule_numbers"] == []


def test_without_the_gateway_list_the_check_reports_that_it_did_not_run():
    out = analyze_nat_rulebase(
        {"objects-dictionary": OBJECTS, "rulebase": [rule(1, ["ghost"])]}
    )
    assert out["summary"]["install_on_checked"] is False
    assert out["summary"]["install_on_unknown_rules"] is None
    assert out["findings"]["install_on_unknown_rule_numbers"] == []
    assert any("install-on" in n.lower() and "not checked" in n.lower()
               for n in out["notes"]), out["notes"]


def test_existing_summary_keys_are_untouched():
    out = analyze([rule(1, ["gw1"])])
    for key in ("total_nat_rules", "disabled_nat_rules", "duplicate_nat_groups",
                "broad_original_any_any_any", "possible_no_translation_rules",
                "nat_hits_available"):
        assert key in out["summary"], key


def test_ui_shows_the_new_finding():
    from conftest import ui_source
    ui = ui_source()
    assert "install_on_unknown" in ui


# ---- the wiring, not just the analyzer --------------------------------

def test_analyze_nat_asks_the_management_server_for_the_gateway_list():
    """A check nothing calls is not a check."""
    import asyncio

    from app.policy import analyze_nat
    from app.runtime import cache_clear

    class FakeClient:
        def __init__(self):
            self.gateway_calls = 0

        async def show_nat_rulebase(self, package):
            return {"objects-dictionary": OBJECTS, "rulebase": [rule(1, ["ghost"])]}

        async def show_gateways_and_servers(self):
            self.gateway_calls += 1
            return LIVE_GATEWAYS

    cache_clear()
    client = FakeClient()
    out = asyncio.run(analyze_nat(client, "External-FW"))
    assert client.gateway_calls == 1
    assert out["summary"]["install_on_checked"] is True
    assert out["findings"]["install_on_unknown_rule_numbers"] == [1]
    cache_clear()


def test_a_failing_gateway_call_does_not_fail_the_nat_analysis():
    import asyncio

    from app.checkpoint import CheckPointAPIError
    from app.policy import analyze_nat
    from app.runtime import cache_clear

    class Denied:
        async def show_nat_rulebase(self, package):
            return {"objects-dictionary": OBJECTS, "rulebase": [rule(1, ["ghost"])]}

        async def show_gateways_and_servers(self):
            raise CheckPointAPIError("show-gateways-and-servers: permission denied")

    cache_clear()
    out = asyncio.run(analyze_nat(Denied(), "External-FW"))
    assert out["summary"]["install_on_checked"] is False
    assert out["summary"]["total_nat_rules"] == 1
    assert any("permission denied" in n for n in out["notes"]), out["notes"]
    cache_clear()
