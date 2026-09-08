"""
v4.24 - Traffic Path never read the `vpn` column.

Found by running `tools.suggest_cases` against the live lab: rule 1 is a VPN
rule, and the tool skipped it for having Any destination and Any service.
Following that back through the code showed something worse than a skipped
case:

    analyzer.py        uses vpn in the rule signature and in shadow analysis
    policy_browser.py  shows the VPN column
    api/export.py      exports the VPN column
    traffic.py         the word "vpn" does not appear in the file

So a rule scoped to one VPN community was matched by the tri-state tracer as
though it applied to every packet. A flow that is NOT inside that community
would be answered `accept · exact` by the rule that permits the community -
a confident wrong answer, produced by the one feature this whole project
exists to keep honest.

The fix is the same rule the rest of the file already follows. Whether a
packet arrives through a VPN community is not in the configuration; it is a
property of the live connection. That is not a no-match - we cannot prove the
packet is outside the community either - it is `unknown`, and it makes the
whole rule unknown, which in turn stops a later exact rule from being declared
final. Exactly what Security Zones and Identity Awareness already do.
"""

from app.resolver import ObjectResolver
from app.traffic import trace_access_tree, vpn_match_state

ANY_VPN = {"uid": "vany", "name": "Any", "type": "Global"}
COMMUNITY = {"uid": "vpn1", "name": "Site2Site-BKK", "type": "CpmiVpnCommunityMeshed"}

OBJECTS = [
    {"uid": "any", "name": "Any", "type": "CpmiAnyObject"},
    {"uid": "acc", "name": "Accept", "type": "RulebaseAction"},
    {"uid": "drop", "name": "Drop", "type": "RulebaseAction"},
    {"uid": "admin", "name": "Admin-Networks", "type": "network",
     "subnet4": "172.23.10.0", "mask-length4": 24},
    {"uid": "https", "name": "https", "type": "service-tcp", "port": "443"},
    ANY_VPN, COMMUNITY,
]
RES = ObjectResolver({o["uid"]: o for o in OBJECTS})


class TestVpnMatchState:
    def test_an_absent_vpn_field_is_no_constraint(self):
        assert vpn_match_state(None, RES)[0] == "match"
        assert vpn_match_state([], RES)[0] == "match"

    def test_vpn_any_is_no_constraint(self):
        state, detail = vpn_match_state(["vany"], RES)
        assert state == "match"
        assert detail == "Any"

    def test_a_named_community_cannot_be_evaluated_statically(self):
        state, detail = vpn_match_state(["vpn1"], RES)
        assert state == "unknown"
        assert "Site2Site-BKK" in detail

    def test_it_is_never_a_no_match(self):
        """We cannot prove a packet is OUTSIDE a community either."""
        for value in (None, [], ["vany"], ["vpn1"], {"community": "vpn1"}):
            assert vpn_match_state(value, RES)[0] in ("match", "unknown")

    def test_a_directional_match_shape_is_unknown_not_ignored(self):
        state, _ = vpn_match_state({"community": "vpn1", "from": "a", "to": "b"}, RES)
        assert state == "unknown"

    def test_any_alongside_a_community_is_still_a_constraint(self):
        assert vpn_match_state(["vany", "vpn1"], RES)[0] == "unknown"


def tree(rules):
    return {"root_layer": "Network", "root_layers": ["Network"], "layers": [
        {"name": "Network", "depth": 0, "path": "Network", "display_prefix": "",
         "payload": {"objects-dictionary": OBJECTS, "rulebase": rules}}]}


def rule(number, name, action, vpn):
    return {"type": "access-rule", "rule-number": number, "name": name,
            "enabled": True, "source": ["admin"], "destination": ["any"],
            "service": ["any"], "vpn": vpn, "action": action}


CLEANUP = {"type": "access-rule", "rule-number": 9, "name": "Cleanup rule",
           "enabled": True, "source": ["any"], "destination": ["any"],
           "service": ["any"], "vpn": ["vany"], "action": "drop"}


class TestTheTracerHonoursIt:
    def test_a_vpn_scoped_rule_no_longer_answers_for_clear_traffic(self):
        out = trace_access_tree(tree([rule(1, "VPN-Only", "acc", ["vpn1"]), CLEANUP]),
                                "172.23.10.5", "192.168.10.10", "tcp", "443", "Network")
        assert out["result"] == "UNVERIFIED", (
            "a rule scoped to a VPN community must not be reported as the "
            "definitive answer for traffic that may not be in it")
        assert out["confidence"] == "unknown"
        assert out["possible_winner"]["rule"] == 1
        assert "Site2Site-BKK" in out["possible_winner"]["vpn_match"]

    def test_the_later_cleanup_rule_is_named_but_not_declared_final(self):
        out = trace_access_tree(tree([rule(1, "VPN-Only", "acc", ["vpn1"]), CLEANUP]),
                                "172.23.10.5", "192.168.10.10", "tcp", "443", "Network")
        assert out["later_exact_rule"]["rule"] == 9
        assert out["matched"] is False

    def test_a_vpn_any_rule_is_unaffected(self):
        out = trace_access_tree(tree([rule(1, "Clear-Traffic", "acc", ["vany"]), CLEANUP]),
                                "172.23.10.5", "192.168.10.10", "tcp", "443", "Network")
        assert out["result"] == "Accept"
        assert out["confidence"] == "exact"

    def test_a_rule_with_no_vpn_field_at_all_is_unaffected(self):
        bare = {"type": "access-rule", "rule-number": 1, "name": "No VPN field",
                "enabled": True, "source": ["admin"], "destination": ["any"],
                "service": ["any"], "action": "acc"}
        out = trace_access_tree(tree([bare, CLEANUP]),
                                "172.23.10.5", "192.168.10.10", "tcp", "443", "Network")
        assert out["result"] == "Accept"
        assert out["confidence"] == "exact"

    def test_a_vpn_rule_whose_addresses_do_not_match_is_still_a_clean_no_match(self):
        """VPN must not turn an otherwise provable miss into uncertainty."""
        out = trace_access_tree(tree([rule(1, "VPN-Only", "acc", ["vpn1"]), CLEANUP]),
                                "10.99.99.9", "192.168.10.10", "tcp", "443", "Network")
        assert out["result"] == "Drop"
        assert out["confidence"] == "exact"


def test_the_ui_reports_the_vpn_dimension():
    from conftest import ui_source
    assert "vpn_match" in ui_source()
