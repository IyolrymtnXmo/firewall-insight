"""
v4.17: an empty rule dimension is unknown, not covered.

Found while writing Chapter 3 of the learning guide, by reading
`_dimension_cover` line by line rather than by hitting the bug in the lab.

Both containment tests are vacuously true against an empty list:

    set([]).issubset(anything)              -> True
    _intervals_cover(earlier, later=[])     -> True   (the for-loop never runs)

So if `show-access-rulebase` ever returned a rule whose source, destination or
service was `[]`, that rule was reported as shadowed by the first earlier rule
it was compared against - a confident finding derived from no data at all.
That is the one thing this project must never do, so the guard is a hard rule
rather than a nicety.

A real Check Point rule always has all three fields, which is why this never
showed up in the lab. It is exactly the kind of defect that only appears on
someone else's estate, in the payload you did not think to test.
"""

from app.analyzer import _dimension_cover, _intervals_cover, analyze_rulebase
from app.resolver import ObjectResolver

OBJS = {
    "any": {"uid": "any", "name": "Any", "type": "CpmiAnyObject"},
    "n10": {"uid": "n10", "name": "LAB-VLAN10", "type": "network",
            "subnet4": "192.168.10.0", "mask-length4": 24},
    "h1":  {"uid": "h1", "name": "AD-Server", "type": "host",
            "ipv4-address": "192.168.10.10"},
    "svc": {"uid": "svc", "name": "https", "type": "service-tcp", "port": "443"},
    "acc": {"uid": "acc", "name": "Accept", "type": "RulebaseAction"},
}
RES = ObjectResolver(OBJS)


class TestTheGuard:
    def test_an_empty_later_side_is_not_covered(self):
        covered, reason = _dimension_cover(["n10"], [], RES, "address")
        assert covered is False
        assert reason == "No values on this dimension"

    def test_an_empty_side_is_not_covered_even_by_any(self):
        """`Any` covers every value there is - but [] is not a value."""
        covered, _ = _dimension_cover(["any"], [], RES, "address")
        assert covered is False

    def test_the_service_dimension_is_guarded_too(self):
        covered, _ = _dimension_cover(["svc"], [], RES, "service")
        assert covered is False

    def test_the_underlying_interval_test_is_still_vacuously_true(self):
        """Documents WHY the guard has to live in _dimension_cover: the
        interval helper cannot tell "nothing to check" from "all checks
        passed", and giving it that job would change its meaning."""
        assert _intervals_cover(RES.address_atoms("n10"), []) is True


def _rule(n, name, src, dst, svc, enabled=True):
    return {"type": "access-rule", "rule-number": n, "name": name,
            "enabled": enabled, "source": src, "destination": dst,
            "service": svc, "vpn": [], "action": "acc"}


class TestEndToEnd:
    PAYLOAD = {
        "objects-dictionary": list(OBJS.values()),
        "rulebase": [
            _rule(1, "Broad", ["any"], ["any"], ["any"]),
            _rule(2, "Source went missing", [], ["h1"], ["svc"]),
        ],
    }

    def test_a_rule_with_an_empty_field_is_not_reported_as_shadowed(self):
        out = analyze_rulebase(self.PAYLOAD)
        assert out["findings"]["shadowing"] == []
        assert out["summary"]["potential_shadowed_or_redundant"] == 0

    def test_the_rule_is_still_listed_and_still_counted(self):
        """Not analysable is not the same as not there."""
        out = analyze_rulebase(self.PAYLOAD)
        assert out["summary"]["total_rules"] == 2
        assert [r["rule"] for r in out["rules"]] == [1, 2]

    def test_a_normal_shadow_is_still_detected(self):
        """The guard must not have switched shadow analysis off."""
        payload = {
            "objects-dictionary": list(OBJS.values()),
            "rulebase": [
                _rule(1, "Broad", ["any"], ["any"], ["any"]),
                _rule(2, "Narrow", ["n10"], ["h1"], ["svc"]),
            ],
        }
        out = analyze_rulebase(payload)
        assert [s["rule"] for s in out["findings"]["shadowing"]] == [2]
