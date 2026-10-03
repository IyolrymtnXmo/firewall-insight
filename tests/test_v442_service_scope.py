"""
v4.42 - a service or address object is only "definite" as far as it is modelled.

The model holds a protocol with a destination port (or an ICMP type), and an
address interval. Check Point objects can say more than that. Where they do,
the rule is narrower than the model, and treating a port hit as a proven match
would be a confident answer built on half of the condition.
"""
from app.analyzer import analyze_rulebase
from app.matching import address_match_state, service_match_state
from app.resolver import ObjectResolver


def res(*objs):
    base = [{"uid": "any", "name": "Any", "type": "CpmiAnyObject"}]
    return ObjectResolver({o["uid"]: o for o in base + list(objs)})


def q(proto, port):
    return {"atoms": [(proto, port, port)], "protocol": proto, "port": port}


HTTPS = {"uid": "s1", "name": "https", "type": "service-tcp", "port": "443"}
HTTPS_SRC = {"uid": "s2", "name": "https-from-1024", "type": "service-tcp", "port": "443", "source-port": ">1023"}
HTTP_SIG = {"uid": "s3", "name": "http-sig", "type": "service-tcp", "port": "80",
            "protocol": "HTTP", "match-by-protocol-signature": True}
HTTP_PLAIN = {"uid": "s4", "name": "http", "type": "service-tcp", "port": "80",
              "protocol": "HTTP", "match-by-protocol-signature": False}
ICMP_3_1 = {"uid": "i1", "name": "host-unreach", "type": "service-icmp", "icmp-type": 3, "icmp-code": 1}
ICMP_8 = {"uid": "i2", "name": "echo-request", "type": "service-icmp", "icmp-type": 8}
OTHER = {"uid": "o1", "name": "gre-expr", "type": "service-other", "ip-protocol": 47, "match": "dport = 1"}


def test_an_unrestricted_service_is_still_a_proven_match():
    assert service_match_state(["s1"], q("tcp", 443), res(HTTPS))[0] == "match"


def test_a_source_port_restriction_makes_a_port_hit_unknown():
    state, why = service_match_state(["s2"], q("tcp", 443), res(HTTPS_SRC))
    assert state == "unknown" and "source port" in why


def test_a_miss_on_a_restricted_service_is_still_a_proven_miss():
    assert service_match_state(["s2"], q("tcp", 80), res(HTTPS_SRC))[0] == "no-match"


def test_protocol_signature_counts_only_when_it_is_switched_on():
    assert service_match_state(["s3"], q("tcp", 80), res(HTTP_SIG))[0] == "unknown"
    assert service_match_state(["s4"], q("tcp", 80), res(HTTP_PLAIN))[0] == "match"


def test_an_icmp_code_makes_a_type_hit_unknown():
    assert service_match_state(["i1"], q("icmp", 3), res(ICMP_3_1))[0] == "unknown"
    assert service_match_state(["i1"], q("icmp", 8), res(ICMP_3_1))[0] == "no-match"
    assert service_match_state(["i2"], q("icmp", 8), res(ICMP_8))[0] == "match"


def test_a_match_expression_on_service_other_is_unknown():
    r = res(OTHER)
    assert service_match_state(["o1"], {"atoms": [("ip-47", 0, 0)]}, r)[0] == "unknown"


def test_a_group_is_proven_by_its_unrestricted_member():
    group = {"uid": "g", "name": "web", "type": "service-group", "members": ["s1", "s2"]}
    assert service_match_state(["g"], q("tcp", 443), res(HTTPS, HTTPS_SRC, group))[0] == "match"


def test_a_group_of_only_restricted_members_is_unknown():
    group = {"uid": "g", "name": "web", "type": "service-group", "members": ["s2"]}
    assert service_match_state(["g"], q("tcp", 443), res(HTTPS_SRC, group))[0] == "unknown"


# ---- shadowing ---------------------------------------------------------------

def _payload(first_service, second_service, objs):
    base = [{"uid": "any", "name": "Any", "type": "CpmiAnyObject"},
            {"uid": "accept", "name": "Accept", "type": "RulebaseAction"},
            {"uid": "drop", "name": "Drop", "type": "RulebaseAction"}]
    mk = lambda n, svc, act: {"type": "access-rule", "rule-number": n, "name": f"r{n}", "enabled": True,
                              "source": ["any"], "destination": ["any"], "service": [svc], "vpn": [],
                              "action": act}
    return {"rulebase": [mk(1, first_service, "accept"), mk(2, second_service, "drop")],
            "objects-dictionary": base + objs}


def test_a_restricted_earlier_service_does_not_shadow_a_later_rule():
    out = analyze_rulebase(_payload("s2", "s1", [HTTPS, HTTPS_SRC]))
    assert out["findings"]["shadowing"] == []


def test_an_unrestricted_earlier_service_still_shadows():
    out = analyze_rulebase(_payload("s1", "s2", [HTTPS, HTTPS_SRC]))
    assert [s["rule"] for s in out["findings"]["shadowing"]] == [2]


def test_the_same_restricted_object_twice_is_still_covered():
    out = analyze_rulebase(_payload("s2", "s2", [HTTPS_SRC]))
    assert [s["rule"] for s in out["findings"]["shadowing"]] == [2]


def test_an_icmp_code_does_not_shadow_the_whole_type():
    plain = {"uid": "i3", "name": "unreach", "type": "service-icmp", "icmp-type": 3}
    assert analyze_rulebase(_payload("i1", "i3", [ICMP_3_1, plain]))["findings"]["shadowing"] == []


# ---- IPv4 and IPv6 on one object ---------------------------------------------

DUAL = {"uid": "h", "name": "dual", "type": "host", "ipv4-address": "10.0.0.5", "ipv6-address": "2001:db8::5"}
NET6 = {"uid": "n6", "name": "v6net", "type": "network", "subnet6": "2001:db8::", "mask-length6": 64}


def test_a_dual_stack_host_matches_in_both_families():
    r = res(DUAL)
    assert address_match_state(["h"], "10.0.0.5", r)[0] == "match"
    assert address_match_state(["h"], "2001:db8::5", r)[0] == "match"
    assert address_match_state(["h"], "2001:db8::6", r)[0] == "no-match"


def test_an_ipv6_network_is_an_interval_of_its_own_family():
    r = res(NET6)
    assert address_match_state(["n6"], "2001:db8::1234", r)[0] == "match"
    assert address_match_state(["n6"], "10.0.0.5", r)[0] == "no-match"


def test_a_dual_stack_network_keeps_both_definitions():
    both = {"uid": "n", "name": "both", "type": "network", "subnet4": "10.1.0.0", "mask-length4": 16,
            "subnet6": "2001:db8:1::", "mask-length6": 48}
    r = res(both)
    assert address_match_state(["n"], "10.1.2.3", r)[0] == "match"
    assert address_match_state(["n"], "2001:db8:1::9", r)[0] == "match"
