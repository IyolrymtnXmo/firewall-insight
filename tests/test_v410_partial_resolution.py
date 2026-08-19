"""
v4.10 regression: matching needs positive evidence, not complete knowledge.

Found by `tools/diag_resolver.py` against a live lab after the v4.9 hydration
fix. Two service groups still could not be resolved, and both for the wrong
reason:

  AD-Services [service-group]   member count: 10
      ldap [service-tcp]  ldap-ssl [service-tcp]  microsoft-ds [service-tcp]
      Kerberos_v5_UDP [service-udp]  ... ALL_DCE_RPC [service-dce-rpc]

  icmp-requests [service-group]  member count: 4
      echo-request / info-req / timestamp / mask-request  [service-icmp]

Two separate defects:

1. One unmodellable member discarded the whole group
   (`if part is None: return None`). ALL_DCE_RPC has no fixed port, so
   AD-Services became `unknown` even for a TCP/389 query that plainly matches
   its ldap member. Containment ("does A cover B?") does need every atom, but
   membership ("is this port in the set?") needs only one hit - positive
   evidence does not require complete knowledge.

2. ICMP services were not modelled at all, so an ICMP-only group answered
   `unknown` to a TCP query it can never match. That is not caution, it is
   missing information: an `unknown` earlier rule blocks any later definitive
   verdict, so rule 6 (Lab-Troubleshoot-ICMP, service icmp-requests) would
   turn otherwise-exact traces into UNVERIFIED whenever source and destination
   happened to match it.
"""

from app.resolver import ObjectResolver
from app.traffic import address_match_state, service_match_state

ANY = {"uid": "any", "name": "Any", "type": "CpmiAnyObject"}
LDAP = {"uid": "ldap", "name": "ldap", "type": "service-tcp", "port": "389"}
LDAP_SSL = {"uid": "ldaps", "name": "ldap-ssl", "type": "service-tcp", "port": "636"}
KRB_UDP = {"uid": "krb", "name": "Kerberos_v5_UDP", "type": "service-udp", "port": "88"}
DCE_RPC = {"uid": "dce", "name": "ALL_DCE_RPC", "type": "service-dce-rpc"}
ECHO_REQ = {"uid": "echo", "name": "echo-request", "type": "service-icmp", "icmp-type": 8}
MASK_REQ = {"uid": "mask", "name": "mask-request", "type": "service-icmp", "icmp-type": 17}
GRE = {"uid": "gre", "name": "gre", "type": "service-other", "ip-protocol": 47}

AD_SERVICES = {
    "uid": "adsvc", "name": "AD-Services", "type": "service-group",
    "members": ["ldap", "ldaps", "krb", "dce"],
}
ICMP_REQUESTS = {
    "uid": "icmpreq", "name": "icmp-requests", "type": "service-group",
    "members": ["echo", "mask"],
}

SERVICES = {
    o["uid"]: o for o in
    [ANY, LDAP, LDAP_SSL, KRB_UDP, DCE_RPC, ECHO_REQ, MASK_REQ, GRE,
     AD_SERVICES, ICMP_REQUESTS]
}


def _q(proto, port):
    return {"atoms": [(proto, port, port)]}


class TestPartialServiceGroup:
    def test_group_with_one_unmodellable_member_still_yields_atoms(self):
        res = ObjectResolver(SERVICES)
        atoms, complete = res.service_atoms_partial("adsvc")
        assert complete is False, "DCE-RPC is genuinely not modellable"
        assert {a.start for a in atoms} == {389, 636, 88}

    def test_strict_resolution_stays_conservative(self):
        """Containment analysis must NOT accept a partial set."""
        res = ObjectResolver(SERVICES)
        assert res.service_atoms("adsvc") is None

    def test_known_member_produces_a_definite_match(self):
        res = ObjectResolver(SERVICES)
        state, detail = service_match_state(["adsvc"], _q("tcp", 389), res)
        assert state == "match"
        assert "AD-Services" in detail

    def test_udp_member_also_matches(self):
        res = ObjectResolver(SERVICES)
        state, _ = service_match_state(["adsvc"], _q("udp", 88), res)
        assert state == "match"

    def test_unmatched_port_is_unknown_not_no_match(self):
        """No known member matched, but DCE-RPC could still match on a real
        gateway - so we must not claim no-match."""
        res = ObjectResolver(SERVICES)
        state, detail = service_match_state(["adsvc"], _q("tcp", 49152), res)
        assert state == "unknown"
        assert "ALL_DCE_RPC" in detail


class TestIcmpModelling:
    def test_icmp_service_is_modelled(self):
        res = ObjectResolver(SERVICES)
        atoms, complete = res.service_atoms_partial("echo")
        assert complete is True
        assert atoms[0].proto == "icmp" and atoms[0].start == 8

    def test_icmp_group_is_fully_modelled(self):
        res = ObjectResolver(SERVICES)
        atoms, complete = res.service_atoms_partial("icmpreq")
        assert complete is True
        assert {a.start for a in atoms} == {8, 17}

    def test_icmp_group_is_a_confident_no_match_for_tcp(self):
        """This is the fix that stops rule 6 poisoning unrelated traces."""
        res = ObjectResolver(SERVICES)
        state, _ = service_match_state(["icmpreq"], _q("tcp", 443), res)
        assert state == "no-match"

    def test_icmp_query_matches_icmp_group(self):
        res = ObjectResolver(SERVICES)
        state, _ = service_match_state(["icmpreq"], _q("icmp", 8), res)
        assert state == "match"

    def test_service_other_uses_its_ip_protocol(self):
        res = ObjectResolver(SERVICES)
        atoms, complete = res.service_atoms_partial("gre")
        assert complete is True
        assert atoms[0].proto == "ip-47"
        state, _ = service_match_state(["gre"], _q("tcp", 443), res)
        assert state == "no-match"

    def test_dce_rpc_alone_remains_unknown(self):
        """Dynamic ports negotiated at runtime: no-match would be a lie."""
        res = ObjectResolver(SERVICES)
        state, _ = service_match_state(["dce"], _q("tcp", 443), res)
        assert state == "unknown"


NET10 = {"uid": "n10", "name": "LAB-VLAN10", "type": "network",
         "subnet4": "192.168.10.0", "mask-length4": 24}
DYNAMIC = {"uid": "dyn", "name": "DynamicObj", "type": "dynamic-object"}
MIXED_GROUP = {"uid": "mixed", "name": "Mixed-Nets", "type": "group",
               "members": ["n10", "dyn"]}
ADDRESSES = {o["uid"]: o for o in [ANY, NET10, DYNAMIC, MIXED_GROUP]}


class TestPartialAddressGroup:
    def test_ip_inside_known_member_matches_despite_dynamic_sibling(self):
        res = ObjectResolver(ADDRESSES)
        state, detail = address_match_state(["mixed"], "192.168.10.5", res)
        assert state == "match"
        assert "Mixed-Nets" in detail

    def test_ip_outside_known_members_is_unknown(self):
        res = ObjectResolver(ADDRESSES)
        state, detail = address_match_state(["mixed"], "10.99.99.1", res)
        assert state == "unknown"
        assert "DynamicObj" in detail

    def test_strict_address_resolution_still_rejects_partial(self):
        res = ObjectResolver(ADDRESSES)
        assert res.address_atoms("mixed") is None

    def test_fully_known_group_gives_confident_no_match(self):
        res = ObjectResolver({o["uid"]: o for o in [ANY, NET10]})
        state, _ = address_match_state(["n10"], "10.99.99.1", res)
        assert state == "no-match"


class TestUnchangedBehaviour:
    def test_empty_group_tells_us_nothing(self):
        res = ObjectResolver({"g": {"uid": "g", "name": "Empty", "type": "group"}})
        assert res.address_atoms("g") is None
        assert res.service_atoms("g") is None

    def test_any_still_matches_everything(self):
        res = ObjectResolver(SERVICES)
        assert service_match_state(["any"], _q("tcp", 1), res)[0] == "match"

    def test_cycle_does_not_recurse_forever(self):
        objs = {
            "a": {"uid": "a", "name": "A", "type": "group", "members": ["b"]},
            "b": {"uid": "b", "name": "B", "type": "group", "members": ["a"]},
        }
        res = ObjectResolver(objs)
        atoms, _ = res.address_atoms_partial("a")
        assert atoms == []

    def test_port_range_and_comparison_operators_still_work(self):
        res = ObjectResolver({
            "hi": {"uid": "hi", "name": "high-ports", "type": "service-tcp",
                   "port": ">1023"},
        })
        atoms, complete = res.service_atoms_partial("hi")
        assert complete is True
        assert (atoms[0].start, atoms[0].end) == (1024, 65535)
