"""
v4.23 - Chapter 4 homework (a), and the hole it exposed.

The homework says: make `address_match_state()` return `unknown` the moment it
meets an object it cannot model, instead of finishing the loop, then run the
acceptance suite and explain which cases break.

Doing it produced a more useful answer than the one the exercise expects. The
383-test suite caught the change with ONE failure, and that failure was about
how the blocker is NAMED (`Mixed-Nets [group]` instead of the leaf
`DynamicObj`), not about a verdict changing. The behaviour the chapter's rule
exists to protect - "check every object for a match BEFORE concluding unknown"
- was not covered by a single test.

Measured with the early return in place:

    field ["InternalZone", "LAB-VLAN10"] vs 192.168.10.50 -> unknown
    field ["LAB-VLAN10", "InternalZone"] vs 192.168.10.50 -> match

The same rule, the same packet, a different answer depending on the order the
Management API happened to list the objects in. On the lab that reads as a
`drop` on a flow the policy permits, and nothing in the suite would have said
so. These tests close that hole.
"""

from app.resolver import ObjectResolver
from app.traffic import address_match_state, service_match_state

ADDRESSES = {o["uid"]: o for o in [
    {"uid": "zone", "name": "InternalZone", "type": "security-zone"},
    {"uid": "lab", "name": "LAB-VLAN10", "type": "network",
     "subnet4": "192.168.10.0", "mask-length4": 24},
    {"uid": "corp", "name": "Net-Corp", "type": "network",
     "subnet4": "172.23.31.0", "mask-length4": 24},
]}

SERVICES = {o["uid"]: o for o in [
    {"uid": "dce", "name": "ALL_DCE_RPC", "type": "service-dce-rpc"},
    {"uid": "ldap", "name": "ldap", "type": "service-tcp", "port": "389"},
]}


def _query(proto, port):
    return {"atoms": [(proto, port, port)], "protocol": proto, "port": port}


class TestAddressOrderCannotChangeTheVerdict:
    def test_an_unmodellable_object_listed_first_does_not_hide_a_real_match(self):
        res = ObjectResolver(ADDRESSES)
        assert address_match_state(["zone", "lab"], "192.168.10.50", res)[0] == "match"

    def test_the_same_field_in_the_other_order_gives_the_same_answer(self):
        res = ObjectResolver(ADDRESSES)
        first = address_match_state(["zone", "lab"], "192.168.10.50", res)
        second = address_match_state(["lab", "zone"], "192.168.10.50", res)
        assert first[0] == second[0] == "match"

    def test_unknown_survives_when_no_object_actually_matches(self):
        res = ObjectResolver(ADDRESSES)
        state, detail = address_match_state(["zone", "lab"], "10.99.99.9", res)
        assert state == "unknown"
        assert "InternalZone" in detail

    def test_a_fully_modelled_field_still_reaches_a_confident_no_match(self):
        res = ObjectResolver(ADDRESSES)
        assert address_match_state(["lab", "corp"], "10.99.99.9", res)[0] == "no-match"


class TestServiceOrderCannotChangeTheVerdict:
    """service_match_state() has the identical shape and the identical risk."""

    def test_a_dynamic_port_service_listed_first_does_not_hide_a_real_match(self):
        res = ObjectResolver(SERVICES)
        assert service_match_state(["dce", "ldap"], _query("tcp", 389), res)[0] == "match"

    def test_the_same_field_in_the_other_order_gives_the_same_answer(self):
        res = ObjectResolver(SERVICES)
        assert (service_match_state(["dce", "ldap"], _query("tcp", 389), res)[0]
                == service_match_state(["ldap", "dce"], _query("tcp", 389), res)[0])

    def test_unknown_survives_when_no_service_matches(self):
        res = ObjectResolver(SERVICES)
        state, detail = service_match_state(["dce", "ldap"], _query("tcp", 9999), res)
        assert state == "unknown"
        assert "ALL_DCE_RPC" in detail
