"""
v4.9 regression: objects-dictionary presence != objects-dictionary completeness.

Found against a live lab (Management API 2.0.1). `tools/diag_resolver.py`
reported 10 objects in the root layer that the resolver could not turn into
ranges - LAB-Internal-Nets, Admin-Networks, AD-Services, dns, ntp,
icmp-requests, External-Cluster, External-GW01/02, Internal-GW01 - all with
"member count: 0" and "in dictionary: True".

Root cause: hydrate_objects() skipped every UID already present in the
dictionary, but those entries came from details-level=standard, which returns
uid/name/type and omits group members and gateway addresses. The resolver then
reported them all as statically unevaluable, which:

  - turned a Traffic Path answer that should be `Rule 7 -> 7.1 -> Accept`
    into UNVERIFIED, and
  - made shadow analysis skip any rule using a group ("Unsupported object
    type"), hiding real findings.
"""

import asyncio

from app.checkpoint import CheckPointClient
from app.resolver import ObjectResolver, needs_detail

# Exactly the shape details-level=standard returns: no members, no address.
THIN_GROUP = {"uid": "g1", "name": "LAB-Internal-Nets", "type": "group"}
THIN_GATEWAY = {"uid": "gw1", "name": "Internal-GW01", "type": "simple-gateway"}
THIN_SERVICE_GROUP = {"uid": "sg1", "name": "dns", "type": "service-group"}

FULL_GROUP = {
    "uid": "g1", "name": "LAB-Internal-Nets", "type": "group",
    "members": ["n10", "n20"],
}
NET10 = {"uid": "n10", "name": "LAB-VLAN10", "type": "network",
         "subnet4": "192.168.10.0", "mask-length4": 24}
NET20 = {"uid": "n20", "name": "LAB-VLAN20", "type": "network",
         "subnet4": "192.168.20.0", "mask-length4": 24}


class TestNeedsDetail:
    def test_thin_group_needs_detail(self):
        assert needs_detail(THIN_GROUP) is True

    def test_thin_gateway_needs_detail(self):
        assert needs_detail(THIN_GATEWAY) is True

    def test_thin_service_group_needs_detail(self):
        assert needs_detail(THIN_SERVICE_GROUP) is True

    def test_group_with_members_is_complete(self):
        assert needs_detail(FULL_GROUP) is False

    def test_network_with_subnet_is_complete(self):
        assert needs_detail(NET20) is False

    def test_host_with_address_is_complete(self):
        assert needs_detail(
            {"uid": "h1", "name": "AD", "type": "host", "ipv4-address": "10.0.0.1"}
        ) is False

    def test_service_with_port_is_complete(self):
        assert needs_detail(
            {"uid": "s1", "name": "https", "type": "service-tcp", "port": "443"}
        ) is False

    def test_any_is_never_refetched(self):
        assert needs_detail(
            {"uid": "any", "name": "Any", "type": "CpmiAnyObject"}
        ) is False

    def test_action_objects_are_never_refetched(self):
        """Accept/Drop are in RULE_FIELDS, so they reach hydration. Skip them:
        each pointless show-object costs a paced, rate-limited round trip."""
        assert needs_detail(
            {"uid": "a1", "name": "Accept", "type": "RulebaseAction"}
        ) is False
        assert needs_detail(
            {"uid": "t1", "name": "Log", "type": "Track"}
        ) is False

    def test_garbage_needs_detail(self):
        assert needs_detail(None) is True
        assert needs_detail({}) is True
        assert needs_detail({"name": "no uid"}) is True


def _client(store):
    client = CheckPointClient.__new__(CheckPointClient)
    client.hydration_truncated = False
    client.fetched = []

    async def call(command, payload=None):
        uid = (payload or {}).get("uid")
        client.fetched.append(uid)
        return {"object": store[uid]} if uid in store else {}

    client.call = call
    return client


class TestHydration:
    def test_thin_dictionary_entry_is_refetched(self):
        existing = {"g1": dict(THIN_GROUP)}
        client = _client({"g1": FULL_GROUP})

        result = asyncio.run(client.hydrate_objects({"g1"}, existing))

        assert client.fetched == ["g1"], "present-but-thin object must be refetched"
        assert result["g1"]["members"] == ["n10", "n20"]

    def test_complete_entry_is_not_refetched(self):
        existing = {"n20": dict(NET20)}
        client = _client({"n20": NET20})

        asyncio.run(client.hydrate_objects({"n20"}, existing))

        assert client.fetched == [], "complete objects must not cost an API call"

    def test_missing_entry_is_fetched(self):
        client = _client({"n10": NET10})
        result = asyncio.run(client.hydrate_objects({"n10"}, {}))
        assert result["n10"]["subnet4"] == "192.168.10.0"

    def test_refresh_can_be_disabled(self):
        existing = {"g1": dict(THIN_GROUP)}
        client = _client({"g1": FULL_GROUP})
        asyncio.run(
            client.hydrate_objects({"g1"}, existing, refresh_incomplete=False)
        )
        assert client.fetched == []

    def test_rate_limit_truncation_is_recorded_not_hidden(self):
        from app.checkpoint import CheckPointRateLimitError

        client = CheckPointClient.__new__(CheckPointClient)
        client.hydration_truncated = False

        async def call(_command, _payload=None):
            raise CheckPointRateLimitError("HTTP 403: too many requests")

        client.call = call
        asyncio.run(client.hydrate_objects({"g1"}, {}))
        assert client.hydration_truncated is True


class TestEndToEndEffect:
    """The reason the fix matters: the group must become matchable."""

    def test_thin_group_cannot_be_matched(self):
        res = ObjectResolver({"g1": THIN_GROUP})
        assert res.address_atoms("g1") is None

    def test_hydrated_group_expands_to_member_subnets(self):
        res = ObjectResolver({"g1": FULL_GROUP, "n10": NET10, "n20": NET20})
        atoms = res.address_atoms("g1")
        assert atoms is not None and len(atoms) == 2

    def test_traffic_source_now_matches_through_the_group(self):
        from app.traffic import address_match_state

        thin = ObjectResolver({"g1": THIN_GROUP})
        state, _ = address_match_state(["g1"], "192.168.20.10", thin)
        assert state == "unknown", "reproduces the UNVERIFIED result"

        full = ObjectResolver({"g1": FULL_GROUP, "n10": NET10, "n20": NET20})
        state, detail = address_match_state(["g1"], "192.168.20.10", full)
        assert state == "match"
        assert "LAB-Internal-Nets" in detail

    def test_ip_outside_the_group_is_a_confident_no_match(self):
        from app.traffic import address_match_state

        full = ObjectResolver({"g1": FULL_GROUP, "n10": NET10, "n20": NET20})
        state, _ = address_match_state(["g1"], "10.99.99.1", full)
        assert state == "no-match"


class TestNestedGroups:
    def test_nested_thin_member_is_detected_as_incomplete(self):
        """A member can be in the dictionary and still be a stub, so the
        hydration loop must re-check completeness, not just presence."""
        outer = {"uid": "g0", "name": "All-Lab", "type": "group", "members": ["g1"]}
        existing = {"g0": outer, "g1": dict(THIN_GROUP)}
        assert needs_detail(existing["g0"]) is False
        assert needs_detail(existing["g1"]) is True

    def test_nested_group_resolves_when_fully_hydrated(self):
        res = ObjectResolver({
            "g0": {"uid": "g0", "name": "All-Lab", "type": "group", "members": ["g1"]},
            "g1": FULL_GROUP, "n10": NET10, "n20": NET20,
        })
        atoms = res.address_atoms("g0")
        assert atoms is not None and len(atoms) == 2


def test_hydration_loop_rechecks_completeness_of_known_members():
    from pathlib import Path
    src = Path("app/main.py").read_text(encoding="utf-8")
    assert "uid not in existing or needs_detail(existing[uid])" in src
