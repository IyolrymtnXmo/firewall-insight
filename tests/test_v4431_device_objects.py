"""v4.43.1 - a gateway / cluster object stands for every address it owns.

E5 (11 Oct 2026): rule 5 Admin-Access has destination External-Cluster.
fw up_execute matched it for 172.23.31.179 (a cluster VIP); 4.43.0 called the
rule a proven no-match because the object's main address is 172.23.34.179.
"""
from app.matching import address_match_state
from app.resolver import ObjectResolver

OBJS = {
    "cl": {"uid": "cl", "name": "External-Cluster", "type": "CpmiGatewayCluster", "ipv4-address": "172.23.34.179"},
    "gw": {"uid": "gw", "name": "GW", "type": "simple-gateway", "ipv4-address": "10.0.0.1",
           "interfaces": [{"name": "eth1", "ipv4-address": "10.1.1.1"}]},
    "h": {"uid": "h", "name": "Host", "type": "host", "ipv4-address": "10.9.9.9"},
}
R = ObjectResolver(OBJS)


def test_main_address_is_a_match():
    assert address_match_state(["cl"], "172.23.34.179", R)[0] == "match"


def test_another_address_of_the_cluster_is_unknown_not_no_match():
    assert address_match_state(["cl"], "172.23.31.179", R)[0] == "unknown"


def test_listed_interface_address_is_a_match():
    assert address_match_state(["gw"], "10.1.1.1", R)[0] == "match"


def test_device_object_never_proves_containment():
    assert R.address_atoms("cl") is None


def test_ordinary_host_is_unchanged():
    assert address_match_state(["h"], "10.9.9.8", R)[0] == "no-match"


# ---- enriched from show-gateways-and-servers --------------------------------
from app.resolver import enrich_devices

GWS = [
    {"uid": "cl", "name": "External-Cluster", "type": "CpmiGatewayCluster", "ipv4-address": "172.23.34.179",
     "interfaces": [{"name": "eth1", "ipv4-address": "172.23.31.179"}, {"name": "eth2", "ipv4-address": "172.23.34.179"}],
     "cluster-member-names": ["GW01"]},
    {"uid": "m1", "name": "GW01", "type": "cluster-member", "ipv4-address": "172.23.31.177",
     "interfaces": [{"name": "eth1", "ipv4-address": "172.23.31.177"}]},
]


def _enriched():
    objs = {k: dict(v) for k, v in OBJS.items()}
    assert enrich_devices(objs, GWS) == 1
    return ObjectResolver(objs)


def test_enriched_vip_is_a_match():
    assert address_match_state(["cl"], "172.23.31.179", _enriched())[0] == "match"


def test_enriched_unrelated_address_is_a_proven_miss():
    assert address_match_state(["cl"], "192.168.10.50", _enriched())[0] == "no-match"


def test_enriched_member_address_stays_unknown():
    assert address_match_state(["cl"], "172.23.31.177", _enriched())[0] == "unknown"


def test_enriched_device_still_never_proves_containment():
    assert _enriched().address_atoms("cl") is None
