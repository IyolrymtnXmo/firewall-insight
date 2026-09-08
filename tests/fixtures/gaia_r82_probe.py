"""
Real Gaia R82 answers, captured from the lab on 8 Sep 2026 by tools.probe_gaia.

These are the oracle. Before this file existed, `app/gaia_topology.py` was
written against shapes taken from the API reference, and the first contact with
a real gateway showed what that is worth: the readers reported `parsed: 7/7`
while silently dropping every next hop, because Gaia nests them one level
deeper than the documentation examples suggest.

Nothing in this file is edited or tidied. It is exactly what
External-GW01 (172.23.31.177) and External-GW02 (172.23.31.178) returned.
"""

# show-routes: next-hop is an OBJECT. A routed prefix carries a `gateways`
# list whose entries hold both the address and the egress interface; a
# connected prefix carries only `interface` and legitimately has no gateway.
SHOW_ROUTES_GW01 = {
    "from": 1, "to": 7, "total": 7,
    "objects": [
        {"active-age": 1513221, "address": "0.0.0.0", "age": 1513221,
         "mask-length": 0,
         "next-hop": {"gateways": [{"address": "172.23.34.254", "interface": "eth2"}]},
         "protocol": "Static"},
        {"address": "10.99.99.0", "mask-length": 30,
         "next-hop": {"interface": "Sync"}, "protocol": "Connected"},
        {"address": "127.0.0.0", "mask-length": 8,
         "next-hop": {"interface": "lo"}, "protocol": "Connected"},
        {"address": "172.23.31.0", "mask-length": 24,
         "next-hop": {"interface": "eth1"}, "protocol": "Connected"},
        {"address": "172.23.34.0", "mask-length": 24,
         "next-hop": {"interface": "eth2"}, "protocol": "Connected"},
        {"active-age": 1513221, "address": "192.168.10.0", "age": 1513221,
         "mask-length": 24,
         "next-hop": {"gateways": [{"address": "172.23.31.176", "interface": "eth1"}]},
         "protocol": "Static"},
        {"active-age": 1513221, "address": "192.168.20.0", "age": 1513221,
         "mask-length": 24,
         "next-hop": {"gateways": [{"address": "172.23.31.176", "interface": "eth1"}]},
         "protocol": "Static"},
    ],
}

# show-static-routes: a different shape again - next-hop is a LIST of objects
# keyed `gateway`, and `type` means "the next hop is a gateway", not the
# routing protocol. Reading `type` as the protocol is how "Static" became
# "gateway" in the first run.
SHOW_STATIC_ROUTES_GW01 = {
    "from": 1, "to": 3, "total": 3,
    "objects": [
        {"address": "0.0.0.0", "mask-length": 0,
         "next-hop": [{"gateway": "172.23.34.254", "priority": "default"}],
         "ping": False, "scope-local": False, "type": "gateway"},
        {"address": "192.168.10.0", "mask-length": 24,
         "next-hop": [{"gateway": "172.23.31.176", "priority": "default"}],
         "ping": False, "scope-local": False, "type": "gateway"},
        {"address": "192.168.20.0", "mask-length": 24,
         "next-hop": [{"gateway": "172.23.31.176", "priority": "default"}],
         "ping": False, "scope-local": False, "type": "gateway"},
    ],
}

SHOW_INTERFACES_GW01 = {
    "objects": [
        {"comments": "", "enabled": False, "ipv4-address": "192.168.99.1",
         "ipv4-mask-length": "24", "ipv6-address": "Not-Configured",
         "name": "Mgmt", "type": "physical"},
        {"comments": "ClusterXL Sync", "enabled": True, "ipv4-address": "10.99.99.1",
         "ipv4-mask-length": "30", "ipv6-address": "Not-Configured",
         "name": "Sync", "type": "physical"},
        {"comments": "VLAN31 Internal + Management", "enabled": True,
         "ipv4-address": "172.23.31.177", "ipv4-mask-length": "24",
         "ipv6-address": "Not-Configured", "name": "eth1", "type": "physical"},
        {"comments": "VLAN34 External", "enabled": True,
         "ipv4-address": "172.23.34.177", "ipv4-mask-length": "24",
         "ipv6-address": "Not-Configured", "name": "eth2", "type": "physical"},
        {"comments": "", "enabled": False, "ipv4-address": "Not-Configured",
         "ipv4-mask-length": "Not-Configured", "name": "eth3", "type": "physical"},
        {"comments": "", "enabled": False, "ipv4-address": "Not-Configured",
         "ipv4-mask-length": "Not-Configured", "name": "eth4", "type": "physical"},
        {"comments": "", "enabled": True, "ipv4-address": "127.0.0.1",
         "ipv4-mask-length": "8", "name": "lo", "type": "loopback"},
    ],
}

# show-cluster-state: what cphaprob answers, as JSON.
CLUSTER_STATE_GW01 = {
    "additional-info": "", "cluster-status": "ok", "message": "Cluster Active",
    "mode": "high-availability",
    "other-cluster-members": [
        {"load": 0, "name": "External-GW02", "peer-id": 2, "status": "standby"}],
    "this-cluster-member": {"load": 100, "name": "External-GW01", "peer-id": 1,
                            "status": "active"},
}
CLUSTER_STATE_GW02 = {
    "additional-info": "", "cluster-status": "ok", "message": "Cluster Active",
    "mode": "high-availability",
    "other-cluster-members": [
        {"load": 100, "name": "External-GW01", "peer-id": 1, "status": "active"}],
    "this-cluster-member": {"load": 0, "name": "External-GW02", "peer-id": 2,
                            "status": "standby"},
}

SHOW_VERSION_GW01 = {
    "os-build": "779", "os-edition": "64-bit",
    "os-kernel-version": "4.18.0-372.9.1cpx86_64",
    "product-version": "Check Point Gaia R82",
}

# Internal-GW01. The probe could not reach it: the route to it was removed and
# no policy permits the Gaia port from here. An unreachable gateway is a real
# operational state, not an edge case, and the map has to say so.
UNREACHABLE_GW_INT = {
    "error": "Unable to connect to the Gaia API at https://172.23.31.176: "
             "All connection attempts failed",
}
