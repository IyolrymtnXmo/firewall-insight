"""
v4.23 - the sampling behind `tools.suggest_cases`, without a lab.

The tool itself needs a Management Server, but the part that can be wrong
without anyone noticing is the sampling: pick the network address of a /24 and
every proposed case tests a host that cannot exist; write an ICMP type as a
port and the case silently tests nothing.
"""

from app.resolver import ObjectResolver
from tools.suggest_cases import _sample_address, _sample_service

OBJECTS = {
    "any": {"uid": "any", "name": "Any", "type": "CpmiAnyObject"},
    "net": {"uid": "net", "name": "LAB-VLAN10", "type": "network",
            "subnet4": "192.168.10.0", "mask-length4": 24},
    "host": {"uid": "host", "name": "RDP-Server", "type": "host",
             "ipv4-address": "192.168.20.100"},
    "zone": {"uid": "zone", "name": "InternalZone", "type": "security-zone"},
    "https": {"uid": "https", "name": "https", "type": "service-tcp", "port": "443"},
    "echo": {"uid": "echo", "name": "echo-request", "type": "service-icmp",
             "icmp-type": 8},
    "anyicmp": {"uid": "anyicmp", "name": "icmp-proto", "type": "service-icmp"},
}
RES = ObjectResolver(OBJECTS)


def test_a_network_yields_a_usable_host_not_the_network_address():
    ip, why = _sample_address(["net"], RES)
    assert ip == "192.168.10.1"
    assert "LAB-VLAN10" in why


def test_a_host_object_yields_its_own_address():
    ip, _ = _sample_address(["host"], RES)
    assert ip == "192.168.20.100"


def test_any_is_skipped_so_the_caller_can_say_it_needs_a_human():
    ip, why = _sample_address(["any"], RES)
    assert ip is None
    assert "Any" in why


def test_an_unmodellable_object_is_skipped_rather_than_guessed():
    ip, _ = _sample_address(["zone"], RES)
    assert ip is None


def test_a_later_usable_object_is_found_past_an_unusable_one():
    ip, _ = _sample_address(["any", "zone", "host"], RES)
    assert ip == "192.168.20.100"


def test_a_tcp_service_yields_a_port_and_its_protocol():
    service, proto, why = _sample_service(["https"], RES)
    assert (service, proto) == ("443", "tcp")
    assert "https" in why


def test_an_icmp_service_yields_a_type_and_the_icmp_protocol():
    """The trap Chapter 4 names: this must not come back as a tcp port."""
    service, proto, _ = _sample_service(["echo"], RES)
    assert proto == "icmp"
    assert service == "8"


def test_an_icmp_object_with_no_type_falls_back_to_echo_request():
    service, proto, _ = _sample_service(["anyicmp"], RES)
    assert (service, proto) == ("8", "icmp")


# ---- v4.24: two defects the first live run against the lab exposed ----

BROAD = {
    "all": {"uid": "all", "name": "All_Internet", "type": "network",
            "subnet4": "0.0.0.0", "mask-length4": 0},
    "eight": {"uid": "eight", "name": "RFC1918-10", "type": "network",
              "subnet4": "10.0.0.0", "mask-length4": 8},
    "host": OBJECTS["host"],
}
BROAD_RES = ObjectResolver(BROAD)


def test_an_object_covering_the_internet_is_not_sampled():
    """The live run emitted `0.0.0.1` for All_Internet - inside it, and useless."""
    ip, why = _sample_address(["all"], BROAD_RES)
    assert ip is None
    assert "All_Internet" in why
    assert "/8 or more" in why


def test_a_slash_eight_is_also_too_broad_to_mean_anything():
    ip, _ = _sample_address(["eight"], BROAD_RES)
    assert ip is None


def test_a_usable_object_beside_a_broad_one_is_still_found():
    ip, _ = _sample_address(["all", "host"], BROAD_RES)
    assert ip == "192.168.20.100"


def test_only_filters_on_the_display_number_not_the_raw_one():
    """`--only 1,2,3` used to pull in inline rules 8.1, 8.2 and 8.3."""
    import argparse
    import tools.suggest_cases as sc
    src = open(sc.__file__, encoding="utf-8").read()
    assert "if only is not None and display not in only" in src
    assert 'help="comma-separated DISPLAY rule numbers' in src
    del argparse
