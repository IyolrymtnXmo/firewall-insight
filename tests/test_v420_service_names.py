"""
v4.20 - a service NAME that resolves to something else must say so.

Chapter 4 records the trap from the live lab: Check Point ships an object
called `RDP`, and it is UDP/259 - Check Point's own control protocol, not
Microsoft Remote Desktop. The object for Remote Desktop is
`Remote_Desktop_Protocol` (TCP/3389).

Typing `RDP` into Traffic Path therefore answers a question nobody asked.
The trace is not wrong - it correctly evaluates UDP/259 - but the person
reading it believes they asked about 3389, and a `drop` verdict for the wrong
flow reads exactly like a `drop` verdict for the right one.

Resolution stays as it was (an exact Check Point object name wins, because
that is what the policy is written in). What changes is that the mismatch is
now stated: the protocol the user selected against the protocol the object
actually is.
"""

import pytest

from app.resolver import ObjectResolver
from app.traffic import resolve_service_query


def res(*objects):
    return ObjectResolver({o["uid"]: o for o in objects})


CP_RDP = {"uid": "u-rdp", "name": "RDP", "type": "service-udp", "port": "259"}
MS_RDP = {"uid": "u-ms", "name": "Remote_Desktop_Protocol", "type": "service-tcp",
          "port": "3389"}
ODD_HTTPS = {"uid": "u-h", "name": "https", "type": "service-tcp", "port": "8443"}


def test_object_name_still_wins_over_the_standard_service_database():
    q = resolve_service_query("RDP", "tcp", res(CP_RDP, MS_RDP))
    assert q["resolved_by"] == "checkpoint-service-object"
    assert q["protocol"] == "udp"
    assert q["port"] == 259
    assert q["display"] == "RDP (UDP/259)"


def test_protocol_mismatch_is_reported_not_silently_swallowed():
    q = resolve_service_query("RDP", "tcp", res(CP_RDP, MS_RDP))
    warnings = " ".join(q.get("warnings") or [])
    assert warnings, "asking for TCP and getting a UDP object must be said out loud"
    assert "UDP" in warnings and "TCP" in warnings
    assert "RDP" in warnings


def test_matching_protocol_produces_no_noise():
    q = resolve_service_query("Remote_Desktop_Protocol", "tcp", res(CP_RDP, MS_RDP))
    assert q["port"] == 3389
    assert not q.get("warnings")


def test_custom_object_shadowing_a_standard_service_name_is_flagged():
    """A policy object named `https` on 8443 is legal, and easy to misread."""
    q = resolve_service_query("https", "tcp", res(ODD_HTTPS))
    assert q["port"] == 8443
    warnings = " ".join(q.get("warnings") or [])
    assert "443" in warnings, warnings
    assert "https" in warnings


def test_numeric_and_standard_lookups_are_unchanged():
    assert resolve_service_query("3389", "tcp", res())["port"] == 3389
    assert not resolve_service_query("3389", "tcp", res()).get("warnings")
    q = resolve_service_query("https", "tcp", res())
    assert q["resolved_by"] == "standard-service-name"
    assert q["port"] == 443


def test_unknown_service_still_raises_rather_than_guessing():
    with pytest.raises(ValueError):
        resolve_service_query("definitely-not-a-service", "tcp", res())


def test_ui_surfaces_the_warning():
    from conftest import ui_source
    assert "service_warnings" in ui_source()
