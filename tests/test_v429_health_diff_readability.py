"""
v4.29 - the health diff must not confuse "became readable" with "was added".

Found by running the tool against the lab, not by reading the code.

At 06:26 on 2026-09-08 a baseline was taken while 172.23.31.176 was
unreachable: an asymmetric route meant the workstation's SYN reached the
gateway and the reply left by another path, so the Gaia API never answered.
The baseline recorded that faithfully - the host is in `unreachable` with the
connection error beside it. After the static route was corrected the same
gateway answered, and the diff against that baseline said:

    172.23.31.176  gateway-added
    "This gateway is in the current reading and not in the baseline."

That sentence is false. The gateway WAS in the baseline. It was in the half of
the baseline that `diff_health()` never looked at, because `index()` reads
`report["gateways"]` and ignores `report["unreachable"]` entirely.

The distinction is not cosmetic. "A gateway was added to the estate" and "a
gateway that we could not read is now readable" call for opposite responses:
the first is a change request somebody should be able to point at, the second
is a fault that has been fixed - or, going the other way, a firewall that has
just stopped answering. Reporting the second as the first tells the reader
that the estate changed when it did not, and it quietly drops the evidence -
the recorded error - that says which of the two happened.

This is the same rule the rest of the project already keeps: a gateway that
did not answer produces no findings, which is not the same as producing none.
A gateway that did not answer is also not a gateway that did not exist.

The baseline payloads below are the real shape, taken from
health-baselines/health-20260908062638.json (kept out of git with the rest of
health-baselines/), trimmed to the fields the diff actually compares.
"""

from app.health import diff_health


def gw(host, *, build="779", ifaces=(("eth1", True, "172.23.31.177/24"),), members=()):
    return {
        "host": host,
        "version": {"product": "Check Point Gaia R82", "build": build,
                    "kernel": "4.18.0-372.9.1cpx86_64"},
        "cluster": {"readable": bool(members), "mode": "high-availability",
                    "status": "ok", "message": "Cluster Active",
                    "members": [{"name": n, "status": s} for n, s in members]},
        "interfaces": [{"name": n, "type": "physical", "enabled": e, "cidr": c}
                       for n, e, c in ifaces],
    }


UNREADABLE = ("Unable to connect to the Gaia API at https://172.23.31.176: "
              "All connection attempts failed")


def report(gateways=(), unreachable=(), taken_at="2026-09-08T06:26:38+00:00"):
    return {"schema": 1, "app_version": "4.29", "taken_at": taken_at,
            "gateways": list(gateways),
            "unreachable": [{"host": h, "error": e} for h, e in unreachable]}


def kinds(diff):
    return [c["kind"] for c in diff["changes"]]


def only(diff, kind):
    found = [c for c in diff["changes"] if c["kind"] == kind]
    assert len(found) == 1, f"expected exactly one {kind}, got {kinds(diff)}"
    return found[0]


# ---- the defect, in both directions ----------------------------------

def test_unreadable_then_readable_is_not_reported_as_a_new_gateway():
    """The lab case of 2026-09-08, reproduced."""
    before = report(gateways=[gw("172.23.31.177")],
                    unreachable=[("172.23.31.176", UNREADABLE)])
    after = report(gateways=[gw("172.23.31.177"), gw("172.23.31.176")])

    diff = diff_health(before, after)

    assert "gateway-added" not in kinds(diff), (
        "the gateway was in the baseline - as one that could not be read"
    )
    change = only(diff, "gateway-became-readable")
    assert change["host"] == "172.23.31.176"
    assert UNREADABLE in change["detail"], (
        "the recorded reason it could not be read is the evidence for what "
        "changed, so the line must carry it"
    )


def test_readable_then_unreadable_is_not_reported_as_a_missing_gateway():
    """The direction that matters operationally: a firewall stopped answering."""
    before = report(gateways=[gw("172.23.31.177"), gw("172.23.31.176")])
    after = report(gateways=[gw("172.23.31.177")],
                   unreachable=[("172.23.31.176", UNREADABLE)])

    diff = diff_health(before, after)

    assert "gateway-missing" not in kinds(diff), (
        "it is not missing from the reading - the reading says why it failed"
    )
    change = only(diff, "gateway-became-unreadable")
    assert change["host"] == "172.23.31.176"
    assert UNREADABLE in change["detail"]


# ---- the cases that must keep their old, correct behaviour -----------

def test_a_genuinely_new_gateway_is_still_reported_as_added():
    before = report(gateways=[gw("172.23.31.177")])
    after = report(gateways=[gw("172.23.31.177"), gw("172.23.31.176")])
    change = only(diff_health(before, after), "gateway-added")
    assert change["host"] == "172.23.31.176"


def test_a_gateway_absent_from_both_halves_is_still_reported_as_missing():
    """Dropped from the configured list, not merely unreachable."""
    before = report(gateways=[gw("172.23.31.177"), gw("172.23.31.176")])
    after = report(gateways=[gw("172.23.31.177")])
    change = only(diff_health(before, after), "gateway-missing")
    assert change["host"] == "172.23.31.176"


def test_unreadable_on_both_sides_is_not_a_change():
    """Still broken is not news. The current read's own finding says it."""
    before = report(gateways=[gw("172.23.31.177")],
                    unreachable=[("172.23.31.176", UNREADABLE)])
    after = report(gateways=[gw("172.23.31.177")],
                   unreachable=[("172.23.31.176", UNREADABLE)])
    diff = diff_health(before, after)
    assert diff["changes"] == []
    assert diff["unchanged"] is True


def test_a_gateway_that_became_readable_is_not_also_diffed_field_by_field():
    """
    There is nothing to compare its interfaces against, so the diff must not
    invent an interface-added line for every port on the box.
    """
    before = report(gateways=[], unreachable=[("172.23.31.176", UNREADABLE)])
    after = report(gateways=[gw("172.23.31.176",
                               ifaces=(("bond1.10", True, "192.168.10.254/24"),
                                       ("bond1.20", True, "192.168.20.254/24")))])
    assert kinds(diff_health(before, after)) == ["gateway-became-readable"]


# ---- unchanged behaviour on the ordinary path ------------------------

def test_interface_and_cluster_changes_still_reported():
    before = report(gateways=[gw("172.23.31.177",
                                 ifaces=(("eth1", True, "172.23.31.177/24"),
                                         ("eth3", False, "")),
                                 members=(("External-GW01", "active"),
                                          ("External-GW02", "standby")))])
    after = report(gateways=[gw("172.23.31.177",
                                ifaces=(("eth1", True, "172.23.31.177/24"),
                                        ("eth3", True, "10.0.0.1/24")),
                                members=(("External-GW01", "standby"),
                                         ("External-GW02", "active")))])
    diff = diff_health(before, after)
    assert kinds(diff).count("interface-changed") == 2      # enabled and cidr
    # A failover moves both members, so both are reported. One line would be
    # the incomplete half of the story.
    roles = {c["subject"]: (c["from"], c["to"])
             for c in diff["changes"] if c["kind"] == "cluster-role-changed"}
    assert roles == {"External-GW01": ("active", "standby"),
                     "External-GW02": ("standby", "active")}


def test_a_gateway_dropped_while_unreadable_is_still_reported_missing():
    """
    Unreachable in the baseline and absent from the current reading entirely:
    it left the configured list. Silence here would mean a gateway could be
    removed without the diff ever mentioning it, so long as it was already
    unreachable when the baseline was taken.
    """
    before = report(gateways=[gw("172.23.31.177")],
                    unreachable=[("172.23.31.176", UNREADABLE)])
    after = report(gateways=[gw("172.23.31.177")])
    change = only(diff_health(before, after), "gateway-missing")
    assert change["host"] == "172.23.31.176"


def test_a_build_upgrade_is_still_reported():
    before = report(gateways=[gw("172.23.31.177", build="779")])
    after = report(gateways=[gw("172.23.31.177", build="801")])
    change = only(diff_health(before, after), "version-changed")
    assert change["from"] == "779" and change["to"] == "801"


def test_a_baseline_written_before_this_fix_still_diffs():
    """Old baselines have no `unreachable` key at all. Absent is not empty."""
    before = {"schema": 1, "taken_at": "2026-09-01T00:00:00+00:00",
              "gateways": [gw("172.23.31.177")]}
    after = report(gateways=[gw("172.23.31.177")])
    assert diff_health(before, after)["unchanged"] is True
