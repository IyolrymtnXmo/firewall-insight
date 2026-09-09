"""
v4.28 - gateway state, read from the shapes a real R82 returned.

Everything here is driven by tests/fixtures/gaia_r82_probe.py. Three traps in
that data, all of which a parser written from documentation walks into:

  "ipv4-address": "Not-Configured"  is a STRING. Treated as an address it
                                    invents a host at Not-Configured.
  "ipv4-mask-length": "24"          also a string.
  enabled:false with an address     a configured interface that is
                                    administratively down. It exists in the lab
                                    right now - Mgmt, 192.168.99.1 - and the
                                    Management API cannot see it, because that
                                    API reports the configured address and not
                                    the link state.

The last one is the reason this feature is worth the second API at all.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fixtures.gaia_r82_probe import (  # noqa: E402
    CLUSTER_STATE_GW01, CLUSTER_STATE_GW02, SHOW_INTERFACES_GW01,
    SHOW_VERSION_GW01)

from app.health import (build_health, diff_health, list_baselines,  # noqa: E402
                        load_baseline, read_cluster_state, read_interfaces,
                        read_version, save_baseline)


def gw(interfaces=None, cluster=None, version=None):
    return {"interfaces": interfaces if interfaces is not None else SHOW_INTERFACES_GW01,
            "cluster": cluster if cluster is not None else CLUSTER_STATE_GW01,
            "version": version if version is not None else SHOW_VERSION_GW01}


class TestReadingTheRealInterfaces:
    def setup_method(self):
        self.rows = {i["name"]: i for i in read_interfaces(SHOW_INTERFACES_GW01)}

    def test_not_configured_is_not_an_address(self):
        eth3 = self.rows["eth3"]
        assert eth3["ipv4"] == ""
        assert eth3["configured"] is False
        assert eth3["cidr"] == ""

    def test_a_string_mask_length_still_makes_a_cidr(self):
        assert self.rows["eth1"]["cidr"] == "172.23.31.177/24"

    def test_comments_survive_because_they_are_how_humans_label_vlans(self):
        assert self.rows["eth2"]["comments"] == "VLAN34 External"

    def test_the_disabled_but_configured_interface_is_visible(self):
        mgmt = self.rows["Mgmt"]
        assert mgmt["configured"] is True
        assert mgmt["enabled"] is False


class TestReadingTheRealClusterState:
    def test_members_come_back_with_roles(self):
        state = read_cluster_state(CLUSTER_STATE_GW01)
        assert state["readable"] is True
        assert state["mode"] == "high-availability"
        assert state["status"] == "ok"
        by_name = {m["name"]: m for m in state["members"]}
        assert by_name["External-GW01"]["status"] == "active"
        assert by_name["External-GW01"]["is_self"] is True
        assert by_name["External-GW02"]["status"] == "standby"

    def test_an_empty_payload_is_reported_unreadable_not_healthy(self):
        assert read_cluster_state({})["readable"] is False
        assert read_cluster_state(None)["readable"] is False

    def test_the_version_is_read(self):
        assert read_version(SHOW_VERSION_GW01)["build"] == "779"
        assert "R82" in read_version(SHOW_VERSION_GW01)["product"]


class TestFindings:
    def test_the_lab_disabled_management_interface_is_found(self):
        """A real finding from the lab, invisible to the Management API."""
        report = build_health({"172.23.31.177": gw()})
        finding = next(f for f in report["findings"] if f["kind"] == "interface-down")
        assert finding["subject"] == "Mgmt"
        assert "192.168.99.1/24" in finding["detail"]
        assert "invisible" in finding["detail"]

    def test_loopback_is_not_reported(self):
        report = build_health({"172.23.31.177": gw()})
        assert not [f for f in report["findings"] if f.get("subject") == "lo"]

    def test_a_healthy_pair_produces_no_cluster_finding(self):
        report = build_health({"172.23.31.177": gw(cluster=CLUSTER_STATE_GW01),
                               "172.23.31.178": gw(cluster=CLUSTER_STATE_GW02)})
        assert not [f for f in report["findings"]
                    if f["kind"] in ("cluster-status", "split-brain", "no-active-member")]

    def test_two_actives_is_reported_as_split_brain(self):
        both_active = dict(CLUSTER_STATE_GW02)
        both_active["this-cluster-member"] = {"name": "External-GW02", "status": "active",
                                              "load": 100, "peer-id": 2}
        report = build_health({"a": gw(cluster=CLUSTER_STATE_GW01),
                               "b": gw(cluster=both_active)})
        finding = next(f for f in report["findings"] if f["kind"] == "split-brain")
        assert finding["severity"] == "high"
        assert "External-GW01" in finding["host"] and "External-GW02" in finding["host"]

    def test_a_cluster_that_is_not_ok_is_reported(self):
        broken = dict(CLUSTER_STATE_GW01, **{"cluster-status": "problem",
                                             "message": "Sync interface down"})
        report = build_health({"a": gw(cluster=broken)})
        finding = next(f for f in report["findings"] if f["kind"] == "cluster-status")
        assert "Sync interface down" in finding["detail"]

    def test_version_drift_across_the_estate(self):
        older = dict(SHOW_VERSION_GW01, **{"os-build": "701"})
        report = build_health({"a": gw(), "b": gw(version=older)})
        finding = next(f for f in report["findings"] if f["kind"] == "version-drift")
        assert "779" in finding["detail"] and "701" in finding["detail"]

    def test_a_gateway_that_did_not_answer_is_a_finding_not_a_gap(self):
        """The lab's Internal-GW01 is unreachable right now. Silence is not health."""
        report = build_health({
            "172.23.31.177": gw(),
            "172.23.31.176": {"error": "All connection attempts failed"}})
        finding = next(f for f in report["findings"] if f["kind"] == "not-read")
        assert "172.23.31.176" in finding["host"]
        assert "Absence of a finding is not" in finding["detail"]
        assert report["summary"]["gateways_unreachable"] == 1
        assert report["summary"]["gateways_read"] == 1


class TestBaselineDiff:
    def test_an_unchanged_estate_reports_nothing(self):
        a = build_health({"gw1": gw()})
        b = build_health({"gw1": gw()})
        out = diff_health(a, b)
        assert out["unchanged"] is True
        assert out["changes"] == []

    def test_a_failover_is_named_as_one(self):
        # CLUSTER_STATE_GW01 and _GW02 describe the SAME state from two
        # vantage points - GW01 active either way - so a failover has to be
        # built, not borrowed from the pair.
        failed_over = {
            "cluster-status": "ok", "message": "Cluster Active",
            "mode": "high-availability",
            "this-cluster-member": {"name": "External-GW01", "status": "standby",
                                    "load": 0, "peer-id": 1},
            "other-cluster-members": [{"name": "External-GW02", "status": "active",
                                       "load": 100, "peer-id": 2}],
        }
        before = build_health({"gw1": gw(cluster=CLUSTER_STATE_GW01)})
        after = build_health({"gw1": gw(cluster=failed_over)})
        change = next(c for c in diff_health(before, after)["changes"]
                      if c["kind"] == "cluster-role-changed")
        assert change["subject"] == "External-GW01"
        assert (change["from"], change["to"]) == ("active", "standby")
        assert "failover" in change["detail"]

    def test_an_interface_going_down_is_caught(self):
        down = {"objects": [dict(o, enabled=False) if o["name"] == "eth2" else o
                            for o in SHOW_INTERFACES_GW01["objects"]]}
        out = diff_health(build_health({"gw1": gw()}),
                          build_health({"gw1": gw(interfaces=down)}))
        change = next(c for c in out["changes"]
                      if c["kind"] == "interface-changed" and c["subject"] == "eth2")
        assert (change["from"], change["to"]) == (True, False)

    def test_a_readdressed_interface_is_caught(self):
        moved = {"objects": [dict(o, **{"ipv4-address": "172.23.31.199"})
                             if o["name"] == "eth1" else o
                             for o in SHOW_INTERFACES_GW01["objects"]]}
        out = diff_health(build_health({"gw1": gw()}),
                          build_health({"gw1": gw(interfaces=moved)}))
        assert any(c["kind"] == "interface-changed" and c["field"] == "cidr"
                   for c in out["changes"])

    def test_an_upgrade_is_caught(self):
        newer = dict(SHOW_VERSION_GW01, **{"os-build": "800"})
        out = diff_health(build_health({"gw1": gw()}),
                          build_health({"gw1": gw(version=newer)}))
        change = next(c for c in out["changes"] if c["kind"] == "version-changed")
        assert (change["from"], change["to"]) == ("779", "800")

    def test_a_gateway_missing_from_the_new_reading_is_reported(self):
        out = diff_health(build_health({"gw1": gw(), "gw2": gw()}),
                          build_health({"gw1": gw()}))
        change = next(c for c in out["changes"] if c["kind"] == "gateway-missing")
        assert change["host"] == "gw2"
        assert "may be down, or simply not read" in change["detail"]


class TestTheBaselineStore:
    def test_round_trip(self, tmp_path):
        report = build_health({"gw1": gw()})
        sid = save_baseline(report, base=tmp_path)
        assert load_baseline(sid, base=tmp_path)["id"] == sid
        assert list_baselines(base=tmp_path)[0]["gateways"] == 1

    @pytest.mark.parametrize("bad", ["../secrets", "a/b", "..", "", ".hidden"])
    def test_a_path_is_refused(self, bad, tmp_path):
        with pytest.raises(ValueError):
            load_baseline(bad, base=tmp_path)


# ---- route and UI -----------------------------------------------------

class TestTheRouteAndPage:
    def setup_method(self):
        from conftest import ui_source
        self.src = (Path(__file__).resolve().parent.parent / "app" / "api"
                    / "health.py").read_text(encoding="utf-8")
        self.ui = ui_source()

    def test_the_routes_are_gets(self):
        for verb in ("router.post", "router.put", "router.patch", "router.delete"):
            assert verb not in self.src
        assert self.src.count("@router.get") == 2

    def test_disabled_is_a_refusal_with_a_reason_not_an_empty_result(self):
        assert "status_code=409" in self.src
        # Asserted on a phrase that survives the line break the source has,
        # rather than on how the literal happens to be wrapped today.
        assert "a statement that the gateways are healthy" in self.src

    def test_the_page_exists(self):
        assert 'id="health"' in self.ui
        assert "showPage('health',this)" in self.ui

    def test_the_page_says_it_is_not_monitoring(self):
        assert "not monitoring" in self.ui
        assert "one reading at one instant" in self.ui

    def test_silence_is_not_rendered_as_health(self):
        assert "which is not the same as producing none" in self.ui
        assert "Nothing above says anything about these" in self.ui

    def test_a_configured_but_disabled_interface_is_painted_as_a_problem(self):
        """down-but-configured is a fault; down-and-unconfigured is not.

        The three-way choice is the contract. v4.30 renamed the neutral pill
        class from 'purple' to 'neutral' when the palette lost its brand hue,
        so the assertion is now on the shape of the decision rather than on
        the class name that happened to be third.
        """
        assert "i.enabled?'good':(i.configured?'bad':" in self.ui
        neutral = self.ui.split("i.enabled?'good':(i.configured?'bad':")[1]
        neutral = neutral.split(")")[0].strip().strip("'")
        assert neutral not in ("good", "bad", "warn"), neutral


def test_the_gaia_client_can_read_everything_health_needs():
    from app.gaia import ALLOWED
    assert {"show-interfaces", "show-cluster-state", "show-version"} <= ALLOWED


# ---- v4.28.3: one failing read must not cost the whole gateway --------

class TestAPartialReadIsStillARead:
    """Internal-GW01 is standalone, so `show-cluster-state` will fail on it.

    Losing its interfaces and its version over a command that was never going
    to apply is the same mistake the routing reader already refuses to make:
    one failure costing everything around it. The lab is about to make this
    concrete - .176 is the gateway whose access is being restored - so it is
    worth pinning before it happens rather than after.
    """

    def standalone(self):
        return {"interfaces": SHOW_INTERFACES_GW01, "version": SHOW_VERSION_GW01,
                "errors": {"cluster": "HTTP 400: this machine is not a cluster member"}}

    def test_the_gateway_still_counts_as_read(self):
        report = build_health({"gw1": gw(), "gwint": self.standalone()})
        assert report["summary"]["gateways_read"] == 2
        assert report["summary"]["gateways_unreachable"] == 0

    def test_its_interfaces_survive(self):
        report = build_health({"gwint": self.standalone()})
        entry = report["gateways"][0]
        assert entry["interfaces_configured"] >= 4
        assert entry["version"]["build"] == "779"

    def test_the_failed_read_is_a_finding_not_a_gap(self):
        report = build_health({"gwint": self.standalone()})
        finding = next(f for f in report["findings"] if f["kind"] == "read-failed")
        assert finding["subject"] == "cluster"
        assert "not a cluster member" in finding["detail"]

    def test_a_missing_cluster_state_is_medium_and_explained_as_expected(self):
        finding = next(f for f in build_health({"gwint": self.standalone()})["findings"]
                       if f["kind"] == "read-failed")
        assert finding["severity"] == "medium"
        assert "expected rather than wrong" in finding["detail"]

    def test_a_missing_interface_list_is_high_because_everything_rests_on_it(self):
        broken = {"cluster": CLUSTER_STATE_GW01, "version": SHOW_VERSION_GW01,
                  "errors": {"interfaces": "HTTP 500"}}
        finding = next(f for f in build_health({"gw": broken})["findings"]
                       if f["kind"] == "read-failed")
        assert finding["severity"] == "high"
        assert "missing that input" in finding["detail"]

    def test_a_gateway_that_answered_nothing_is_still_unreachable(self):
        report = build_health({"gw": {"error": "All connection attempts failed"}})
        assert report["summary"]["gateways_unreachable"] == 1
        assert report["summary"]["gateways_read"] == 0


def test_read_all_state_keeps_the_reads_that_worked():
    """The client half of the same rule, with a fake transport."""
    import asyncio

    import app.gaia as G

    class Fake(G.GaiaClient):
        def __init__(self):
            super().__init__("10.0.0.1", user="u", password="p")

        async def login(self):
            self.sid = "SID"
            return {"sid": "SID"}

        async def interfaces(self):
            return SHOW_INTERFACES_GW01

        async def cluster_state(self):
            raise G.GaiaAPIError("HTTP 400: not a cluster member")

        async def version(self):
            return SHOW_VERSION_GW01

        async def close(self):
            pass

    original = G.GaiaClient
    G.GaiaClient = lambda host: Fake()
    try:
        out = asyncio.run(G.read_all_state(["10.0.0.1"]))
    finally:
        G.GaiaClient = original

    entry = out["10.0.0.1"]
    assert "error" not in entry, "one failed read must not condemn the gateway"
    assert entry["interfaces"] is SHOW_INTERFACES_GW01
    assert entry["version"] is SHOW_VERSION_GW01
    assert "cluster" in entry["errors"]
