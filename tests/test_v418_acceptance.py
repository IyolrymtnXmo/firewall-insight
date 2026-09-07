"""
v4.18: the acceptance runner has to run.

`tools/acceptance.py` is the answer to "is Project Dev tested yet?" - it runs a
fixed matrix against the live lab and prints a score. It can only be exercised
for real against a Management Server, which CI does not have and neither does
this test.

What CAN be proven offline is the part that actually breaks: that the runner
calls the application's own functions with the signatures they really have.
A tool that dies on `TypeError: package_access_tree() takes 2 positional
arguments` the first time it meets a real server is worse than no tool - it
fails at the moment you were relying on it.

So this drives the whole runner against a fake Management Server and asserts it
completes, scores, and writes its evidence file. Every signature, every result
key it reads, and the traffic path it walks are covered by that.
"""

import asyncio
import json

import pytest

import tools.acceptance as ACC
from app.runtime import cache_clear

OBJS = [
    {"uid": "any", "name": "Any", "type": "CpmiAnyObject"},
    {"uid": "acc", "name": "Accept", "type": "RulebaseAction"},
    {"uid": "drp", "name": "Drop", "type": "RulebaseAction"},
    {"uid": "n10", "name": "LAB-VLAN10", "type": "network",
     "subnet4": "192.168.10.0", "mask-length4": 24},
    {"uid": "n20", "name": "LAB-VLAN20", "type": "network",
     "subnet4": "192.168.20.0", "mask-length4": 24},
    {"uid": "ad", "name": "AD-Server", "type": "host", "ipv4-address": "192.168.10.10"},
    {"uid": "ldap", "name": "ldap", "type": "service-tcp", "port": "389"},
]

RULES = [
    {"type": "access-rule", "rule-number": 1, "name": "VLAN20-to-AD", "enabled": True,
     "source": ["n20"], "destination": ["ad"], "service": ["ldap"], "vpn": [],
     "action": "acc"},
    {"type": "access-rule", "rule-number": 2, "name": "Lab-Outbound", "enabled": True,
     "source": ["n10"], "destination": ["any"], "service": ["any"], "vpn": [],
     "action": "acc", "inline-layer": "InternetLayer"},
    {"type": "access-rule", "rule-number": 3, "name": "Cleanup rule", "enabled": True,
     "source": ["any"], "destination": ["any"], "service": ["any"], "vpn": [],
     "action": "drp"},
]

GATEWAYS = [
    {"uid": "c1", "name": "External-Cluster", "type": "CpmiGatewayCluster",
     "ipv4-address": "172.23.34.179",
     "cluster-member-names": ["External-GW01"],
     "interfaces": [{"ipv4-address": "172.23.31.179", "ipv4-mask-length": 24}]},
    {"uid": "g1", "name": "External-GW01", "type": "cluster-member",
     "ipv4-address": "172.23.31.177",
     "interfaces": [{"ipv4-address": "172.23.31.177", "ipv4-mask-length": 24}]},
    {"uid": "m1", "name": "CP-MGMT-01", "type": "checkpoint-host",
     "ipv4-address": "172.23.31.180",
     "management-blades": {"network-policy-management": True}},
    {"uid": "m2", "name": "CP-MGMT-02", "type": "checkpoint-host",
     "ipv4-address": "172.23.31.181",
     "management-blades": {"network-policy-management": True, "secondary": True}},
]


class FakeClient:
    """Enough Management Server to drive the whole runner."""
    hydration_truncated = False
    nat_show_hits_supported = True

    async def login(self, force=False):
        return {"sid": "fake-sid", "api-server-version": "2.0.1"}

    async def show_packages(self):
        return [{"name": "Standard"}]

    async def show_package_access_layers(self, package):
        return [{"name": "Network", "uid": "u1"}]

    async def show_rulebase_tree(self, root, max_depth=10):
        return {"root_layer": root, "errors": [], "total_layers": 2, "layers": [
            {"name": root, "uid": "u1", "depth": 0, "path": root,
             "parent_layer": None, "parent_rule": None, "display_prefix": "",
             "rule_count": len(RULES),
             "payload": {"layer": root, "rulebase": RULES,
                         "objects-dictionary": OBJS}},
            {"name": "InternetLayer", "uid": "u2", "depth": 1,
             "path": f"{root}/InternetLayer", "parent_layer": root,
             "parent_rule": 2, "display_prefix": "2", "rule_count": 1,
             "payload": {"layer": "InternetLayer", "objects-dictionary": OBJS,
                         "rulebase": [
                             {"type": "access-rule", "rule-number": 1,
                              "name": "Allow-Web", "enabled": True,
                              "source": ["any"], "destination": ["any"],
                              "service": ["any"], "vpn": [], "action": "acc"}]}},
        ]}

    async def hydrate_objects(self, uids, existing, *, refresh_incomplete=True,
                              on_progress=None):
        return existing

    async def show_nat_rulebase(self, package):
        return {"package": package, "total": 2, "objects-dictionary": OBJS,
                "rulebase": [{"type": "nat-rule", "rule-number": 1},
                             {"type": "nat-rule", "rule-number": 2}]}

    async def show_gateways_and_servers(self):
        return GATEWAYS

    async def close(self):
        return None


@pytest.fixture
def report(tmp_path, monkeypatch):
    cache_clear()
    monkeypatch.setattr(ACC, "CheckPointClient", FakeClient)
    monkeypatch.setattr(ACC, "CASES_FILE", tmp_path / "cases.json")
    out = tmp_path / "report.json"
    code = asyncio.run(ACC.run("Standard", str(out)))
    return code, json.loads(out.read_text(encoding="utf-8"))


class TestItRuns:
    def test_the_runner_completes_against_a_management_server(self, report):
        """The point of this file: no TypeError from a drifted signature."""
        _code, data = report
        assert data["result"]["judged"] > 0

    def test_it_writes_evidence_a_reviewer_can_open(self, report):
        _code, data = report
        for key in ("app_version", "package", "api_version", "access_summary",
                    "data_quality", "traffic", "topology", "checks", "result"):
            assert key in data, key

    def test_every_check_records_its_group_and_verdict(self, report):
        _code, data = report
        for row in data["checks"]:
            assert row["group"] and row["check"]
            assert row["ok"] in (True, False, None)

    def test_the_exit_code_follows_the_result(self, report):
        code, data = report
        assert code == (1 if data["result"]["failed"] else 0)


class TestItChecksTheRightThings:
    def test_the_read_only_guarantee_is_one_of_the_checks(self, report):
        _code, data = report
        row = next(r for r in data["checks"] if r["group"] == "safety")
        assert row["ok"] is True, row

    def test_it_walks_the_inline_aware_trace_not_the_single_layer_one(self):
        """The UI follows Parent Rule -> Inline Layer -> child. Testing the
        single-layer helper instead would pass while the real path was broken."""
        src = (ACC.__file__ and open(ACC.__file__, encoding="utf-8").read())
        assert "trace_access_tree(" in src
        assert "would test a different code path" in src

    def test_traffic_cases_are_recorded_with_their_verdicts(self, report):
        _code, data = report
        assert data["traffic"], "no traffic case was evaluated"
        for row in data["traffic"]:
            assert "action" in row and "confidence" in row

    def test_topology_evidence_names_the_cluster_and_the_ha_roles(self, report):
        _code, data = report
        t = data["topology"]
        assert t["clusters"] == ["External-Cluster"]
        assert {m["role"] for m in t["management"]} == {"primary", "secondary"}
        assert t["limitations"]

    def test_a_case_with_no_expectation_is_recorded_but_not_judged(self, tmp_path,
                                                                  monkeypatch):
        cache_clear()
        cases = tmp_path / "cases.json"
        cases.write_text(json.dumps({"layer": "Network", "cases": [
            {"name": "unjudged", "src": "192.168.20.50", "dst": "192.168.10.10",
             "protocol": "tcp", "service": "389", "expect": None}]}),
            encoding="utf-8")
        monkeypatch.setattr(ACC, "CheckPointClient", FakeClient)
        monkeypatch.setattr(ACC, "CASES_FILE", cases)
        out = tmp_path / "r.json"
        asyncio.run(ACC.run("Standard", str(out)))
        data = json.loads(out.read_text(encoding="utf-8"))
        row = next(r for r in data["checks"] if r["check"] == "unjudged")
        assert row["ok"] is None

    def test_a_wrong_expectation_fails_the_run(self, tmp_path, monkeypatch):
        """A matrix that cannot fail is decoration, not a test."""
        cache_clear()
        cases = tmp_path / "cases.json"
        cases.write_text(json.dumps({"layer": "Network", "cases": [
            {"name": "should be accepted", "src": "192.168.20.50",
             "dst": "192.168.10.10", "protocol": "tcp", "service": "389",
             "expect": {"action": "drop"}}]}), encoding="utf-8")
        monkeypatch.setattr(ACC, "CheckPointClient", FakeClient)
        monkeypatch.setattr(ACC, "CASES_FILE", cases)
        out = tmp_path / "r.json"
        code = asyncio.run(ACC.run("Standard", str(out)))
        assert code == 1
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["result"]["failed"] >= 1


class TestTheDefaultMatrix:
    def test_it_seeds_a_cases_file_rather_than_hiding_the_expectations(self,
                                                                      tmp_path,
                                                                      monkeypatch):
        monkeypatch.setattr(ACC, "CASES_FILE", tmp_path / "new.json")
        ACC.load_cases()
        assert (tmp_path / "new.json").exists()

    def test_the_default_cases_cover_both_an_allow_and_a_deny(self):
        want = {c["expect"]["action"] for c in ACC._default_cases()["cases"]
                if c.get("expect")}
        assert {"accept", "drop"} <= want

    def test_rule_numbers_are_not_asserted(self):
        """They shift when a rule is inserted; a test that breaks on
        renumbering teaches you to ignore it."""
        for case in ACC._default_cases()["cases"]:
            assert "rule" not in (case.get("expect") or {})


class TestAFailureNamesTheRule:
    """A run that says "expected accept, got drop" and stops there sends you
    back to SmartConsole to work out which rule did it. The evidence records
    the walked path so the report answers that itself."""

    def test_every_traffic_row_names_what_decided_it(self, report):
        _code, data = report
        for row in data["traffic"]:
            assert "decided_by" in row and row["decided_by"]
            assert "path" in row

    def test_the_path_carries_rule_layer_and_action(self, report):
        _code, data = report
        walked = [r for r in data["traffic"] if r["path"]]
        assert walked, "no case walked a rule"
        for step in walked[0]["path"]:
            for key in ("rule", "name", "layer", "action"):
                assert key in step, key

    def test_a_failing_check_puts_the_rule_in_its_detail(self, tmp_path, monkeypatch):
        import asyncio, json
        from app.runtime import cache_clear
        cache_clear()
        cases = tmp_path / "cases.json"
        cases.write_text(json.dumps({"layer": "Network", "cases": [
            {"name": "wrong on purpose", "src": "192.168.20.50",
             "dst": "192.168.10.10", "protocol": "tcp", "service": "389",
             "expect": {"action": "drop"}}]}), encoding="utf-8")
        monkeypatch.setattr(ACC, "CheckPointClient", FakeClient)
        monkeypatch.setattr(ACC, "CASES_FILE", cases)
        out = tmp_path / "r.json"
        asyncio.run(ACC.run("Standard", str(out)))
        row = next(r for r in json.loads(out.read_text(encoding="utf-8"))["checks"]
                   if r["check"] == "wrong on purpose")
        assert row["ok"] is False
        assert "via" in row["detail"] and "rule" in row["detail"].lower()


class TestPerPackageCases:
    """The lab grew from one policy package to three (External-FW, Internal-FW,
    Standard). One flat list of flows cannot describe three different
    rulebases, so cases can be keyed by package."""

    def _run(self, tmp_path, monkeypatch, cases, package="Standard"):
        import asyncio, json
        from app.runtime import cache_clear
        cache_clear()
        f = tmp_path / "cases.json"
        f.write_text(json.dumps(cases), encoding="utf-8")
        monkeypatch.setattr(ACC, "CheckPointClient", FakeClient)
        monkeypatch.setattr(ACC, "CASES_FILE", f)
        out = tmp_path / f"{package}.json"
        code = asyncio.run(ACC.run(package, str(out)))
        return code, json.loads(out.read_text(encoding="utf-8"))

    CASES = {"layer": "Network", "packages": {
        "Standard": [{"name": "in-standard", "src": "192.168.20.50",
                      "dst": "192.168.10.10", "protocol": "tcp",
                      "service": "389", "expect": {"action": "accept"}}],
        "Other": [{"name": "in-other", "src": "1.1.1.1", "dst": "2.2.2.2",
                   "protocol": "tcp", "service": "80", "expect": None}],
    }}

    def test_only_the_named_packages_cases_run(self, tmp_path, monkeypatch):
        _code, data = self._run(tmp_path, monkeypatch, self.CASES)
        names = [t["case"] for t in data["traffic"]]
        assert names == ["in-standard"]

    def test_a_package_with_no_cases_says_so_rather_than_passing_silently(
            self, tmp_path, monkeypatch):
        """Zero cases and zero failures looks identical to a clean run."""
        _code, data = self._run(tmp_path, monkeypatch, self.CASES, package="Nothing")
        row = next(r for r in data["checks"]
                   if "no traffic cases defined" in r["check"])
        assert row["ok"] is None

    def test_a_flat_case_list_still_works(self, tmp_path, monkeypatch):
        flat = {"layer": "Network", "cases": [
            {"name": "flat", "src": "192.168.20.50", "dst": "192.168.10.10",
             "protocol": "tcp", "service": "389", "expect": {"action": "accept"}}]}
        _code, data = self._run(tmp_path, monkeypatch, flat)
        assert [t["case"] for t in data["traffic"]] == ["flat"]


class TestAnyAnyAnyPermitIsAFinding:
    def test_a_permit_all_rule_is_reported_as_a_finding(self, tmp_path, monkeypatch):
        """Internal-FW is a single Any/Any/Any Accept. That is a statement
        about the POLICY, not about whether this tool works - so it is
        reported and counted separately, never as a tool failure. Mixing them
        would mean the run could not be green until the estate was perfect,
        and nobody would look at it again."""
        import asyncio, json
        from app.runtime import cache_clear

        class PermitAll(FakeClient):
            async def show_rulebase_tree(self, root, max_depth=10):
                return {"root_layer": root, "errors": [], "total_layers": 1,
                        "layers": [{"name": root, "uid": "u1", "depth": 0,
                                    "path": root, "parent_layer": None,
                                    "parent_rule": None, "display_prefix": "",
                                    "rule_count": 1,
                                    "payload": {"layer": root,
                                                "objects-dictionary": OBJS,
                                                "rulebase": [{
                                                    "type": "access-rule",
                                                    "rule-number": 1,
                                                    "name": "Allow-Any",
                                                    "enabled": True,
                                                    "source": ["any"],
                                                    "destination": ["any"],
                                                    "service": ["any"],
                                                    "vpn": [], "action": "acc"}]}}]}

        cache_clear()
        f = tmp_path / "cases.json"
        f.write_text(json.dumps({"layer": "Network", "packages": {"P": []}}),
                     encoding="utf-8")
        monkeypatch.setattr(ACC, "CheckPointClient", PermitAll)
        monkeypatch.setattr(ACC, "CASES_FILE", f)
        out = tmp_path / "r.json"
        asyncio.run(ACC.run("P", str(out)))
        data = json.loads(out.read_text(encoding="utf-8"))
        assert any("permit Any -> Any -> Any" in f
                   for f in data["policy_findings"]), data["policy_findings"]
        # ...and it did not make the tool look broken
        assert all(r["ok"] is not False for r in data["checks"]
                   if r["group"] == "access")

    def test_a_cleanup_drop_is_not_counted_as_one(self, report):
        """The distinction the whole check depends on."""
        _code, data = report
        row = next(r for r in data["checks"]
                   if r["check"].startswith("cleanup rule told apart"))
        assert row["ok"] is True

    def test_a_package_without_inline_layers_is_not_a_failure(self, tmp_path,
                                                              monkeypatch):
        """A package is not obliged to contain inline layers."""
        import asyncio, json
        from app.runtime import cache_clear

        class Flat(FakeClient):
            async def show_packages(self):
                return [{"name": "P"}]

            async def show_rulebase_tree(self, root, max_depth=10):
                return {"root_layer": root, "errors": [], "total_layers": 1,
                        "layers": [{"name": root, "uid": "u1", "depth": 0,
                                    "path": root, "parent_layer": None,
                                    "parent_rule": None, "display_prefix": "",
                                    "rule_count": 1,
                                    "payload": {"layer": root,
                                                "objects-dictionary": OBJS,
                                                "rulebase": [RULES[0]]}}]}

        cache_clear()
        f = tmp_path / "c.json"
        f.write_text(json.dumps({"layer": "Network", "packages": {"P": []}}),
                     encoding="utf-8")
        monkeypatch.setattr(ACC, "CheckPointClient", Flat)
        monkeypatch.setattr(ACC, "CASES_FILE", f)
        out = tmp_path / "r.json"
        code = asyncio.run(ACC.run("P", str(out)))
        assert code == 0, "a small package must not fail the run"
