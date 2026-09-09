"""
v4.12 regression: the step indicator must report real server phases.

v4.11 showed Traffic Path a four-step list, but the browser makes ONE request
and cannot see server-side phases, so the list was driven by a client-side
guess. In practice it sat on step 1 for the whole run and then jumped to done —
decoration that lied about what was happening, the same class of dishonesty as
reporting a partial result as complete.

Two fixes:
  1. the backend records its phase against a client-supplied request id, and
     the UI polls /api/progress for it
  2. object hydration - which dominates first-load time at ~0.55s per object -
     reports a moving per-object counter, so a 20s wait shows real movement
     instead of one frozen step
"""

from conftest import app_source

import asyncio

from fastapi.testclient import TestClient

import app.main as M
import app.policy as P
import app.progress as PR
import app.runtime as R

# v4.13 split main.py: the progress registry, the cache and the Management
# client each live in their own module now. `policy` imported progress_set by
# name, so a spy must patch it there, not on main.


def _client():
    R.cache_clear()
    PR._progress.clear()
    return TestClient(M.app)


class TestProgressEndpoint:
    def test_unknown_rid_is_not_an_error(self):
        d = _client().get("/api/progress", params={"rid": "nope"}).json()
        assert d["done"] is False and d["phase"] == 0

    def test_phases_round_trip(self):
        c = _client()
        PR.progress_set("r1", 1, "Analyzing each layer", 3, "detail here")
        d = c.get("/api/progress", params={"rid": "r1"}).json()
        assert (d["phase"], d["label"], d["total"], d["detail"]) == (
            1, "Analyzing each layer", 3, "detail here")
        assert d["done"] is False

    def test_done_reports_the_final_phase(self):
        c = _client()
        PR.progress_set("r2", 1, "Working", 4)
        PR.progress_done("r2", "All finished")
        d = c.get("/api/progress", params={"rid": "r2"}).json()
        assert d["done"] is True
        assert d["phase"] == 4
        assert d["label"] == "All finished"

    def test_a_missing_rid_is_simply_ignored(self):
        """Requests without ?rid must not blow up or leak entries."""
        PR._progress.clear()
        PR.progress_set(None, 1, "x", 2)
        PR.progress_done(None)
        assert PR._progress == {}

    def test_stale_entries_are_evicted(self):
        PR._progress.clear()
        PR._progress["old"] = {"phase": 0, "ts": 0.0}
        PR.progress_set("fresh", 0, "now", 1)
        assert "old" not in PR._progress
        assert "fresh" in PR._progress


OBJS = [{"uid": f"g{i}", "name": f"Group-{i}", "type": "group"} for i in range(8)]


class _FakeClient:
    """Stands in for CheckPointClient; hydration is deliberately slow."""
    hydration_truncated = False
    nat_show_hits_supported = None

    def __init__(self):
        self.hydrate_calls = 0

    async def show_package_access_layers(self, package):
        return [{"name": "Network", "uid": "u1"}]

    async def show_rulebase_tree(self, root, max_depth=10):
        rules = [{"type": "access-rule", "rule-number": 1, "enabled": True,
                  "source": [o["uid"] for o in OBJS], "destination": ["any"],
                  "service": ["any"], "vpn": [], "action": "acc"}]
        return {"root_layer": root, "errors": [], "total_layers": 1, "layers": [{
            "name": root, "uid": "u1", "depth": 0, "path": root,
            "parent_layer": None, "parent_rule": None, "display_prefix": "",
            "rule_count": 1,
            "payload": {"layer": root, "rulebase": rules, "objects-dictionary":
                        OBJS + [{"uid": "any", "name": "Any", "type": "CpmiAnyObject"},
                                {"uid": "acc", "name": "Accept", "type": "RulebaseAction"}]},
        }]}

    async def hydrate_objects(self, uids, existing, *, refresh_incomplete=True, on_progress=None):
        from app.resolver import needs_detail
        targets = [u for u in uids if u and (
            u not in existing or (refresh_incomplete and needs_detail(existing[u])))]
        for i, uid in enumerate(targets, 1):
            self.hydrate_calls += 1
            if on_progress:
                on_progress(i, len(targets))
            await asyncio.sleep(0)
            existing[uid] = {"uid": uid, "name": uid, "type": "network",
                             "subnet4": "10.0.0.0", "mask-length4": 24}
        return existing

    async def show_nat_rulebase(self, package):
        return {"package": package, "rulebase": [], "objects-dictionary": [], "total": 0}

    async def close(self):
        pass


class TestRealPhases:
    def test_hydration_reports_a_moving_object_counter(self):
        """The captured details must count up, not repeat one frozen string."""
        seen = []
        real = P.progress_set

        def spy(rid, phase, label="", total=0, detail=""):
            if detail:
                seen.append(detail)
            real(rid, phase, label, total, detail)

        P.progress_set = spy
        try:
            R.cp = _FakeClient()
            R.cache_clear(); PR._progress.clear()
            r = TestClient(M.app).get("/api/package-analyze",
                                      params={"package": "Standard", "rid": "rp"})
            assert r.status_code == 200, r.text
        finally:
            P.progress_set = real

        counted = [d for d in seen if "resolving object" in d]
        assert len(counted) >= 5, counted
        assert "resolving object 1/" in counted[0]
        # strictly increasing, i.e. it actually moves
        nums = [int(d.split("resolving object ")[1].split("/")[0]) for d in counted]
        assert nums == sorted(nums) and nums[-1] > nums[0], nums

    def test_analysis_reports_done_at_the_end(self):
        R.cp = _FakeClient()
        c = _client()
        r = c.get("/api/package-analyze", params={"package": "Standard", "rid": "rd"})
        assert r.status_code == 200
        assert c.get("/api/progress", params={"rid": "rd"}).json()["done"] is True

    def test_a_cached_result_reports_done_immediately(self):
        """Second call is instant; the overlay must not hang on step 1."""
        R.cp = _FakeClient()
        c = _client()
        c.get("/api/package-analyze", params={"package": "Standard", "rid": "a"})
        PR._progress.clear()
        c.get("/api/package-analyze", params={"package": "Standard", "rid": "b"})
        d = c.get("/api/progress", params={"rid": "b"}).json()
        assert d["done"] is True
        assert d["label"] == "Served from cache"

    def test_traffic_path_walks_its_four_phases_in_order(self):
        # Both modules do `from ..progress import progress_set`, so the name is
        # bound per module and a spy has to replace it in each place that
        # emits: policy.py drives phase 0, api/traffic.py drives 1-3.
        import app.api.traffic as AT

        labels = []
        real = P.progress_set

        def spy(rid, phase, label="", total=0, detail=""):
            if label and (not labels or labels[-1] != (phase, label)):
                labels.append((phase, label))
            real(rid, phase, label, total, detail)

        P.progress_set = spy
        AT.progress_set = spy
        try:
            R.cp = _FakeClient()
            R.cache_clear(); PR._progress.clear()
            r = TestClient(M.app).get("/api/traffic-path", params={
                "layer": "Network", "src": "10.0.0.1", "dst": "10.0.0.2",
                "protocol": "tcp", "service": "443", "package": "Standard",
                "rid": "rt"})
            assert r.status_code == 200, r.text
        finally:
            P.progress_set = real
            AT.progress_set = real

        phases = [p for p, _ in labels]
        assert phases == sorted(phases), labels
        names = [l for _, l in labels]
        assert "Loading package / inline layer tree" in names
        assert "Resolving objects and service" in names
        assert "Walking the ordered rulebase" in names
        assert "Correlating NAT" in names

    def test_progress_never_breaks_the_real_request(self):
        """Progress is best-effort; a bad rid must not fail the analysis."""
        R.cp = _FakeClient()
        c = _client()
        r = c.get("/api/package-analyze", params={"package": "Standard"})
        assert r.status_code == 200


class TestFrontendWiring:
    SRC = None

    @classmethod
    def setup_class(cls):
        from pathlib import Path
        cls.SRC = app_source()

    def test_client_generates_and_sends_a_request_id(self):
        assert "function newRid()" in self.SRC
        assert "q.set('rid',rid)" in self.SRC
        assert "'&rid='+rid" in self.SRC

    def test_client_polls_the_progress_endpoint(self):
        assert "function trackProgress(" in self.SRC
        assert "'/api/progress?rid='" in self.SRC

    def test_polling_is_always_stopped(self):
        assert "const stopProgress=trackProgress(rid)" in self.SRC
        assert "stopProgress();" in self.SRC
        assert "finally{ stopP(); }" in self.SRC

    def test_progress_failures_never_fail_the_request(self):
        assert "never fail the real request for it" in self.SRC

    def test_hydration_detail_is_displayed(self):
        assert "function busyDetail(" in self.SRC
        assert 'id="busyDetail"' in self.SRC
        assert "busyDetail(p.detail || '')" in self.SRC

    def test_dashboard_steps_are_labelled_as_genuinely_separate(self):
        assert "These ARE three separate requests" in self.SRC


class TestSidebarAndFonts:
    SRC = None

    @classmethod
    def setup_class(cls):
        from pathlib import Path
        cls.SRC = app_source()

    def test_toasts_are_top_right(self):
        assert "#toasts{\n  position:fixed;right:18px;top:18px;" in self.SRC
        assert "bottom:18px;z-index:9500" not in self.SRC

    def test_sidebar_collapses_to_a_rail(self):
        """Collapsing narrows the sidebar column and the layer painted behind it.

        The two widths must agree: the sidebar is a sticky element inside a
        grid column, and a separate fixed layer paints that column full-height.
        When they disagreed by 28px in v4.30 the rail colour bled into the work
        area as a seam. The exact pixel count is not the contract - the fact
        that both numbers are the same, and smaller than the expanded rail, is.
        """
        assert "function toggleRail(" in self.SRC
        assert 'id="railToggle"' in self.SRC
        railed = int(self.SRC.split("body.rail .app{grid-template-columns:")[1]
                     .split("px")[0])
        painted = int(self.SRC.split("body.rail .app:before{width:")[1].split("px")[0])
        expanded = int(self.SRC.split(".app:before{\n  content:")[1]
                       .split("width:")[1].split("px")[0])
        assert railed == painted, f"rail column {railed}px, painted {painted}px"
        assert railed < expanded

    def test_rail_shows_tooltips_from_data_label(self):
        assert 'data-label="Network Mapping"' in self.SRC
        assert "content:attr(data-label)" in self.SRC

    def test_rail_state_is_remembered(self):
        assert "localStorage.setItem('fw-rail'" in self.SRC
        assert "localStorage.getItem('fw-rail')" in self.SRC

    def test_rail_has_a_keyboard_shortcut(self):
        assert "ev.key.toLowerCase() === 'b'" in self.SRC

    def test_the_loaded_faces_match_the_declared_stacks(self):
        """Whatever the UI face is, the <link> must actually fetch it.

        Before v4.30 this pinned Nunito + Anuphan + JetBrains Mono by name.
        The rebuild changed all three, and a name-pinned test would have gone
        red without saying anything true. What matters is that the first
        family named in each stack is one the page actually loads - a silent
        fallback to Segoe UI is the failure this catches.
        """
        for var in ("--font-ui:", "--font-mono:"):
            first = self.SRC.split(var)[1].split(",")[0].strip().strip("'")
            assert first.replace(" ", "+") in self.SRC, (
                f"{var}{first} is declared but never loaded")

    def test_a_thai_face_is_carried_by_the_ui_stack(self):
        """The tool is written and read by a Thai team; Thai text must have a
        face chosen for it rather than falling through to a system default."""
        stack = self.SRC.split("--font-ui:")[1].split(";")[0]
        assert "Thai" in stack, stack

    def test_font_variables_have_offline_fallbacks(self):
        assert "system-ui" in self.SRC
        assert "'Noto Sans Thai'" in self.SRC

    def test_air_gapped_installs_are_documented_in_place(self):
        assert "Air-gapped install" in self.SRC

    def test_tabular_data_is_monospaced(self):
        """Rule numbers, addresses, ports and counts line up in columns, which
        needs a mono face and tabular figures - not one specific mono face."""
        mono = self.SRC.split("--font-mono:")[1].split(";")[0]
        assert "mono" in mono.lower(), mono
        assert "font-variant-numeric:tabular-nums" in self.SRC
