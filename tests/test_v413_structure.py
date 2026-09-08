"""
v4.13: main.py was 2,473 lines, 83% of it an embedded frontend string.

Before this release app/main.py held the routes, the policy orchestration, the
cache, the progress registry, and 100KB of HTML+CSS+JS as one Python string.
That meant no syntax highlighting or linting for the frontend, no browser
caching of assets, and one file that every change had to touch.

These tests keep the structure from collapsing back.
"""

from pathlib import Path

from conftest import ui_source

APP = Path(__file__).resolve().parent.parent / "app"


class TestFrontendIsNotEmbedded:
    def test_assets_are_real_files(self):
        assert (APP / "templates" / "index.html").is_file()
        assert (APP / "static" / "css" / "app.css").is_file()
        assert (APP / "static" / "js" / "app.js").is_file()

    def test_no_python_module_embeds_markup(self):
        for py in APP.rglob("*.py"):
            text = py.read_text(encoding="utf-8")
            assert "<!doctype html" not in text.lower(), py
            assert "<style>" not in text, py

    def test_template_links_the_assets(self):
        html = (APP / "templates" / "index.html").read_text(encoding="utf-8")
        assert '<link rel="stylesheet" href="/static/css/app.css">' in html
        assert '<script src="/static/js/app.js"></script>' in html

    def test_main_is_thin(self):
        lines = (APP / "main.py").read_text(encoding="utf-8").count("\n")
        assert lines < 60, f"main.py grew back to {lines} lines"


class TestModuleBoundaries:
    def test_expected_modules_exist(self):
        for name in ("version.py", "runtime.py", "progress.py", "policy.py",
                     "config.py", "checkpoint.py", "resolver.py", "analyzer.py",
                     "nat_analyzer.py", "inline_layers.py", "policy_browser.py",
                     "traffic.py", "matching.py", "nat_correlate.py", "path_map.py",
                     "snapshot.py", "snapshot_diff.py", "compliance.py", "gaia.py",
                     "gaia_topology.py"):
            assert (APP / name).is_file(), name

    def test_routes_are_split_by_area(self):
        for name in ("meta", "access", "nat", "traffic", "topology", "export", "ui",
                     "snapshot", "compliance"):
            assert (APP / "api" / f"{name}.py").is_file(), name

    def test_no_module_is_oversized(self):
        for py in APP.rglob("*.py"):
            lines = py.read_text(encoding="utf-8").count("\n")
            assert lines < 700, f"{py.name} is {lines} lines"

    def test_routers_do_not_import_each_other(self):
        """Route modules must depend on services, not on sibling routes."""
        for py in (APP / "api").glob("*.py"):
            if py.name == "__init__.py":
                continue
            text = py.read_text(encoding="utf-8")
            for sibling in ("meta", "access", "nat", "topology", "export"):
                if sibling == py.stem:
                    continue
                assert f"from .{sibling}" not in text, f"{py.name} -> {sibling}"

    def test_version_has_one_home(self):
        # The point of this test is "defined once", not "equals 4.13.0" -
        # pinning the number turned every release into an edit here.
        import re
        src = (APP / "version.py").read_text(encoding="utf-8")
        assert re.search(r'^APP_VERSION = "\d+\.\d+\.\d+"$', src, re.M), src
        others = [p.name for p in APP.rglob("*.py")
                  if p.name != "version.py"
                  and "APP_VERSION =" in p.read_text(encoding="utf-8")]
        assert others == [], others


class TestReadOnlyIsStillStructural:
    def test_every_route_is_a_get(self):
        """The read-only guarantee is easiest to verify if no route can mutate."""
        for py in (APP / "api").rglob("*.py"):
            text = py.read_text(encoding="utf-8")
            for verb in ("router.post", "router.put", "router.patch", "router.delete"):
                assert verb not in text, f"{py.name} declares {verb}"

    def test_no_mutating_management_api_call_exists(self):
        joined = "\n".join(p.read_text(encoding="utf-8") for p in APP.rglob("*.py"))
        for command in ('"publish"', '"install-policy"', '"set-access-rule"',
                        '"add-access-rule"', '"delete-access-rule"'):
            assert command not in joined, command

    def test_no_mutating_gaia_command_exists(self):
        """v4.27 added a second API whose reads and writes share a prefix space.

        The Management API made this cheap: its reads all start with `show-`.
        Gaia lists `show-routes` beside `set-static-route`, `run-script` and
        `run-reboot`, so the same guarantee needs its own scan - plus the
        runtime allowlist in app/gaia.py, which refuses anything else before
        a request is built.
        """
        joined = "\n".join(p.read_text(encoding="utf-8") for p in APP.rglob("*.py"))
        for command in ("run-script", "run-reboot", "set-static-route",
                        "add-static-route", "delete-static-route", "add-license",
                        "delete-license", "set-interface", "set-initial-setup",
                        "put-file", "set-global-params"):
            assert f'"{command}"' not in joined, command
            assert f"'{command}'" not in joined, command

    def test_the_gaia_allowlist_contains_only_reads(self):
        from app.gaia import ALLOWED
        assert ALLOWED, "an empty allowlist would silently disable the feature"
        for command in ALLOWED:
            assert command.startswith("show-"), command


class TestUiSurvivedTheMove:
    def test_ui_source_still_contains_the_app(self):
        ui = ui_source()
        assert "Firewall <span>Insight</span>" in ui
        assert "function trackProgress(" in ui
        assert "backdrop-filter:blur(9px)" in ui

    def test_assets_are_not_accidentally_truncated(self):
        css = (APP / "static" / "css" / "app.css").read_text(encoding="utf-8")
        js = (APP / "static" / "js" / "app.js").read_text(encoding="utf-8")
        assert css.count("{") == css.count("}"), "unbalanced CSS braces"
        assert len(css) > 25_000 and len(js) > 45_000