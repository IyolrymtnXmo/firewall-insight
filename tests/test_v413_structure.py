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
        """main.py should say what the application is made of, nothing more.

        This counted every line, docstrings included, and v4.33 pushed it to
        exactly 60 by adding two lines of code and four of explanation. Cutting
        the explanation to satisfy the number would have made the file worse
        while measuring nothing, so it counts statements instead - which is the
        property the test was always about. The file it was written against had
        a 100KB HTML string in it.
        """
        import ast
        tree = ast.parse((APP / "main.py").read_text(encoding="utf-8"))

        def statements(node):
            return sum(1 + statements(child)
                       for child in ast.iter_child_nodes(node)
                       if isinstance(child, ast.stmt)
                       and not (isinstance(child, ast.Expr)
                                and isinstance(child.value, ast.Constant)
                                and isinstance(child.value.value, str)))

        count = statements(tree)
        assert count < 30, f"main.py grew to {count} statements"


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
    # Until v4.30 this class asserted that *no* route used a mutating verb.
    # That was a proxy for the real guarantee - the tool never changes firewall
    # policy - and it was an exact proxy for as long as the application had
    # nothing of its own to write.
    #
    # v4.30 gave it something: the Settings page saves Check Point and Gaia
    # credentials so an operator does not have to hand-edit .env. Those writes
    # go to a local encrypted file. They do not reach a firewall.
    #
    # Deleting the test would have given that up quietly, so it is restated as
    # what is still true and still worth protecting: mutating verbs exist in
    # exactly one named module, and that module cannot touch policy. A new
    # POST anywhere else fails here, which is the property that mattered.
    MUTATING_VERBS = ("router.post", "router.put", "router.patch", "router.delete")
    #
    # v4.33 adds the second exception. `jobs.py` writes a schedule file and a
    # run file, and starting a review is a POST because it is not idempotent -
    # each one costs a full read of the Management Server. Like credentials.py
    # it writes locally and reads remotely, and the tests below hold it to the
    # same boundary. Adding to this set is meant to be a visible act.
    #
    # v4.35 adds the third. `auth.py` signs people in: a POST because it sets a
    # cookie and rate-limits, and because a GET that forwards a password to the
    # Management Server would put it in every proxy log on the way. It writes
    # no file of its own beyond the key that signs the cookie.
    #
    # v4.39 adds the fourth. `alerts.py` saves alert destinations: a PUT and a
    # DELETE that write alerts.json and an encrypted entry in credentials.enc,
    # and a POST that sends a test message - a POST because it messages a
    # channel, which a link-prefetching GET must never do. It does not import
    # the policy layer or the Management client; test_v439_alerts.py holds it
    # to that.
    MAY_MUTATE = {"credentials.py", "jobs.py", "auth.py", "alerts.py"}

    def test_only_the_credential_route_may_mutate(self):
        for py in (APP / "api").rglob("*.py"):
            if py.name in self.MAY_MUTATE:
                continue
            text = py.read_text(encoding="utf-8")
            for verb in self.MUTATING_VERBS:
                assert verb not in text, (
                    f"{py.name} declares {verb}. Every route that reads policy is a "
                    f"GET; only {sorted(self.MAY_MUTATE)} may mutate, and only the "
                    f"local credential store.")

    def test_the_exception_is_a_real_module_not_a_stale_name(self):
        """An allowance for a file that no longer exists protects nothing."""
        for name in self.MAY_MUTATE:
            assert (APP / "api" / name).is_file(), name

    def test_the_mutating_module_writes_only_to_the_credential_store(self):
        """Its writes must land on a local file, never on a firewall.

        credentials.py talks to a Management Server (to validate a login) and
        to Gaia (same), so "it makes no network calls" would be false. What
        holds is narrower and is the thing that matters: it never imports the
        policy layer, and the only Management API verbs it names are login and
        logout.
        """
        text = (APP / "api" / "credentials.py").read_text(encoding="utf-8")

        for forbidden in ("from ..policy", "from ..checkpoint import",
                          "show_rulebase", "install_policy", "publish"):
            assert forbidden not in text, f"credentials.py reaches {forbidden}"

        called = {line.split("web_api/")[1].split('"')[0].split("'")[0]
                  for line in text.splitlines() if "web_api/" in line}
        called |= {line.split("gaia_api/")[1].split('"')[0].split("'")[0]
                   for line in text.splitlines() if "gaia_api/" in line}
        assert called <= {"login", "logout"}, called

    def test_the_jobs_module_writes_only_to_local_files(self):
        """It reads policy through the runner; its own writes are local.

        A review does read the Management Server, heavily - that is the point.
        What must stay true is that everything it *writes* goes to this
        machine: a run file and a schedule file. It must not learn a verb of
        its own.
        """
        text = (APP / "api" / "jobs.py").read_text(encoding="utf-8")
        for forbidden in ('"add-', '"set-', '"delete-', '"publish"',
                          '"install-policy"', "web_api/", "gaia_api/"):
            assert forbidden not in text, f"jobs.py reaches {forbidden}"

    def test_starting_a_review_is_not_a_get(self):
        """A GET that costs a full read of the Management Server is a trap.

        Anything that prefetches links - a browser, a scanner, a chat client
        unfurling a URL - would trigger an 80-second analysis. It is a POST
        because it is not idempotent and not free.
        """
        text = (APP / "api" / "jobs.py").read_text(encoding="utf-8")
        assert '@router.post("/api/runs")' in text
        assert '@router.get("/api/runs")' in text, (
            "listing runs should still be a GET; it is free and idempotent")

    def test_the_auth_module_keeps_no_password(self):
        """It validates one and drops it. It must not learn to keep one.

        The whole reason sign-in uses Check Point credentials is that this
        application then has no password store of its own. A line that wrote
        the supplied password anywhere would quietly turn it into one.
        """
        text = (APP / "api" / "auth.py").read_text(encoding="utf-8")
        for forbidden in ("credential_store", "write_text", "write_bytes",
                          "open(", "json.dump"):
            assert forbidden not in text, f"auth.py persists something: {forbidden}"

    def test_signing_in_only_logs_in_and_out(self):
        text = (APP / "api" / "auth.py").read_text(encoding="utf-8")
        called = {line.split("web_api/")[1].split('"')[0].split("'")[0]
                  for line in text.splitlines() if "web_api/" in line}
        assert called <= {"login", "logout"}, called

    def test_the_public_path_list_has_not_grown(self):
        """Every route is behind the gate unless it is named here.

        A middleware cannot be forgotten the way a decorator can, so the only
        way to expose something is to add it to this set - which should be a
        deliberate, visible act.
        """
        from app.main import PUBLIC_PATHS
        assert PUBLIC_PATHS == {"/", "/health", "/api/auth/status",
                                "/api/auth/login", "/api/auth/logout"}, PUBLIC_PATHS

    def test_the_documented_surface_matches_the_code(self):
        """The README states this guarantee; a drifting claim is a defect.

        README said "Every HTTP route is a GET" for seven releases after that
        stopped being true. On a tool whose entire pitch is that it is safe to
        point at production, a safety claim the code does not honour is worse
        than no claim.
        """
        readme = (APP.parent / "README.md").read_text(encoding="utf-8")
        assert "Every HTTP route is a `GET`" not in readme, (
            "README still claims every route is a GET")
        assert "/api/credentials" in readme, (
            "README does not disclose the mutating credential routes")

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