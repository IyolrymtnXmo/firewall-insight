"""
v4.38.2 - the documentation describes the application that ships with it.

By v4.38 the README said every route was a GET (37 routes, 8 were not), that a
snapshot was the only write (there were seven kinds), that the suite had 381
tests (906), and nothing at all about signing in, which every data route had
required since v4.35. None of it was a typo. Each sentence had been true once
and nobody's change touched it afterwards.

These tests do not check prose. They check the handful of facts a reader acts
on, derived from the code, so that the next route, tool or version without a
matching line in the docs fails here instead of drifting.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.routing import APIRoute

from app.main import app
from app.version import APP_VERSION

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")


def _api_table() -> str:
    return README.split("## API reference", 1)[1].split("\n## ", 1)[0]


class TestTheReadmeIsTheApplication:
    def test_every_route_is_in_the_api_reference(self):
        table = _api_table()
        missing = []
        for route in app.routes:
            if not isinstance(route, APIRoute):
                continue
            for method in sorted(route.methods - {"HEAD"}):
                # A row is "| METHOD | `/path` or `/path?query` |".
                row = re.search(
                    rf"^\|\s*{method}\s*\|\s*`{re.escape(route.path)}[`?]",
                    table, re.MULTILINE)
                if not row:
                    missing.append(f"{method} {route.path}")
        assert not missing, (
            "routes the README's API reference does not list: "
            + ", ".join(missing))

    def test_the_api_reference_lists_nothing_that_does_not_exist(self):
        real = {(m, r.path) for r in app.routes if isinstance(r, APIRoute)
                for m in r.methods - {"HEAD"}}
        rows = re.findall(r"^\|\s*(GET|POST|PUT|DELETE|PATCH)\s*\|\s*`([^`?]+)",
                          _api_table(), re.MULTILINE)
        ghosts = [f"{m} {p}" for m, p in rows if (m, p) not in real]
        assert not ghosts, f"the README documents routes that do not exist: {ghosts}"

    def test_every_tool_is_documented(self):
        tools = sorted(p.stem for p in (ROOT / "tools").glob("*.py")
                       if p.stem not in ("__init__", "ch3_demo"))
        undocumented = [t for t in tools if f"tools.{t}" not in README]
        assert not undocumented, f"tools the README does not mention: {undocumented}"

    def test_it_no_longer_claims_every_route_is_a_get(self):
        assert "Every route is a `GET`" not in README
        assert "only write anywhere" not in README

    def test_it_says_how_to_sign_in_and_how_to_get_back_in(self):
        assert "## Signing in" in README
        assert "tools.reset_credentials --clear checkpoint" in README

    def test_it_does_not_pin_a_test_count(self):
        """"381 tests" was correct once. A count in prose goes stale on the next test."""
        claims = re.findall(r"\b\d{3,4} (?:tests|passed)\b", README)
        assert not claims, f"the README pins test counts that will drift: {claims}"


class TestTheChangelogKeepsUp:
    def test_the_newest_entry_is_the_running_version(self):
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        newest = re.search(r"^## v(\d+\.\d+\.\d+)", changelog, re.MULTILINE)
        assert newest and newest.group(1) == APP_VERSION, (
            f"app/version.py is {APP_VERSION} but the newest CHANGELOG entry is "
            f"{newest.group(1) if newest else 'missing'} - a version was bumped "
            "without saying what changed")


class TestHealthReportsWhatIsTrue:
    def test_version_matches_and_the_stale_phase_is_gone(self):
        from fastapi.testclient import TestClient
        body = TestClient(app).get("/health").json()
        assert body["version"] == APP_VERSION
        assert "phase" not in body, (
            '"phase": "4.0" was set in v4.0 and never changed; a monitor reading '
            "it would be reading nothing")


# Files a stranger copies, or that ship in the image. Addresses in them should
# be ones that can never belong to anybody.
SHARED = ["README.md", ".env.example", "Dockerfile", "docker-compose.yml", ".dockerignore"]
ALLOWED = ("192.0.2.", "198.51.100.", "203.0.113.", "127.0.0.", "0.0.0.0")


class TestSetupFilesCarryNoRealAddresses:
    """v4.35 guarded the served page. `.env.example` was not covered, and still
    shipped the lab's three real gateway addresses."""

    @pytest.mark.parametrize("name", SHARED)
    def test_only_documentation_addresses(self, name):
        text = (ROOT / name).read_text(encoding="utf-8")
        found = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))
        real = sorted(ip for ip in found if not ip.startswith(ALLOWED))
        assert not real, (
            f"{name} contains {real}. Use RFC 5737 addresses "
            "(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).")


class TestTheContainerCanUseTheWayBackIn:
    def test_the_image_includes_tools(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        assert re.search(r"^COPY tools\b", dockerfile, re.MULTILINE), (
            "tools/ is not in the image, so reset_credentials - the way back in "
            "when nobody can sign in - does not exist inside the container")

    def test_secrets_are_not_sent_as_build_context(self):
        ignored = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        for secret in (".env", "credentials.enc*", ".credential_key", ".session_key"):
            assert secret in ignored, f"{secret} is sent to the Docker daemon on every build"

    def test_history_survives_a_rebuild(self):
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        for d in ("runs", "snapshots", "health-baselines", "reports"):
            assert f":/app/{d}" in compose, f"{d}/ is discarded on every rebuild"
