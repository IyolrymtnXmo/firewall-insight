"""
v4.31 - the chrome must not state things the application does not know.

Three claims live in the frame around every page: the connection badge, the
Read chip, and the browser tab itself. Each was wrong in a different way, and
all three were found by looking at screenshots of the running application
rather than by reading code.

  * The badge said "Not tested" directly beside the Settings panel's own
    "Connected to https://..." - `setConn()` was reachable only from the
    header's test button.
  * The Read chip said "No call yet" after a page's worth of traces, because
    `lastReadLabel` was set at three call sites and Traffic Path, the network
    map, compliance, health and diff were not among them.
  * There was no icon of any kind, so every page load ended in
    `GET /favicon.ico 404` - the only red line in the console.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app

ROOT = Path(__file__).resolve().parent.parent
INDEX = (ROOT / "app" / "templates" / "index.html").read_text(encoding="utf-8")
APPJS = (ROOT / "app" / "static" / "js" / "app.js").read_text(encoding="utf-8")

# Splitting source on newline-anchored markers; named so the literals do not
# have to survive every layer of quoting between here and the file.
NL = chr(10)
BLANK2 = NL + NL


class TestTheTabHasAnIcon:
    def test_an_icon_is_declared(self):
        assert 'rel="icon"' in INDEX, "no favicon is declared, so the browser asks for /favicon.ico"

    def test_it_is_inline_and_needs_no_extra_request(self):
        """A file would have to be served, cached and version-stamped.

        The icon is the application's own shield, inlined as a data URI, so it
        costs no request and cannot 404.
        """
        link = INDEX.split('rel="icon"', 1)[1].split(">", 1)[0]
        href = link.split('href="', 1)[1].split('"', 1)[0]
        assert href.startswith("data:image/svg+xml,"), href[:60]
        # `xmlns='http://www.w3.org/2000/svg'` inside the markup is a namespace
        # identifier, not a resource - nothing dereferences it. What matters is
        # that the href itself is a data URI, so there is no request to make.

    def test_it_is_the_shield_the_application_already_draws(self):
        """Same path data as the #ic-shield symbol in the sprite."""
        shield = INDEX.split('<g id="ic-shield">', 1)[1].split("</g>", 1)[0]
        first_path = shield.split('d="', 1)[1].split('"', 1)[0]
        link = INDEX.split('rel="icon"', 1)[1].split(">", 1)[0]
        assert first_path in link, "the tab icon is not the application's shield"

    def test_the_served_page_keeps_it(self):
        """`index()` rewrites asset URLs; a data URI must survive untouched."""
        with TestClient(app) as client:
            html = client.get("/").text
        assert 'rel="icon"' in html
        assert "data:image/svg+xml" in html


class TestTheReadChipTracksActualReads:
    def test_the_stamp_is_set_where_every_read_passes(self):
        """In api(), not at call sites - call sites are what drifted.

        Setting it in three handlers meant every reader added later started out
        silently not counting.
        """
        body = APPJS.split("async function api(u)", 1)[1].split("\n}", 1)[0]
        assert "lastReadLabel" in body, "api() does not record the read"

    def test_a_failed_read_is_not_recorded_as_a_read(self):
        """The stamp sits after the not-ok throw, so a 502 does not count."""
        body = APPJS.split("async function api(u)", 1)[1].split("\n}", 1)[0]
        assert body.index("if(!r.ok)") < body.index("lastReadLabel"), (
            "a failed request would stamp the chip")

    def test_progress_polling_is_not_counted(self):
        """A 50-second analysis must not restamp the chip twice a second.

        trackProgress() deliberately uses fetch directly rather than api().
        """
        body = APPJS.split("function trackProgress(rid)", 1)[1].split("\n}", 1)[0]
        assert "fetch(" in body
        assert "api(" not in body, "progress polling now goes through api()"


class TestTheConnectionBadgeIsOwnedByWhatProvesIt:
    def test_the_settings_test_updates_the_badge(self):
        body = APPJS.split("async function testCred(type)", 1)[1]
        body = body.split("\nasync function", 1)[0]
        assert "setConn(" in body, (
            "a successful test in Settings leaves the header saying Not tested")

    def test_saving_credentials_retires_the_previous_claim(self):
        """New settings rebuild the client and drop the session.

        Whatever the badge said about the previous Management Server is no
        longer something the application knows.
        """
        body = APPJS.split("async function saveCred(type)", 1)[1]
        body = body.split("\nasync function", 1)[0]
        assert "setConn('','Not tested')" in body, (
            "saving new credentials leaves a stale Connected badge")

    @pytest.mark.parametrize("guard", ["type === 'checkpoint'"])
    def test_gaia_does_not_speak_for_the_management_connection(self, guard):
        """Different API, different credentials, different question."""
        body = APPJS.split("async function testCred(type)", 1)[1]
        body = body.split("\nasync function", 1)[0]
        before = body.split("setConn(", 1)[0]
        assert guard in before, (
            "the Gaia branch can reach setConn(), so a gateway result would "
            "rewrite the Management API badge")


class TestTheBadgeReportsARealVersion:
    """`Connected · API ?` - the version came from a key that is never sent.

    A Check Point login returns `api-server-version` (older builds:
    `web-api-version`), which `api/meta.py` has always read. The credential
    test endpoint read `api-version` instead, so it always produced an empty
    string.

    Nothing revealed it until v4.31 put the value in the header badge, at which
    point every successful test from Settings rendered "Connected · API ?".
    Checked against the lab afterwards: the endpoint returns "2.0.1".
    """

    def test_the_endpoint_reads_the_keys_check_point_sends(self):
        src = (ROOT / "app" / "api" / "credentials.py").read_text(encoding="utf-8")
        block = src.split("api_version = ", 1)[1].split(BLANK2, 1)[0]
        assert "api-server-version" in block, (
            "the endpoint does not read the key a Check Point login returns")

    def test_it_reads_the_same_keys_as_the_other_connection_test(self):
        """Two endpoints answering the same question must not disagree."""
        creds = (ROOT / "app" / "api" / "credentials.py").read_text(encoding="utf-8")
        meta = (ROOT / "app" / "api" / "meta.py").read_text(encoding="utf-8")
        for key in ("api-server-version", "web-api-version"):
            assert key in meta, f"meta.py no longer reads {key}"
            assert key in creds, f"credentials.py does not read {key}"


class TestConnectingLeavesTheApplicationUsable:
    """A proven connection must not be followed by an empty selector.

    `loadMetadata()` fills the package and layer lists and was reachable from
    exactly one unlabelled icon button in the header. Connecting and then
    pressing Analyze produced "pick a package in the selector at the top" -
    pointing at a selector with nothing in it.
    """

    def test_both_connection_tests_load_the_metadata(self):
        for fn in ("async function testConn(ev)", "async function testCred(type)"):
            body = APPJS.split(fn, 1)[1].split(NL + "async function", 1)[0]
            assert "loadMetadata()" in body, (
                f"{fn.split()[-1]} proves the connection and leaves the selectors empty")

    def test_metadata_is_still_not_loaded_on_page_load(self):
        """The promise in the status line is about page load, and it holds.

        Every loadMetadata() caller is a button somebody pressed, so "no API
        calls are made automatically" is still true.
        """
        init = APPJS.split("window.addEventListener('DOMContentLoaded'", 1)[1]
        init = init.split(NL + "});", 1)[0]
        assert "loadMetadata" not in init, (
            "metadata is loaded on page load, which the status line denies")
        assert "No API calls are made automatically" in init

    def test_the_guard_can_tell_the_two_problems_apart(self):
        """"Not picked yet" and "there are none" need different answers."""
        body = APPJS.split("async function dashboardRefresh()", 1)[1]
        body = body.split(NL + "}", 1)[0]
        assert "ensurePackages()" in body
        assert "No packages to select" in body, (
            "an empty list is still reported as an unmade selection")
