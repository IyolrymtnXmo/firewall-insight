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

        # v4.33: the promise moved into reportAutomationState(), because with a
        # schedule enabled it is no longer unconditionally true. It also names
        # the Management API now - the function reads /api/schedules from this
        # application's own backend, which is a local file read, and the promise
        # was always about the Management Server.
        assert "reportAutomationState()" in init
        promise = APPJS.split("async function reportAutomationState", 1)[1]
        promise = promise.split(NL + "}", 1)[0]
        assert "No Management API calls are made automatically" in promise
        assert "schedule(s) are enabled" in promise, (
            "the line does not say when the application does call out on its own")

    def test_the_guard_can_tell_the_two_problems_apart(self):
        """"Not picked yet" and "there are none" need different answers."""
        body = APPJS.split("async function dashboardRefresh()", 1)[1]
        body = body.split(NL + "}", 1)[0]
        assert "ensurePackages()" in body
        assert "No packages to select" in body, (
            "an empty list is still reported as an unmade selection")


class TestTheResultsCardCannotBeHidden:
    """Every page kept its result in a card that could be folded shut.

    `data-fold="pg-*"` wrapped the *results* card on seven pages - Configured
    Rulebase, Findings, NAT Results, Trace Result, Gateway Readings, Compliance
    Result, Snapshot Difference - and the whole card header was a click target,
    not just the 26px chevron. One stray click collapsed the only part of the
    page that shows an answer, and `toggleFold()` writes the state to
    localStorage, so it stayed collapsed on the next visit and every visit
    after that.

    That is indistinguishable from the feature being broken, and it was
    reported as exactly that: "Policy Diff, press Compare, nothing appears".

    Folding a region is worth keeping where a page has several of them - the
    Dashboard has seven and putting one away still leaves six. Folding the only
    region on a page leaves a heading and nothing else.
    """

    RESULT_PAGES = ["pg-browser", "pg-access", "pg-nat", "pg-traffic",
                    "pg-health", "pg-compliance", "pg-diff"]

    def test_no_results_card_is_foldable(self):
        for key in self.RESULT_PAGES:
            assert f'data-fold="{key}"' not in INDEX, (
                f"{key} can be folded shut, hiding the result the page exists to show")

    def test_no_page_level_fold_was_reintroduced_under_another_name(self):
        import re
        assert not re.search(r'data-fold="pg-', INDEX)

    def test_folding_is_kept_where_a_page_has_several_regions(self):
        """The Dashboard is the case the feature was built for."""
        import re
        keys = re.findall(r'data-fold="([^"]+)"', INDEX)
        assert keys, "folding was removed entirely; the Dashboard needs it"
        assert all(k.startswith("dash-") or k.startswith("settings-") for k in keys), keys
        assert len([k for k in keys if k.startswith("dash-")]) >= 5


class TestAResultIsBroughtIntoView:
    """Rendering a result off-screen reads as not rendering one.

    Measured on a 1280x720 window: the Policy Diff result sits at y=765 with a
    720px viewport, so Compare produced 5,837px of content entirely below the
    fold while the card heading - already the last thing on screen - did not
    change. Compliance and Gateway Health have the same shape.
    """

    def test_the_three_deep_pages_reveal_their_result(self):
        for target in ("revealResult(diffResult)",
                       "revealResult(complianceResult)",
                       "revealResult(healthResult)"):
            assert target in APPJS, f"missing: {target}"

    def test_the_helper_scrolls_the_least_it_can(self):
        """`nearest` does nothing when the result is already visible."""
        body = APPJS.split("function revealResult(el)", 1)[1].split(NL + "}", 1)[0]
        assert "block:'nearest'" in body, body

    def test_it_does_not_ask_for_smooth_scrolling(self):
        """Measured: smooth does not move `main.main` at all; instant does.

        body and html have been overflow:hidden since v4.30.3, so the scroll
        container is `main.main`. Instant is also what prefers-reduced-motion
        would ask for, so there is nothing to branch on.
        """
        body = APPJS.split("function revealResult(el)", 1)[1].split(NL + "}", 1)[0]
        assert "smooth" not in body, "smooth scrolling silently does nothing in main.main"

    def test_the_reveal_happens_after_the_result_is_written(self):
        for result_id in ("diffResult", "complianceResult", "healthResult"):
            assert APPJS.index(f"{result_id}.innerHTML") < APPJS.index(f"revealResult({result_id})"), (
                f"{result_id} is revealed before it is filled")


class TestChangingPageStartsAtTheTop:
    """The scroll offset of the page you left was applied to the one you opened.

    The scroll lives on `main.main` - body and html have been overflow:hidden
    since v4.30.3 - and `showPage()` never reset it. Measured: leaving a
    scrolled Compliance run for Policy Diff put the Compare button at y=-95,
    above the viewport, so pressing it looked like being thrown somewhere else.
    The same clamping is what made a collapsing card appear to jump pages: the
    content shrank and the browser moved the scroll to fit.
    """

    def test_showpage_resets_the_scroll_container(self):
        body = APPJS.split("function showPage(id,b)", 1)[1].split(NL + "}", 1)[0]
        assert "scrollTop = 0" in body or "scrollTop=0" in body, (
            "showPage does not reset the scroll, so a new page opens mid-way down")

    def test_it_resets_the_element_that_actually_scrolls(self):
        """body and html are overflow:hidden; resetting them would do nothing."""
        body = APPJS.split("function showPage(id,b)", 1)[1].split(NL + "}", 1)[0]
        assert "main.main" in body, body[:400]


class TestAComplianceRunIsReadable:
    """Every offender of every failing check, expanded, plus the full clause.

    On a 13-rule lab one check alone printed 13 rows of a seven-column table,
    and each check repeated the whole standard quotation underneath. Measured
    against the NIST profile: the result is 32% shorter now, with nothing
    removed - the rows past the first five and the quotation sit behind a
    native <details> whose summary states the count.

    <details> rather than the `data-fold` mechanism on purpose: it is keyboard
    accessible and it forgets, so a run cannot open already collapsed the way
    the results cards did before v4.31.2.
    """

    def test_offenders_are_previewed_not_dumped(self):
        assert "COMPLIANCE_PREVIEW_ROWS" in APPJS
        assert "function complianceOffenders" in APPJS
        assert "complianceOffenders(r)" in APPJS, "the check card does not use the helper"

    def test_the_disclosure_states_how_many_rows_it_holds(self):
        body = APPJS.split("function complianceOffenders", 1)[1].split(NL + "}", 1)[0]
        assert "Show the remaining" in body and "of ${esc(list.length)}" in body, body

    def test_the_citation_folds_the_quote_and_keeps_the_clause(self):
        body = APPJS.split("function complianceSource_cite", 1)[1].split(NL + "}", 1)[0]
        assert "<summary>${head}</summary>" in body, "the standard is not the summary line"
        assert "s.quote" in body, "the quotation was removed rather than folded"

    def test_the_disclosures_are_styled_and_focusable(self):
        css = (ROOT / "app" / "static" / "css" / "app.css").read_text(encoding="utf-8")
        assert "details.cite > summary" in css
        assert "details.more-rows > summary" in css
        assert "focus-visible" in css.split("details.cite > summary", 1)[1][:1200], (
            "the disclosures cannot be reached from the keyboard visibly")
