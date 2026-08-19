"""
v4.11 UX layer.

The problem: every long call ran with no feedback except one line of text, so
"working", "finished" and "crashed" were indistinguishable and diagnosing a
failure meant opening DevTools -> Network. A firewall analysis tool whose
errors are invisible is worse than one that is merely slow.

These are structural assertions on the served page. Behaviour (blur applied,
overlay dismissed, failure reaching the UI, no horizontal overflow at 390px,
double-submit blocked) was verified in a headless Chromium run; these tests
stop the wiring from silently disappearing in a later edit.
"""

from pathlib import Path

SRC = Path("app/main.py").read_text(encoding="utf-8")


class TestChrome:
    def test_all_feedback_regions_exist(self):
        for el in ['id="topProgress"', 'id="busyOverlay"', 'id="toasts"',
                   'id="statusBar"', 'id="statusIcon"', 'id="statusTime"',
                   'id="offlineBar"', 'id="navToggle"', 'id="srLive"']:
            assert el in SRC, el

    def test_status_stays_a_plain_text_node(self):
        """Every legacy `S.textContent = ...` must keep working, so #status
        holds only text and the icon/timestamp are siblings."""
        assert '<span class="status-icon" id="statusIcon">' in SRC
        assert '<div id="status" class="status">' in SRC

    def test_nested_status_box_is_neutralised(self):
        assert ".statusbar .status{" in SRC
        assert "background:none;border:0" in SRC

    def test_screen_reader_live_region_is_polite(self):
        assert 'id="srLive" class="sr-only" role="status" aria-live="polite"' in SRC

    def test_error_toasts_announce_as_alerts(self):
        assert "kind === 'error' ? 'alert' : 'status'" in SRC


class TestBlurOverlay:
    def test_overlay_uses_backdrop_blur_and_transparency(self):
        assert "backdrop-filter:blur(9px)" in SRC
        assert "-webkit-backdrop-filter:blur(9px)" in SRC
        assert "--glass:rgba(14,13,19,.62)" in SRC

    def test_light_theme_has_its_own_glass(self):
        assert ".light{\n  --glass:rgba(255,255,255,.62);" in SRC

    def test_overlay_reports_elapsed_time(self):
        assert "busyElapsed" in SRC
        assert "(ms / 1000).toFixed(1) + 's'" in SRC

    def test_slow_operations_explain_themselves(self):
        assert "UX_LONG_MS = 6000" in SRC
        assert "10–20s is normal" in SRC

    def test_step_progress_exists(self):
        assert "function busyStep(" in SRC
        assert ".busy-step.done .dot{background:var(--good)}" in SRC

    def test_overlay_is_reference_counted(self):
        """Nested tasks must not let an inner busyHide() clear the outer one."""
        assert "uxBusyDepth++" in SRC
        assert "if(uxBusyDepth > 0) return;" in SRC


class TestRequestTracking:
    def test_every_request_drives_the_progress_bar(self):
        assert "uxRequestStart();" in SRC
        assert "uxRequestEnd();" in SRC
        assert "uxInFlight" in SRC

    def test_requests_have_a_timeout(self):
        assert "UX_TIMEOUT_MS" in SRC
        assert "new AbortController()" in SRC
        assert "ctl.abort()" in SRC

    def test_http_status_is_kept_in_the_error(self):
        assert "'HTTP '+r.status+': '+(d.detail||JSON.stringify(d))" in SRC

    def test_busy_state_is_exposed_to_assistive_tech(self):
        assert "setAttribute('aria-busy', 'true')" in SRC


class TestErrorSurfacing:
    def test_no_bare_message_dump_remains(self):
        """`catch(e){S.textContent=e.message}` showed a raw string with no
        explanation and no way to report it."""
        assert "S.textContent=e.message" not in SRC

    def test_errors_are_translated_into_causes(self):
        for phrase in ["Cannot reach Firewall Insight",
                       "Management API rate limit",
                       "Management Server unreachable",
                       "Authentication failed",
                       "Request timed out"]:
            assert phrase in SRC, phrase

    def test_error_details_are_copyable(self):
        assert "actionLabel: 'Copy details'" in SRC
        assert "navigator.clipboard.writeText" in SRC

    def test_uncaught_failures_still_reach_the_user(self):
        assert "window.addEventListener('error'" in SRC
        assert "window.addEventListener('unhandledrejection'" in SRC

    def test_offline_is_detected(self):
        assert "window.addEventListener('offline'" in SRC
        assert "window.addEventListener('online'" in SRC

    def test_panels_can_render_an_inline_error_with_retry(self):
        assert "function errorState(" in SRC
        assert "errorState(e,'onclick=\"loadPolicyBrowser()\"')" in SRC
        assert "errorState(e,'onclick=\"trace()\"')" in SRC


class TestTaskWrapper:
    def test_task_blocks_concurrent_duplicates(self):
        assert "const uxRunning = new Set();" in SRC
        assert "if(uxRunning.has(key))" in SRC

    def test_task_restores_the_button_even_on_failure(self):
        assert "delete btn.dataset.busy" in SRC
        assert "}finally{" in SRC

    def test_busy_buttons_cannot_be_clicked_twice(self):
        assert 'button[data-busy="1"]{' in SRC
        assert "pointer-events:none" in SRC

    def test_long_operations_are_wired_through_task(self):
        for key in ["task('dashboard'", "task('conn'", "task('meta'", "task('map'"]:
            assert key in SRC, key


class TestLoadingStates:
    def test_skeletons_replace_blank_space(self):
        assert "function skeletonTable(" in SRC
        assert "browserResults.innerHTML=skeletonTable(" in SRC
        assert "@keyframes shimmer" in SRC

    def test_empty_states_tell_the_user_what_to_do(self):
        assert "function emptyState(" in SRC
        assert "function primeEmptyStates(" in SRC
        assert "No policy loaded yet" in SRC

    def test_traffic_empty_state_explains_the_simulation(self):
        assert "it never sends a packet" in SRC


class TestHonestReporting:
    """The UX must not present a partial result as a complete one."""

    def test_backend_reports_data_quality(self):
        assert "def data_quality(c, tree)" in SRC
        assert '"object_hydration_truncated": truncated' in SRC
        assert 'result["data_quality"] = data_quality(c, tree)' in SRC

    def test_frontend_renders_the_warning(self):
        assert "function dataQualityBanner(" in SRC
        assert "This result is incomplete" in SRC
        assert "renderDataQuality('accessDq'" in SRC
        assert "renderDataQuality('browserDq'" in SRC

    def test_incomplete_results_also_raise_a_toast(self):
        assert "function reportDataQuality(" in SRC
        assert "incomplete result" in SRC

    def test_unverified_trace_is_explained_not_hidden(self):
        assert "UNVERIFIED \\u2014 deliberately not guessing" in SRC
        assert "confidently wrong" in SRC

    def test_inferred_confidence_warns_rather_than_celebrates(self):
        assert "Matched, but inferred" in SRC
        assert "notify('warn'" in SRC

    def test_nat_hit_support_is_reported(self):
        assert "NAT hit counts unavailable" in SRC


class TestResponsive:
    def test_mobile_nav_drawer_exists(self):
        assert "function toggleNav(" in SRC
        assert "body.nav-open .sidebar{transform:translateX(0)}" in SRC

    def test_grid_shrink_trap_is_fixed(self):
        """`1fr` is minmax(auto,1fr) and will not shrink below content
        min-width, so one 650px table forced the whole page to scroll."""
        assert ".dashboard-grid{grid-template-columns:minmax(0,1fr)!important}" in SRC
        assert ".cards>*,.dashboard-grid>*" in SRC
        assert ".table-wrap{min-width:0;max-width:100%}" in SRC

    def test_wide_tables_scroll_inside_their_container(self):
        assert ".table-wrap{" in SRC
        assert "-webkit-overflow-scrolling:touch" in SRC

    def test_table_headers_stick_while_scrolling(self):
        assert ".table-wrap thead th{" in SRC
        assert "position:sticky" in SRC


class TestMotion:
    def test_reduced_motion_is_respected(self):
        assert "@media(prefers-reduced-motion:reduce)" in SRC
        assert "animation-duration:.001ms!important" in SRC

    def test_page_changes_are_animated(self):
        assert "@keyframes pageIn" in SRC
        assert ".page.active{display:block;animation:pageIn" in SRC

    def test_focus_is_visible_for_keyboard_users(self):
        assert ":focus-visible{outline:2px solid var(--purple2)" in SRC

    def test_escape_dismisses_transient_ui(self):
        assert "ev.key === 'Escape'" in SRC


class TestConnectionBadge:
    def test_badge_has_states(self):
        assert "function setConn(" in SRC
        assert ".badge.conn.ok .dot{background:var(--good)" in SRC
        assert ".badge.conn.bad .dot{background:var(--bad)" in SRC
        assert ".badge.conn.testing .dot{background:var(--warn)" in SRC

    def test_failed_connection_updates_the_badge(self):
        assert "setConn('bad','Connection failed')" in SRC


def test_read_only_promise_is_stated_on_load():
    assert "Read-only tool" in SRC
    assert "never publishes or installs policy" in SRC


def test_version_is_bumped():
    assert 'APP_VERSION = "4.11.0"' in SRC
