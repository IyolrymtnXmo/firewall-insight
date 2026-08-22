"""
v4.13 UI: sidebar footer, rail alignment, and two things that were built but
never reachable.

The rail was reported as "still broken after collapse". It was: `.menu button`
sets `justify-content:flex-start` for the expanded layout, and the rail rules
never overrode it, so every icon hugged the left edge of a 74px column.

Two dead ends were also found while fixing it:
  - "Export Raw CSV" on the Access Policy page printed "will be added after
    package/inline validation" and exported nothing, because the CSV endpoint
    was still layer-first after the UI became package-first in v4.2
  - zero-hit and disabled rules have been computed since v4.0, complete with
    layer and display rule, and were rendered nowhere at all
"""

from conftest import app_source

SRC = app_source()


class TestSidebarFooter:
    def test_theme_toggle_is_a_sun_moon_icon(self):
        assert 'id="themeToggle"' in SRC
        assert "ico-sun" in SRC and "ico-moon" in SRC
        assert "Light Mode</span>" not in SRC, "the old label/switch is gone"

    def test_the_icon_shows_the_theme_you_will_switch_to(self):
        # Specificity matters here: `.icon-btn .ico` is (0,2,0) and silently
        # beat a bare `.ico-moon{display:none}` at (0,1,0), so both the sun
        # and the moon rendered at once. The pair must match that weight.
        assert ".icon-btn .ico-sun{display:block}" in SRC
        assert ".icon-btn .ico-moon{display:none}" in SRC
        assert ".light .icon-btn .ico-sun{display:none}" in SRC
        assert ".light .icon-btn .ico-moon{display:block}" in SRC

    def test_stacked_buttons_do_not_collapse(self):
        """`flex:1 1 0` sizes the main axis, so switching the row to a column
        made flex-basis apply to height and the buttons shrank to 19px."""
        assert "body.rail .icon-btn{flex:0 0 auto;width:44px;height:38px}" in SRC

    def test_the_icons_are_svg_not_font_glyphs(self):
        """Glyphs like ☀/☾ depend on the font stack and rendered wrong in the
        fallback face; SVG is crisp and inherits currentColor."""
        assert '<svg class="ico ico-sun"' in SRC
        assert '<svg class="ico ico-moon"' in SRC
        assert "stroke:currentColor" in SRC

    def test_collapse_is_a_quiet_icon_button(self):
        assert '<button class="icon-btn" id="railToggle"' in SRC
        assert ".icon-btn{" in SRC
        assert "background:transparent;border:1px solid transparent" in SRC

    def test_both_actions_have_keyboard_shortcuts(self):
        assert "ev.key.toLowerCase() === 'b'" in SRC   # collapse
        assert "ev.key.toLowerCase() === 'j'" in SRC   # theme

    def test_toggling_the_rail_updates_the_button_meaning(self):
        assert "'Expand sidebar (Ctrl+B)' : 'Collapse sidebar (Ctrl+B)'" in SRC


class TestRailAlignment:
    def test_rail_overrides_the_expanded_justification(self):
        """Verified in Chromium: all six icons centre at offset 0.0px."""
        assert "justify-content:center;align-items:center;" in SRC

    def test_rail_stacks_the_footer_actions(self):
        assert "body.rail .side-actions{flex-direction:column" in SRC

    def test_rail_icons_come_from_data_icon(self):
        assert "content:attr(data-icon)" in SRC
        assert 'data-icon="⇄"' in SRC


class TestCsvExportIsNoLongerAStub:
    def test_the_stub_message_is_gone(self):
        assert "will be added after package/inline validation" not in SRC

    def test_the_button_calls_a_package_first_endpoint(self):
        assert "/api/package-policy-browser.csv?package=" in SRC
        assert '@router.get("/api/package-policy-browser.csv")' in SRC

    def test_the_export_keeps_inline_context(self):
        assert '"Display Rule"' in SRC
        assert '"Layer Path"' in SRC

    def test_the_filename_is_sanitised(self):
        """A package name reaches Content-Disposition, so strip anything odd."""
        assert 'ch if ch.isalnum() or ch in "-_" else "_"' in SRC


class TestUnusedRulesAreVisible:
    def test_there_is_a_tab_for_them(self):
        assert "renderAccess('unused')" in SRC
        assert "Unused Rules (${deadRules(d).length})" in SRC

    def test_zero_hit_and_disabled_are_merged(self):
        assert "function deadRules(d)" in SRC
        assert "zero_hit_rules" in SRC
        assert "reason:'Disabled'" in SRC
        assert "reason:'Zero hits'" in SRC

    def test_a_rule_is_not_listed_twice(self):
        """A disabled rule also has zero hits; it must appear once."""
        assert "const seen=new Set(),out=[];" in SRC
        assert "if(seen.has(key))continue;" in SRC

    def test_the_dashboard_links_to_it(self):
        assert "drillTo('access','unused')" in SRC

    def test_zero_hits_is_not_presented_as_proof(self):
        """Hit counters reset on policy install and on gateway restart, so
        'unused' is a review candidate, never a delete instruction."""
        assert "candidate for review, not proof that it is safe to delete" in SRC
        assert "reset on policy install" in SRC