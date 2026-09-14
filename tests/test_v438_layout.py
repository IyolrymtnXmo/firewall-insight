"""
v4.38 - a panel draws inside its own box, and a row is one row.

Everything here was measured in a browser against the lab before it was
changed, so the numbers in the docstrings are readings and not estimates. The
viewport was 1600x900.

    hero row 462 tall     dash-trend 265, dash-hits 299
                          -> 197px and 163px of nothing under two of three
                             cards in the same row
    band-b   617 tall     right column held one 234px card
                          -> 383px of empty column with a border down it
    trend svg 406px wide  viewBox 320 wide, xMidYMid meet
                          -> the chart drew 320 and left 43px down each side
    topo svg  299px tall  viewBox 220 tall, content laid out to y=246
                          -> 246 * 1.359 = 334px in a 299px panel with
                             overflow:hidden, so the bottom row was cut in half
                             and its labels were not on the page at all
    topo links            5 of 13 passed inside the ring of a node they do
                             not connect, because every link was a bezier
                             between two centres
    prose                 195-197 characters per line
    a heading and its
      own explanation     977px apart, at opposite ends of one card
    diff counters         8 tiles on a 5-column grid -> 2 empty cells

These are structural assertions against the source, the way the rest of this
suite tests the UI. The browser measurements that confirmed the fix are in the
commit message; what these tests defend is the decision, so that a later edit
cannot quietly put a fixed viewBox or a second empty column back.
"""

from __future__ import annotations

import re

from tests.conftest import ui_source

CSS_JS = ui_source()


def _rule(selector: str) -> str:
    """The declaration block for *selector*, or "" if it is not there."""
    m = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", CSS_JS)
    return m.group(1) if m else ""


class TestAPanelDrawsInsideItsOwnBox:
    """A viewBox that does not match its element letterboxes or clips."""

    def test_the_topology_preview_measures_its_panel(self):
        body = CSS_JS.split("function renderTopoPreview()", 1)[1].split("\n}\n", 1)[0]
        assert "getBoundingClientRect()" in body, (
            "the preview no longer measures its panel, so it is back to "
            "guessing at a size and letterboxing inside it")
        assert "setAttribute('viewBox'" in body
        markup = CSS_JS.split('id="topoPreview"', 1)[1].split(">", 1)[0]
        assert "viewBox" not in markup, (
            "the markup pins a viewBox again. The renderer sets one from the "
            "panel, so a second one written here is a size that disagrees "
            "with itself - 900x220 against a 1301x299 panel is what pushed "
            "the bottom row off the page.")

    def test_the_layout_leaves_room_for_what_it_draws(self):
        """The clipping was a layout that did not account for the label."""
        body = CSS_JS.split("function renderTopoPreview()", 1)[1].split("\n}\n", 1)[0]
        assert "LABEL_DROP" in body and "PAD_B" in body, (
            "the bottom margin no longer accounts for the label under a node, "
            "which is exactly what fell off the bottom of the panel")
        assert "HALO" in body, "the top margin no longer accounts for the hover halo"

    def test_the_trend_chart_is_drawn_at_the_size_of_its_panel(self):
        body = CSS_JS.split("function renderHitTrend(", 1)[1].split("\n}\n", 1)[0]
        assert "box.clientWidth" in body, (
            "the trend chart is back to a fixed width, so it is letterboxed "
            "inside a panel wider than itself")
        assert "const W=320,H=158" not in CSS_JS

    def test_both_are_redrawn_when_the_window_changes(self):
        """A measured drawing is wrong the moment the thing it measured moves."""
        assert "renderTopoPreview(); }catch(_){}" in CSS_JS
        assert re.search(r"addEventListener\('resize'", CSS_JS)


class TestLinksDoNotRunThroughNodes:
    def test_a_link_leaves_the_ring_and_not_the_centre(self):
        body = CSS_JS.split("function renderTopoPreview()", 1)[1].split("\n}\n", 1)[0]
        assert "const route = (a, b) =>" in body, (
            "the corridor routing is gone; a bezier between two centres runs "
            "across whatever stands between them")
        # Every endpoint is offset by the ring radius, so no line is drawn
        # underneath a glyph.
        assert "a.y + dir*R" in body and "t.y + R" in body and "u.y - R" in body

    def test_the_middle_of_a_link_is_pinned_to_the_corridor(self):
        body = CSS_JS.split("function renderTopoPreview()", 1)[1].split("\n}\n", 1)[0]
        assert "midY" in body, (
            "links no longer travel through the empty band between the two "
            "rows, which is the only reason they cannot cross a node")

    def test_one_line_is_drawn_per_pair(self):
        """A cluster and its members declare the same pair several times."""
        body = CSS_JS.split("function renderTopoPreview()", 1)[1].split("\n}\n", 1)[0]
        assert "const seen = new Map()" in body
        assert "'route'" in body, "a read route no longer beats a declared link"


class TestARowIsOneRow:
    def test_the_hero_cards_share_the_row_height(self):
        assert "align-items:stretch" in _rule(".band-d.hero"), (
            "the three cards in the hero row take their own heights again, "
            "which is what left 197px under the shortest of them")
        assert "flex:1 1 auto" in _rule(".band-d.hero > .card > .fold-body")

    def test_folding_a_hero_card_still_folds_it(self):
        """The stretch above would otherwise hold the space open."""
        assert "flex:0 0 0" in _rule(".band-d.hero > .card.is-folded > .fold-body")

    def test_the_second_dashboard_column_is_gone(self):
        assert "minmax(0,1fr) 340px" not in CSS_JS, (
            "band-b has a second column again; it held one short card and "
            "383px of empty page")
        assert "minmax(0,1fr)" in _rule(".band-b")


class TestProseHasAMeasure:
    def test_an_explanatory_paragraph_is_capped(self):
        """195 characters a line is not a matter of taste."""
        assert "max-width:none" in _rule(".page-head p")
        assert "max-width:none" in _rule(
            ".panel > p.muted,\n.card  > p.muted,\n.panel > p:not([class]),\n"
            ".card  > p:not([class])")

    def test_a_caption_sits_under_the_heading_it_explains(self):
        assert "hint-sub" in CSS_JS
        block = _rule(".section-title .hint-sub")
        assert "display:block" in block, (
            "the caption is an inline item in a flex row again, which is how "
            "it ended up 977px from the heading it explains")
        assert "text-align:left" in block

    def test_a_short_label_still_sits_on_the_right(self):
        """Compliance passes an id and a severity, which is not a sentence.

        The split is the point: `.hint` stays where it was, `.hint-sub` moves.
        """
        assert '<span class="hint">${esc(r.id)} · severity' in CSS_JS

    def test_a_wrapping_table_cell_is_given_leading(self):
        # Asserted on the declaration rather than through _rule(), which
        # matches the `td` inside the earlier `th,td{...}` rule.
        assert "td{line-height:1.55}" in CSS_JS.replace(" ", "")


class TestACounterGridDivides:
    def test_eight_counters_are_not_laid_on_five_columns(self):
        assert "repeat(4,minmax(0,1fr))" in _rule(
            ".cards:has(> :nth-child(8):last-child)"), (
            "eight counters on a five-column grid leaves two empty cells")

    def test_the_default_is_unchanged_for_everything_else(self):
        """`:has()` is an enhancement, so the base rule must still be there."""
        assert "repeat(5,minmax(0,1fr))" in _rule(".cards")


class TestAnEmptyResultStillReportsItself:
    def test_a_section_that_found_nothing_is_quieter_not_absent(self):
        """"No rules were added" is a result and stays on the page."""
        body = CSS_JS.split("function diffSection(", 1)[1].split("\n}\n", 1)[0]
        assert "card-quiet" in body
        assert "rows.length === 0" in body
        assert _rule(".card-quiet"), "the quiet style is gone, so the class does nothing"

    def test_it_keeps_its_count_its_heading_and_its_answer(self):
        body = CSS_JS.split("function diffSection(", 1)[1].split("\n}\n", 1)[0]
        assert "${esc(rows.length)}" in body, "the count is no longer printed"
        assert "hint-sub" in body, "the caption is no longer printed"
        assert "diffRows(rows,cols)" in body, "the answer is no longer printed"
