"""
v4.15 regression: the AlgoSec-style graph view of Network Mapping.

v4.14 laid the map out as two columns. That reads well for "which port on this
gateway reaches which subnet", but it is not what a topology map is normally
for: you want the *shape* of the estate - which gateways sit between which
segments - and a column layout hides that behind a bundle of parallel edges.

v4.15 adds a physics layout (Fruchterman-Reingold) where gateways become hubs
and subnets orbit them, plus the controls that make a big one usable: drag to
place a node, save the arrangement, merge equivalent subnets, collapse the
leaves, search and step through matches, and export. The column view stays as
the "Cards" layout because it still answers its own question better.

What these tests pin is the contract, not the pixels:

  - the layout is DETERMINISTIC (no Math.random anywhere in the engine), or a
    saved arrangement would be meaningless and two runs would never match
  - a saved arrangement is keyed to the exact node set it was drawn for
  - Auto Merge is a presentation grouping that drops nothing and says so
  - collapse hides only the subnets behind exactly one device
  - the honesty guarantees from v4.14 survive: nothing is inferred

Behaviour that only a browser can show - that the simulation separates nodes,
that a drag pins one, that the PNG export produces real pixels - is verified in
headless Chromium; the numbers from that run are in CHANGELOG.md.
"""

from pathlib import Path

from conftest import app_source, ui_source

APP = Path(__file__).resolve().parent.parent / "app"


def _script() -> str:
    return (APP / "static" / "js" / "app.js").read_text(encoding="utf-8")


def _stylesheet() -> str:
    return "\n".join(p.read_text(encoding="utf-8")
                     for p in sorted((APP / "static" / "css").glob("*.css")))


# --------------------------------------------------------------------------
class TestTwoLayouts:
    def test_both_layouts_exist_and_are_dispatched(self):
        src = _script()
        assert "function renderTopoGraph(" in src
        assert "function renderTopoCards(" in src
        assert "if(TOPO.mode === 'graph') renderTopoGraph(d); else renderTopoCards(d);" in src

    def test_graph_is_the_default(self):
        assert "mode: 'graph'," in _script()

    def test_the_choice_is_remembered(self):
        src = _script()
        assert "localStorage.setItem('fw-topo-mode'" in src
        assert "localStorage.getItem('fw-topo-mode')" in src

    def test_the_switch_is_in_the_toolbar(self):
        src = ui_source()
        assert 'data-topo-mode="graph"' in src
        assert 'data-topo-mode="cards"' in src

    def test_cards_mode_is_still_reachable_and_documented(self):
        """It answers a question the graph deliberately hides."""
        assert "deliberately hides to stay legible" in _script()


# --------------------------------------------------------------------------
class TestLayoutEngine:
    SRC = None

    @classmethod
    def setup_class(cls):
        cls.SRC = _script()

    def test_the_layout_is_a_named_algorithm_not_a_guess(self):
        assert "Fruchterman-Reingold" in self.SRC
        assert "function topoRelax(" in self.SRC

    def test_the_engine_never_calls_math_random(self):
        """Determinism is load-bearing: saved positions and screenshots both
        depend on the same input laying out the same way every time."""
        engine = self.SRC[self.SRC.index("function topoSeed("):self.SRC.index("function topoIterations(")]
        # a call always has parens; the comment above it says "No Math.random"
        assert "Math.random()" not in engine
        assert "golden angle" in engine

    def test_overlapping_nodes_get_an_extra_shove(self):
        """k^2/d alone lets labels sit on top of each other at close range."""
        assert "(d < gap ? (gap - d) * 8 : 0)" in self.SRC

    def test_unlinked_nodes_are_pulled_in_harder(self):
        """A node with no edges otherwise drifts out and stretches the map."""
        assert "const grav = nd.deg ? 0.9 : 1.7;" in self.SRC

    def test_iteration_count_is_bounded_by_graph_size(self):
        """The simulation is O(n^2) per iteration; a big estate must not hang."""
        assert "function topoIterations(" in self.SRC
        assert "n > 400 ? 120" in self.SRC

    def test_a_large_graph_skips_the_settling_animation(self):
        assert "g.nodes.length > 220" in self.SRC

    def test_reduced_motion_skips_the_settling_animation(self):
        assert "prefers-reduced-motion: reduce" in self.SRC

    def test_a_re_render_does_not_re_run_the_physics(self):
        """Toggling a filter must not throw away the user's arrangement."""
        assert "if(!fresh){" in self.SRC
        assert "function topoRemember(" in self.SRC

    def test_a_superseded_animation_stops_itself(self):
        assert "a re-render superseded us" in self.SRC


# --------------------------------------------------------------------------
class TestPlaceAndSave:
    SRC = None

    @classmethod
    def setup_class(cls):
        cls.SRC = _script()

    def test_dragging_a_node_pins_it(self):
        assert "DRAG.node.fixed = true;" in self.SRC
        assert "TOPO.pinned.set(DRAG.node.id" in self.SRC

    def test_drag_state_is_not_re_registered_on_every_render(self):
        """The SVG is rebuilt each render; a per-render window listener would
        accumulate one handler per render for the life of the session."""
        assert "never removed, so a long session would accumulate" in self.SRC
        assert self.SRC.count("window.addEventListener('mouseup'") == 1

    def test_save_and_reset_exist_and_are_in_the_toolbar(self):
        assert "function topoSaveMap(" in self.SRC
        assert "function topoResetMap(" in self.SRC
        assert "topoSaveMap()" in ui_source()
        assert "topoResetMap()" in ui_source()

    def test_a_saved_arrangement_is_keyed_to_its_node_set(self):
        """Reapplying one topology's coordinates to a different estate would
        put nodes on objects they were never drawn for."""
        assert "function topoKey(" in self.SRC
        assert "silently reapplied to different objects" in self.SRC

    def test_saving_says_where_the_data_went(self):
        assert "stored in this browser" in self.SRC

    def test_blocked_browser_storage_is_reported_not_swallowed(self):
        assert "Could not save the map" in self.SRC
        assert "Private-mode windows" in self.SRC


# --------------------------------------------------------------------------
class TestMergeAndCollapse:
    SRC = None

    @classmethod
    def setup_class(cls):
        cls.SRC = _script()

    def test_merge_groups_by_the_set_of_devices_that_reach_a_subnet(self):
        assert "const sig = [...c.users.keys()].sort().join('|')" in self.SRC

    def test_merge_never_drops_a_subnet(self):
        """It is a presentation grouping. The members stay addressable."""
        assert "no subnet is dropped and the count is shown" in self.SRC
        assert "members: group.flatMap(c => c.members)" in self.SRC

    def test_merge_reports_how_many_it_combined(self):
        assert "subnets merged" in self.SRC
        assert "No subnet was dropped" in self.SRC

    def test_merge_says_so_when_there_is_nothing_to_merge(self):
        """Silence would read as 'it did not work'."""
        assert "Nothing to merge" in self.SRC

    def test_collapse_only_hides_single_homed_subnets(self):
        """A subnet reached by two gateways is part of the path between them,
        so hiding it would change what the map appears to say."""
        assert "c.users.size === 1 ? [...c.users.keys()][0] : null" in self.SRC

    def test_a_collapsed_device_shows_how_many_it_is_hiding(self):
        assert "nd.leaves && nd.collapsed" in self.SRC

    def test_hidden_nodes_are_counted_in_the_status_line(self):
        assert "bits.push(`${g.hidden} hidden`)" in self.SRC


# --------------------------------------------------------------------------
class TestFindAndExport:
    SRC = None

    @classmethod
    def setup_class(cls):
        cls.SRC = _script()

    def test_search_steps_through_matches(self):
        assert "function topoStepHit(" in self.SRC
        assert "TOPO.hitIdx = (TOPO.hitIdx + dir + TOPO.hits.length) % TOPO.hits.length" in self.SRC

    def test_stepping_centres_the_match(self):
        assert "function topoCentre(" in self.SRC
        assert "TOPO.view.tx = TOPO.vb.w / 2 - TOPO.view.scale * x;" in self.SRC

    def test_the_match_position_is_shown(self):
        assert 'id="topoHits"' in ui_source()
        assert "${TOPO.hitIdx + 1} of ${TOPO.hits.length}" in self.SRC

    def test_stepping_with_no_query_explains_itself(self):
        assert "Nothing to step through" in self.SRC

    def test_the_legend_can_be_hidden(self):
        assert "function topoToggleLegend(" in self.SRC
        assert 'id="topoLegendBtn"' in ui_source()

    def test_export_offers_both_an_image_and_data(self):
        assert "function topoExportPng(" in self.SRC
        assert "function topoExportCsv(" in self.SRC
        assert "topoExportPng()" in ui_source()
        assert "topoExportCsv()" in ui_source()

    def test_the_exported_image_carries_its_own_styling(self):
        """A serialised SVG leaves the page stylesheet behind, so the export
        would otherwise be black shapes on a transparent field."""
        assert "function topoStyleBlock(" in self.SRC
        assert "custom properties they reference" in self.SRC

    def test_a_failed_rasterisation_is_reported(self):
        assert "Image export failed" in self.SRC

    def test_csv_quotes_are_escaped(self):
        assert '.replace(/"/g,\'""\')' in self.SRC


# --------------------------------------------------------------------------
class TestViewControls:
    def test_the_pan_zoom_pad_is_present(self):
        src = ui_source()
        assert 'class="topo-pad"' in src
        assert 'id="topoZoomRange"' in src
        for fn in ("topoPan(", "topoZoom(", "topoZoomTo(", "topoFit()"):
            assert fn in src, fn

    def test_every_pad_control_is_labelled(self):
        """The pad is icon-only, so without labels it is unusable by screen
        reader and unexplained on hover."""
        src = ui_source()
        pad = src[src.index('class="topo-pad"'):src.index('</section>', src.index('class="topo-pad"'))]
        for btn in pad.split("<button")[1:]:
            assert "aria-label=" in btn.split(">")[0], btn[:80]

    def test_fit_uses_the_real_content_bounds(self):
        src = _script()
        assert "world.getBBox()" in src

    def test_the_slider_follows_programmatic_zoom(self):
        assert "s.value = String(Math.round(TOPO.view.scale * 100))" in _script()


# --------------------------------------------------------------------------
class TestHonestyStillHolds:
    def test_the_banner_still_refuses_to_claim_discovery(self):
        src = ui_source()
        assert "Physical cabling, switches and live routing are not inferred" in src

    def test_the_module_header_says_what_the_data_is(self):
        src = _script()
        assert "Physical cabling, switching, routing protocols and" in src
        assert "logical map, not a survey" in src

    def test_a_merged_node_lists_its_members_on_hover(self):
        assert "nd.members.map(n => n.name).join('\\n')" in _script()

    def test_graph_classes_are_all_styled(self):
        css = _stylesheet()
        for cls in (".topo-g-node", ".topo-g-edge", ".topo-pad", ".topo-seg",
                    ".topo-stage", ".topo-find", ".pad-zoom", ".pad-dir"):
            assert cls in css, cls

    def test_graph_nodes_are_keyboard_reachable(self):
        assert 'role="button" tabindex="0" aria-label=' in _script()

    def test_a_collapsible_device_reports_its_state(self):
        assert 'aria-expanded="${!nd.collapsed}"' in _script()


# --------------------------------------------------------------------------
# v4.15.1 - the polish pass after seeing it against the live lab
# --------------------------------------------------------------------------
class TestFitsThePanel:
    SRC = None

    @classmethod
    def setup_class(cls):
        cls.SRC = _script()

    def test_the_viewbox_is_the_containers_own_pixel_size(self):
        """A fixed 1600x1000 viewBox letterboxed a wide panel: the map was
        pinned inside a centred 1.6:1 box with empty panel either side."""
        assert "function topoVB(" in self.SRC
        assert "viewBox=\"0 0 ${TOPO.vb.w} ${TOPO.vb.h}\"" in self.SRC

    def test_a_collapsed_or_hidden_panel_falls_back_to_a_sane_box(self):
        """getBoundingClientRect returns zeros for a display:none panel."""
        assert "VB_FALLBACK" in self.SRC
        assert "r.width < 80 || r.height < 80" in self.SRC

    def test_one_world_unit_is_one_css_pixel(self):
        """This is what lets the drag conversion be just the zoom factor."""
        assert "const unit = () => 1 / TOPO.view.scale;" in self.SRC

    def test_edge_length_scales_with_the_panel(self):
        """A fixed spacing laid the lab out larger than the panel, so it was
        fitted at 67% and a bigger screen bought you smaller labels."""
        assert "function topoK(" in self.SRC
        assert "Math.max(90, Math.min(170, ideal))" in self.SRC

    def test_the_layout_takes_the_panels_aspect_ratio(self):
        """Otherwise a wide panel gets a tall map that has to shrink to fit."""
        assert "Anisotropic gravity" in self.SRC
        assert "const ax = 1 / Math.sqrt(g.aspect || 1), ay = Math.sqrt(g.aspect || 1);" in self.SRC

    def test_fit_reserves_the_floating_pads_footprint(self):
        """The node nearest the corner otherwise settles behind the pad."""
        assert "footprint as unusable" in self.SRC
        assert "const usableW = Math.max(240, vb.w - (pr ? pr.width + 26 : 0));" in self.SRC

    def test_a_resize_refits_on_the_trailing_edge_only(self):
        """resize fires continuously; restarting the layout per frame would
        make the map thrash while the window is being dragged."""
        assert "window.addEventListener('resize'" in self.SRC
        assert "clearTimeout(topoResizeTimer)" in self.SRC


class TestLabelLegibility:
    SRC = None

    @classmethod
    def setup_class(cls):
        cls.SRC = _script()

    def test_edge_labels_sit_beside_the_line_not_on_it(self):
        assert "function topoLabelAt(" in self.SRC
        assert "printed on top of" in self.SRC

    def test_short_edges_get_no_label(self):
        assert "if(len < ((TOPO.graph && TOPO.graph.k) || 150) * 0.5) return null;" in self.SRC

    def test_a_suppressed_label_still_occupies_its_dom_slot(self):
        """Nodes move while the simulation runs, so emitting conditionally
        would slide every later <text> onto the wrong link."""
        assert "would slide the DOM index away from the link" in self.SRC
        assert "t.setAttribute('display', 'none')" in self.SRC

    def test_labels_are_painted_with_a_background_outline(self):
        css = _stylesheet()
        assert "paint-order:stroke" in css

    def test_node_spacing_accounts_for_the_label_not_just_the_chip(self):
        assert "String(dv.name || '').length * 4.2" in self.SRC
        assert "String(c.name || '').length * 4" in self.SRC


class TestClickTargets:
    SRC = None

    @classmethod
    def setup_class(cls):
        cls.SRC = _script()

    def test_only_a_device_with_something_behind_it_is_expandable(self):
        """Clicking a management server with no modelled subnets used to do
        nothing at all; it now isolates, which is the useful thing left."""
        # v4.16 also made a merged subnet expandable, so the device half of
        # the condition is what this test is about.
        assert "nd.kind === 'device' && nd.leaves > 0" in self.SRC
        assert "has nothing to collapse" in self.SRC

    def test_double_click_isolates_anything(self):
        assert "svg.addEventListener('dblclick'" in self.SRC
        assert "the net effect is just a focus" in self.SRC

    def test_the_hint_mentions_double_click(self):
        assert "double-click anything, to isolate it" in ui_source()


class TestNoEmojiInTheChrome:
    def test_toolbar_and_pad_buttons_draw_svg_line_art(self):
        """Emoji render at the font's own colour and weight and looked pasted
        on beside the SVG icon set the rest of the app uses."""
        src = ui_source()
        bar = src[src.index('class="topo-bar"'):src.index('id="topology"')]
        pad = src[src.index('class="topo-pad"'):src.index("</section>", src.index('class="topo-pad"'))]
        for cp in ("&#128247;", "&#128196;", "&#9650;", "&#9660;",
                   "&#9664;", "&#9654;", "&#9673;"):
            assert cp not in bar, cp
            assert cp not in pad, cp
        assert bar.count("<svg") >= 4, bar.count("<svg")   # 2 step arrows + 2 exports
        assert pad.count("<svg") >= 5, pad.count("<svg")   # 4 pan arrows + fit

    def test_the_icons_inherit_the_button_colour(self):
        css = _stylesheet()
        assert ".icon-btn.sq .ico{" in css
        assert "stroke:currentColor" in css
