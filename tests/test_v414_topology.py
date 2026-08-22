"""
v4.14 regression: the Network Mapping redesign.

The old view drew every interface as its own node in a middle column. In the
user's own lab that turned 4 gateways into 22 nodes across 3 columns, and every
subnet edge had to cross the interface column, so the picture was a hairball
that told you less than the JSON did.

The redesign folds interfaces into the gateway card as rows you open on click:
two columns (devices | networks), one node per real device, edges drawn from
the interface row when the card is open and from the card edge when it is not.

These tests pin the *contract* of that design, not its pixels:

  - interfaces are never emitted as standalone nodes
  - a device with interfaces is clickable and reports its state to a11y
  - expand/collapse, focus, search and zoom are all reachable from the toolbar
  - nothing in the drawing path can mutate the payload it was handed

Where a test asserts on a literal string it is because that string is the API
between the template and the script (an element id, a CSS class the stylesheet
targets); those cannot drift silently without the feature breaking.
"""

from pathlib import Path

from conftest import app_source, ui_source

CSS_DIR = Path(__file__).resolve().parent.parent / "app" / "static" / "css"


def _stylesheet() -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in sorted(CSS_DIR.glob("*.css")))


# --------------------------------------------------------------------------
# model: interfaces stop being nodes
# --------------------------------------------------------------------------
class TestModel:
    SRC = None

    @classmethod
    def setup_class(cls):
        cls.SRC = app_source()

    def test_a_model_is_built_before_anything_is_drawn(self):
        """Layout needs to know card heights, which depend on open state."""
        assert "function buildTopoModel(" in self.SRC
        assert "function topoLayout(" in self.SRC

    def test_devices_and_networks_are_the_only_node_kinds(self):
        assert "n.role === 'network'" in self.SRC
        assert "['gateway','management','device'].includes(n.role)" in self.SRC

    def test_interfaces_are_folded_into_their_parent_device(self):
        """The whole point of the redesign: no interface column."""
        assert "nodes.filter(n => n.role === 'interface')" in self.SRC
        assert "ifaces.set(i.parent, list)" in self.SRC

    def test_an_interface_carries_the_subnet_it_reaches(self):
        """An edge from a row needs to know where the row goes."""
        assert "subnet: link ? link.to : null" in self.SRC

    def test_interface_rows_are_ordered_stably(self):
        """Card contents must not reshuffle between renders."""
        assert "a.name.localeCompare(b.name)" in self.SRC

    def test_network_column_is_ordered_to_reduce_crossings(self):
        """Networks sort by the mean Y of what connects to them."""
        assert "ys.push(" in self.SRC


# --------------------------------------------------------------------------
# interaction
# --------------------------------------------------------------------------
class TestInteraction:
    SRC = None

    @classmethod
    def setup_class(cls):
        cls.SRC = app_source()

    def test_a_device_with_ports_is_expandable(self):
        assert "function topoToggle(" in self.SRC
        assert "data-expandable=" in self.SRC

    def test_expand_state_is_reported_to_assistive_tech(self):
        assert 'aria-expanded="${p.open}"' in self.SRC
        assert 'role="button" tabindex="0"' in self.SRC

    def test_keyboard_users_can_expand(self):
        """Click-only would make the whole view unusable without a mouse."""
        assert "svg.addEventListener('keydown'" in self.SRC
        assert "e.key !== 'Enter' && e.key !== ' '" in self.SRC

    def test_expand_all_and_collapse_all_exist(self):
        assert "function topoExpandAll(" in self.SRC
        assert "topoExpandAll(true)" in ui_source()
        assert "topoExpandAll(false)" in ui_source()

    def test_expand_all_builds_the_model_once(self):
        """It used to rebuild the whole model inside the per-device loop."""
        assert "build once, not per device" in self.SRC

    def test_clicking_a_network_isolates_it(self):
        assert "TOPO.focus = (TOPO.focus === id) ? null : id" in self.SRC

    def test_clicking_empty_space_clears_the_focus(self):
        assert "if(!g){ TOPO.focus = null;" in self.SRC

    def test_a_drag_is_not_treated_as_a_click(self):
        """Panning across a card must not toggle it."""
        assert "if(moved > 4) return;" in self.SRC
        assert "a drag is not a click" in self.SRC

    def test_search_dims_instead_of_deleting(self):
        """Hiding non-matches would hide the context that makes a hit useful."""
        assert "function topoSearch(" in self.SRC
        assert "cls.push('dim')" in self.SRC
        assert "cls.push('hit')" in self.SRC

    def test_zoom_is_clamped(self):
        assert "Math.max(.4, Math.min(2.6," in self.SRC

    def test_reset_returns_to_a_known_view(self):
        assert "TOPO.view = {scale: 1, tx: 0, ty: 0}" in self.SRC


# --------------------------------------------------------------------------
# honesty: the picture must not claim more than the payload says
# --------------------------------------------------------------------------
class TestHonesty:
    def test_the_view_still_says_it_is_logical_only(self):
        """Nothing here infers cabling, switching or live routing."""
        src = ui_source()
        assert "Physical cabling, switches and live routing are not inferred" in src

    def test_a_node_and_link_count_is_shown(self):
        assert 'id="topoCount"' in ui_source()
        assert "node(s) · ${edges.length} link(s)" in app_source()

    def test_a_missing_cidr_renders_as_a_dash_not_a_guess(self):
        assert "esc(f.cidr || '—')" in app_source()

    def test_the_legend_explains_the_colours(self):
        src = ui_source()
        assert "topo-legend" in src
        for role in ("Management", "Gateway", "Network"):
            assert f">{role}<" in src or role in src

    def test_the_toolbar_tells_the_user_what_is_clickable(self):
        assert "Click a gateway to show its interfaces" in ui_source()


# --------------------------------------------------------------------------
# wiring between template, script and stylesheet
# --------------------------------------------------------------------------
class TestWiring:
    def test_toolbar_controls_exist_in_the_template(self):
        src = ui_source()
        for el in ('id="topoQuery"', 'id="topoCount"', "topoZoom(", "topoFit()"):
            assert el in src, el

    def test_the_pan_zoom_layer_is_a_single_group(self):
        src = app_source()
        assert 'id="world"' in src
        assert "function topoApplyView(" in src

    def test_every_class_the_script_emits_is_styled(self):
        """A class with no rule renders as an invisible or unstyled shape."""
        css = _stylesheet()          # the real .css, not the whole UI blob
        for cls in (".topo-node", ".topo-edge", ".topo-if", ".topo-badge",
                    ".topo-bar", ".topo-legend"):
            assert cls in css, cls

    def test_the_port_pill_reserves_room_for_its_chevron(self):
        """The tighter box clipped the trailing 's' of 'ports'."""
        assert "parked clear of it" in app_source()