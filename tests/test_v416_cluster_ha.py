"""
v4.16: cluster membership and management HA, from API fields only.

The lab draws External-Cluster, External-GW01 and External-GW02 as three peer
firewalls. They are not peers - it is one ClusterXL enforcement point and its
two members - and the map was therefore over-stating how independent they are.

`python -m tools.diag_topology` against the live R82 lab settled how to fix it:

    External-Cluster  [CpmiGatewayCluster]
      cluster-member-names: ['External-GW01', 'External-GW02']
      -> members are already in the gateways-and-servers payload
    External-GW01  cluster-member  back-reference: NONE
    CP-MGMT-01  management-blades enabled: [logging-and-status,
                                            network-policy-management]
    CP-MGMT-02  management-blades enabled: [logging-and-status,
                                            network-policy-management, secondary]

Two things follow, and the tests below exist to keep them true:

  1. Membership comes from `cluster-member-names` on the cluster. Members do
     not point back at their cluster, so that list is the only source. It is
     NOT read off the addresses - a /30 with .1 and .2 looks like sync and a
     third address on a member's subnet looks like a VIP, and those readings
     are right most of the time. A map that is "usually right" about which
     boxes are one firewall is worse than one that says it does not know.

  2. Management HA is real and knowable: `management-blades.secondary` marks
     the standby, and a domain has exactly one primary, so primary+secondary
     IS the pair. What is NOT knowable is whether they are currently in sync -
     the object model has no such field - so the map may say HA is configured
     and must never imply it is healthy.
"""

from pathlib import Path

from conftest import ui_source

from app.topology_map import network_map

APP = Path(__file__).resolve().parent.parent / "app"


def _script() -> str:
    return (APP / "static" / "js" / "app.js").read_text(encoding="utf-8")


# The lab, as tools/diag_topology reported it.
LAB = [
    {"uid": "m1", "name": "CP-MGMT-01", "type": "checkpoint-host",
     "ipv4-address": "172.23.31.180",
     "management-blades": {"logging-and-status": True, "network-policy-management": True},
     "interfaces": [{"name": "eth0", "ipv4-address": "0.0.0.0"}]},
    {"uid": "m2", "name": "CP-MGMT-02", "type": "checkpoint-host",
     "ipv4-address": "172.23.31.181",
     "management-blades": {"logging-and-status": True, "network-policy-management": True,
                           "secondary": True},
     "interfaces": []},
    {"uid": "c1", "name": "External-Cluster", "type": "CpmiGatewayCluster",
     "ipv4-address": "172.23.34.179",
     "cluster-member-names": ["External-GW01", "External-GW02"],
     "interfaces": [
         {"ipv4-address": "172.23.31.179", "ipv4-mask-length": 24,
          "topology": {"leads-to-internet": False}},
         {"ipv4-address": "172.23.34.179", "ipv4-mask-length": 24,
          "topology": {"leads-to-internet": True}}]},
    {"uid": "g1", "name": "External-GW01", "type": "cluster-member",
     "ipv4-address": "172.23.31.177",
     "interfaces": [{"ipv4-address": "10.99.99.1", "ipv4-mask-length": 30},
                    {"ipv4-address": "172.23.31.177", "ipv4-mask-length": 24}]},
    {"uid": "g2", "name": "External-GW02", "type": "cluster-member",
     "ipv4-address": "172.23.31.178",
     "interfaces": [{"ipv4-address": "10.99.99.2", "ipv4-mask-length": 30},
                    {"ipv4-address": "172.23.31.178", "ipv4-mask-length": 24}]},
    {"uid": "i1", "name": "Internal-GW01", "type": "simple-gateway",
     "ipv4-address": "172.23.31.176",
     "interfaces": [{"ipv4-address": "192.168.10.254", "ipv4-mask-length": 24}]},
]


def _node(d, name):
    return next(n for n in d["nodes"] if n.get("name") == name)


def _edges(d, kind):
    return [e for e in d["edges"] if e.get("kind") == kind]


class TestClusterMembership:
    D = None

    @classmethod
    def setup_class(cls):
        cls.D = network_map(LAB)

    def test_a_cluster_is_not_just_another_gateway(self):
        assert _node(self.D, "External-Cluster")["role"] == "cluster"
        assert _node(self.D, "External-GW01")["role"] == "cluster-member"
        assert _node(self.D, "Internal-GW01")["role"] == "gateway"

    def test_members_come_from_the_clusters_own_list(self):
        cl = _node(self.D, "External-Cluster")
        assert cl["members"] == ["External-GW01", "External-GW02"]
        assert cl["member_ids"] == ["g1", "g2"]

    def test_membership_is_an_edge_of_its_own_kind(self):
        got = {(e["from"], e["to"]) for e in _edges(self.D, "membership")}
        assert got == {("c1", "g1"), ("c1", "g2")}

    def test_the_pre_r8120_member_type_still_works(self):
        lab = [dict(o) for o in LAB]
        for o in lab:
            if o["type"] == "cluster-member":
                o["type"] = "CpmiClusterMember"
        assert _node(network_map(lab), "External-GW01")["role"] == "cluster-member"

    def test_the_older_cluster_members_object_list_still_works(self):
        lab = [dict(o) for o in LAB]
        for o in lab:
            if o["name"] == "External-Cluster":
                del o["cluster-member-names"]
                o["cluster-members"] = [{"name": "External-GW01"}, {"name": "External-GW02"}]
        assert len(_edges(network_map(lab), "membership")) == 2

    def test_a_member_the_api_did_not_return_is_reported_not_dropped(self):
        """Silently losing a member would make a two-member cluster look like
        a one-member cluster, which is a different fact."""
        lab = [o for o in LAB if o["name"] != "External-GW02"]
        d = network_map(lab)
        assert len(_edges(d, "membership")) == 1
        assert any("External-GW02" in l for l in d["limitations"])

    def test_membership_is_never_inferred_from_addresses(self):
        """Strip the member list and the app must admit it does not know."""
        lab = [dict(o) for o in LAB]
        for o in lab:
            o.pop("cluster-member-names", None)
        d = network_map(lab)
        assert _edges(d, "membership") == []
        assert _node(d, "External-Cluster")["member_ids"] == []


class TestManagementHA:
    D = None

    @classmethod
    def setup_class(cls):
        cls.D = network_map(LAB)

    def test_the_secondary_blade_names_the_standby(self):
        assert _node(self.D, "CP-MGMT-01")["mgmt_role"] == "primary"
        assert _node(self.D, "CP-MGMT-02")["mgmt_role"] == "secondary"

    def test_the_pair_is_drawn_as_its_own_edge_kind(self):
        assert [(e["from"], e["to"]) for e in _edges(self.D, "mgmt-ha")] == [("m1", "m2")]

    def test_the_map_says_configured_never_healthy(self):
        """Sync state is not in the object model, so claiming it would be a
        statement the code cannot back up."""
        note = " ".join(self.D["limitations"])
        assert "shown as configured" in note
        assert "currently synchronised is not exposed" in note

    def test_a_log_only_server_is_not_treated_as_a_management_peer(self):
        lab = [dict(o) for o in LAB]
        for o in lab:
            if o["name"] == "CP-MGMT-02":
                o["management-blades"] = {"logging-and-status": True}
        d = network_map(lab)
        assert _edges(d, "mgmt-ha") == []
        assert "mgmt_role" not in _node(d, "CP-MGMT-02")

    def test_two_primaries_draw_nothing_and_say_why(self):
        """Without exactly one primary the pairing is genuinely ambiguous."""
        lab = [dict(o) for o in LAB]
        for o in lab:
            if o["name"] == "CP-MGMT-02":
                o["management-blades"] = {"network-policy-management": True}
        d = network_map(lab)
        assert _edges(d, "mgmt-ha") == []
        assert any("no HA pairing is drawn" in l for l in d["limitations"])


class TestInterfaceTopology:
    def test_an_internet_facing_subnet_is_marked_from_the_gateways_own_flag(self):
        d = network_map(LAB)
        assert _node(d, "172.23.34.0/24").get("external") is True
        assert _node(d, "172.23.31.0/24").get("external") is None

    def test_nothing_is_marked_external_without_the_flag(self):
        lab = [dict(o) for o in LAB]
        for o in lab:
            for f in o.get("interfaces", []):
                f.pop("topology", None)
        d = network_map(lab)
        assert not [n for n in d["nodes"] if n.get("external")]


class TestFrontend:
    SRC = None

    @classmethod
    def setup_class(cls):
        cls.SRC = _script()

    def test_the_new_roles_are_still_drawn_as_devices(self):
        """Adding a role without adding it here silently deletes those nodes."""
        assert "['gateway','management','device','cluster','cluster-member']" in self.SRC

    def test_relationship_links_are_not_drawn_like_traffic_paths(self):
        assert "e.kind === 'membership' || e.kind === 'mgmt-ha'" in self.SRC
        assert "not traffic paths" in self.SRC
        css = (APP / "static" / "css" / "app.css").read_text(encoding="utf-8")
        assert ".topo-g-edge.membership line{" in css
        assert ".topo-g-edge.mgmt-ha line{" in css
        assert "stroke-dasharray" in css

    def test_collapsing_a_cluster_folds_its_members_in(self):
        assert "const clusterHidden = new Set();" in self.SRC
        assert "not peers of it" in self.SRC

    def test_a_network_only_hidden_members_touch_folds_with_them(self):
        """Otherwise it is left stranded on the map with no links at all."""
        assert "every(u => clusterHidden.has(u))" in self.SRC

    def test_a_cluster_internal_network_is_marked_from_the_graph(self):
        assert "nd.internal = byId.get(cl[0])" in self.SRC
        assert "not off the addresses" in self.SRC

    def test_the_sync_tooltip_states_the_evidence_before_the_conclusion(self):
        assert "No interface of ${nd.internal} is on this network" in self.SRC
        assert "On a ClusterXL deployment that is the sync network" in self.SRC

    def test_the_ha_tooltip_repeats_the_configured_not_healthy_caveat(self):
        assert "live sync state is not exposed by the API" in self.SRC

    def test_the_legend_covers_the_new_marks(self):
        src = ui_source()
        for label in ("Cluster", "Faces internet", "Management HA"):
            assert label in src, label


class TestLayoutHandlesTheNewShape:
    SRC = None

    @classmethod
    def setup_class(cls):
        cls.SRC = _script()

    def test_disconnected_components_are_packed_not_flung(self):
        """The HA pair has no interface to the estate, so it is a second
        component; plain FR compresses one and throws the other to the edge."""
        assert "function topoComponents(" in self.SRC
        assert "function topoPack(" in self.SRC
        assert "as a rigid body into a" in self.SRC

    def test_packing_yields_to_a_hand_placed_node(self):
        assert "they own the arrangement" in self.SRC

    def test_packing_is_deterministic(self):
        assert "JS sort\n   is stable" in self.SRC

    def test_a_member_link_is_pulled_shorter_than_a_subnet_link(self):
        assert "len: e.kind === 'membership' ? 0.78 : 1," in self.SRC
        assert "const f = d * d / (K * (l.len || 1));" in self.SRC

    def test_spacing_clears_the_widest_label(self):
        assert "Math.max(topoK(n, TOPO.vb), widest * 1.35)" in self.SRC

    def test_labels_that_still_collide_are_measured_and_dropped(self):
        """No cheap formula predicts a label landing on a third node's label,
        so measure what rendered instead of guessing."""
        assert "function topoDeclutter(" in self.SRC
        assert "the edge\n   label is the one that gives way" in self.SRC
        assert "texts.length > 200" in self.SRC


# --------------------------------------------------------------------------
# v4.16.1 - defects the live lab showed that the fixture did not
# --------------------------------------------------------------------------
class TestRoleSplitDidNotBreakCards:
    def test_both_new_roles_have_a_card_fill(self):
        """Cards mode styles by role. Splitting `gateway` into gateway /
        cluster / cluster-member left the two new roles with no rule at all,
        so they rendered as unfilled, unstroked rectangles."""
        css = (APP / "static" / "css" / "app.css").read_text(encoding="utf-8")
        for sel in (".cluster .card{", ".cluster-member .card{",
                    ".light .cluster .card{", ".light .cluster-member .card{"):
            assert sel in css, sel

    def test_every_role_the_map_emits_is_styled_in_both_modes(self):
        css = (APP / "static" / "css" / "app.css").read_text(encoding="utf-8")
        for role in ("gateway", "management", "device", "cluster", "cluster-member"):
            assert f".{role} .card{{" in css, f"cards: {role}"
            assert f".topo-g-node.{role} .chip{{" in css, f"graph: {role}"


class TestMergedSubnetsOpenBackUp:
    SRC = None

    @classmethod
    def setup_class(cls):
        cls.SRC = _script()

    def test_a_merged_node_is_expandable(self):
        """It answers "how many subnets are behind these devices"; without a
        way to ask "which ones" the answer is a dead end."""
        assert "nd.kind === 'merged'" in self.SRC
        assert "or the answer is a dead end" in self.SRC

    def test_opening_one_group_does_not_turn_merging_off(self):
        assert "TOPO.unmerged.has('merged:' + sig)" in self.SRC
        assert "if(TOPO.unmerged.has(id)) TOPO.unmerged.delete(id); else TOPO.unmerged.add(id);" in self.SRC

    def test_toggling_auto_merge_forgets_which_groups_were_opened(self):
        assert "TOPO.unmerged.clear();" in self.SRC


class TestPackingPicksTheBestArrangement:
    SRC = None

    @classmethod
    def setup_class(cls):
        cls.SRC = _script()

    def test_shelf_width_is_chosen_by_what_renders_largest(self):
        """One guessed width put the management pair below the estate on a
        panel twice as wide as tall, so fit had to shrink everything."""
        assert "keep the one that\n     renders biggest" in self.SRC
        assert "for(const k of [0.7, 1, 1.3, 1.7, 2.2, 1e9])" in self.SRC

    def test_the_choice_is_deterministic(self):
        assert "ties keep the first" in self.SRC

    def test_components_are_padded_by_their_own_labels(self):
        """A constant pad let a subnet name in one component print over a
        management server's name in the next."""
        assert "nd.r * 0.85" in self.SRC
        assert "not a constant" in self.SRC


class TestNewNodesJoinAnExistingArrangement:
    SRC = None

    @classmethod
    def setup_class(cls):
        cls.SRC = _script()

    def test_a_node_added_later_starts_near_its_neighbours(self):
        """On the spiral it starts in the middle of everything and drags its
        links across the whole map."""
        assert "nd.seeded = true;" in self.SRC
        assert "Start it where its neighbours already are" in self.SRC

    def test_seeding_by_neighbour_only_applies_to_a_partial_refresh(self):
        assert "if(fresh && fresh < g.nodes.length){" in self.SRC


class TestPlacedMarker:
    SRC = None

    @classmethod
    def setup_class(cls):
        cls.SRC = _script()

    def test_saving_shows_the_markers_immediately(self):
        """Save pins every node, but nothing re-rendered, so the map only
        caught up on the next unrelated interaction."""
        assert "so the placed markers appear straight away" in self.SRC

    def test_a_placed_node_is_marked_without_underlining_its_name(self):
        css = (APP / "static" / "css" / "app.css").read_text(encoding="utf-8")
        assert ".topo-g-node.pinned .pin{" in css
        assert "made them all\n   look like links" in css
        assert "text-decoration:underline" not in css.split(".topo-g-node.pinned")[1][:200]
