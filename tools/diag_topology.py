r"""
Diagnostic: what does this Management Server actually say about clusters and
management servers?

Read-only. Uses only show-* calls.

Why this exists
---------------
Network Mapping draws External-Cluster, External-GW01 and External-GW02 as
three peer firewalls. In a ClusterXL deployment they are not peers: the cluster
is one logical enforcement point and the gateways are its members. The map is
therefore over-stating how independent they are.

`show-gateways-and-servers` returns BOTH the cluster object and its members as
top-level entries (types `CpmiGatewayCluster` / `simple-cluster` for the
cluster, `cluster-member` - `CpmiClusterMember` before R81.20 - for members),
which is why they come out flat.

The fix has to be driven by what the API says, not by reading the addresses.
It is tempting to infer membership from the numbers: a /30 with .1 and .2 looks
like a sync network, and a third address on the same subnet as two gateways
looks like a VIP. That inference is usually right and occasionally wrong, and a
map that is "usually right" about which boxes are one firewall is worse than a
map that says it does not know.

So this script prints, per object:
  * the exact `type` string this build uses
  * whether the cluster payload already carries its members
    (`cluster-members` / `cluster-member-names`), or whether a follow-up
    show-object is needed to get them
  * for management servers, which `management-blades` are enabled

Management HA note
------------------
The `checkpoint-host` object model has no field for a Management HA peer -
there is no "secondary of" or "ha-peer" attribute. If this script prints none,
that is the answer, and the map must not draw a link between two management
servers, because nothing in the data supports one.

Usage
-----
    .\.venv\Scripts\Activate.ps1
    python -m tools.diag_topology
"""

from __future__ import annotations

import asyncio
import json

from app.checkpoint import CheckPointClient

CLUSTER_TYPES = {
    "CpmiGatewayCluster", "simple-cluster", "CpmiVsxClusterNetobj",
    "CpmiVsClusterNetobj", "gateway-cluster",
}
MEMBER_TYPES = {"cluster-member", "CpmiClusterMember", "CpmiVsxClusterMember"}
MEMBER_KEYS = ("cluster-members", "cluster-member-names", "members")


def _addr(o: dict) -> str:
    return str(o.get("ipv4-address") or o.get("ip-address") or "-")


def _ifaces(o: dict) -> list[dict]:
    v = o.get("interfaces")
    return v if isinstance(v, list) else []


async def main() -> None:
    c = CheckPointClient()
    try:
        objs = await c.show_gateways_and_servers()

        print(f"show-gateways-and-servers returned {len(objs)} object(s)\n")
        print(f"{'NAME':<22}{'TYPE':<26}{'ADDRESS':<17}{'IFACES':>7}")
        print("-" * 72)
        for o in objs:
            print(f"{str(o.get('name'))[:21]:<22}{str(o.get('type'))[:25]:<26}"
                  f"{_addr(o):<17}{len(_ifaces(o)):>7}")

        clusters = [o for o in objs if o.get("type") in CLUSTER_TYPES]
        members = [o for o in objs if o.get("type") in MEMBER_TYPES]
        hosts = [o for o in objs if o.get("type") == "checkpoint-host"]

        print(f"\nclusters: {len(clusters)}   cluster members: {len(members)}   "
              f"management/hosts: {len(hosts)}")

        # ---- clusters ---------------------------------------------------
        print("\n=== CLUSTERS ===")
        if not clusters:
            print("none. Nothing to group - the flat map is correct here.")
        for cl in clusters:
            print(f"\n{cl.get('name')}  [{cl.get('type')}]  {_addr(cl)}")
            present = [k for k in MEMBER_KEYS if cl.get(k)]
            if present:
                for k in present:
                    v = cl[k]
                    if isinstance(v, list):
                        names = [m.get("name") if isinstance(m, dict) else str(m) for m in v]
                        print(f"  {k}: {names}")
                    else:
                        print(f"  {k}: {v!r}")
                print("  -> members are already in the gateways-and-servers payload")
            else:
                print("  no member list in this payload; asking show-object...")
                try:
                    full = (await c.call("show-object",
                                         {"uid": cl.get("uid"), "details-level": "full"})
                            ).get("object", {})
                except Exception as exc:                       # noqa: BLE001
                    print(f"  show-object failed: {exc}")
                    full = {}
                found = [k for k in MEMBER_KEYS if full.get(k)]
                if found:
                    for k in found:
                        v = full[k]
                        names = ([m.get("name") if isinstance(m, dict) else str(m) for m in v]
                                 if isinstance(v, list) else v)
                        print(f"  show-object.{k}: {names}")
                    print("  -> membership IS available, one extra show-object per cluster")
                else:
                    print("  -> membership NOT exposed. Keys seen on the object:")
                    print("    ", sorted(full.keys()) or "(empty)")

            for i, f in enumerate(_ifaces(cl)):
                if not isinstance(f, dict):
                    continue
                extra = {k: f[k] for k in
                         ("interface-type", "topology", "cluster-network-type", "network-mask")
                         if f.get(k) is not None}
                print(f"    if{i+1} {f.get('name','?'):<10}"
                      f"{f.get('ipv4-address') or f.get('ip-address') or '-':<17}"
                      f"/{f.get('ipv4-mask-length') or f.get('mask-length4') or '?'}"
                      f"  {extra if extra else ''}")

        # ---- members ----------------------------------------------------
        if members:
            print("\n=== CLUSTER MEMBERS (as returned top-level) ===")
            for m in members:
                back = {k: m[k] for k in ("cluster", "cluster-name", "belongs-to") if m.get(k)}
                print(f"{m.get('name')}  {_addr(m)}  back-reference: {back or 'NONE'}")
            if not any(m.get(k) for m in members
                       for k in ("cluster", "cluster-name", "belongs-to")):
                print("-> members do not point back at their cluster; the link has to come "
                      "from the cluster's own member list.")

        # ---- management servers ----------------------------------------
        print("\n=== MANAGEMENT / CHECKPOINT HOSTS ===")
        for h in hosts:
            print(f"\n{h.get('name')}  {_addr(h)}")
            blades = h.get("management-blades") or h.get("management_blades")
            if isinstance(blades, dict):
                on = sorted(k for k, v in blades.items() if v is True)
                print(f"  management-blades enabled: {on or '(none reported)'}")
            else:
                print("  management-blades: not present in this payload")
            ha = {k: v for k, v in h.items()
                  if any(t in k.lower() for t in ("ha", "secondary", "primary", "peer", "standby"))}
            print(f"  any HA-ish field: {ha or 'NONE'}")

        if hosts and not any(
            any(t in k.lower() for t in ("ha", "secondary", "peer", "standby"))
            for h in hosts for k in h
        ):
            print("\n-> No Management HA relationship is exposed on these objects.")
            print("   The map must NOT draw a link between two management servers:")
            print("   nothing in the data supports one. Their roles can still be")
            print("   labelled from management-blades, which IS real data.")

        # ---- what the map will do with this ----------------------------
        print("\n=== WHAT THE MAP DOES TODAY ===")
        flat = [o.get("name") for o in objs
                if o.get("type") in CLUSTER_TYPES | MEMBER_TYPES]
        print(f"drawn as independent peers: {flat}")
        print("(each is its own node with its own subnet edges)")
    finally:
        await c.close()


if __name__ == "__main__":
    asyncio.run(main())
