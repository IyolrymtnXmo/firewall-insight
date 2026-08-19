r"""
Diagnostic: find which objects the resolver cannot turn into IP/port ranges.

Read-only. Uses only the same show-* calls the application already makes.

Why this exists
---------------
Traffic Path returned UNVERIFIED with
    "Static match unavailable for LAB-Internal-Nets [group]"
which means ObjectResolver.address_atoms() returned None for that object.
That happens when either:

  (A) the group object is in objects-dictionary but has no "members" list
      (details-level=standard does not always include members, and
       hydrate_objects() skips any UID already present in the dictionary), or
  (B) the group HAS members, but one of the member objects was never
      hydrated, so resolver.obj() falls back to {"type": "unknown"} and
      address_atoms() bails out on the whole group.

This script prints enough to tell (A) from (B).

Usage
-----
    .\.venv\Scripts\Activate.ps1
    python -m tools.diag_resolver Standard
"""

from __future__ import annotations

import asyncio
import sys

from app.checkpoint import CheckPointClient
from app.resolver import ObjectResolver


def _member_uids(obj: dict) -> list[str]:
    out = []
    for key in ("members", "include", "except"):
        value = obj.get(key)
        if isinstance(value, list):
            for item in value:
                uid = item if isinstance(item, str) else (
                    item.get("uid") if isinstance(item, dict) else None
                )
                if uid:
                    out.append(uid)
        elif isinstance(value, dict) and value.get("uid"):
            out.append(value["uid"])
    return out


def _report_layer(layer_name: str, payload: dict) -> None:
    objects = {
        o["uid"]: o
        for o in payload.get("objects-dictionary", [])
        if isinstance(o, dict) and o.get("uid")
    }
    res = ObjectResolver(objects)

    print(f"\n{'=' * 78}")
    print(f"LAYER: {layer_name}   ({len(objects)} objects in dictionary)")
    print("=" * 78)

    # Every UID referenced by a rule field, so we test exactly what the
    # traffic matcher tests.
    referenced: set[str] = set()

    def walk(items):
        for item in items or []:
            if not isinstance(item, dict):
                continue
            if item.get("type") == "access-rule":
                for field in ("source", "destination", "service"):
                    value = item.get(field)
                    if isinstance(value, list):
                        for x in value:
                            uid = x if isinstance(x, str) else (
                                x.get("uid") if isinstance(x, dict) else None
                            )
                            if uid:
                                referenced.add(uid)
            if isinstance(item.get("rulebase"), list):
                walk(item["rulebase"])

    walk(payload.get("rulebase", []))

    unresolvable = []
    partial = []

    for uid in sorted(referenced):
        obj = res.obj(uid)
        name = str(obj.get("name") or uid)
        typ = str(obj.get("type") or "unknown")

        in_dict = uid in objects
        addr_atoms, addr_ok = res.address_atoms_partial(uid)
        svc_atoms, svc_ok = res.service_atoms_partial(uid)
        addr = addr_atoms if addr_ok and addr_atoms else None
        svc = svc_atoms if svc_ok and svc_atoms else None
        # Partially modelled is still useful for matching - say so.
        if not (addr or svc) and (addr_atoms or svc_atoms):
            kind = "service" if "service" in typ else "address"
            partial.append({
                "name": name,
                "type": typ,
                "ranges": len(addr_atoms) + len(svc_atoms),
                "blockers": res.unmodelled_names(uid, kind),
            })
            continue

        # An object is fine if it resolves as either an address or a service.
        if addr is not None or svc is not None or res.is_any_uid(uid):
            continue

        members = _member_uids(obj)
        missing_members = [m for m in members if m not in objects]

        unresolvable.append({
            "uid": uid,
            "name": name,
            "type": typ,
            "in_dictionary": in_dict,
            "member_count": len(members),
            "missing_members": missing_members,
        })

    if partial:
        print(f"  {len(partial)} object(s) PARTIALLY modelled - traffic matching"
              " works through the parts we understand,")
        print("  but containment (shadow/redundancy) analysis is limited for them:\n")
        for item in partial:
            print(f"  ~ {item['name']}  [{item['type']}]  {item['ranges']} range(s) usable")
            for blocker in item["blockers"][:6]:
                print(f"      blocked by: {blocker}")
        print()

    if not unresolvable:
        if partial:
            print("  No object is completely unusable.")
        else:
            print("  OK - every referenced object resolves to an IP or port range.")
        return

    print(f"  {len(unresolvable)} object(s) CANNOT be resolved statically:\n")
    for item in unresolvable:
        print(f"  - {item['name']}  [{item['type']}]")
        print(f"      uid              : {item['uid']}")
        print(f"      in dictionary    : {item['in_dictionary']}")
        print(f"      member count     : {item['member_count']}")

        if item["member_count"] == 0:
            print("      >> CAUSE (A): no members returned.")
            print("         The group is in objects-dictionary, so")
            print("         hydrate_objects() skipped it, and details-level")
            print("         'standard' did not include its members.")
        elif item["missing_members"]:
            print(f"      >> CAUSE (B): {len(item['missing_members'])} member(s)"
                  " missing from the dictionary:")
            for m in item["missing_members"][:8]:
                print(f"         {m}")
            print("         Member expansion in hydrate_rulebase() did not")
            print("         reach these - check for a silent rate-limit break")
            print("         in CheckPointClient.hydrate_objects().")
        else:
            kind = "service" if "service" in item["type"] else "address"
            blockers = res.unmodelled_names(item["uid"], kind)
            print(f"      >> Members hydrated, but {len(blockers)} of them cannot")
            print(f"         be modelled as a {kind} range:")
            for b in blockers[:8]:
                print(f"         {b}")
            print("         Matching still works through the members that ARE")
            print("         modelled; only containment analysis is limited.")
        print()


async def main(package: str) -> None:
    client = CheckPointClient()
    try:
        info = await client.login()
        print(f"Connected. Management API "
              f"{info.get('api-server-version') or info.get('web-api-version')}")

        roots = await client.show_package_access_layers(package)
        print(f"Package '{package}' access layer(s): "
              f"{[r['name'] for r in roots] or 'NONE RESOLVED'}")
        if not roots:
            print("Could not resolve an access layer - stopping.")
            return

        # Reuse the application's own tree + hydration path so the diagnosis
        # reflects what the app actually sees.
        from app.main import hydrate_rulebase

        for root in roots:
            tree = await client.show_rulebase_tree(root["name"])
            for node in tree.get("layers", []):
                payload, _ = await hydrate_rulebase(client, node["payload"])
                _report_layer(node["name"], payload)

            if tree.get("errors"):
                print("\nLayer load errors:")
                for err in tree["errors"]:
                    print(f"  {err}")
    finally:
        await client.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python -m tools.diag_resolver <policy-package-name>")
        raise SystemExit(2)
    asyncio.run(main(sys.argv[1]))
