r"""
Diagnostic: why did a trace come back UNVERIFIED?

Read-only. Loads the package the way the application does, then prints, for
one connection, every rule that was not a proven miss - with the state of each
column (source, destination, service, VPN, envelope) and the reason text.

Usage
-----
    python -m tools.diag_trace External-FW 192.168.20.50 192.168.20.100 tcp 3389
"""

from __future__ import annotations

import asyncio
import json
import sys

from app.checkpoint import CheckPointClient
from app.policy import package_access_tree
from app.resolver import ObjectResolver
from app.traffic import resolve_service_query, trace_access_tree, trace_layer_candidates


async def main(package: str, src: str, dst: str, proto: str, service: str) -> None:
    from app.api.credentials import load_credentials_on_startup
    from app.config import settings
    load_credentials_on_startup()
    print(f"Management Server: {settings.checkpoint_mgmt}")
    c = CheckPointClient()
    try:
        await c.login()
        tree = await package_access_tree(c, package, hydrate=True)
        objects = {}
        for node in tree.get("layers", []):
            for obj in node.get("payload", {}).get("objects-dictionary", []) or []:
                if isinstance(obj, dict) and obj.get("uid"):
                    objects[obj["uid"]] = obj
        res = ObjectResolver(objects)
        query = resolve_service_query(service, proto, res)
        print(f"Query: {src} -> {dst}  {query.get('display')}  atoms={query.get('atoms')}\n")
        for node in tree.get("layers", []):
            out = trace_layer_candidates(node.get("payload") or {}, src, dst, proto, query)
            print(f"LAYER {node.get('name')}: {len(out['candidates'])} rule(s) not a proven miss")
            for cand in out["candidates"]:
                print(f"  rule {cand['rule']} ({cand['name']})  action={cand['action']}  STATE={cand['state']}")
                for dim in ("source", "destination", "service", "vpn", "envelope"):
                    print(f"      {dim:<12} {cand.get(dim + '_state')!s:<9} {cand.get(dim + '_match')}")
                if cand["state"] != "match":
                    raw = next((r for r in _rules(node["payload"].get("rulebase", []))
                                if r.get("rule-number") == cand["rule"]), {})
                    for uid in res.uids(raw.get("service")):
                        o = res.obj(uid)
                        print(f"      service object: {o.get('name')} [{o.get('type')}]")
                        for m in (o.get("members") or []):
                            mu = m if isinstance(m, str) else m.get("uid")
                            mo = res.obj(mu)
                            keep = {k: v for k, v in mo.items() if k in (
                                "name", "type", "port", "source-port", "protocol",
                                "match-by-protocol-signature", "icmp-type", "icmp-code",
                                "ip-protocol", "match", "members")}
                            atoms, ok = res.service_atoms_partial(mu)
                            print(f"        member {json.dumps(keep, ensure_ascii=False)[:300]}"
                                  f"  -> atoms={len(atoms)} complete={ok}")
            print()

        # The verdict the application and tools.acceptance report: the tree
        # walk over all layers, then the implied-rule gate.
        from app.implied import build_context
        try:
            properties = await c.show_global_properties()
        except Exception:                                         # noqa: BLE001
            properties = None
        try:
            devices = await c.show_gateways_and_servers()
        except Exception:                                         # noqa: BLE001
            devices = None
        got = trace_access_tree(tree, src, dst, proto, query,
                                implied=build_context(properties, devices))
        implied = got.get("implied_rules") or {}
        print(f"VERDICT  {got.get('result')} · {got.get('confidence')}"
              f"   gateway_final={got.get('gateway_final')}")
        for st in got.get("path") or []:
            print(f"  path   {st.get('layer')} rule {st.get('display_rule') or st.get('rule')}"
                  f" ({st.get('name')})  state={st.get('state')}")
        print(f"  implied rules: {implied.get('state')}")
        for line in implied.get("reasons") or []:
            print(f"      {line}")
        print(f"  reason: {got.get('reason')}")
    finally:
        await c.close()


def _rules(items):
    out = []
    for x in items or []:
        if isinstance(x, dict):
            if x.get("type") == "access-rule":
                out.append(x)
            if isinstance(x.get("rulebase"), list):
                out.extend(_rules(x["rulebase"]))
    return out


if __name__ == "__main__":
    if len(sys.argv) < 6:
        print("usage: python -m tools.diag_trace <package> <src> <dst> <tcp|udp|icmp> <port-or-service>")
        raise SystemExit(2)
    asyncio.run(main(*sys.argv[1:6]))
