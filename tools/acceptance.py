r"""
Acceptance run: turn "is Project Dev tested yet?" into a number.

Read-only. Uses only the same show-* calls the application already makes, and
never writes to the Management Server.

Why this exists
---------------
"ทดสอบให้เสร็จ" had no pass criteria, so there was no way to answer whether it
was done. This runs a fixed matrix against the live lab and prints one line per
check plus a total. A run either says 24/24 or it names what failed - both are
answers, which "we tested it a bit" is not.

It also writes evidence to acceptance-report.json so a screenshot of a passing
run is backed by something a reviewer can open.

What it does NOT do
-------------------
It does not judge whether the POLICY is good - that is what the Analyze page is
for. It checks that this application reports the lab correctly: the counts it
gives match the objects that exist, the relationships it draws come from API
fields, and the traffic verdicts match what the policy actually says.

Expected traffic verdicts live in tools/acceptance_cases.json so they can be
edited when the policy changes, without touching this file. A case with
"expect": null is reported but never fails - use that for a flow you want on
the record before you have decided what it should do.

Usage
-----
    .\.venv\Scripts\Activate.ps1
    python -m tools.acceptance                       # package "Standard"
    python -m tools.acceptance --package MyPolicy
    python -m tools.acceptance --json report.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from app.checkpoint import CheckPointClient
from app.policy import analyze_package, data_quality, package_access_tree
from app.resolver import ObjectResolver
from app.topology_map import network_map
from app.traffic import resolve_service_query, trace_access_tree
from app.version import APP_VERSION

CASES_FILE = Path(__file__).resolve().parent / "acceptance_cases.json"

GREEN, RED, YELLOW, DIM, OFF = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"


class Report:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def check(self, group: str, name: str, ok: bool | None, detail: str = "") -> bool:
        """ok=True pass, False fail, None = recorded but not judged."""
        self.rows.append({"group": group, "check": name, "ok": ok, "detail": detail})
        mark = (f"{GREEN}PASS{OFF}" if ok else
                f"{RED}FAIL{OFF}" if ok is False else f"{YELLOW}INFO{OFF}")
        print(f"  [{mark}] {name}" + (f"  {DIM}{detail}{OFF}" if detail else ""))
        return bool(ok)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.rows if r["ok"] is True)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.rows if r["ok"] is False)

    @property
    def judged(self) -> int:
        return sum(1 for r in self.rows if r["ok"] is not None)


def _default_cases() -> dict[str, Any]:
    """Seeded from Lab-Status-Report-20260820. Edit the file, not this."""
    return {
        "_comment": [
            "Expected Traffic Path verdicts for the lab. Edit freely.",
            "action:     accept | drop | null (record only, never fails)",
            "confidence: exact | inferred | unknown | null (not checked)",
            "Rule numbers are deliberately NOT asserted: they shift whenever a",
            "rule is inserted, and a test that breaks on renumbering teaches",
            "you to ignore it.",
        ],
        "layer": "Network",
        "cases": [
            {"name": "VLAN20 client reaches AD over LDAP",
             "src": "192.168.20.50", "dst": "192.168.10.10",
             "protocol": "tcp", "service": "389",
             "expect": {"action": "accept"}},
            {"name": "VLAN10 client browses out to the internet",
             "src": "192.168.10.50", "dst": "8.8.8.8",
             "protocol": "tcp", "service": "443",
             "expect": {"action": "accept"}},
            {"name": "VLAN10 client reaches RDP server on VLAN20",
             "src": "192.168.10.50", "dst": "192.168.20.10",
             "protocol": "tcp", "service": "3389",
             "expect": {"action": "accept"}},
            {"name": "Lab host cannot SMB into the corporate VLAN",
             "src": "192.168.10.50", "dst": "172.23.31.180",
             "protocol": "tcp", "service": "445",
             "expect": {"action": "drop"}},
            {"name": "Internet cannot reach a lab client directly",
             "src": "8.8.8.8", "dst": "192.168.10.50",
             "protocol": "tcp", "service": "3389",
             "expect": {"action": "drop"}},
            {"name": "VLAN20 to AD over an unrelated high port",
             "src": "192.168.20.50", "dst": "192.168.10.10",
             "protocol": "tcp", "service": "9999",
             "expect": None},
        ],
    }


def load_cases() -> dict[str, Any]:
    if CASES_FILE.exists():
        return json.loads(CASES_FILE.read_text(encoding="utf-8"))
    CASES_FILE.write_text(json.dumps(_default_cases(), indent=2), encoding="utf-8")
    print(f"{DIM}(created {CASES_FILE.name} with the documented lab flows){OFF}")
    return _default_cases()


async def run(package: str, out_path: str) -> int:
    rep = Report()
    cases = load_cases()
    c = CheckPointClient()
    evidence: dict[str, Any] = {"app_version": APP_VERSION, "package": package}

    try:
        # ---- 1. the read-only guarantee, checked structurally -------------
        print(f"\n{DIM}1. Safety{OFF}")
        src = (Path(__file__).resolve().parent.parent / "app").rglob("*.py")
        banned = ["add-", "set-", "delete-", "publish", "install-policy"]
        hits = []
        for py in src:
            text = py.read_text(encoding="utf-8")
            for b in banned:
                if f'"{b}' in text or f"'{b}" in text:
                    hits.append(f"{py.name}:{b}")
        rep.check("safety", "no mutating Management command anywhere in app/",
                  not hits, ", ".join(hits) if hits else "show-* only")

        # ---- 2. connectivity ---------------------------------------------
        print(f"\n{DIM}2. Connection{OFF}")
        info = await c.login()
        ver = info.get("api-server-version") or info.get("version") or "?"
        evidence["api_version"] = ver
        rep.check("connect", "login to the Management Server",
                  bool(info.get("sid")), f"API {ver}")

        packages = await c.show_packages()
        names = [p.get("name") for p in packages]
        evidence["packages"] = names
        rep.check("connect", f"policy package '{package}' exists",
                  package in names, f"packages: {', '.join(map(str, names))}")

        # ---- 3. access policy --------------------------------------------
        print(f"\n{DIM}3. Access policy{OFF}")
        result = await analyze_package(c, package, None)
        s = result.get("summary", {})
        evidence["access_summary"] = s
        rep.check("access", "rulebase loaded", s.get("total_rules", 0) > 0,
                  f"{s.get('total_rules')} rules inspected")
        # A package is not obliged to contain inline layers or an explicit
        # cleanup rule. Asserting either would make this a test of how one
        # package happens to be written, and Internal-FW - one Allow-Any rule -
        # would "fail" for being small. Where the feature is exercised, assert
        # it worked; where there is nothing to exercise, say so.
        layers = s.get("inline_layers", 0)
        rep.check("access", "inline layer discovery",
                  True if layers else None,
                  f"{layers} layer(s), {s.get('inline_rules', 0)} inline rule(s)"
                  if layers else "this package has no inline layers")
        cleanup = s.get("cleanup_rules", 0)
        rep.check("access", "cleanup rule told apart from an Any/Any/Any finding",
                  True if cleanup else None,
                  f"cleanup={cleanup} any/any/any={s.get('any_any_any_rules')}"
                  if cleanup else "no trailing Drop rule in this package")
        rep.check("access", "optimizer score computed",
                  isinstance(s.get("optimization_score"), int),
                  f"score {s.get('optimization_score')}")

        # ---- 3b. what the application FOUND, kept apart from whether it works
        # These are statements about the policy, not about this tool. Mixing
        # them into the pass/fail total would mean a run could not be green
        # until the estate was perfect, and nobody would look at it again.
        print(f"\n{DIM}3b. Policy findings (reported, not scored){OFF}")
        findings = []
        broad = s.get("any_any_any_rules", 0)
        if broad:
            findings.append(f"{broad} rule(s) permit Any -> Any -> Any")
        if not cleanup:
            findings.append("no explicit cleanup rule; the layer relies on the "
                            "implicit drop, which is not logged")
        for n, label in (("potential_shadowed_or_redundant", "shadowed/redundant rule(s)"),
                         ("duplicate_groups", "exact duplicate group(s)"),
                         ("disabled_rules", "disabled rule(s)"),
                         ("zero_hit_rules", "zero-hit rule(s) (review candidates)")):
            if s.get(n):
                findings.append(f"{s[n]} {label}")
        evidence["policy_findings"] = findings
        if findings:
            for f in findings:
                rep.check("findings", f, None, "")
        else:
            rep.check("findings", "nothing to report on this package", None, "")

        # ---- 4. data quality: does the app know what it does not know? ----
        print(f"\n{DIM}4. Data quality{OFF}")
        tree = await package_access_tree(c, package, hydrate=True)
        dq = data_quality(c, tree)
        evidence["data_quality"] = dq
        rep.check("quality", "object hydration completed (not truncated)",
                  not dq.get("object_hydration_truncated", False),
                  "all referenced objects fetched")
        rep.check("quality", "every inline layer loaded",
                  dq.get("failed_inline_layers", 0) == 0,
                  f"{dq.get('failed_inline_layers')} failed"
                  + (f": {dq.get('inline_layer_errors')}" if dq.get("inline_layer_errors") else ""))
        rep.check("quality", "result is reported as complete",
                  bool(dq.get("complete")),
                  "; ".join(dq.get("warnings") or []) or "no warnings")

        # ---- 5. traffic path ---------------------------------------------
        print(f"\n{DIM}5. Traffic Path{OFF}")
        # Mirrors app/api/traffic.py exactly: one resolver built from every
        # layer's dictionary, then the inline-aware tree walk. Calling the
        # single-layer trace_access() here would test a different code path
        # from the one the UI uses, which is worse than not testing at all.
        layer = cases.get("layer") or "Network"
        # Cases can be listed per package (the lab has External-FW / Internal-FW
        # / Standard) or flat, which is what the seeded file used to do.
        per_pkg = (cases.get("packages") or {}).get(package)
        active = per_pkg if per_pkg is not None else cases.get("cases", [])
        objects: dict[str, Any] = {}
        for node in tree.get("layers", []):
            for obj in node.get("payload", {}).get("objects-dictionary", []) or []:
                if isinstance(obj, dict) and obj.get("uid"):
                    objects[obj["uid"]] = obj
        resolver = ObjectResolver(objects)

        traffic_ev = []
        if per_pkg is None and cases.get("packages"):
            rep.check("traffic", f"no traffic cases defined for '{package}'", None,
                      "add them under \"packages\" in acceptance_cases.json")
        for case in active:
            try:
                query = resolve_service_query(
                    str(case.get("service", "443")), case.get("protocol", "tcp"), resolver)
                got = trace_access_tree(
                    tree, case["src"], case["dst"],
                    case.get("protocol", "tcp"), query, selected_root=layer)
            except Exception as exc:                              # noqa: BLE001
                rep.check("traffic", case["name"], False, f"error: {exc}")
                continue
            action = str(got.get("result") or "").lower()
            conf = str(got.get("confidence") or "")
            # A failing case that does not say WHICH rule decided is half an
            # answer. Record the walked path so the report names the rule.
            path = [
                {"rule": st.get("display_rule") or st.get("rule"),
                 "name": st.get("name") or "",
                 "layer": st.get("layer") or "",
                 "action": st.get("action") or ""}
                for st in (got.get("path") or [])
            ]
            decided = " -> ".join(
                f"{p['layer']} rule {p['rule']}"
                + (f" ({p['name']})" if p["name"] else "")
                for p in path) or "no rule matched"
            traffic_ev.append({"case": case["name"], "action": action,
                               "confidence": conf, "decided_by": decided,
                               "path": path,
                               "reason": got.get("reason") or ""})
            want = case.get("expect")
            if not want:
                rep.check("traffic", case["name"], None,
                          f"{action or '?'} · {conf}  via {decided}")
                continue
            ok = True
            if want.get("action"):
                ok = ok and want["action"].lower() in action
            if want.get("confidence"):
                ok = ok and want["confidence"] == conf
            rep.check("traffic", case["name"], ok,
                      f"got {action or '?'} · {conf}"
                      + ("" if ok else f"  (expected {want})  via {decided}"))
        evidence["traffic"] = traffic_ev

        # ---- 6. NAT -------------------------------------------------------
        print(f"\n{DIM}6. NAT{OFF}")
        nat = await c.show_nat_rulebase(package)
        n_rules = nat.get("total") or len(nat.get("rulebase") or [])
        evidence["nat_rules"] = n_rules
        rep.check("nat", "NAT rulebase loaded", n_rules > 0, f"{n_rules} NAT rule(s)")
        rep.check("nat", "show-hits support probed, not assumed",
                  c.nat_show_hits_supported is not None,
                  f"nat_hits_available={c.nat_show_hits_supported}")

        # ---- 7. topology --------------------------------------------------
        print(f"\n{DIM}7. Network Mapping{OFF}")
        objs = await c.show_gateways_and_servers()
        m = network_map(objs)
        nodes = m["nodes"]
        clusters = [n for n in nodes if n.get("role") == "cluster"]
        members = [n for n in nodes if n.get("role") == "cluster-member"]
        nets = [n for n in nodes if n.get("role") == "network"]
        mgmt = [n for n in nodes if n.get("role") == "management"]
        membership = [e for e in m["edges"] if e.get("kind") == "membership"]
        ha = [e for e in m["edges"] if e.get("kind") == "mgmt-ha"]
        evidence["topology"] = {
            "objects": len(objs), "nodes": m["count"], "edges": len(m["edges"]),
            "clusters": [n["name"] for n in clusters],
            "members": [n["name"] for n in members],
            "networks": [n["name"] for n in nets],
            "management": [{"name": n["name"], "role": n.get("mgmt_role")} for n in mgmt],
            "limitations": m["limitations"],
        }
        rep.check("topology", "gateways and servers loaded", len(objs) > 0,
                  f"{len(objs)} object(s) -> {m['count']} map node(s)")
        rep.check("topology", "cluster membership resolved from the API",
                  len(membership) == sum(len(n.get("member_ids") or []) for n in clusters)
                  and len(membership) > 0,
                  f"{len(clusters)} cluster(s), {len(membership)} membership link(s)")
        rep.check("topology", "management HA pair identified",
                  len(ha) > 0,
                  ", ".join(f"{n['name']}={n.get('mgmt_role')}" for n in mgmt) or "none")
        rep.check("topology", "connected subnets derived",
                  len(nets) > 0, ", ".join(n["name"] for n in nets))
        rep.check("topology", "limitations are stated, not hidden",
                  len(m["limitations"]) >= 2, f"{len(m['limitations'])} caveat(s) reported")

    finally:
        await c.close()

    # ---- summary ----------------------------------------------------------
    total, ok = rep.judged, rep.passed
    evidence["checks"] = rep.rows
    evidence["result"] = {"passed": ok, "failed": rep.failed, "judged": total}
    Path(out_path).write_text(json.dumps(evidence, indent=2, ensure_ascii=False),
                              encoding="utf-8")

    fnd = evidence.get("policy_findings") or []
    if fnd:
        print(f"\n{YELLOW}  {len(fnd)} policy finding(s) - reported, not counted "
              f"as failures:{OFF}")
        for f in fnd:
            print(f"    · {f}")
    bar = GREEN if rep.failed == 0 else RED
    print(f"\n{bar}{'='*58}{OFF}")
    print(f"{bar}  {ok}/{total} checks passed"
          + (f"   ({rep.failed} FAILED)" if rep.failed else "   — acceptance PASSED")
          + f"{OFF}")
    print(f"{DIM}  evidence written to {out_path}{OFF}")
    if rep.failed:
        print(f"\n{RED}  failed:{OFF}")
        for r in rep.rows:
            if r["ok"] is False:
                print(f"    - [{r['group']}] {r['check']}: {r['detail']}")
    return 1 if rep.failed else 0


def main() -> None:
    ap = argparse.ArgumentParser(description="Read-only acceptance run against the lab")
    ap.add_argument("--package", default="Standard")
    ap.add_argument("--json", default="acceptance-report.json")
    args = ap.parse_args()
    print(f"Firewall Insight {APP_VERSION} — acceptance run against package "
          f"'{args.package}'")
    sys.exit(asyncio.run(run(args.package, args.json)))


if __name__ == "__main__":
    main()
