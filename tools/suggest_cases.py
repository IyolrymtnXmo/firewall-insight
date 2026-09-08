r"""
Propose acceptance cases from the live rulebase - read-only, and it proposes.

Chapter 4 homework (c) asks for acceptance cases covering the rules that have
none. Writing those by hand means inventing addresses, and an invented address
usually falls through to the cleanup rule, so the case passes while testing
nothing. Guessing what a verdict "should" be is exactly what README principle
11 forbids.

So this reads each rule's own objects and derives one flow that rule is
actually about: an address inside its source, an address inside its
destination, and one service it permits. It then runs the same trace the UI
runs and prints what the application says today.

It does NOT write acceptance_cases.json, and every case it prints carries
"expect": null - recorded, never judged. Promoting one to a real expectation
is a human decision made against SmartConsole or a gateway log, which stays
the only oracle. The tool removes the typing, not the judgement.

Usage
-----
    .\.venv\Scripts\Activate.ps1
    python -m tools.suggest_cases --package External-FW
    python -m tools.suggest_cases --package External-FW --only 1,2,3,7
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from ipaddress import ip_address
from typing import Any

from app.checkpoint import CheckPointClient
from app.policy import package_access_tree
from app.resolver import ObjectResolver
from app.traffic import resolve_service_query, trace_access_tree
from app.version import APP_VERSION

GREEN, YELLOW, DIM, OFF = "\033[32m", "\033[33m", "\033[2m", "\033[0m"


def _rules(items):
    out = []
    for x in items or []:
        if not isinstance(x, dict):
            continue
        if x.get("type") == "access-rule":
            out.append(x)
        if isinstance(x.get("rulebase"), list):
            out.extend(_rules(x["rulebase"]))
    return out


# An object that covers /8 or more is Any wearing a name. The first live run
# proved why this matters: `All_Internet` is 0.0.0.0/0, and sampling it gave
# `0.0.0.1` - an address that is inside the object, looks like a real test
# input, and tests nothing at all. A human has to choose which off-lab address
# means something here, so say so instead of emitting a number.
# 2**24 addresses = a /8. Counting addresses, not the gap between the
# endpoints: a /8 spans 16,777,215 steps but holds 16,777,216 addresses.
TOO_BROAD = 2 ** 24


def _sample_address(values: Any, res: ObjectResolver) -> tuple[str | None, str]:
    """One address inside this field, and where it came from."""
    broad = []
    for uid in res.uids(values):
        if res.is_any_uid(uid):
            continue
        atoms, _complete = res.address_atoms_partial(uid)
        for atom in atoms:
            if atom.version != 4:
                continue
            if atom.end - atom.start + 1 >= TOO_BROAD:
                broad.append(res.describe_uid(uid))
                continue
            # A network's first address is the network address itself, which no
            # host ever holds. Step one in, and only when the range is big
            # enough for that to still be inside it.
            value = atom.start + 1 if atom.end > atom.start else atom.start
            return str(ip_address(value)), res.describe_uid(uid)
    if broad:
        return None, (f"{', '.join(sorted(set(broad)))} covers /8 or more - every "
                      "address is inside it, so a sample proves nothing")
    return None, "Any (or no address this resolver can model)"


def _sample_service(values: Any, res: ObjectResolver) -> tuple[str | None, str, str]:
    """(service, protocol, provenance) for one service this rule permits."""
    for uid in res.uids(values):
        if res.is_any_uid(uid):
            continue
        atoms, _complete = res.service_atoms_partial(uid)
        for atom in atoms:
            if atom.proto in ("tcp", "udp"):
                return str(atom.start), atom.proto, res.describe_uid(uid)
            if atom.proto == "icmp":
                # ICMP carries a message type, not a port. Chapter 4 flags this
                # as the trap in this homework, and 0-255 means "any type", so
                # echo-request is the useful representative.
                value = atom.start if atom.end - atom.start < 255 else 8
                return str(value), "icmp", res.describe_uid(uid)
    return None, "tcp", "Any (or no service this resolver can model)"


async def run(package: str, only: set[int] | None) -> int:
    c = CheckPointClient()
    try:
        await c.login()
        tree = await package_access_tree(c, package, hydrate=True)
        layers = tree.get("layers", [])
        if not layers:
            print("No Access layers loaded.")
            return 1

        objects: dict[str, Any] = {}
        for node in layers:
            for o in node.get("payload", {}).get("objects-dictionary", []) or []:
                if isinstance(o, dict) and o.get("uid"):
                    objects[o["uid"]] = o
        res = ObjectResolver(objects)
        root = layers[0].get("name")

        proposed = []
        for node in layers:
            prefix = str(node.get("display_prefix") or "")
            for rule in _rules(node.get("payload", {}).get("rulebase", [])):
                number = rule.get("rule-number")
                display = f"{prefix}.{number}" if prefix else str(number)
                # Match the DISPLAY number. An inline child's own rule-number
                # restarts at 1 inside its layer, so `--only 1,2,3` used to drag
                # in rules 8.1, 8.2 and 8.3 from the Inline Layer as well.
                if only is not None and display not in only:
                    continue
                name = rule.get("name") or f"Rule {display}"

                src, src_from = _sample_address(rule.get("source"), res)
                dst, dst_from = _sample_address(rule.get("destination"), res)
                service, proto, svc_from = _sample_service(rule.get("service"), res)

                missing = [label for label, value in
                           (("source", src), ("destination", dst), ("service", service))
                           if value is None]
                if missing:
                    print(f"{YELLOW}[skip]{OFF} rule {display} ({name}): "
                          f"{', '.join(missing)} is Any or unmodellable - "
                          f"pick a real address by hand.")
                    continue

                query = resolve_service_query(service, proto, res)
                got = trace_access_tree(tree, src, dst, proto, query, selected_root=root)
                verdict = str(got.get("result") or "?")
                confidence = str(got.get("confidence") or "")
                decided = " -> ".join(
                    f"{s.get('layer')} rule {s.get('display_rule')}"
                    for s in (got.get("path") or [])) or "no rule matched"

                print(f"{GREEN}[case]{OFF} rule {display} ({name})")
                print(f"       {src} -> {dst} {proto}/{service}")
                print(f"       {DIM}from {src_from} / {dst_from} / {svc_from}{OFF}")
                print(f"       today: {verdict} · {confidence}  via {decided}")
                if decided and f"rule {display}" not in decided:
                    print(f"       {YELLOW}note: an earlier rule decides this flow, so the "
                          f"case does not exercise rule {display}{OFF}")

                proposed.append({
                    "name": f"{name} (rule {display})",
                    "src": src, "dst": dst, "protocol": proto, "service": service,
                    "expect": None,
                    "why": (f"derived from rule {display} source={src_from} "
                            f"destination={dst_from} service={svc_from}; "
                            f"confirm against SmartConsole before setting expect"),
                })

        print(f"\n{DIM}Paste into tools/acceptance_cases.json under "
              f'"packages" -> "{package}", then set "expect" only for the flows '
              f"you have confirmed:{OFF}\n")
        print(json.dumps(proposed, indent=2, ensure_ascii=False))
        return 0
    finally:
        await c.close()


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Propose acceptance cases from the live rulebase (read-only)")
    ap.add_argument("--package", default="Standard")
    ap.add_argument("--only", default="",
                    help="comma-separated DISPLAY rule numbers, e.g. 1,2,3,7 or 8.1")
    args = ap.parse_args()
    only = {x.strip() for x in args.only.split(",") if x.strip()} or None
    print(f"Firewall Insight {APP_VERSION} - candidate acceptance cases for "
          f"package '{args.package}'\n")
    sys.exit(asyncio.run(run(args.package, only)))


if __name__ == "__main__":
    main()
