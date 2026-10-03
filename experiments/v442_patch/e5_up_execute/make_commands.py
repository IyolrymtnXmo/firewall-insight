"""E5 - compare Firewall Insight with the gateway's own policy execution.

`fw up_execute` (R82) runs a connection through the installed Access Control
policy on the gateway without sending a packet, and prints the rule that
decided. It is the closest thing to ground truth that does not need live
traffic. This script does NOT run it. It turns the acceptance cases into the
commands for a person to run on the gateway in expert mode, and into a CSV to
write the answers in.

    python make_commands.py ..\\..\\..\\tools\\acceptance_cases.json External-FW ^
           ..\\..\\..\\acceptance-report.json

writes e5_commands_<package>.txt and e5_compare_<package>.csv next to it.
The syntax follows the R82 CLI Reference Guide ("fw up_execute"):

    fw up_execute mode=access in_ifn=<interface> ipp=6|17 src= dst= dport=
    fw up_execute mode=access in_ifn=<interface> ipp=1 src= dst= type= code=

`in_ifn` is the gateway interface the connection arrives on (for example the
VLAN 20 sub-interface for a source in VLAN 20), or `localhost` for traffic the
gateway itself sends. It is left as <IN_IFN> for you to fill in from the lab
diagram. The guide lists DCE-RPC, Content Awareness, VPN traffic and Resource
objects as unsupported, so a case that depends on one of those is a case the
gateway tool cannot settle either - record that in gateway_note.
"""
from __future__ import annotations
import csv, json, sys
from pathlib import Path

IPP = {"tcp": 6, "udp": 17}


def main(cases_path: str, package: str, report_path: str | None = None) -> None:
    cases = json.loads(Path(cases_path).read_text(encoding="utf-8"))
    active = (cases.get("packages") or {}).get(package) or cases.get("cases") or []
    said = {}
    if report_path and Path(report_path).exists():
        report = json.loads(Path(report_path).read_text(encoding="utf-8"))
        for row in (report.get("evidence") or report).get("traffic", []) or []:
            said[row.get("case")] = row

    here = Path(__file__).resolve().parent
    lines = [f"# Run on the gateway that enforces {package}, in expert mode.",
             "# One command per case; copy the action and the rule number it prints",
             f"# into e5_compare_{package}.csv.", ""]
    rows = []
    for n, case in enumerate(active, 1):
        proto = str(case.get("protocol", "tcp")).lower()
        service = str(case.get("service", ""))
        tool = said.get(case["name"], {})
        if proto in IPP and service.isdigit():
            cmd = (f"fw up_execute mode=access in_ifn=<IN_IFN> ipp={IPP[proto]} "
                   f"src={case['src']} dst={case['dst']} dport={service}")
        elif proto == "icmp" and service.isdigit():
            cmd = (f"fw up_execute mode=access in_ifn=<IN_IFN> ipp=1 "
                   f"src={case['src']} dst={case['dst']} type={service} code=0")
        else:
            cmd = f"# {proto}/{service}: a service name - look up its port, then write the command by hand"
        lines += [f"# {n}. {case['name']}", cmd, ""]
        rows.append({"n": n, "case": case["name"], "src": case["src"], "dst": case["dst"],
                     "protocol": proto, "service": service,
                     "tool_action": tool.get("action", ""), "tool_confidence": tool.get("confidence", ""),
                     "tool_decided_by": tool.get("decided_by", ""),
                     "tool_implied_rules": tool.get("implied_rules", ""),
                     "gateway_action": "", "gateway_rule": "", "gateway_note": ""})
    (here / f"e5_commands_{package}.txt").write_text("\n".join(lines), encoding="utf-8")
    with open(here / f"e5_compare_{package}.csv", "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else ["n"])
        w.writeheader(); w.writerows(rows)
    print(f"{len(rows)} case(s) -> e5_commands_{package}.txt, e5_compare_{package}.csv")


if __name__ == "__main__":
    main(*sys.argv[1:4])
