r"""
E5v2 and B4 lab driver (Firewall Insight 4.43, NCCY2026 reviewer round, 11 Oct 2026).

This file is an EXPERIMENT HARNESS, not part of the application. Two of its
steps WRITE to the lab Management Server (setup, teardown) with an
administrator account whose password you type; app/ itself stays read-only and
its source scan is unchanged. Every write is logged to lab_changes.json so it
can be undone.

Run from the repository root (the folder that contains app/):

    .\.venv\Scripts\Activate.ps1
    python experiments\v443_patch\lab\e5_lab.py check              read-only: names exist?
    python experiments\v443_patch\lab\e5_lab.py setup  --admin USER   WRITE: test objects, E5 rules,
                                                                      read-only admin, log implied rules,
                                                                      publish + install External-FW
    python experiments\v443_patch\lab\e5_lab.py tool                read-only: Firewall Insight on every case
    python experiments\v443_patch\lab\e5_lab.py commands            writes the gateway + client command files
    python experiments\v443_patch\lab\e5_lab.py logs --minutes 60   read-only: gateway log records of the lab client
    python experiments\v443_patch\lab\e5_lab.py probe-ro            B4: read path + write attempts as the read-only admin
    python experiments\v443_patch\lab\e5_lab.py teardown --admin USER WRITE: undo setup, publish + install

Outputs go to experiments\v443_patch\lab\out\ .
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import secrets
import string
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
HERE = Path(__file__).resolve().parent
OUT = HERE / "out"
OUT.mkdir(exist_ok=True)
CASES = json.loads((HERE / "e5v2_cases.json").read_text(encoding="utf-8"))
CHANGES = OUT / "lab_changes.json"
RO_SECRET = HERE / ".ro_secret"          # gitignored; the generated read-only password
RO_NAME = "fi-readonly"

PKG = CASES["package"]
LAYER = CASES["layer"]
CLUSTER = "External-Cluster"
CLEANUP = "Cleanup rule"

# ---------------------------------------------------------------- test objects
OBJECTS = [
    ("add-network", {"name": "E5-N-VLAN10", "subnet": "192.168.10.0", "mask-length": 24}),
    ("add-host", {"name": "E5-H-Dual", "ipv4-address": "192.168.10.51", "ipv6-address": "2001:db8:10::51"}),
    ("add-host", {"name": "E5-H6-Srv", "ipv6-address": "2001:db8:20::100"}),
    ("add-service-tcp", {"name": "E5-tcp8081-sport", "port": "8081", "source-port": "40000-40100"}),
    ("add-service-tcp", {"name": "E5-tcp8082", "port": "8082"}),
    ("add-service-tcp", {"name": "E5-tcp8083", "port": "8083"}),
    ("add-time", {"name": "E5-Expired", "start-now": False,
                  "start": {"date": "01-Jan-2025", "time": "00:00"},
                  "end-never": False, "end": {"date": "01-Jan-2026", "time": "00:00"}}),
]
RULES = [   # each inserted directly above the cleanup rule, so they keep this order
    {"name": "E5-SrcPort", "source": ["E5-N-VLAN10"], "destination": ["Any"], "service": ["E5-tcp8081-sport"]},
    {"name": "E5-Time", "source": ["E5-N-VLAN10"], "destination": ["Any"], "service": ["E5-tcp8082"],
     "time": ["E5-Expired"]},
    {"name": "E5-InstallOn", "source": ["E5-N-VLAN10"], "destination": ["Any"], "service": ["E5-tcp8083"],
     "install-on": [CLUSTER]},
    {"name": "E5-IPv6", "source": ["E5-H-Dual"], "destination": ["E5-H6-Srv"], "service": ["ssh"]},
]


# ---------------------------------------------------------------- tiny write client
class Mgmt:
    """Minimal Management API client used ONLY by setup / teardown / probe-ro."""

    def __init__(self, base: str, verify: bool = False):
        import httpx
        self.base = base.rstrip("/")
        self.http = httpx.Client(verify=verify, timeout=120)
        self.sid = None

    def post(self, cmd: str, body: dict | None = None, ok_errors: tuple = ()) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.sid:
            headers["X-chkp-sid"] = self.sid
        body = dict(body or {})
        if cmd.startswith(("add-", "set-")) and cmd != "set-global-properties":
            body.setdefault("ignore-warnings", True)
        r = self.http.post(f"{self.base}/web_api/{cmd}", json=body, headers=headers)
        try:
            data = r.json()
        except Exception:
            data = {"raw": r.text[:300]}
        if r.status_code >= 400:
            msg = data.get("message") or data.get("code") or str(data)
            if any(e in str(msg) for e in ok_errors):
                return {"_skipped": msg}
            raise RuntimeError(f"{cmd}: HTTP {r.status_code}: {msg}")
        return data

    def login(self, user: str, password: str) -> dict:
        d = self.post("login", {"user": user, "password": password})
        self.sid = d["sid"]
        return d

    def wait(self, task_id: str, what: str) -> dict:
        for _ in range(240):
            t = self.post("show-task", {"task-id": task_id, "details-level": "full"})
            task = (t.get("tasks") or [{}])[0]
            status = task.get("status")
            if status not in ("in progress", "pending"):
                print(f"  {what}: {status}")
                return task
            time.sleep(3)
        raise RuntimeError(f"{what}: task did not finish")

    def publish_and_install(self) -> None:
        p = self.post("publish")
        if p.get("task-id"):
            self.wait(p["task-id"], "publish")
        inst = self.post("install-policy", {"policy-package": PKG, "access": True,
                                            "threat-prevention": False, "targets": [CLUSTER]})
        task = self.wait(inst["task-id"], f"install-policy {PKG} on {CLUSTER}")
        (OUT / f"install_{datetime.now():%Y%m%d_%H%M%S}.json").write_text(json.dumps(task, indent=1, default=str))

    def logout(self) -> None:
        try:
            self.post("logout")
        except Exception:
            pass


def mgmt_url() -> str:
    from app.api.credentials import load_credentials_on_startup
    from app.config import settings
    load_credentials_on_startup()
    return settings.checkpoint_mgmt


def log_change(entry: dict) -> None:
    data = json.loads(CHANGES.read_text()) if CHANGES.exists() else []
    entry["at"] = datetime.now().isoformat(timespec="seconds")
    data.append(entry)
    CHANGES.write_text(json.dumps(data, indent=1))


# ---------------------------------------------------------------- steps
async def _read_client():
    from app.api.credentials import load_credentials_on_startup
    from app.checkpoint import CheckPointClient
    load_credentials_on_startup()
    c = CheckPointClient()
    await c.login()
    return c


async def step_check() -> None:
    c = await _read_client()
    try:
        out = {}
        pk = await c.show_package(PKG)
        out["package_targets"] = [t.get("name") for t in (pk.get("installation-targets") or []) if isinstance(t, dict)] \
            if isinstance(pk.get("installation-targets"), list) else pk.get("installation-targets")
        out["access_layers"] = [x.get("name") for x in (pk.get("access-layers") or []) if isinstance(x, dict)]
        rb = await c.call("show-access-rulebase", {"name": LAYER, "limit": 100, "details-level": "standard"})
        rules = []

        def walk(items):
            for x in items or []:
                if x.get("type") == "access-rule":
                    rules.append((x.get("rule-number"), x.get("name")))
                walk(x.get("rulebase"))
        walk(rb.get("rulebase"))
        out["rules"] = rules
        gp = await c.show_global_properties()
        fw = (gp or {}).get("firewall") or {}
        out["implied_on"] = {k: fw.get(k + "-position", "") for k, v in fw.items()
                             if k.startswith("accept-") and not k.endswith("-position") and v is True}
        out["log_implied_rules"] = fw.get("log-implied-rules")
        gws = await c.show_gateways_and_servers()
        out["devices"] = [(g.get("name"), g.get("type"), g.get("ipv4-address")) for g in gws or []]
        print(json.dumps(out, indent=1))
        (OUT / "check.json").write_text(json.dumps(out, indent=1))
        assert CLEANUP in [n for _, n in rules], f"no rule named '{CLEANUP}' in {LAYER}"
        print("\nOK: names found. Next: setup")
    finally:
        await c.close()


def step_setup(admin: str) -> None:
    m = Mgmt(mgmt_url())
    m.login(admin, getpass.getpass(f"Password for {admin} (write account, not stored): "))
    try:
        for cmd, body in OBJECTS:
            r = m.post(cmd, body, ok_errors=("already exists", "More than one object"))
            print(f"  {cmd} {body['name']}: {'exists' if '_skipped' in r else 'created'}")
            if "_skipped" not in r:
                log_change({"op": cmd, "name": body["name"]})
        for rule in RULES:
            body = {"layer": LAYER, "position": {"above": CLEANUP}, "action": "Accept",
                    "track": {"type": "Log"}, "comments": "NCCY2026 E5v2 test rule - remove with teardown", **rule}
            m.post("add-access-rule", body)
            log_change({"op": "add-access-rule", "name": rule["name"]})
            print(f"  rule {rule['name']}: created")
        # B4: a dedicated read-only administrator. On this Security Management
        # Server the API refuses add-administrator ("only on domains of type
        # MDS"), so it is created in SmartConsole instead - see the message below.
        try:
            pw = "Fi!" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(17))
            r = m.post("add-administrator", {"name": RO_NAME, "password": pw, "must-change-password": False,
                                             "authentication-method": "check point password",
                                             "permissions-profile": "Read Only All"},
                       ok_errors=("already exists",))
            if "_skipped" not in r:
                RO_SECRET.write_text(pw)
                log_change({"op": "add-administrator", "name": RO_NAME})
                print(f"  administrator {RO_NAME} (Read Only All): created, password in {RO_SECRET.name}")
        except RuntimeError as e:
            print(f"  administrator {RO_NAME}: NOT created by API ({str(e)[:90]}...)")
            print("    -> create it in SmartConsole: Manage & Settings > Permissions & Administrators > New,")
            print(f"       name {RO_NAME}, Check Point Password, Permission Profile 'Read Only All', publish.")
        # log implied rules so a real connection an implied rule accepts leaves a record
        gp = (m.post("show-global-properties").get("firewall") or {})
        want = {"log-implied-rules": True, "accept-icmp-requests": True,
                "accept-icmp-requests-position": "before last"}
        changed = {k: v for k, v in want.items() if gp.get(k) != v}
        if changed:
            m.post("set-global-properties", {"firewall": changed})
            log_change({"op": "set-global-properties", "old": {k: gp.get(k) for k in changed}})
            print(f"  Global Properties: {changed}")
        m.publish_and_install()
        print("\nOK. Next: tool, then commands, then run the commands on the gateway and the client.")
    except Exception:
        m.post("discard")
        print("ERROR - session discarded, nothing was published.")
        raise
    finally:
        m.logout()


def step_teardown(admin: str) -> None:
    m = Mgmt(mgmt_url())
    m.login(admin, getpass.getpass(f"Password for {admin} (write account, not stored): "))
    try:
        for rule in reversed(RULES):
            r = m.post("delete-access-rule", {"layer": LAYER, "name": rule["name"]}, ok_errors=("not found",))
            print(f"  rule {rule['name']}: {'absent' if '_skipped' in r else 'deleted'}")
        for cmd, body in reversed(OBJECTS):
            dcmd = cmd.replace("add-", "delete-")
            r = m.post(dcmd, {"name": body["name"]}, ok_errors=("not found",))
            print(f"  {body['name']}: {'absent' if '_skipped' in r else 'deleted'}")
        r = m.post("delete-administrator", {"name": RO_NAME}, ok_errors=("not found",))
        print(f"  administrator {RO_NAME}: {'absent' if '_skipped' in r else 'deleted'}")
        changes = json.loads(CHANGES.read_text()) if CHANGES.exists() else []
        restore = {}
        for ch in changes:
            if ch.get("op") == "set-global-properties":
                for k, v in (ch.get("old") or {}).items():
                    restore.setdefault(k, v)
        restore = {k: v for k, v in restore.items() if v is not None}
        if restore:
            m.post("set-global-properties", {"firewall": restore})
            print(f"  Global Properties restored: {restore}")
        m.publish_and_install()
        log_change({"op": "teardown"})
        RO_SECRET.unlink(missing_ok=True)
        print("\nOK: lab restored.")
    except Exception:
        m.post("discard")
        print("ERROR - session discarded.")
        raise
    finally:
        m.logout()


async def step_tool() -> None:
    from app.policy import package_access_tree
    from app.resolver import ObjectResolver
    from app.traffic import resolve_service_query, trace_access_tree
    from app.implied import build_context
    from app.envelope import make_target
    from app.version import APP_VERSION
    c = await _read_client()
    try:
        tree = await package_access_tree(c, PKG, hydrate=True)
        objects = {o["uid"]: o for n in tree.get("layers", []) for o in n.get("payload", {}).get("objects-dictionary", []) or []
                   if isinstance(o, dict) and o.get("uid")}
        res = ObjectResolver(objects)
        gws = await c.show_gateways_and_servers()
        ctx = build_context(await c.show_global_properties(), gws)
        from app.resolver import enrich_tree
        enrich_tree(tree, gws)
        pk = await c.show_package(PKG)
        tg = pk.get("installation-targets")
        target = make_target(tg[0].get("uid", ""), tg[0].get("name", "")) if isinstance(tg, list) and len(tg) == 1 else None
        rows = []
        for case in CASES["cases"]:
            svc = str(case.get("icmp_type")) if case["proto"] == "icmp" else str(case["dport"])
            q = resolve_service_query(svc, case["proto"], res)
            o = trace_access_tree(tree, case["src"], case["dst"], case["proto"], q, LAYER, implied=ctx, target=target)
            path = [f"{s.get('layer')} {s.get('display_rule') or s.get('rule')} ({s.get('name') or ''})" for s in o.get("path") or []]
            w = o.get("winner") or {}
            rows.append({"id": case["id"], "name": case["name"], "result": o.get("result"),
                         "confidence": o.get("confidence"), "gateway_final": o.get("gateway_final"),
                         "decided_by": o.get("decided_by", "explicit" if o.get("confidence") in ("exact", "none") else None),
                         "winner_rule": w.get("display_rule") or w.get("rule"), "winner_name": w.get("name"),
                         "path": path, "implied": (o.get("implied_rules") or {}).get("state"),
                         "reason": o.get("reason")})
            print(f"{case['id']:>4}  {str(o.get('result')):<11} {str(o.get('confidence')):<9} {' -> '.join(path)}")
        out = {"app_version": APP_VERSION, "target": target and sorted(target["names"]),
               "implied_enabled": {k: ctx["positions"].get(k) for k in ctx["enabled"]},
               "run_at": datetime.now().isoformat(timespec="seconds"), "rows": rows}
        (OUT / "e5v2_tool.json").write_text(json.dumps(out, indent=1, default=str))
        print(f"\nwritten {OUT / 'e5v2_tool.json'}")
    finally:
        await c.close()


def step_commands() -> None:
    gw = ["# Run on the ACTIVE member of External-Cluster, expert mode.",
          "# First check the syntax your build accepts:  fw up_execute 2>&1 | head -40",
          "# Then run everything at once and paste the whole output back:",
          "#   bash e5v2_gateway.sh 2>&1 | tee /var/log/e5v2_upexec.txt", ""]
    for c in CASES["cases"]:
        ipp = {"tcp": 6, "udp": 17, "icmp": 1}[c["proto"]]
        v6 = ":" in c["src"]
        args = ("" if v6 else "mode=access ") + f"in_ifn={c['in_ifn']} ipp={ipp} src={c['src']} dst={c['dst']}"
        if c["proto"] == "icmp":
            args += f" type={c['icmp_type']} code={c['icmp_code']}"
        else:
            args += f" dport={c['dport']}"
            if c.get("sport"):
                args += f" sport={c['sport']}"
        tool = "fw6 up_execute" if v6 else "fw up_execute"
        gw += [f'echo "===== {c["id"]} {c["name"]}"', f"{tool} {args}", ""]
    (OUT / "e5v2_gateway.sh").write_text("\n".join(gw), newline="\n")
    extra = [ln for i, ln in enumerate(gw) if "N17" in ln or (i and "N17" in gw[i - 1])]
    (OUT / "e5v2_gateway_extra.sh").write_text("\n".join(extra) + "\n", newline="\n")
    lp = ["# Run on YOUR LAPTOP (VPN to the lab) in PowerShell. Then run:  python experiments/v443_patch/lab/e5_lab.py logs --minutes 20",
          '"laptop addresses: $((Get-NetIPAddress -AddressFamily IPv4 | ? { $_.IPAddress -notlike \'127.*\' }).IPAddress -join \', \')"', ""]
    for c in CASES.get("laptop_cases", []):
        lp += [f'"===== {c["id"]} {c["name"]}  $(Get-Date -Format o)"', c["cmd"], ""]
    (OUT / "e5v2_laptop.ps1").write_text("\n".join(lp), encoding="utf-8")
    ps = ["# Run on Client-01 (192.168.10.50) in PowerShell. Paste the whole output back.",
          "function SPORT($p, $ip, $port) {",
          "  $c = New-Object System.Net.Sockets.TcpClient([System.Net.IPEndPoint]::new([ipaddress]::Any, [int]$p))",
          "  $t = $c.ConnectAsync($ip, [int]$port); $ok = $t.Wait(4000)",
          "  \"sport=$p -> ${ip}:$port connected=$($c.Connected) finished=$ok\"; $c.Close() }", ""]
    for c in CASES["cases"]:
        if not c.get("real"):
            continue
        cmd = c["real"]
        if cmd.startswith("SPORT "):
            _, p, ip, port = cmd.split()
            cmd = f"SPORT {p} {ip} {port}"
        ps += [f'"===== {c["id"]} {c["name"]}  $(Get-Date -Format o)"', cmd, ""]
    (OUT / "e5v2_client.ps1").write_text("\n".join(ps), encoding="utf-8")
    print(f"written {OUT / 'e5v2_gateway.sh'} and {OUT / 'e5v2_laptop.ps1'}")


async def step_logs(minutes: int) -> None:
    """Read the gateway's own log records for the laptop flows, then trace each
    distinct connection with Firewall Insight and compare the deciding rule."""
    from app.policy import package_access_tree
    from app.resolver import ObjectResolver
    from app.traffic import resolve_service_query, trace_access_tree
    from app.implied import build_context
    from app.envelope import make_target
    want_dst = {c["dst"] for c in CASES.get("laptop_cases", [])}
    c = await _read_client()
    try:
        recs = []
        start = datetime.fromtimestamp(time.time() - minutes * 60).astimezone().isoformat(timespec="seconds")
        endt = datetime.now().astimezone().isoformat(timespec="seconds")
        for dst in sorted(want_dst):
            page = await c.call("show-logs", {"new-query": {
                "time-frame": "custom", "custom-start": start, "custom-end": endt,
                "max-logs-per-request": 100, "filter": f'dst:"{dst}"'}})
            while True:
                batch = page.get("logs") or []
                recs.extend(batch)
                qid = page.get("query-id")
                if not batch or not qid or len(batch) < 100 or len(recs) > 3000:
                    break
                page = await c.call("show-logs", {"query-id": qid})
        (OUT / "e5v2_logs.json").write_text(json.dumps(recs, indent=1, default=str))
        print(f"{len(recs)} log record(s) -> {OUT / 'e5v2_logs.json'}")
        # distinct connections seen by the gateway
        tree = await package_access_tree(c, PKG, hydrate=True)
        objects = {o["uid"]: o for n in tree.get("layers", []) for o in n.get("payload", {}).get("objects-dictionary", []) or []
                   if isinstance(o, dict) and o.get("uid")}
        res = ObjectResolver(objects)
        gws = await c.show_gateways_and_servers()
        ctx = build_context(await c.show_global_properties(), gws)
        from app.resolver import enrich_tree
        enrich_tree(tree, gws)
        pk = await c.show_package(PKG)
        tg = pk.get("installation-targets")
        target = make_target(tg[0].get("uid", ""), tg[0].get("name", "")) if isinstance(tg, list) and len(tg) == 1 else None
        seen, rows = set(), []
        for r in recs:
            proto = str(r.get("proto") or r.get("protocol") or "").lower()
            proto = {"6": "tcp", "17": "udp", "1": "icmp"}.get(proto, proto)
            port = r.get("service") if proto in ("tcp", "udp") else (r.get("icmp_type") or 8)
            key = (r.get("src"), r.get("dst"), proto, str(port))
            if r.get("policy_name") not in (None, PKG):
                continue          # the same packet is also logged by the inner gateway's policy
            if key in seen or proto not in ("tcp", "udp", "icmp") or r.get("dst") not in want_dst:
                continue
            mt = [m for m in (r.get("match_table") or []) if isinstance(m, dict)]
            gw_rule = ".".join(str(m.get("rule")) for m in mt) if mt else (r.get("rule") or r.get("match_id"))
            seen.add(key)
            try:
                q = resolve_service_query(str(port), proto, res)
                o = trace_access_tree(tree, r.get("src"), r.get("dst"), proto, q, LAYER, implied=ctx, target=target)
            except Exception as exc:                          # noqa: BLE001
                o = {"result": f"error: {exc}"}
            w = o.get("winner") or {}
            rows.append({"src": key[0], "dst": key[1], "proto": proto, "port": key[3],
                         "gateway_action": r.get("action"), "gateway_rule": gw_rule,
                         "gateway_rule_name": r.get("rule_name"), "gateway_layer": r.get("layer_name"),
                         "gateway_parent_rule": r.get("parent_rule"),
                         "tool_result": o.get("result"), "tool_confidence": o.get("confidence"),
                         "tool_rule": w.get("display_rule") or w.get("rule"), "tool_rule_name": w.get("name"),
                         "tool_path": [f"{s.get('display_rule') or s.get('rule')} ({s.get('name') or ''})" for s in o.get("path") or []]})
        (OUT / "e5v2_logs_compare.json").write_text(json.dumps(rows, indent=1, default=str))
        for x in rows:
            print(f"{x['src']:>15} -> {x['dst']:<15} {x['proto']}/{x['port']:<6} GW: {x['gateway_action']} rule {x['gateway_rule']} "
                  f"({x['gateway_rule_name']}) | TOOL: {x['tool_result']} {x['tool_confidence']} {x['tool_path']}")
        print(f"written {OUT / 'e5v2_logs_compare.json'}")
    finally:
        await c.close()


async def step_probe_ro() -> None:
    """B4: what can the read-only administrator do?"""
    from app.config import settings
    from app.api.credentials import load_credentials_on_startup
    load_credentials_on_startup()
    pw = RO_SECRET.read_text().strip() if RO_SECRET.exists() else getpass.getpass(f"Password of {RO_NAME}: ")
    result = {"account": RO_NAME, "profile": "Read Only All", "read": {}, "write": []}
    # 1. the application's read path, under the read-only account
    settings.checkpoint_user, settings.checkpoint_password = RO_NAME, pw
    from app.checkpoint import CheckPointClient
    from app.policy import package_access_tree
    c = CheckPointClient()
    try:
        await c.login()
        tree = await package_access_tree(c, PKG, hydrate=True)
        n = sum(len(x.get("payload", {}).get("rulebase") or []) for x in tree.get("layers", []))
        gp = await c.show_global_properties()
        gws = await c.show_gateways_and_servers()
        result["read"] = {"package_tree_layers": len(tree.get("layers", [])), "top_level_items": n,
                          "global_properties": bool(gp), "gateways": len(gws or [])}
    finally:
        await c.close()
    # 2. write attempts - each must be refused by the server
    m = Mgmt(settings.checkpoint_mgmt)
    m_login = m.login(RO_NAME, pw)
    attempts = [
        ("add-host", {"name": "E5-RO-PROBE", "ip-address": "192.0.2.1"}),
        ("set-access-rule", {"layer": LAYER, "name": CLEANUP, "comments": "read-only probe"}),
        ("delete-host", {"name": "E5-H6-Srv"}),
        ("add-access-rule", {"layer": LAYER, "position": "top", "name": "E5-RO-PROBE"}),
    ]
    accepted = False
    for cmd, body in attempts:
        try:
            m.post(cmd, body)
            accepted = True
            result["write"].append({"command": cmd, "refused": False})
        except RuntimeError as e:
            result["write"].append({"command": cmd, "refused": True, "server": str(e)[:300]})
    if accepted:
        m.post("discard")
        result["note"] = "A write was ACCEPTED in the session; the session was discarded, nothing published."
    else:
        for cmd, body in (("publish", {}), ("install-policy", {"policy-package": PKG, "access": True,
                                                               "threat-prevention": False, "targets": [CLUSTER]})):
            try:
                r = m.post(cmd, body)
                result["write"].append({"command": cmd, "refused": False, "task": r.get("task-id")})
            except RuntimeError as e:
                result["write"].append({"command": cmd, "refused": True, "server": str(e)[:300]})
        try:
            m.post("discard")
        except RuntimeError as e:   # a read-only login has no work session to discard
            result["discard"] = str(e)[:300]
    result["login"] = {k: m_login.get(k) for k in ("read-only", "session-type", "api-server-version") if k in m_login}
    m.logout()
    result["all_writes_refused"] = all(w["refused"] for w in result["write"])
    result["run_at"] = datetime.now().isoformat(timespec="seconds")
    (OUT / "b4_readonly.json").write_text(json.dumps(result, indent=1))
    print(json.dumps(result, indent=1))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["check", "setup", "tool", "commands", "logs", "probe-ro", "teardown"])
    ap.add_argument("--admin", default="admin")
    ap.add_argument("--minutes", type=int, default=60)
    a = ap.parse_args()
    if a.step == "check":
        asyncio.run(step_check())
    elif a.step == "setup":
        step_setup(a.admin)
    elif a.step == "teardown":
        step_teardown(a.admin)
    elif a.step == "tool":
        asyncio.run(step_tool())
    elif a.step == "commands":
        step_commands()
    elif a.step == "logs":
        asyncio.run(step_logs(a.minutes))
    elif a.step == "probe-ro":
        asyncio.run(step_probe_ro())


if __name__ == "__main__":
    main()
