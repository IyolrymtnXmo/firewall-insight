"""E2d - do implied rules produce wrong definite answers?

The explicit policy is fully static (networks, hosts, ranges, TCP/UDP), so
every wrong definite answer here comes from implied rules alone. The gateway
model knows Global Properties and the addresses of the Check Point devices,
and enforces implied rules in the order the R82 Security Management guide
gives:

    implied First  ->  explicit rules except the last  ->  implied Before Last
    ->  the last explicit rule  ->  implied Last  ->  implicit cleanup (drop)

It is written from the vendor documentation and shares no code with app/.
The tool is given the same Global Properties and device list in the JSON
shape of show-global-properties / show-gateways-and-servers.

usage: python e2d_implied.py <dir-containing-app/> <label>
"""
from __future__ import annotations
import sys, random, ipaddress, json, importlib, inspect
from collections import Counter
APPDIR, LABEL = sys.argv[1], sys.argv[2]
sys.path.insert(0, APPDIR)
traffic = importlib.import_module("app.traffic")
try:
    implied = importlib.import_module("app.implied")
except ModuleNotFoundError:
    implied = None
HAS_IMPLIED = "implied" in inspect.signature(traffic.trace_access_tree).parameters
from gen import Pool, Rule, payload, dim_iv
from e1_anomaly import rand_addr, rand_svc, pick

LO, HI = int(ipaddress.ip_address("10.0.0.0")), int(ipaddress.ip_address("10.255.255.255"))
CONTROL_TCP = {256, 257, 18190, 18191, 18192, 18210, 18211, 18264}
POSITIONS = ["first", "before last", "last"]
ip = lambda n: str(ipaddress.ip_address(n))


def make_estate(rng):
    """Check Point devices and Global Properties for one policy."""
    gws = [rng.randint(LO, HI) for _ in range(rng.randint(2, 3))]
    mgmt = rng.randint(LO, HI)
    gp = {
        "accept-control-connections": True,
        "accept-outgoing-packets-originating-from-gw": rng.random() < 0.8,
        "accept-outgoing-packets-originating-from-gw-position": rng.choice(POSITIONS),
        "accept-icmp-requests": rng.random() < 0.5,
        "accept-icmp-requests-position": rng.choice(POSITIONS),
        "accept-domain-name-over-udp": rng.random() < 0.5,
        "accept-domain-name-over-udp-position": rng.choice(POSITIONS),
        "accept-rip": rng.random() < 0.3,
        "accept-rip-position": rng.choice(POSITIONS),
        "accept-smart-update-connections": True,
        "log-implied-rules": False,
    }
    devices = [{"uid": f"gw{i}", "name": f"GW-{i}", "type": "simple-gateway", "ipv4-address": ip(a),
                "interfaces": [{"name": "eth0", "ipv4-address": ip(a)}]} for i, a in enumerate(gws)]
    devices.append({"uid": "mgmt", "name": "MGMT", "type": "checkpoint-host", "ipv4-address": ip(mgmt)})
    return gws, mgmt, gp, devices


def implied_hits(gp, gws, mgmt, s, d, proto, port):
    """[(position, name)] of the implied rules that match this connection."""
    out = []
    if gp["accept-control-connections"] and proto == "tcp" and port in CONTROL_TCP:
        if (s in gws and d == mgmt) or (s == mgmt and d in gws):
            out.append(("first", "accept-control-connections"))
    if gp["accept-outgoing-packets-originating-from-gw"] and s in gws:
        out.append((gp["accept-outgoing-packets-originating-from-gw-position"],
                    "accept-outgoing-packets-originating-from-gw"))
    if gp["accept-icmp-requests"] and proto == "icmp" and port == 8:
        out.append((gp["accept-icmp-requests-position"], "accept-icmp-requests"))
    if gp["accept-domain-name-over-udp"] and proto == "udp" and port == 53:
        out.append((gp["accept-domain-name-over-udp-position"], "accept-domain-name-over-udp"))
    if gp["accept-rip"] and proto == "udp" and port == 520:
        out.append((gp["accept-rip-position"], "accept-rip"))
    return out


def explicit_match(pool, r, s, d, proto, port):
    inside = lambda iv, x: any(a <= x <= b for a, b in iv)
    S = dim_iv(pool, r.src, known=False); D = dim_iv(pool, r.dst, known=False)
    if not (inside(S, s) and inside(D, d)):
        return False
    if r.svc == ["any"]:
        return True
    if proto == "icmp":
        return False                         # generated services are TCP/UDP only
    P = dim_iv(pool, r.svc, known=False, svc=True)
    return inside(P, port + (0 if proto == "tcp" else 65536))


def gateway(pool, rules, gp, gws, mgmt, s, d, proto, port):
    hits = implied_hits(gp, gws, mgmt, s, d, proto, port)
    at = lambda pos: next((name for p, name in hits if p == pos), None)
    if at("first"):
        return ("implied", at("first"), "accept")
    for r in rules[:-1]:
        if explicit_match(pool, r, s, d, proto, port):
            return ("explicit", r.num, r.action)
    if at("before last"):
        return ("implied", at("before last"), "accept")
    if rules and explicit_match(pool, rules[-1], s, d, proto, port):
        return ("explicit", rules[-1].num, rules[-1].action)
    if at("last"):
        return ("implied", at("last"), "accept")
    return ("explicit", None, "drop")


def sample(rng, pool, rules, gws, mgmt, share):
    """`share` of the connections are ones an implied rule may concern."""
    if rng.random() < share:
        kind = rng.choice(["from-gw", "from-gw", "control", "icmp", "dns", "rip"])
        if kind == "from-gw":
            return rng.choice(gws), rng.randint(LO, HI), "tcp", rng.choice([443, 80, 53, 123])
        if kind == "control":
            a, b = rng.choice(gws), mgmt
            if rng.random() < 0.5:
                a, b = b, a
            return a, b, "tcp", rng.choice(sorted(CONTROL_TCP))
        proto, port = {"icmp": ("icmp", 8), "dns": ("udp", 53), "rip": ("udp", 520)}[kind]
        return rng.randint(LO, HI), rng.randint(LO, HI), proto, port
    if rng.random() < 0.8:
        r = rng.choice(rules)
        S = dim_iv(pool, r.src, known=False); D = dim_iv(pool, r.dst, known=False)
        pt = lambda iv: rng.randint(*rng.choice(iv))
        if r.svc == ["any"]:
            p = rng.choice([443, 80, 22])
        else:
            p = pt(dim_iv(pool, r.svc, known=False, svc=True))
        return pt(S), pt(D), ("tcp" if p < 65536 else "udp"), (p if p < 65536 else p - 65536)
    return rng.randint(LO, HI), rng.randint(LO, HI), "tcp", rng.choice([443, 80, 22, rng.randrange(1, 65536)])


def run(share, n_pol=30, n_rules=40, flows=400, seed=17):
    rng = random.Random(seed); C = Counter(); detail = Counter()
    for _ in range(n_pol):
        pool = Pool(rng)
        rules = [Rule(0, pick(rng, rand_addr, pool), pick(rng, rand_addr, pool), pick(rng, rand_svc, pool),
                      "accept" if rng.random() < 0.7 else "drop") for _ in range(n_rules)]
        if rng.random() < 0.5:                       # half the policies end in an explicit cleanup
            rules.append(Rule(0, ["any"], ["any"], ["any"], "drop", tag="cleanup"))
        for n, r in enumerate(rules, 1):
            r.num = n
        gws, mgmt, gp, devices = make_estate(rng)
        pl = payload(pool, rules)
        tree = {"root_layer": "L", "root_layers": ["L"],
                "layers": [{"name": "L", "depth": 0, "path": "L", "display_prefix": "", "payload": pl}]}
        ctx = implied.build_context({"firewall": gp}, devices) if (implied and HAS_IMPLIED) else None
        for _ in range(flows):
            s, d, proto, port = sample(rng, pool, rules, gws, mgmt, share)
            gt = gateway(pool, rules, gp, gws, mgmt, s, d, proto, port)
            q = {"atoms": [(proto, port, port)], "protocol": proto, "port": port, "display": f"{proto}/{port}"}
            kw = {"implied": ctx} if HAS_IMPLIED else {}
            o = traffic.trace_access_tree(tree, ip(s), ip(d), proto, q, "L", **kw)
            if o.get("matched") and o.get("confidence") == "exact":
                w = o["winner"]
                ok = gt[0] == "explicit" and gt[1] == w["rule"] and gt[2] == str(w["action"]).lower()
                C["correct" if ok else "wrong"] += 1
                if not ok:
                    detail["wrong_action" if gt[2] != str(w["action"]).lower() else "wrong_rule_same_action"] += 1
            elif not o.get("matched") and o.get("confidence") == "none":
                ok = gt[0] == "explicit" and gt[1] is None
                C["correct" if ok else "wrong"] += 1
                if not ok:
                    detail["wrong_action" if gt[2] != "drop" else "wrong_rule_same_action"] += 1
            else:
                C["abstain"] += 1
                detail["abstain_but_explicit_decided" if gt[0] == "explicit" else "abstain_and_implied_decided"] += 1
    n = sum(C.values())
    return {"implied_share": share, "flows": n, "W": 100 * C["wrong"] / n, "A": 100 * C["abstain"] / n,
            "counts": dict(C), "detail": dict(detail)}


if __name__ == "__main__":
    out = {"label": LABEL, "implied_gate": HAS_IMPLIED, "e2d": [run(s) for s in (0.1, 0.2, 0.3)]}
    print(json.dumps(out))
    json.dump(out, open(f"e2d_implied_{LABEL}.json", "w"), indent=1)
