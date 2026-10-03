"""Synthetic Check Point policy generator + independent oracle.

Everything here is written independently of app/ so that the oracle does not
share code (or bugs) with the analyzer under test.  Objects and rules are
emitted in the same JSON shape that show-access-rulebase returns.
"""
from __future__ import annotations
import ipaddress, random, itertools
from dataclasses import dataclass, field

PROTO_BASE = {"tcp": 0, "udp": 65536}
SVC_MAX = 2 * 65536 - 1
ADDR_MAX = 2**32 - 1

def merge(iv):
    iv = sorted(iv)
    out = []
    for a, b in iv:
        if out and a <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return out

def subset(a, b):
    """interval-union a subset of interval-union b (both merged)"""
    for s, e in a:
        if not any(bs <= s and e <= be for bs, be in b):
            return False
    return True

def contains(iv, x):
    return any(s <= x <= e for s, e in iv)

@dataclass
class Obj:
    uid: str
    js: dict
    iv: list | None          # known interval set, None = not statically resolvable
    hidden: list | None = None  # ground-truth interval set used by the oracle

class Pool:
    def __init__(self, rng: random.Random):
        self.rng = rng
        self.objs: dict[str, Obj] = {}
        self.n = 0
        self.add(Obj("any", {"uid": "any", "name": "Any", "type": "CpmiAnyObject"}, [(0, ADDR_MAX)], [(0, ADDR_MAX)]))
        for a in ("accept", "drop"):
            self.objs[a] = Obj(a, {"uid": a, "name": a.capitalize(), "type": "RulebaseAction"}, None)

    def uid(self, p):
        self.n += 1
        return f"{p}{self.n}"

    def add(self, o):
        self.objs[o.uid] = o
        return o.uid

    # ---- address objects -------------------------------------------------
    def network(self, cidr):
        net = ipaddress.ip_network(cidr, strict=False)
        u = self.uid("net")
        return self.add(Obj(u, {"uid": u, "name": f"N_{net}", "type": "network",
                               "subnet4": str(net.network_address), "mask-length4": net.prefixlen},
                            [(int(net.network_address), int(net.broadcast_address))]))

    def host(self, ip):
        u = self.uid("h")
        v = int(ipaddress.ip_address(ip))
        return self.add(Obj(u, {"uid": u, "name": f"H_{ip}", "type": "host", "ipv4-address": ip}, [(v, v)]))

    def arange(self, a, b):
        u = self.uid("r")
        return self.add(Obj(u, {"uid": u, "name": f"R_{a}-{b}", "type": "address-range",
                               "ipv4-address-first": a, "ipv4-address-last": b},
                            [(int(ipaddress.ip_address(a)), int(ipaddress.ip_address(b)))]))

    def group(self, members, typ="group"):
        u = self.uid("g")
        ivs = [self.objs[m].iv for m in members]
        hid = [self.objs[m].hidden if self.objs[m].hidden is not None else self.objs[m].iv for m in members]
        iv = None if any(x is None for x in ivs) else merge([p for x in ivs for p in x])
        hidden = merge([p for x in hid for p in (x or [])])
        return self.add(Obj(u, {"uid": u, "name": f"G_{u}", "type": typ, "members": list(members)}, iv, hidden))

    def opaque_addr(self, typ, hidden_cidrs):
        """security-zone / dynamic-object: statically unresolvable, hidden truth for oracle"""
        u = self.uid("z")
        hid = merge([(int(ipaddress.ip_network(c).network_address), int(ipaddress.ip_network(c).broadcast_address)) for c in hidden_cidrs])
        return self.add(Obj(u, {"uid": u, "name": f"{typ}_{u}", "type": typ}, None, hid))

    # ---- services --------------------------------------------------------
    def svc(self, proto, lo, hi=None):
        hi = lo if hi is None else hi
        u = self.uid("s")
        port = str(lo) if lo == hi else f"{lo}-{hi}"
        b = PROTO_BASE[proto]
        return self.add(Obj(u, {"uid": u, "name": f"{proto}_{port}", "type": f"service-{proto}", "port": port},
                            [(b + lo, b + hi)]))

    def dcerpc(self):
        u = self.uid("rpc")
        return self.add(Obj(u, {"uid": u, "name": f"DCE_RPC_{u}", "type": "service-dce-rpc"}, None,
                            [(135, 135), (49152, 65535)]))

    def truth(self, uid):
        o = self.objs[uid]
        return o.hidden if o.hidden is not None else o.iv

@dataclass
class Rule:
    num: int
    src: list
    dst: list
    svc: list
    action: str
    negate_src: bool = False
    tag: str = ""

    def js(self):
        d = {"type": "access-rule", "rule-number": self.num, "name": f"r{self.num}{('-' + self.tag) if self.tag else ''}",
             "enabled": True, "source": self.src, "destination": self.dst, "service": self.svc,
             "vpn": [], "action": self.action}
        if self.negate_src:
            d["source-negate"] = True
        return d

def dim_iv(pool, uids, known=True, svc=False):
    full = [(0, SVC_MAX)] if svc else [(0, ADDR_MAX)]
    if not uids:
        return None
    out = []
    for u in uids:
        if u == "any":
            return full
        x = pool.objs[u].iv if known else pool.truth(u)
        if x is None:
            return None
        out.extend(x)
    return merge(out)

def payload(pool, rules):
    used = set()
    for r in rules:
        used |= set(r.src) | set(r.dst) | set(r.svc) | {r.action}
    # objects-dictionary after the tool's hydration step: include the
    # transitive closure of group members (show-object rounds in policy.py)
    stack = list(used)
    while stack:
        u = stack.pop()
        for m in pool.objs[u].js.get("members", []) or []:
            if m not in used:
                used.add(m); stack.append(m)
    objs = [pool.objs[u].js for u in used]
    return {"rulebase": [r.js() for r in rules], "objects-dictionary": objs}

