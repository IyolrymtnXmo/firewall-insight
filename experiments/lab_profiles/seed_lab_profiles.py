"""
E4 - seed test policy packages ("profiles") into the LAB Management Server.

* Separate from Firewall Insight: this script lives outside app/ and uses its
  own write-capable account (SEED_USER / SEED_PASSWORD). Firewall Insight itself
  stays read-only and is evaluated with its normal read-only account.
* Creates NEW policy packages FIT-P1..FIT-P3 and objects prefixed FIT<n>_ only.
  It refuses to touch a package that already exists and NEVER calls
  install-policy, so no gateway and no traffic is affected.
* Ground truth (expected answers) is computed offline by the independent oracle
  in e1_anomaly.py and written next to this script.

Usage (PowerShell, repo root):
  $env:SEED_USER="admin"; $env:SEED_PASSWORD="..."
  .venv\\Scripts\\python experiments\\lab_profiles\\seed_lab_profiles.py
  .venv\\Scripts\\python experiments\\lab_profiles\\seed_lab_profiles.py --delete   # remove FIT-* again
"""
from __future__ import annotations
import argparse, ipaddress, json, os, random, sys, time
from pathlib import Path
import httpx

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE)); sys.path.insert(0, str(ROOT))
from gen import payload, dim_iv, contains            # noqa: E402
from e1_anomaly import make_policy, truth            # noqa: E402

PROFILES = {"P1": (40, 11), "P2": (150, 22), "P3": (420, 33)}   # n_base, seed
FLOWS_PER_PROFILE = 300


def env_mgmt():
    url = os.environ.get("SEED_MGMT")
    if not url:
        for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
            if line.strip().upper().startswith("CHECKPOINT_MGMT="):
                url = line.split("=", 1)[1].strip().strip('"').strip("'")
    if not url:
        sys.exit("Set SEED_MGMT or CHECKPOINT_MGMT in .env")
    return url.rstrip("/")


class API:
    def __init__(self):
        self.base = env_mgmt()
        user, pw = os.environ.get("SEED_USER"), os.environ.get("SEED_PASSWORD")
        if not user or not pw:
            sys.exit("Set SEED_USER and SEED_PASSWORD (write-capable lab account)")
        self.c = httpx.Client(verify=False, timeout=120)
        r = self.c.post(f"{self.base}/web_api/login", json={"user": user, "password": pw, "session-name": "FIT-seed"})
        r.raise_for_status(); self.sid = r.json()["sid"]
        self.n = 0

    def call(self, cmd, body=None, ok_codes=()):
        for attempt in range(6):
            r = self.c.post(f"{self.base}/web_api/{cmd}", json=body or {}, headers={"X-chkp-sid": self.sid})
            if r.status_code == 403 and "too many" in r.text.lower():
                time.sleep(2 * (attempt + 1)); continue
            if r.is_error:
                code = r.json().get("code", "") if r.headers.get("content-type", "").startswith("application/json") else ""
                if code in ok_codes:
                    return r.json()
                raise RuntimeError(f"{cmd} -> HTTP {r.status_code}: {r.text[:400]}")
            self.n += 1
            return r.json()
        raise RuntimeError(f"{cmd}: rate limited")

    def publish(self):
        t = self.call("publish")
        tid = t.get("task-id")
        while tid:
            s = self.call("show-task", {"task-id": tid})
            st = s["tasks"][0]["status"]
            if st != "in progress":
                if st != "succeeded":
                    raise RuntimeError(f"publish {st}: {s}")
                break
            time.sleep(1)

    def close(self):
        try: self.call("logout")
        except Exception: pass


def cp_name(p, uid):
    return "Any" if uid == "any" else f"FIT{p}_{uid}"


def object_body(o, name):
    js = o.js; t = js["type"]
    if t == "host": return "add-host", {"name": name, "ip-address": js["ipv4-address"]}
    if t == "network": return "add-network", {"name": name, "subnet": js["subnet4"], "mask-length": js["mask-length4"]}
    if t == "address-range": return "add-address-range", {"name": name, "ip-address-first": js["ipv4-address-first"], "ip-address-last": js["ipv4-address-last"]}
    if t == "security-zone": return "add-security-zone", {"name": name}
    if t == "dynamic-object": return "add-dynamic-object", {"name": name}
    if t == "service-tcp": return "add-service-tcp", {"name": name, "port": js["port"]}
    if t == "service-udp": return "add-service-udp", {"name": name, "port": js["port"]}
    if t == "group": return "add-group", {"name": name}
    if t == "service-group": return "add-service-group", {"name": name}
    raise ValueError(t)


def depth(pool, uid, memo):
    if uid in memo: return memo[uid]
    m = pool.objs[uid].js.get("members") or []
    memo[uid] = 0 if not m else 1 + max(depth(pool, x, memo) for x in m)
    return memo[uid]


def sample_flows(rng, pool, rules, n):
    """flows + ground-truth gateway decision (knows hidden values of zones / dynamic objects)"""
    out = []
    lo, hi = int(ipaddress.ip_address("10.0.0.0")), int(ipaddress.ip_address("10.255.255.255"))
    for _ in range(n):
        if rng.random() < 0.8:
            r = rng.choice(rules)
            S = dim_iv(pool, r.src, known=False); D = dim_iv(pool, r.dst, known=False); P = dim_iv(pool, r.svc, known=False, svc=True)
            pick = lambda iv: (lambda a: rng.randint(a[0], a[1]))(rng.choice(iv))
            s, d, p = pick(S), pick(D), pick(P)
        else:
            s, d, p = rng.randint(lo, hi), rng.randint(lo, hi), rng.choice([443, 80, 22, 3389, 65536 + 53])
        win = None
        for r in rules:
            S = dim_iv(pool, r.src, known=False); D = dim_iv(pool, r.dst, known=False); P = dim_iv(pool, r.svc, known=False, svc=True)
            if S and D and P and contains(S, s) and contains(D, d) and contains(P, p):
                win = (r.num, r.action); break
        proto = "tcp" if p < 65536 else "udp"
        out.append({"src": str(ipaddress.ip_address(s)), "dst": str(ipaddress.ip_address(d)), "proto": proto,
                    "port": p if p < 65536 else p - 65536, "gt_rule": win[0] if win else None,
                    "gt_action": win[1] if win else "drop"})
    return out


def seed(api, pkey):
    n_base, seed_v = PROFILES[pkey]
    p = pkey[1:]
    pkg = f"FIT-{pkey}"
    existing = {x["name"] for x in api.call("show-packages", {"limit": 500}).get("packages", [])}
    if pkg in existing:
        print(f"{pkg} already exists - skipped (run --delete first to rebuild)"); return
    rng = random.Random(seed_v)
    pool, rules = make_policy(rng, n_base=n_base, k_pair=max(8, n_base // 5), k_comp=max(3, n_base // 15),
                              k_und=max(3, n_base // 15), k_empty=0, broad=True)
    labels = truth(pool, rules)
    pl = payload(pool, rules)
    used = [o["uid"] for o in pl["objects-dictionary"] if o["uid"] not in ("any", "accept", "drop")]
    memo = {}
    used.sort(key=lambda u: depth(pool, u, memo))
    t0 = time.time()
    for u in used:                                   # leaf objects first, then groups by nesting depth
        cmd, body = object_body(pool.objs[u], cp_name(p, u))
        body["ignore-warnings"] = True
        api.call(cmd, body)
    for u in used:                                   # fill group members (members exist by now)
        m = pool.objs[u].js.get("members")
        if m:
            cmd = "set-group" if pool.objs[u].js["type"] == "group" else "set-service-group"
            api.call(cmd, {"name": cp_name(p, u), "members": [cp_name(p, x) for x in m], "ignore-warnings": True})
    api.publish()
    api.call("add-package", {"name": pkg, "access": True, "threat-prevention": False,
                             "comments": "Firewall Insight evaluation profile - test only, never installed"})
    layer = f"{pkg} Network"
    api.call("delete-access-rule", {"layer": layer, "rule-number": 1})      # default cleanup; ours is last
    for i, r in enumerate(rules, 1):
        api.call("add-access-rule", {"layer": layer, "position": "bottom", "name": f"R{r.num}",
                                     "source": [cp_name(p, x) for x in r.src],
                                     "destination": [cp_name(p, x) for x in r.dst],
                                     "service": [cp_name(p, x) for x in r.svc],
                                     "action": "Accept" if r.action == "accept" else "Drop",
                                     "track": {"type": "Log"}, "ignore-warnings": True})
        if i % 100 == 0:
            api.publish()
    api.publish()
    flows = sample_flows(random.Random(seed_v + 1), pool, rules, FLOWS_PER_PROFILE)
    gt = {"package": pkg, "layer": layer, "rules": len(rules), "objects": len(used),
          "labels": {str(k): list(v) for k, v in labels.items()},
          "any_any_any": [r.num for r in rules if r.src == ["any"] and r.dst == ["any"] and r.svc == ["any"] and not (r is rules[-1] and r.action == "drop")],
          "flows": flows, "seed_seconds": round(time.time() - t0, 1)}
    (HERE / f"ground_truth_{pkey}.json").write_text(json.dumps(gt, indent=1), encoding="utf-8")
    print(f"{pkg}: {len(rules)} rules, {len(used)} objects, {gt['seed_seconds']} s")


def delete_all(api):
    for pkey in PROFILES:
        try: api.call("delete-package", {"name": f"FIT-{pkey}"}, ok_codes=("generic_err_object_not_found",))
        except Exception as e: print("delete-package", pkey, e)
    api.publish()
    for kind in ("group", "service-group", "host", "network", "address-range", "service-tcp", "service-udp",
                 "security-zone", "dynamic-object"):
        while True:
            objs = api.call("show-objects", {"type": kind, "filter": "FIT", "limit": 500}).get("objects", [])
            objs = [o for o in objs if o.get("name", "").startswith("FIT")]
            if not objs: break
            for o in objs:
                api.call(f"delete-{kind}", {"uid": o["uid"], "ignore-warnings": True})
            api.publish()
    print("FIT-* removed")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--profiles", nargs="*", default=list(PROFILES))
    ap.add_argument("--delete", action="store_true")
    a = ap.parse_args()
    api = API()
    try:
        if a.delete: delete_all(api)
        else:
            for pk in a.profiles: seed(api, pk)
    finally:
        api.close()
