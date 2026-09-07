r"""
Runs every claim made in Chapter 3 of the learning guide against the real
modules, and prints the result.

The guide quotes this script's output verbatim. If the output stops matching
what the guide says, the guide is out of date - that is the point: a chapter
about how the resolver behaves should not be able to drift away from how the
resolver actually behaves without somebody noticing.

Read-only. No network, no Management API, no .env needed - the objects below
are a hand-built dictionary that reproduces the shapes seen in the lab.

    python -m tools.ch3_demo
"""
from app.resolver import ObjectResolver, AddrAtom, PortAtom, needs_detail
from app.analyzer import analyze_rulebase, is_cleanup_rule, _intervals_cover, _dimension_cover

O = {
 "any":  {"uid":"any","name":"Any","type":"CpmiAnyObject"},
 "h1":   {"uid":"h1","name":"AD-Server","type":"host","ipv4-address":"192.168.10.10"},
 "n10":  {"uid":"n10","name":"LAB-VLAN10","type":"network","subnet4":"192.168.10.0","mask-length4":24},
 "n20":  {"uid":"n20","name":"LAB-VLAN20","type":"network","subnet4":"192.168.20.0","mask-length4":24},
 "n8":   {"uid":"n8","name":"RFC1918-10","type":"network","subnet4":"10.0.0.0","mask-length4":8},
 "n24":  {"uid":"n24","name":"Ten-Ten-Twenty","type":"network","subnet4":"10.10.20.0","mask-length4":24},
 "rng":  {"uid":"rng","name":"Pool","type":"address-range","ipv4-address-first":"192.168.10.50","ipv4-address-last":"192.168.10.60"},
 "grp":  {"uid":"grp","name":"LAB-Internal-Nets","type":"group","members":["n10","n20"]},
 "thin": {"uid":"thin","name":"LAB-Internal-Nets","type":"group"},          # in dict, no members
 "dyn":  {"uid":"dyn","name":"Branch-Office","type":"dynamic-object"},
 "grpX": {"uid":"grpX","name":"Mixed","type":"group","members":["n10","dyn"]},
 "https":{"uid":"https","name":"https","type":"service-tcp","port":"443"},
 "ldap": {"uid":"ldap","name":"ldap","type":"service-tcp","port":"389"},
 "hi":   {"uid":"hi","name":"high-ports","type":"service-tcp","port":">1023"},
 "ping": {"uid":"ping","name":"echo-request","type":"service-icmp","icmp-type":8},
 "rpc":  {"uid":"rpc","name":"ALL_DCE_RPC","type":"service-dce-rpc"},
 "ad":   {"uid":"ad","name":"AD-Services","type":"service-group","members":["ldap","rpc"]},
 "icmpg":{"uid":"icmpg","name":"ICMP-Only","type":"service-group","members":["ping"]},
 "acc":  {"uid":"acc","name":"Accept","type":"RulebaseAction"},
 "drp":  {"uid":"drp","name":"Drop","type":"RulebaseAction"},
}
r = ObjectResolver(O)

def line(t): print("\n" + "="*4, t)

line("1  needs_detail: 'in the dictionary' != 'usable'")
for k in ("grp","thin","any","acc","dyn"):
    print(f"  {O[k]['name']:<20} type={O[k]['type']:<18} needs_detail={needs_detail(O[k])}")

line("2  AddrAtom = integers, so containment is <= and >=")
for k in ("h1","n10","rng","n8"):
    a=r.address_atoms(k)[0]
    print(f"  {O[k]['name']:<16} {a.start:>12} .. {a.end:>12}  (v{a.version})")
print("  10.0.0.0/8 covers 10.10.20.0/24 ?",
      _intervals_cover(r.address_atoms("n8"), r.address_atoms("n24")))
print("  10.10.20.0/24 covers 10.0.0.0/8 ?",
      _intervals_cover(r.address_atoms("n24"), r.address_atoms("n8")))

line("3  partial vs strict on a group with one unmodellable member")
print("  partial(Mixed) =", r.address_atoms_partial("grpX"))
print("  strict (Mixed) =", r.address_atoms("grpX"))
print("  blocked by     :", r.unmodelled_names("grpX","address"))

line("4  the real v4.10 bug: AD-Services -> ALL_DCE_RPC")
print("  partial(AD-Services) =", r.service_atoms_partial("ad"))
print("  strict (AD-Services) =", r.service_atoms("ad"))
print("  blocked by           :", r.unmodelled_names("ad","service"))
print("  -> does TCP/389 hit a partial atom?",
      any(a.proto=="tcp" and a.start<=389<=a.end for a in r.service_atoms_partial("ad")[0]))

line("5  ICMP modelled = confident NO instead of unknown")
print("  ICMP-Only atoms:", r.service_atoms_partial("icmpg"))
atoms,_ = r.service_atoms_partial("icmpg")
print("  TCP/443 inside any of them?",
      any((a.proto in ('tcp','any')) and a.start<=443<=a.end for a in atoms))

line("6  port syntax the resolver understands")
for k in ("https","hi"):
    print(f"  {O[k]['name']:<12} port={O[k]['port']:<8} -> {r.service_atoms(k)}")

line("7  is_cleanup_rule is POSITIONAL, not by name")
mk=lambda n,act,name="": {"type":"access-rule","rule-number":n,"name":name,"enabled":True,
                          "source":["any"],"destination":["any"],"service":["any"],"vpn":[],"action":act}
rules=[mk(1,"acc"), mk(2,"acc"), mk(3,"drp","Cleanup rule")]
for x in rules: print(f"  rule {x['rule-number']} ({x['name'] or '-'}): cleanup={is_cleanup_rule(x,rules,r)}")
mid=[mk(1,"drp","Cleanup rule"), mk(2,"acc")]
print("  a rule NAMED 'Cleanup rule' but not last:", is_cleanup_rule(mid[0],mid,r))

line("8  end to end on a small rulebase")
pay={"objects-dictionary":list(O.values()),"rulebase":[
  {"type":"access-rule","rule-number":1,"name":"Broad","enabled":True,
   "source":["n8"],"destination":["any"],"service":["any"],"vpn":[],"action":"acc"},
  {"type":"access-rule","rule-number":2,"name":"Narrow (shadowed)","enabled":True,
   "source":["n24"],"destination":["h1"],"service":["https"],"vpn":[],"action":"acc"},
  {"type":"access-rule","rule-number":3,"name":"Dup A","enabled":True,
   "source":["n10"],"destination":["h1"],"service":["https"],"vpn":[],"action":"acc"},
  {"type":"access-rule","rule-number":4,"name":"Dup B","enabled":True,
   "source":["n10"],"destination":["h1"],"service":["https"],"vpn":[],"action":"acc"},
  {"type":"access-rule","rule-number":5,"name":"Off","enabled":False,
   "source":["n10"],"destination":["h1"],"service":["https"],"vpn":[],"action":"acc"},
  {"type":"access-rule","rule-number":6,"name":"Cleanup rule","enabled":True,
   "source":["any"],"destination":["any"],"service":["any"],"vpn":[],"action":"drp"},
]}
out=analyze_rulebase(pay)
import json; print(json.dumps(out["summary"], indent=2))
for s in out["findings"]["shadowing"]:
    print(f"  rule {s['rule']} covered by {s['covered_by']}: {s['classification']} "
          f"[{s['source_reason']} / {s['destination_reason']} / {s['service_reason']}]")
print("  duplicate groups:", [d["rule_numbers"] for d in out["findings"]["duplicates"]])
print("  cleanup:", out["findings"]["cleanup_rule_numbers"],
      " any/any/any:", out["findings"]["any_any_any_rule_numbers"])

line("9  the v4.17 guard: an empty later-side is unknown, not covered")
print("  _dimension_cover(source=[n10], later=[]) ->",
      _dimension_cover(["n10"], [], r, "address"))
# the helper is still vacuously true - that is WHY the guard lives one
# level up, in _dimension_cover, where "nothing to check" can be told
# apart from "every check passed".
print("  _intervals_cover(earlier, later=[]) ->",
      _intervals_cover(r.address_atoms("n10"), []), "  <- guarded upstream")
