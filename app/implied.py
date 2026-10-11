"""
v4.42 - implied rules stop a result from being reported as definite.

Implied rules are generated from Global Properties, not written in the
rulebase, so `show-access-rulebase` never returns them. The gateway still
enforces them, and it places each one First, Before Last or Last relative to
the explicit rules. A rule placed First decides before rule 1 is looked at.

v4.41 attached a warning to every trace and left the result marked exact.
That is not enough: a warning next to "Drop, confidence exact" is still a
definite answer about a connection an implied rule may have accepted.

v4.42 reads the two things it needs, both with show- commands:

  * show-global-properties      which implied rules are switched on
  * show-gateways-and-servers   which addresses belong to Check Point devices

and then decides, per connection, whether an implied rule could apply:

  clear     no implied rule this module knows of can match the connection;
            the explicit-rulebase result stands
  possible  an implied rule may match it; the result is demoted
  unread    Global Properties or the gateway list could not be read, or a
            switched-on implied rule is one this module does not recognise;
            every result is demoted

The test is deliberately wider than the implied rules themselves. Most of
them (control connections, outgoing packets from the gateway, Remote Access,
SmartUpdate, VRRP, gateway administration) only concern traffic that starts
or ends on a Check Point device, and blades add more of the same kind that
have no checkbox at all. So a connection with a Check Point device at either
end is never reported as definite, whatever the checkboxes say. The remaining
implied rules are matched by service.

This module does not model what an implied rule decides. It only answers
"could one apply?", which is all that is needed to keep a wrong answer from
being called definite.
"""

from __future__ import annotations

from ipaddress import ip_address, ip_network
from typing import Any

# Implied rules that only concern traffic to or from a Check Point device.
# They are covered by the endpoint test, so being switched on adds nothing.
ENDPOINT_KEYS = {
    "accept-control-connections",
    "accept-ips1-management-connections",
    "accept-remote-access-control-connections",
    "accept-smart-update-connections",
    "accept-outgoing-packets-originating-from-gw",
    "accept-outgoing-packets-originating-from-connectra-gw",
    "accept-outgoing-packets-to-cp-online-services",
    "accept-dynamic-addr-modules-outgoing-internet-connections",
    "accept-identity-awareness-control-connections",
    "accept-incoming-traffic-to-dhcp-and-dns-services-of-gws",
    "accept-vrrp-packets-originating-from-cluster-members",
    "accept-web-and-ssh-connections-for-gw-administration",
}

# v4.43: the part of each service implied rule whose decision is modelled.
# A connection whose service lies wholly inside one of these sets, and that
# no other implied rule can touch, is decided by position (First / Before
# Last / Last) instead of being demoted. ICMP is limited to echo-request:
# the other members of icmp-requests are not claimed.
DECIDE_KEYS: dict[str, tuple[str, int, int]] = {
    "accept-icmp-requests": ("icmp", 8, 8),
    "accept-domain-name-over-udp": ("udp", 53, 53),
    "accept-domain-name-over-tcp": ("tcp", 53, 53),
    "accept-rip": ("udp", 520, 520),
}
POSITIONS = ("first", "before last", "last")

# Implied rules that match by service, whatever the endpoints are.
# key -> (protocols, first port/type, last port/type)
SERVICE_KEYS: dict[str, tuple[tuple[str, ...], int, int]] = {
    "accept-icmp-requests": (("icmp", "icmp6"), 0, 255),
    "accept-domain-name-over-udp": (("udp",), 53, 53),
    "accept-domain-name-over-tcp": (("tcp",), 53, 53),
    "accept-rip": (("udp",), 520, 520),
}


def _addresses_of(obj: dict[str, Any]) -> tuple[list[tuple[int, int]], bool]:
    """(addresses as (int, version), has_dynamic_address) for one device."""
    out: list[tuple[int, int]] = []

    def add(value: Any) -> None:
        if not value:
            return
        try:
            a = ip_address(str(value))
        except ValueError:
            return
        out.append((int(a), a.version))

    for key in ("ipv4-address", "ipv6-address", "ip-address"):
        add(obj.get(key))
    for itf in obj.get("interfaces") or []:
        if isinstance(itf, dict):
            for key in ("ipv4-address", "ipv6-address", "ip-address"):
                add(itf.get(key))
    for member in obj.get("cluster-members") or []:
        if isinstance(member, dict):
            more, _dyn = _addresses_of(member)
            out.extend(more)
    return out, bool(obj.get("dynamic-ip"))


def build_context(global_properties: Any, gateways: Any) -> dict[str, Any]:
    """
    Turn the two API answers into what assess() needs.

    Either argument may be None (the read failed). That is recorded, not
    hidden: assess() then answers `unread` for every connection.
    """
    ctx: dict[str, Any] = {
        "properties_read": False, "gateways_read": False,
        "enabled": [], "unrecognised": [], "positions": {},
        "addresses": set(), "dynamic_devices": [], "problems": [],
    }

    firewall = None
    if isinstance(global_properties, dict):
        firewall = global_properties.get("firewall")
    if isinstance(firewall, dict):
        ctx["properties_read"] = True
        for key, value in firewall.items():
            if not key.startswith("accept-") or key.endswith("-position"):
                continue
            if value is not True:
                continue
            ctx["enabled"].append(key)
            ctx["positions"][key] = str(firewall.get(key + "-position") or "")
            if key not in ENDPOINT_KEYS and key not in SERVICE_KEYS:
                ctx["unrecognised"].append(key)
    else:
        ctx["problems"].append("Global Properties were not read")

    if isinstance(gateways, list):
        ctx["gateways_read"] = True
        for obj in gateways:
            if not isinstance(obj, dict):
                continue
            found, dynamic = _addresses_of(obj)
            ctx["addresses"].update(found)
            if dynamic or not found:
                ctx["dynamic_devices"].append(str(obj.get("name") or obj.get("uid") or "?"))
    else:
        ctx["problems"].append("the list of gateways and servers was not read")

    return ctx


def _endpoint_addresses(text: str) -> list[tuple[int, int]] | None:
    """Addresses a trace endpoint stands for; None when it cannot be decided."""
    raw = str(text or "").strip()
    try:
        a = ip_address(raw)
        return [(int(a), a.version)]
    except ValueError:
        pass
    try:
        n = ip_network(raw, strict=False)
        if n.num_addresses == 1:
            return [(int(n.network_address), n.version)]
        return None
    except ValueError:
        pass
    # A hostname: use the answers the tracer itself used.
    from .matching import _domain_candidates
    ips, _error = _domain_candidates(raw)
    out = []
    for value in ips:
        try:
            a = ip_address(value)
            out.append((int(a), a.version))
        except ValueError:
            continue
    return out or None


def assess(ctx: dict[str, Any] | None, src: str, dst: str, service_query: dict[str, Any]) -> dict[str, Any]:
    """Could an implied rule apply to this connection?"""
    if ctx is None:
        return {"state": "unread", "reasons": ["Implied rules were not assessed for this trace."], "rules": []}

    if ctx.get("problems"):
        return {"state": "unread", "rules": [],
                "reasons": ["Implied rules cannot be assessed: " + "; ".join(ctx["problems"]) + "."]}

    if ctx.get("unrecognised"):
        return {"state": "unread", "rules": list(ctx["unrecognised"]),
                "reasons": ["Global Properties switch on implied rule(s) this version does not recognise: "
                            + ", ".join(ctx["unrecognised"]) + "."]}

    reasons: list[str] = []
    rules: list[str] = []
    other = False            # a reason this module cannot turn into a decision
    service_hits: list[dict[str, Any]] = []

    if ctx.get("dynamic_devices"):
        other = True
        reasons.append(
            "Check Point device(s) with no fixed address ("
            + ", ".join(ctx["dynamic_devices"][:4])
            + "): it cannot be shown that this connection does not start or end on one.")

    for label, text in (("source", src), ("destination", dst)):
        found = _endpoint_addresses(text)
        if found is None:
            other = True
            reasons.append(f"The {label} {text} has no single address, so it cannot be "
                           "shown that it is not a Check Point device.")
            continue
        if any(item in ctx["addresses"] for item in found):
            other = True
            reasons.append(
                f"The {label} {text} is an address of a Check Point gateway or server. "
                "Implied rules for control, administration and gateway-originated "
                "traffic are enforced outside the rulebase the API returns.")
            rules.extend(k for k in ctx.get("enabled", []) if k in ENDPOINT_KEYS)

    atoms = service_query.get("atoms") or []
    for key in ctx.get("enabled", []):
        if key not in SERVICE_KEYS:
            continue
        protos, first, last = SERVICE_KEYS[key]
        for proto, start, end in atoms:
            if proto in protos or proto == "any":
                if not (end < first or start > last):
                    position = ctx["positions"].get(key) or "position not reported"
                    reasons.append(f"Implied rule {key} is switched on ({position}) and matches this service.")
                    rules.append(key)
                    service_hits.append({"rule": key, "position": ctx["positions"].get(key) or "",
                                         "whole": _inside_decide_set(key, atoms)})
                    break

    if reasons:
        out = {"state": "possible", "reasons": reasons, "rules": sorted(set(rules))}
        if not other and len(service_hits) == 1 and service_hits[0]["whole"] \
                and service_hits[0]["position"] in POSITIONS:
            out["decidable"] = {"rule": service_hits[0]["rule"], "position": service_hits[0]["position"]}
        return out
    return {"state": "clear", "rules": [],
            "reasons": ["No implied rule that is switched on can match this connection."]}


def _inside_decide_set(key: str, atoms: list) -> bool:
    """Does every atom of the query lie inside the modelled part of `key`?"""
    if key not in DECIDE_KEYS or not atoms:
        return False
    proto, lo, hi = DECIDE_KEYS[key]
    return all(p == proto and lo <= a and b <= hi for p, a, b in atoms)


def decide(out: dict[str, Any], decidable: dict[str, str], last_rule: Any) -> str | None:
    """
    v4.43 - who decides when one service implied rule matches the connection?

    The gateway order is: implied First, explicit rules except the last,
    implied Before Last, the last explicit rule, implied Last, implicit
    cleanup. `out` is the explicit result of a single Ordered Layer.
    Returns "implied", "explicit", or None when the explicit result is not
    definite (then the caller demotes as before).
    """
    conf = out.get("confidence")
    if conf not in ("exact", "none"):
        return None
    position = decidable["position"]
    if position == "first":
        return "implied"
    if conf == "none":                    # no explicit rule matched
        return "implied"
    if position == "last":
        return "explicit"
    # before last: the explicit rule reached through the root layer decides
    # unless it is the last explicit rule of that layer.
    path = out.get("path") or []
    top = path[0].get("rule") if path else None
    if top is None or last_rule is None:
        return None
    return "implied" if str(top) == str(last_rule) else "explicit"


def apply(out: dict[str, Any], assessment: dict[str, Any], last_rule: Any = None) -> dict[str, Any]:
    """
    Fold the assessment into a trace result.

    `clear` leaves the result as it is. Anything else removes the definite
    status: a matched rule becomes `inferred`, and "no rule matched" becomes
    UNVERIFIED, because an implied rule may have accepted the connection.
    """
    out["implied_rules"] = assessment
    if assessment.get("state") == "clear":
        return out

    dec = assessment.get("decidable")
    who = decide(out, dec, last_rule) if dec else None
    if who == "explicit":
        assessment["state"] = "resolved"
        assessment["reasons"] = list(assessment.get("reasons") or []) + [
            f"Implied rule {dec['rule']} is placed {dec['position']}; the explicit result above is "
            "enforced before it."]
        return out
    if who == "implied":
        assessment["state"] = "decides"
        winner = {"rule": f"implied:{dec['rule']}", "implied_rule": dec["rule"],
                  "display_rule": f"Implied rule {dec['rule']} ({dec['position']})",
                  "name": dec["rule"], "action": "Accept", "layer": "Implied rules",
                  "transition": "final", "implied_position": dec["position"]}
        out.update({"matched": True, "winner": winner, "path": (out.get("path") or []) + [winner],
                    "result": "Accept", "confidence": "exact", "decided_by": "implied",
                    "reason": (f"Implied rule {dec['rule']} is switched on ({dec['position']}) and this "
                               "connection lies wholly inside its service, so it decides: Accept. "
                               "No other implied rule can match the connection.")})
        out["gateway_final"] = True
        return out

    note = " ".join(assessment.get("reasons") or [])
    if out.get("matched") and out.get("confidence") == "exact":
        out["confidence"] = "inferred"
    elif not out.get("matched") and out.get("confidence") in ("exact", "none"):
        out["result"] = "UNVERIFIED"
        out["confidence"] = "unknown"
    out["reason"] = ((out.get("reason") or "") + " " + note).strip()
    out["gateway_final"] = False
    return out
