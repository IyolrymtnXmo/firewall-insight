"""
Predicates: does this address / service / VPN condition match the query?

Split out of traffic.py in v4.24, when adding the VPN dimension pushed that
file past the 700-line module guard. The split is not only about size: this
file answers "does X match Y", and traffic.py walks the rulebase asking it.
The matchers have no idea rules exist, which is why nat_correlate.py can use
the same address matcher without importing the Access tracer.

Two kinds of question live here and they need different strictness - the
distinction Chapter 3 of the learning guide is built around:

  matching     needs ONE piece of positive evidence, so it uses the *_partial
               resolvers and an unresolvable sibling does not spoil a real hit
  containment  needs to know everything, and lives in resolver.py

Everything here is tri-state where it can be. `unknown` is a real answer and
must never be collapsed into `no-match`: a no-match lets the walk continue to
a later rule and report it as definitive, which turns "we cannot tell" into a
confident wrong answer.
"""

from __future__ import annotations

import socket
from ipaddress import ip_address
from typing import Any

from .resolver import ObjectResolver


def _domain_candidates(text: str) -> tuple[list[str], str | None]:
    value = str(text or "").strip()
    try:
        ip_address(value)
        return [value], None
    except ValueError:
        pass

    ips = []
    try:
        for info in socket.getaddrinfo(value, None, type=socket.SOCK_STREAM):
            addr = info[4][0]
            if addr not in ips:
                ips.append(addr)
    except OSError as exc:
        return [], str(exc)
    return ips, None


def _domain_object_match(uid: str, domain: str, res: ObjectResolver) -> bool:
    o = res.obj(uid)
    name = str(o.get("name") or "").strip().lower()
    typ = str(o.get("type") or "").lower()
    query = str(domain or "").strip().lower().rstrip(".")

    if not query:
        return False

    # Check Point DNS-domain objects commonly use the domain itself as name.
    candidate = name.lstrip(".").rstrip(".")
    if "dns-domain" in typ or "domain" in typ:
        if candidate == query:
            return True
        # Leading-dot / sub-domain style object: .example.com
        if name.startswith(".") and (query == candidate or query.endswith("." + candidate)):
            return True

    members = o.get("members")
    if isinstance(members, list):
        for child in members:
            cu = child if isinstance(child, str) else child.get("uid") if isinstance(child, dict) else None
            if cu and _domain_object_match(cu, query, res):
                return True
    return False


def address_matches(values: Any, address_text: str, res: ObjectResolver) -> tuple[bool, str]:
    raw = str(address_text or "").strip()
    try:
        ip = ip_address(raw)
        ips = [ip]
        is_domain = False
        dns_error = None
    except ValueError:
        is_domain = True
        resolved, dns_error = _domain_candidates(raw)
        ips = []
        for value in resolved:
            try:
                ips.append(ip_address(value))
            except ValueError:
                pass

    for uid in res.uids(values):
        if res.is_any_uid(uid):
            if is_domain and ips:
                return True, f"Any · {raw} → {', '.join(str(x) for x in ips[:4])}"
            return True, "Any"

        if is_domain and _domain_object_match(uid, raw, res):
            return True, f"{res.describe_uid(uid)} · domain match"

        atoms, _complete = res.address_atoms_partial(uid)
        for ip in ips:
            n = int(ip)
            if any(a.version == ip.version and a.start <= n <= a.end for a in atoms):
                if is_domain:
                    return True, f"{res.describe_uid(uid)} · {raw} → {ip}"
                return True, res.describe_uid(uid)

    if is_domain:
        if ips:
            return False, f"No matching object for {raw} ({', '.join(str(x) for x in ips[:4])})"
        return False, f"Domain not resolved/matched: {raw}" + (f" ({dns_error})" if dns_error else "")
    return False, "No matching object"


def _service_object_by_name(name: str, res: ObjectResolver) -> tuple[str, list] | None:
    q = str(name or "").strip().lower()
    if not q:
        return None
    for uid, obj in res.objects.items():
        if str(obj.get("name") or "").strip().lower() != q:
            continue
        atoms = res.service_atoms(uid)
        if atoms:
            return uid, atoms
    return None


def _service_name_warnings(raw, requested_proto, uid, atoms, res) -> list[str]:
    """
    Say when the object we resolved is not the service the person meant.

    The lab taught this one: Check Point ships an object called `RDP` which is
    UDP/259 (its own control protocol), while Remote Desktop is
    `Remote_Desktop_Protocol`, TCP/3389. Resolving the exact object name is
    correct - the rulebase is written in object names - but a `drop` verdict
    for UDP/259 looks identical to a `drop` verdict for TCP/3389, and the
    person reading it asked about the second one.

    So the resolution does not change. What changes is that the trace states
    the discrepancy instead of leaving the reader to notice a small port in a
    display string.
    """
    warnings: list[str] = []
    name = str(res.obj(uid).get("name") or raw)
    described = res.describe_uid(uid)
    protos = sorted({a.proto for a in atoms if a.proto})

    if protos and requested_proto not in protos and "any" not in protos:
        shown = "/".join(x.upper() for x in protos)
        warnings.append(
            f"You selected {requested_proto.upper()}, but the policy object "
            f"'{name}' is {shown} - {described}. The trace evaluates the object, "
            f"so this answers a different flow from {requested_proto.upper()} "
            f"traffic to the same destination."
        )

    try:
        standard = socket.getservbyname(str(raw).lower(), requested_proto)
    except OSError:
        standard = None
    if standard is not None and not any(
        a.proto in (requested_proto, "any") and a.start <= standard <= a.end
        for a in atoms
    ):
        warnings.append(
            f"'{raw}' is also a standard service name "
            f"({requested_proto.upper()}/{standard}), but this policy has an object "
            f"of that name resolving to {described}. The policy object wins, "
            "because that is what the rulebase references."
        )

    return warnings


def resolve_service_query(service_text: str, proto: str, res: ObjectResolver) -> dict[str, Any]:
    raw = str(service_text or "").strip()
    p = str(proto or "tcp").lower()

    if raw.isdigit():
        port = int(raw)
        # ICMP has no ports. The number is a message type, and writing it as
        # ICMP/8 borrows port notation for something that is not a port -
        # which is how someone ends up looking for "port 8" in a gateway log.
        if p in ("icmp", "icmp6"):
            if not (0 <= port <= 255):
                raise ValueError("ICMP type must be between 0 and 255")
            return {
                "input": raw, "protocol": p, "port": port,
                "atoms": [(p, port, port)],
                "resolved_by": "numeric-icmp-type",
                "display": f"{p.upper()} type {port}",
            }
        if not (0 <= port <= 65535):
            raise ValueError("Port must be between 0 and 65535")
        return {
            "input": raw, "protocol": p, "port": port,
            "atoms": [(p, port, port)],
            "resolved_by": "numeric-port",
            "display": f"{p.upper()}/{port}",
        }

    cp_obj = _service_object_by_name(raw, res)
    if cp_obj:
        uid, atoms = cp_obj
        atom_tuples = [(a.proto, a.start, a.end) for a in atoms]
        # Use a representative port for legacy NAT/display paths.
        selected = next((a for a in atoms if a.proto in (p, "any")), atoms[0])
        return {
            "input": raw,
            "protocol": selected.proto if selected.proto != "any" else p,
            "port": selected.start,
            "atoms": atom_tuples,
            "resolved_by": "checkpoint-service-object",
            "object_uid": uid,
            "display": res.describe_uid(uid),
            "warnings": _service_name_warnings(raw, p, uid, atoms, res),
        }

    # OS standard service database: https, ssh, smtp, domain, ntp, etc.
    try:
        port = socket.getservbyname(raw.lower(), p)
        return {
            "input": raw, "protocol": p, "port": port,
            "atoms": [(p, port, port)],
            "resolved_by": "standard-service-name",
            "display": f"{raw} ({p.upper()}/{port})",
        }
    except OSError:
        raise ValueError(
            f"Unknown service '{raw}'. Enter a port number, a standard service "
            f"name (for example https/ssh/smtp), or an exact Check Point service object name."
        )


def service_matches_query(values: Any, query: dict[str, Any], res: ObjectResolver) -> tuple[bool, str]:
    q_atoms = query.get("atoms") or []
    for uid in res.uids(values):
        if res.is_any_uid(uid):
            return True, "Any"
        atoms, _complete = res.service_atoms_partial(uid)
        for qp, qs, qe in q_atoms:
            for a in atoms:
                proto_ok = a.proto == "any" or qp == "any" or a.proto == qp
                # A queried service is covered when its range overlaps the rule service.
                if proto_ok and not (qe < a.start or qs > a.end):
                    return True, res.describe_uid(uid)
    return False, "No matching service"


def address_match_state(values: Any, address_text: str, res: ObjectResolver) -> tuple[str, str]:
    """
    Tri-state address matcher:
      match    = condition is proven to match
      no-match = condition is proven not to match
      unknown  = rule uses an object type this static simulator cannot evaluate
    """
    raw = str(address_text or "").strip()
    try:
        ip = ip_address(raw)
        ips = [ip]
        is_domain = False
    except ValueError:
        is_domain = True
        resolved, _ = _domain_candidates(raw)
        ips = []
        for value in resolved:
            try:
                ips.append(ip_address(value))
            except ValueError:
                pass

    saw_unknown = False
    unknown_names = []

    for uid in res.uids(values):
        if res.is_any_uid(uid):
            return "match", "Any"

        obj = res.obj(uid)
        typ = str(obj.get("type") or "").lower()
        name = str(obj.get("name") or uid)

        if is_domain and _domain_object_match(uid, raw, res):
            return "match", f"{res.describe_uid(uid)} · domain match"

        # Partial resolution: a group with one unmodellable member still
        # proves a match through the members we DO understand.
        atoms, complete = res.address_atoms_partial(uid)

        for ip in ips:
            n = int(ip)
            if any(a.version == ip.version and a.start <= n <= a.end for a in atoms):
                return "match", res.describe_uid(uid)

        if not complete:
            saw_unknown = True
            blockers = res.unmodelled_names(uid, "address")
            label = f"{name} [{typ or 'unknown'}]"
            for blocker in (blockers or [label]):
                entry = blocker if blocker == label else f"{name} \u2192 {blocker}"
                if entry not in unknown_names:
                    unknown_names.append(entry)

    if saw_unknown:
        return "unknown", "Static match unavailable for " + ", ".join(unknown_names[:4])

    return "no-match", "No matching object"


def service_match_state(values: Any, query: dict[str, Any], res: ObjectResolver) -> tuple[str, str]:
    q_atoms = query.get("atoms") or []
    saw_unknown = False
    unknown_names = []

    for uid in res.uids(values):
        if res.is_any_uid(uid):
            return "match", "Any"

        # Partial resolution: AD-Services contains ALL_DCE_RPC, which has no
        # fixed port, but a TCP/389 query still matches its ldap member.
        atoms, complete = res.service_atoms_partial(uid)

        for qp, qs, qe in q_atoms:
            for a in atoms:
                proto_ok = a.proto == "any" or qp == "any" or a.proto == qp
                if proto_ok and not (qe < a.start or qs > a.end):
                    return "match", res.describe_uid(uid)

        if not complete:
            obj = res.obj(uid)
            saw_unknown = True
            name = str(obj.get("name") or uid)
            label = f"{name} [{obj.get('type') or 'unknown'}]"
            for blocker in (res.unmodelled_names(uid, "service") or [label]):
                entry = blocker if blocker == label else f"{name} \u2192 {blocker}"
                if entry not in unknown_names:
                    unknown_names.append(entry)

    if saw_unknown:
        return "unknown", "Static service match unavailable for " + ", ".join(unknown_names[:4])
    return "no-match", "No matching service"


def vpn_match_state(values: Any, res: ObjectResolver) -> tuple[str, str]:
    """
    Tri-state for the VPN column, which the tracer used to ignore entirely.

    Whether a packet arrives inside a VPN community is a property of the live
    connection, not of the configuration. So this returns:

        match    the rule places no VPN constraint (field absent, or Any)
        unknown  the rule is scoped to a community we cannot verify

    and never `no-match`: we cannot prove the packet is OUTSIDE the community
    any more than we can prove it is inside. `unknown` is the honest answer,
    and it makes the whole rule unknown, which in turn stops a later exact
    rule from being declared final - the same treatment Security Zones and
    Identity Awareness already get.

    Note that `trace_access()` - the single-layer boolean tracer kept for
    compatibility - still ignores the column. It is not the path the UI or the
    acceptance runner take; trace_access_tree() is.
    """
    if not values:
        return "match", "Any"

    uids = res.uids(values)
    if not uids:
        # A directional match arrives as a dict of community/from/to rather
        # than a list of uids. Not understanding the shape is not permission
        # to ignore it.
        return "unknown", "Rule carries a VPN condition this simulator cannot evaluate"

    scoped = [u for u in uids if not res.is_any_uid(u)]
    if not scoped:
        return "match", "Any"

    names = ", ".join(res.describe_uid(u) for u in scoped[:4])
    return "unknown", (
        f"Rule applies only to VPN community {names}; whether this flow "
        "arrives through it is live connection state, not configuration"
    )
