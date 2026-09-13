"""
Ask a traffic question in words, in Thai or English, and get the trace's answer.

    "ทำไม 192.0.2.10 เข้า AD-Server ด้วย RDP ไม่ได้"
    "can Admin-PC reach web01.example.com on https?"

WHAT THIS IS
A front door to Traffic Path. The words are turned into the three things the
trace needs - a source, a destination, a service - and the trace that
/api/traffic-path runs is run, unchanged. The verdict, the UNVERIFIED and the
confidence are the trace's. This module only reads the question and writes the
answer out in sentences.

WHAT THIS IS NOT
It is not a language model and does not guess. If the question names a network
where the trace needs one address, it says so and suggests one rather than
picking; if it cannot find a source, a destination or a service, it says which
is missing. A confident wrong answer about a firewall is worse than a question
back, which is the principle the whole application is built on - it would be
a strange place to abandon it.

An LLM could sit in front of this to understand looser phrasing. It would still
have to hand these three fields to the same trace and never decide the verdict
itself, and it would send the question - which names hosts and services - to
an outside service. That is a decision for whoever owns the estate, so it is
not done here.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

THAI = re.compile(r"[฀-๿]")

IPV4 = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?:/(\d{1,2}))?(?::(\d{1,5}))?(?![\w.])")
FQDN = re.compile(r"(?<![\w.@-])((?=[A-Za-z0-9-]*[A-Za-z])[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})(?![\w.-])")
PROTO_PORT = re.compile(r"\b(tcp|udp)\s*[/:]?\s*(\d{1,5})\b", re.I)
PORT_WORD = re.compile(r"(?:\bport|พอร์ต)\s*(\d{1,5})", re.I)

# Service words people use, mapped to what the trace accepts.
SERVICE_WORDS = {
    "https": ("tcp", 443), "http": ("tcp", 80), "ssh": ("tcp", 22), "rdp": ("tcp", 3389),
    "remote desktop": ("tcp", 3389), "telnet": ("tcp", 23), "ftp": ("tcp", 21),
    "smtp": ("tcp", 25), "dns": ("udp", 53), "ntp": ("udp", 123), "ldaps": ("tcp", 636),
    "ldap": ("tcp", 389), "smb": ("tcp", 445), "mssql": ("tcp", 1433), "mysql": ("tcp", 3306),
    "postgres": ("tcp", 5432), "snmp": ("udp", 161), "syslog": ("udp", 514),
    "ping": ("icmp", 8), "icmp": ("icmp", 8),
}

FROM_MARKERS = ("from", "จาก")
TO_MARKERS = ("to", "reach", "access", "ไปหา", "ไปยัง", "ไป", "ถึง", "เข้าถึง", "เข้า", "->", "→")

ENDPOINT_TYPES = {"host", "network", "address-range", "group", "simple-gateway",
                  "simple-cluster", "cluster-member", "checkpoint-host", "CpmiGatewayCluster"}
ADDRESSED = {"host", "simple-gateway", "simple-cluster", "cluster-member", "checkpoint-host"}


def _names(objects: dict[str, dict[str, Any]]):
    endpoints, services = [], []
    for o in objects.values():
        name = str(o.get("name") or "")
        if len(name) < 3:
            continue
        kind = str(o.get("type") or "")
        if kind.startswith("service-") and kind != "service-group":
            services.append(o)
        elif kind in ENDPOINT_TYPES:
            endpoints.append(o)
    key = lambda o: -len(str(o.get("name")))
    return sorted(endpoints, key=key), sorted(services, key=key)


def _find_names(text: str, objs: list[dict[str, Any]], taken: list[tuple[int, int]]):
    found = []
    for o in objs:
        pat = re.compile(r"(?<![\w-])" + re.escape(str(o["name"])) + r"(?![\w-])", re.I)
        for m in pat.finditer(text):
            span = (m.start(), m.end())
            if any(a < span[1] and span[0] < b for a, b in taken):
                continue
            taken.append(span)
            found.append((span, o))
    return found


def _last(window: str, marker: str) -> int:
    """Position of the last *marker* in *window*, as a word where that means anything.

    Latin markers need boundaries - "to" is inside "desktop" and "reach" inside
    "reachable" - while Thai is written without spaces between words, so a
    boundary there would never match.
    """
    if re.fullmatch(r"[a-z]+", marker):
        hits = [m.start() for m in re.finditer(r"\b" + marker + r"\b", window)]
        return hits[-1] if hits else -1
    return window.rfind(marker)


def _role(text: str, start: int, prev_end: int) -> str | None:
    window = text[prev_end:start].lower()
    best, role = -1, None
    for marker in TO_MARKERS:
        i = _last(window, marker)
        if i > best:
            best, role = i, "destination"
    for marker in FROM_MARKERS:
        i = _last(window, marker)
        if i > best:
            best, role = i, "source"
    return role


def parse(question: str, objects: dict[str, dict[str, Any]]) -> dict[str, Any]:
    text = str(question or "").strip()
    lang = "th" if THAI.search(text) else "en"
    endpoint_objs, service_objs = _names(objects)
    taken: list[tuple[int, int]] = []

    mentions: list[tuple[tuple[int, int], dict[str, Any]]] = []
    for span, o in _find_names(text, endpoint_objs, taken):
        mentions.append((span, {"text": o["name"], "kind": "object", "object": o}))
    svc_named = _find_names(text, service_objs, taken)

    port_from_ip = None
    for m in IPV4.finditer(text):
        span = (m.start(), m.end())
        if any(a < span[1] and span[0] < b for a, b in taken):
            continue
        taken.append(span)
        try:
            ipaddress.ip_address(m.group(1))
        except ValueError:
            continue
        if m.group(3):
            port_from_ip = int(m.group(3))
        if m.group(2):
            mentions.append((span, {"text": m.group(0), "kind": "cidr",
                                    "network": f"{m.group(1)}/{m.group(2)}"}))
        else:
            mentions.append((span, {"text": m.group(1), "kind": "ip", "value": m.group(1)}))
    for m in FQDN.finditer(text):
        span = (m.start(), m.end())
        if any(a < span[1] and span[0] < b for a, b in taken):
            continue
        if m.group(1).lower() in SERVICE_WORDS:
            continue
        taken.append(span)
        mentions.append((span, {"text": m.group(1), "kind": "fqdn", "value": m.group(1)}))

    mentions.sort(key=lambda x: x[0][0])
    roles: dict[str, dict[str, Any]] = {}
    unplaced = []
    prev = 0
    for span, ep in mentions:
        role = _role(text, span[0], prev)
        prev = span[1]
        if role and role not in roles:
            roles[role] = ep
        else:
            unplaced.append(ep)
    for ep in unplaced:
        for role in ("source", "destination"):
            if role not in roles:
                roles[role] = ep
                break

    service = None
    m = PROTO_PORT.search(text)
    if m:
        service = {"input": m.group(2), "protocol": m.group(1).lower(), "from": m.group(0)}
    elif (m := PORT_WORD.search(text)):
        service = {"input": m.group(1), "protocol": "tcp", "from": m.group(0)}
    elif svc_named:
        o = svc_named[0][1]
        service = {"input": o["name"], "protocol": "udp" if o.get("type") == "service-udp" else "tcp",
                   "from": o["name"]}
    else:
        low = text.lower()
        for word in sorted(SERVICE_WORDS, key=len, reverse=True):
            if re.search(r"(?<![\w-])" + re.escape(word) + r"(?![\w-])", low):
                proto, port = SERVICE_WORDS[word]
                service = {"input": str(port), "protocol": proto, "from": word}
                break
    if service is None and port_from_ip:
        service = {"input": str(port_from_ip), "protocol": "tcp", "from": f":{port_from_ip}"}

    missing, clarify = [], []
    resolved: dict[str, Any] = {}
    for role in ("source", "destination"):
        ep = roles.get(role)
        if ep is None:
            missing.append(role)
            continue
        value, note = _address_for(ep)
        if value is None:
            clarify.append({"role": role, "text": ep["text"], "why": note["why"],
                            "suggestion": note.get("suggestion")})
        resolved[role] = {"text": ep["text"], "kind": ep["kind"], "value": value}
    if service is None:
        missing.append("service")

    return {"lang": lang, "source": resolved.get("source"),
            "destination": resolved.get("destination"), "service": service,
            "missing": missing, "clarify": clarify,
            "ready": not missing and not clarify}


def _address_for(ep: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
    kind = ep["kind"]
    if kind in ("ip", "fqdn"):
        return ep["value"], {}
    if kind == "cidr":
        net = ipaddress.ip_network(ep["network"], strict=False)
        first = next(net.hosts(), net.network_address)
        return None, {"why": f"{net} is a network, and a trace needs one address",
                      "suggestion": str(first)}
    o = ep["object"]
    t = o.get("type")
    if t in ADDRESSED and o.get("ipv4-address"):
        return o["ipv4-address"], {}
    if t == "network" and o.get("subnet4"):
        net = ipaddress.ip_network(f"{o['subnet4']}/{o.get('mask-length4', 32)}", strict=False)
        first = next(net.hosts(), net.network_address)
        return None, {"why": f"{o['name']} is the network {net}; a trace needs one address in it",
                      "suggestion": str(first)}
    if t == "address-range" and o.get("ipv4-address-first"):
        return None, {"why": f"{o['name']} is the range {o['ipv4-address-first']}-"
                             f"{o.get('ipv4-address-last')}; a trace needs one address in it",
                      "suggestion": o["ipv4-address-first"]}
    if t == "group":
        return None, {"why": f"{o['name']} is a group; a trace needs one address from it"}
    return None, {"why": f"{o['name']} has no single address this read can use"}


# ---- the answer ------------------------------------------------------------------

def _rule(step: dict[str, Any] | None) -> str:
    if not step:
        return "?"
    name = f" ({step['name']})" if step.get("name") else ""
    return f"rule {step.get('display_rule')}{name} in {step.get('layer')}"


def _unknown_reasons(step: dict[str, Any] | None) -> list[str]:
    out = []
    for dim in ("source", "destination", "service", "vpn"):
        if (step or {}).get(f"{dim}_state") == "unknown":
            out.append(f"{dim}: {step.get(f'{dim}_match')}")
    return out


def explain(result: dict[str, Any], parsed: dict[str, Any]) -> dict[str, Any]:
    th = parsed.get("lang") == "th"
    access = result.get("access") or {}
    q = result.get("query") or {}
    flow = f"{q.get('source')} → {q.get('destination')} {q.get('service_display') or ''}".strip()
    conf = access.get("confidence")
    verdict, lines = "unknown", []

    if access.get("matched"):
        step = access.get("winner") or {}
        action = str(step.get("action") or access.get("result") or "")
        allowed = action.lower() in ("accept", "allow")
        verdict = "allowed" if allowed else "blocked"
        firm = conf == "exact"
        if th:
            head = ("ได้" if allowed else "ไม่ได้") + ("" if firm else " (น่าจะ — ความมั่นใจไม่เต็ม)")
            lines.append(f"{head}: {flow} ตรงกับ {_rule(step)} ซึ่ง {action}")
        else:
            head = ("Allowed" if allowed else "Blocked") + ("" if firm else " (probably - not certain)")
            lines.append(f"{head}: {flow} matches {_rule(step)}, which says {action}.")
        if not firm:
            lines.append(("เหตุผลที่ไม่แน่ชัด: " if th else "Why it is not certain: ")
                         + str(access.get("reason")))
    elif access.get("result") == "UNVERIFIED":
        possible = access.get("possible_winner")
        later = access.get("later_exact_rule")
        reasons = _unknown_reasons(possible)
        if th:
            lines.append(f"ตอบแน่ชัดไม่ได้: {_rule(possible)} อาจเป็น rule ที่ตัดสิน "
                         "แต่มีเงื่อนไขที่ประเมินจาก configuration ไม่ได้")
            if later:
                lines.append(f"ถ้า rule นั้นไม่ตรง ทราฟฟิกจะไปจบที่ {_rule(later)} ({later.get('action')}) "
                             "— แต่จะบอกว่านั่นคือคำตอบสุดท้ายไม่ได้")
        else:
            lines.append(f"Cannot say for certain: {_rule(possible)} may decide this flow, "
                         "but it has conditions a configuration read cannot evaluate.")
            if later:
                lines.append(f"If it does not match, the flow ends at {_rule(later)} "
                             f"({later.get('action')}) - but that cannot be declared final.")
        lines += [("  • " + r) for r in reasons]
    else:
        verdict = "no-rule"
        lines.append((f"ไม่มี rule ที่ตัดสินทราฟฟิกนี้: {access.get('reason')}" if th else
                      f"No rule decides this flow: {access.get('reason')}"))

    nat = [n for n in result.get("nat") or [] if n.get("state") in ("match", "unknown")]
    if nat:
        lines.append((f"NAT ที่เกี่ยวข้อง {len(nat)} rule" if th else f"{len(nat)} NAT rule(s) may apply")
                     + " — " + ", ".join(str(n.get("rule") or n.get("display_rule") or "?") for n in nat[:6]))
    dq = result.get("data_quality") or {}
    if dq and not dq.get("complete", True):
        lines.append("คำเตือน: policy โหลดมาไม่ครบ ผลนี้อาจไม่สมบูรณ์" if th else
                     "Warning: the policy did not load completely; this answer may be incomplete.")
    lines.append("นี่คือการจำลองจาก configuration ไม่ใช่ log จริงของ gateway" if th else
                 "This is a simulation from configuration, not a gateway log.")
    return {"verdict": verdict, "confidence": conf, "answer": lines}


def clarification(parsed: dict[str, Any]) -> list[str]:
    th = parsed.get("lang") == "th"
    words = {"source": ("ต้นทาง", "a source"), "destination": ("ปลายทาง", "a destination"),
             "service": ("พอร์ตหรือ service", "a port or service")}
    lines = []
    if parsed["missing"]:
        names = [words[m][0 if th else 1] for m in parsed["missing"]]
        lines.append(("ยังขาด: " if th else "I could not find ") + ", ".join(names)
                     + ("" if th else " in the question."))
    for c in parsed["clarify"]:
        tip = (f" ลองใช้ {c['suggestion']}" if th else f" Try {c['suggestion']}.") if c.get("suggestion") else ""
        lines.append(f"{c['why']}.{tip}")
    if th:
        lines.append("ตัวอย่าง: 'จาก 192.0.2.10 ไป 198.51.100.5 พอร์ต 443'")
    else:
        lines.append("Example: 'from 192.0.2.10 to 198.51.100.5 port 443'")
    return lines
