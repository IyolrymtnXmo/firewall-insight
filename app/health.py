"""
Gateway state, and what changed since the last baseline.

Written against the payloads in tests/fixtures/gaia_r82_probe.py - unedited
answers from Check Point Gaia R82 - rather than against the API reference. The
route readers were written the other way round, reported 7/7 on a run where
every next hop was dropped, and that is the whole argument for doing it this
way.

What that real data actually says, and what it costs to read carelessly:

  "ipv4-address": "Not-Configured"   a STRING, not an absent field. Parsed as
                                     an address it becomes a host that is not
                                     there.
  "ipv4-mask-length": "24"           a string too.
  "enabled": false + an address      a configured interface that is
                                     administratively down. Present in the lab
                                     right now (Mgmt, 192.168.99.1), and
                                     invisible from the Management API.

Findings here are about the *state* of the estate, not the quality of the
policy, so they follow the same split the acceptance runner uses: this module
reports what it found, and never scores it. And where the data cannot answer -
a gateway that did not respond - it says so instead of leaving a gap that
reads as health.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .version import APP_VERSION

BASELINE_DIR = Path(__file__).resolve().parent.parent / "health-baselines"
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")

NOT_CONFIGURED = {"not-configured", "not configured", "", "none", "unassigned"}
IGNORED_INTERFACES = {"lo"}


def _configured(value: Any) -> str:
    text = str(value or "").strip()
    return "" if text.lower() in NOT_CONFIGURED else text


def read_interfaces(payload: Any) -> list[dict[str, Any]]:
    rows = payload.get("objects") if isinstance(payload, dict) else payload
    out = []
    for item in rows or []:
        if not isinstance(item, dict):
            continue
        address = _configured(item.get("ipv4-address"))
        mask = _configured(item.get("ipv4-mask-length"))
        out.append({
            "name": str(item.get("name") or ""),
            "type": str(item.get("type") or ""),
            "enabled": bool(item.get("enabled", False)),
            "ipv4": address,
            "mask": mask,
            "cidr": f"{address}/{mask}" if address and mask else address,
            "comments": str(item.get("comments") or ""),
            "configured": bool(address),
        })
    return out


def read_cluster_state(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {"readable": False, "members": [], "mode": "", "status": ""}
    this = payload.get("this-cluster-member") or {}
    others = payload.get("other-cluster-members") or []
    members = []
    for entry in [this] + [o for o in others if isinstance(o, dict)]:
        if not isinstance(entry, dict) or not entry.get("name"):
            continue
        members.append({
            "name": str(entry.get("name")),
            "status": str(entry.get("status") or "").lower(),
            "load": entry.get("load"),
            "peer_id": entry.get("peer-id"),
            "is_self": entry is this,
        })
    return {
        "readable": bool(members),
        "mode": str(payload.get("mode") or ""),
        "status": str(payload.get("cluster-status") or "").lower(),
        "message": str(payload.get("message") or ""),
        "members": members,
    }


def read_version(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    return {
        "product": str(payload.get("product-version") or ""),
        "build": str(payload.get("os-build") or ""),
        "kernel": str(payload.get("os-kernel-version") or ""),
    }


def build_health(per_gateway: dict[str, Any]) -> dict[str, Any]:
    """
    `per_gateway` maps a host to {"interfaces":…, "cluster":…, "version":…}
    or to {"error": "…"} when it could not be read.
    """
    gateways, findings, unreachable = [], [], []
    builds: dict[str, list[str]] = {}
    active_by_cluster: dict[str, list[str]] = {}

    for host, raw in (per_gateway or {}).items():
        if isinstance(raw, dict) and raw.get("error"):
            unreachable.append({"host": host, "error": raw["error"]})
            continue

        interfaces = read_interfaces((raw or {}).get("interfaces"))
        cluster = read_cluster_state((raw or {}).get("cluster"))
        version = read_version((raw or {}).get("version"))

        # A read that failed on its own is reported, never left as a gap. A
        # standalone gateway has no cluster state and saying so is the answer;
        # an interface list that failed to load is a hole in everything below
        # it, and the reader has to be told which of the two happened.
        for name, message in ((raw or {}).get("errors") or {}).items():
            findings.append({
                "severity": "medium" if name == "cluster" else "high",
                "host": host, "kind": "read-failed", "subject": name,
                "detail": (f"'{name}' could not be read from this gateway: {message}. "
                           + ("A standalone gateway has no cluster state, which is "
                              "expected rather than wrong." if name == "cluster" else
                              "Everything reported below for this gateway is "
                              "missing that input.")),
            })

        for iface in interfaces:
            if iface["name"] in IGNORED_INTERFACES:
                continue
            if iface["configured"] and not iface["enabled"]:
                findings.append({
                    "severity": "medium", "host": host, "kind": "interface-down",
                    "subject": iface["name"],
                    "detail": (
                        f"{iface['name']} has address {iface['cidr']} but is "
                        "administratively disabled. The Management API shows the "
                        "address and not the state, so this is invisible there."),
                })

        if cluster["readable"]:
            if cluster["status"] and cluster["status"] != "ok":
                findings.append({
                    "severity": "high", "host": host, "kind": "cluster-status",
                    "subject": cluster.get("mode") or "cluster",
                    "detail": f"Cluster status is '{cluster['status']}': "
                              f"{cluster['message'] or 'no message returned'}.",
                })
            for member in cluster["members"]:
                if member["status"] == "active":
                    active_by_cluster.setdefault(cluster["mode"] or "cluster", [])
                    if member["name"] not in active_by_cluster[cluster["mode"] or "cluster"]:
                        active_by_cluster[cluster["mode"] or "cluster"].append(member["name"])
            if not any(m["status"] == "active" for m in cluster["members"]):
                findings.append({
                    "severity": "high", "host": host, "kind": "no-active-member",
                    "subject": "cluster",
                    "detail": "No member of this cluster reports itself active.",
                })

        if version.get("build"):
            builds.setdefault(f"{version['product']} build {version['build']}", []).append(host)

        gateways.append({
            "host": host, "version": version, "cluster": cluster,
            "interfaces": interfaces,
            "interfaces_up": sum(1 for i in interfaces if i["enabled"]),
            "interfaces_configured": sum(1 for i in interfaces if i["configured"]),
        })

    for mode, actives in active_by_cluster.items():
        if len(actives) > 1:
            findings.append({
                "severity": "high", "host": ", ".join(actives), "kind": "split-brain",
                "subject": mode,
                "detail": (f"{len(actives)} members report themselves active "
                           f"({', '.join(actives)}). In high availability exactly "
                           "one should."),
            })

    if len(builds) > 1:
        findings.append({
            "severity": "medium", "host": "estate", "kind": "version-drift",
            "subject": "software version",
            "detail": "Gateways are not on the same build: " + "; ".join(
                f"{build} on {', '.join(hosts)}" for build, hosts in sorted(builds.items())),
        })

    if unreachable:
        findings.append({
            "severity": "high", "host": ", ".join(u["host"] for u in unreachable),
            "kind": "not-read", "subject": "reachability",
            "detail": ("These gateways did not answer, so nothing below says "
                       "anything about their state. Absence of a finding is not "
                       "health."),
        })

    return {
        "schema": 1,
        "app_version": APP_VERSION,
        "taken_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "gateways": gateways,
        "unreachable": unreachable,
        "findings": findings,
        "summary": {
            "gateways_read": len(gateways),
            "gateways_unreachable": len(unreachable),
            "findings": len(findings),
            "high": sum(1 for f in findings if f["severity"] == "high"),
        },
        "notes": [
            "State is read at one instant over the Gaia API. It is not monitoring.",
            "A gateway that did not answer produces no findings, which is not the "
            "same as producing none.",
        ],
    }


# ---- baseline ---------------------------------------------------------

WATCHED_INTERFACE_FIELDS = ("enabled", "cidr", "type")


def diff_health(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """
    What moved since the baseline.

    Interface state and cluster roles are exactly the things that change under
    you between two audits, and a role flip is the one people most want a line
    about: `External-GW01 active -> standby` means a failover happened, and
    nothing in the policy would tell you.
    """
    def index(report):
        out = {}
        for gw in report.get("gateways") or []:
            out[gw["host"]] = {
                "interfaces": {i["name"]: i for i in gw.get("interfaces") or []},
                "members": {m["name"]: m for m in (gw.get("cluster") or {}).get("members") or []},
                "version": gw.get("version") or {},
            }
        return out

    def unread(report):
        """
        The half of a report that says which gateways did not answer, and why.

        A gateway here is not absent from the estate - it is present and
        unreadable, and the two call for opposite responses. Reports written
        before this key existed simply have none, which is not the same as
        having an empty one, but reads the same way here.
        """
        return {u["host"]: u.get("error") or "no reason was recorded"
                for u in report.get("unreachable") or []}

    before, after = index(baseline), index(current)
    was_unread, is_unread = unread(baseline), unread(current)
    changes: list[dict[str, Any]] = []

    for host, now in after.items():
        was = before.get(host)
        if was is None:
            if host in was_unread:
                changes.append({
                    "host": host, "kind": "gateway-became-readable",
                    "subject": "reachability",
                    "detail": ("This gateway answered. In the baseline it did "
                               f"not: {was_unread[host]}. Nothing is said about "
                               "what its state was in between."),
                })
            else:
                changes.append({"host": host, "kind": "gateway-added",
                                "detail": "This gateway is in the current reading "
                                          "and not in the baseline."})
            continue

        for name, iface in now["interfaces"].items():
            old = was["interfaces"].get(name)
            if old is None:
                changes.append({"host": host, "kind": "interface-added",
                                "subject": name,
                                "detail": f"{name} appeared since the baseline."})
                continue
            for field in WATCHED_INTERFACE_FIELDS:
                if old.get(field) != iface.get(field):
                    changes.append({
                        "host": host, "kind": "interface-changed", "subject": name,
                        "field": field, "from": old.get(field), "to": iface.get(field),
                        "detail": f"{name} {field}: {old.get(field)} → {iface.get(field)}",
                    })
        for name in was["interfaces"]:
            if name not in now["interfaces"]:
                changes.append({"host": host, "kind": "interface-removed",
                                "subject": name,
                                "detail": f"{name} is no longer reported."})

        for name, member in now["members"].items():
            old = was["members"].get(name)
            if old and old.get("status") != member.get("status"):
                changes.append({
                    "host": host, "kind": "cluster-role-changed", "subject": name,
                    "from": old.get("status"), "to": member.get("status"),
                    "detail": (f"{name} went {old.get('status')} → "
                               f"{member.get('status')}. A failover happened, or "
                               "somebody moved it."),
                })

        if was["version"] and now["version"] and was["version"] != now["version"]:
            changes.append({
                "host": host, "kind": "version-changed", "subject": "software",
                "from": was["version"].get("build"), "to": now["version"].get("build"),
                "detail": (f"Build {was['version'].get('build')} → "
                           f"{now['version'].get('build')}."),
            })

    for host in list(before) + [h for h in was_unread if h not in before]:
        if host in after:
            continue
        if host in is_unread:
            if host in was_unread:
                continue        # unreadable in both. Still broken is not news.
            changes.append({
                "host": host, "kind": "gateway-became-unreadable",
                "subject": "reachability",
                "detail": ("This gateway did not answer, so nothing in this "
                           f"reading describes its state: {is_unread[host]}. "
                           "It was read in the baseline."),
            })
        else:
            changes.append({"host": host, "kind": "gateway-missing",
                            "detail": "In the baseline, absent from the current "
                                      "reading. It may be down, or simply not read."})

    return {
        "baseline": {"taken_at": baseline.get("taken_at"),
                     "app_version": baseline.get("app_version"),
                     "id": baseline.get("id")},
        "current": {"taken_at": current.get("taken_at"),
                    "app_version": current.get("app_version")},
        "changes": changes,
        "summary": {"changes": len(changes)},
        "unchanged": not changes,
        "notes": [
            "Compares state, not policy. Use the Policy Diff page for rules.",
            "A gateway missing from one side is reported, never treated as equal.",
        ],
    }


def _dir(base: Path | None = None) -> Path:
    path = Path(base) if base else BASELINE_DIR
    path.mkdir(parents=True, exist_ok=True)
    return path


def save_baseline(report: dict[str, Any], base: Path | None = None) -> str:
    stamp = re.sub(r"[^0-9]", "", str(report.get("taken_at") or ""))[:14]
    sid, n = f"health-{stamp}", 1
    directory = _dir(base)
    candidate = sid
    while (directory / f"{candidate}.json").exists():
        n += 1
        candidate = f"{sid}-{n}"
    report["id"] = candidate
    (directory / f"{candidate}.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return candidate


def list_baselines(base: Path | None = None) -> list[dict[str, Any]]:
    out = []
    for path in sorted(_dir(base).glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            continue
        out.append({"id": data.get("id") or path.stem,
                    "taken_at": data.get("taken_at"),
                    "app_version": data.get("app_version"),
                    "gateways": (data.get("summary") or {}).get("gateways_read"),
                    "findings": (data.get("summary") or {}).get("findings")})
    return sorted(out, key=lambda x: str(x.get("taken_at") or ""), reverse=True)


def load_baseline(sid: str, base: Path | None = None) -> dict[str, Any]:
    if not SAFE_ID.match(str(sid or "")):
        raise ValueError(f"Not a baseline id: {sid!r}")
    path = _dir(base) / f"{sid}.json"
    if path.resolve().parent != _dir(base).resolve():
        raise ValueError(f"Not a baseline id: {sid!r}")
    if not path.is_file():
        raise FileNotFoundError(f"No health baseline named {sid}")
    return json.loads(path.read_text(encoding="utf-8"))
