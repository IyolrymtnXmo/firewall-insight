"""
Capture a policy package as a file that can be compared with a later one.

A snapshot is deliberately more than a dump of the API response. It carries,
per rule, the *resolved reach* of each dimension - the address and port
intervals the objects actually cover at capture time - because that is the
only way a later comparison can notice that a group gained a member while
every rule referencing it stayed textually identical. See snapshot_diff.py.

It is also deliberately less than a dump: no object dictionary, no payload
bodies. A snapshot should be small enough to keep one per audit cycle for
years and readable enough that a person can open it in an editor and see what
their firewall looked like on a given day.

Writing a snapshot file is the one thing in this application that touches the
disk. It changes nothing on the Management Server - the read-only guarantee is
about the estate, not about the laptop - but it is worth knowing that it
happens, so the route that does it says so in its response.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .nat_analyzer import describe_nat_field, nat_field_values
from .policy_browser import _action_name, _single_name, _walk_rulebase
from .resolver import ObjectResolver
from .version import APP_VERSION

SCHEMA = 1
SNAPSHOT_DIR = Path(__file__).resolve().parent.parent / "snapshots"
# A snapshot id becomes a file name. Anything outside this set is refused
# rather than sanitised: quietly rewriting a path is how a traversal bug ends
# up looking like it works. The first character must be alphanumeric, which
# rules out "..", "." and dot-files without needing a second rule about them.
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")

ADDRESS_DIMENSIONS = {"source": "source", "destination": "destination"}
SERVICE_DIMENSIONS = {"service": "service"}
PLAIN_DIMENSIONS = {"vpn": "vpn", "install_on": "install-on"}


def _address_dimension(values: Any, res: ObjectResolver) -> dict[str, Any]:
    uids = res.uids(values)
    atoms, complete = [], True
    for uid in uids:
        part, part_complete = res.address_atoms_partial(uid)
        complete = complete and part_complete
        for atom in part:
            atoms.append([atom.version, atom.start, atom.end])
    return {"uids": uids, "text": res.describe_list(values),
            "atoms": sorted(atoms), "complete": complete}


def _service_dimension(values: Any, res: ObjectResolver) -> dict[str, Any]:
    uids = res.uids(values)
    atoms, complete = [], True
    for uid in uids:
        part, part_complete = res.service_atoms_partial(uid)
        complete = complete and part_complete
        for atom in part:
            atoms.append([atom.proto, atom.start, atom.end])
    return {"uids": uids, "text": res.describe_list(values),
            "atoms": sorted(atoms), "complete": complete}


def _plain_dimension(values: Any, res: ObjectResolver) -> dict[str, Any]:
    # VPN and install-on have no intervals to resolve, so they are compared on
    # the objects they name and nothing else. Empty atoms with complete=True
    # keeps them out of the scope comparison instead of making it unavailable.
    return {"uids": res.uids(values), "text": res.describe_list(values),
            "atoms": [], "complete": True}


def build_snapshot(
    tree: dict[str, Any],
    nat_payload: dict[str, Any] | None,
    package: str,
    taken_at: str | None = None,
) -> dict[str, Any]:
    rules: list[dict[str, Any]] = []
    position = 0

    for node in tree.get("layers", []) or []:
        payload = node.get("payload") or {}
        objects = {
            o["uid"]: o for o in payload.get("objects-dictionary", []) or []
            if isinstance(o, dict) and o.get("uid")
        }
        res = ObjectResolver(objects)
        prefix = str(node.get("display_prefix") or "")

        for section, rule in _walk_rulebase(payload.get("rulebase", [])):
            position += 1
            number = rule.get("rule-number")
            hits = rule.get("hits") if isinstance(rule.get("hits"), dict) else {}
            row = {
                "uid": str(rule.get("uid") or ""),
                "display_rule": f"{prefix}.{number}" if prefix else str(number),
                "rule_number": number,
                "position": position,
                "layer": node.get("name"),
                "section": section or "",
                "name": rule.get("name") or "",
                "enabled": bool(rule.get("enabled", True)),
                "action": _action_name(rule, res),
                "track": _single_name(rule.get("track"), res),
                "comments": rule.get("comments") or "",
                "inline_layer": _single_name(rule.get("inline-layer"), res),
                "hits": hits.get("value"),
                "last_hit": hits.get("last-date") or hits.get("last-hit"),
            }
            for name, field in ADDRESS_DIMENSIONS.items():
                row[name] = _address_dimension(rule.get(field), res)
            for name, field in SERVICE_DIMENSIONS.items():
                row[name] = _service_dimension(rule.get(field), res)
            for name, field in PLAIN_DIMENSIONS.items():
                row[name] = _plain_dimension(rule.get(field), res)
            rules.append(row)

    nat_rules = _nat_rows(nat_payload)

    return {
        "schema": SCHEMA,
        "package": package,
        "app_version": APP_VERSION,
        "taken_at": taken_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "access": {"rules": rules},
        "nat": {"rules": nat_rules},
        "summary": {"access_rules": len(rules), "nat_rules": len(nat_rules)},
        "notes": [
            "Resolved intervals are recorded per dimension so a later comparison "
            "can see an object's contents change while the rule text does not.",
            "Those intervals are produced by this application, so comparing "
            "snapshots taken by different versions of it can show differences "
            "that are not policy changes.",
        ],
    }


def _nat_rows(payload: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not payload:
        return []
    objects = {
        o["uid"]: o for o in payload.get("objects-dictionary", []) or []
        if isinstance(o, dict) and o.get("uid")
    }
    res = ObjectResolver(objects)

    rows, position = [], 0

    def walk(items):
        nonlocal position
        for item in items or []:
            if not isinstance(item, dict):
                continue
            if item.get("type") == "nat-rule":
                position += 1
                rows.append({
                    "uid": str(item.get("uid") or ""),
                    "rule": item.get("rule-number"),
                    "position": position,
                    "name": item.get("name") or "",
                    "enabled": bool(item.get("enabled", True)),
                    "original_source": describe_nat_field(res, item.get("original-source")),
                    "original_destination": describe_nat_field(res, item.get("original-destination")),
                    "original_service": describe_nat_field(res, item.get("original-service")),
                    "translated_source": describe_nat_field(res, item.get("translated-source")),
                    "translated_destination": describe_nat_field(res, item.get("translated-destination")),
                    "translated_service": describe_nat_field(res, item.get("translated-service")),
                    "install_on": describe_nat_field(res, item.get("install-on")),
                    "method": _nat_method(item),
                })
            if isinstance(item.get("rulebase"), list):
                walk(item["rulebase"])

    walk(payload.get("rulebase", []))
    return rows


def _nat_method(rule: dict[str, Any]) -> str:
    for key in ("method", "nat-method", "translated-source-method"):
        value = rule.get(key)
        if isinstance(value, dict):
            return str(value.get("name") or value.get("uid") or "")
        if value:
            return str(value)
    return ""


# ---- on-disk store ----------------------------------------------------

def snapshot_id(package: str, taken_at: str) -> str:
    safe_package = re.sub(r"[^A-Za-z0-9._-]", "_", str(package or "package"))
    safe_package = re.sub(r"^[^A-Za-z0-9]+", "", safe_package) or "package"
    stamp = re.sub(r"[^0-9]", "", str(taken_at))[:14]
    return f"{safe_package}-{stamp}"


def _dir(base: Path | None = None) -> Path:
    path = Path(base) if base else SNAPSHOT_DIR
    path.mkdir(parents=True, exist_ok=True)
    return path


def save_snapshot(snapshot: dict[str, Any], base: Path | None = None) -> str:
    sid = snapshot_id(snapshot.get("package", ""), snapshot.get("taken_at", ""))
    directory = _dir(base)
    candidate, n = sid, 1
    while (directory / f"{candidate}.json").exists():
        n += 1
        candidate = f"{sid}-{n}"
    snapshot["id"] = candidate
    (directory / f"{candidate}.json").write_text(
        json.dumps(snapshot, indent=2, ensure_ascii=False), encoding="utf-8")
    return candidate


def list_snapshots(base: Path | None = None) -> list[dict[str, Any]]:
    out = []
    for path in sorted(_dir(base).glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            continue
        # Hit totals per snapshot, so a trend over time can be drawn from
        # readings that actually happened. The Management API reports a running
        # total and a last-hit date, never a time series - the only honest way
        # to get one is to compare snapshots the user took. A rule that reports
        # no count at all is excluded from the total rather than counted as 0,
        # and `hit_counted_rules` says how many rules the total covers.
        rules = ((data.get("access") or {}).get("rules")) or []
        counted = [r for r in rules
                   if isinstance(r, dict) and isinstance(r.get("hits"), int)]
        out.append({
            "id": data.get("id") or path.stem,
            "package": data.get("package"),
            "taken_at": data.get("taken_at"),
            "app_version": data.get("app_version"),
            "access_rules": (data.get("summary") or {}).get("access_rules"),
            "nat_rules": (data.get("summary") or {}).get("nat_rules"),
            "total_hits": sum(r["hits"] for r in counted) if counted else None,
            "hit_counted_rules": len(counted),
            "zero_hit_rules": sum(1 for r in counted if r["hits"] == 0),
            "bytes": path.stat().st_size,
        })
    return sorted(out, key=lambda x: str(x.get("taken_at") or ""), reverse=True)


def load_snapshot(sid: str, base: Path | None = None) -> dict[str, Any]:
    if not SAFE_ID.match(str(sid or "")):
        raise ValueError(f"Not a snapshot id: {sid!r}")
    path = _dir(base) / f"{sid}.json"
    # Belt and braces: the pattern already excludes separators, but resolve
    # and re-check rather than trusting one regex with a file read behind it.
    if path.resolve().parent != _dir(base).resolve():
        raise ValueError(f"Not a snapshot id: {sid!r}")
    if not path.is_file():
        raise FileNotFoundError(f"No snapshot named {sid}")
    return json.loads(path.read_text(encoding="utf-8"))
