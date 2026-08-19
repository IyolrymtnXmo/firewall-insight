from __future__ import annotations
from typing import Any
from .resolver import ObjectResolver


def _walk_rulebase(items: list[dict[str, Any]], section: str = ""):
    """Flatten Access rulebase while preserving section names."""
    for item in items or []:
        if not isinstance(item, dict):
            continue

        item_type = item.get("type")
        if item_type == "access-section":
            section_name = item.get("name") or section
            yield from _walk_rulebase(item.get("rulebase", []), section_name)
            continue

        if item_type == "access-rule":
            yield section, item

        nested = item.get("rulebase")
        if item_type != "access-section" and isinstance(nested, list):
            yield from _walk_rulebase(nested, section)


def _action_name(rule: dict[str, Any], resolver: ObjectResolver) -> str:
    value = rule.get("action")
    if isinstance(value, dict):
        return str(value.get("name") or value.get("uid") or "")
    return resolver.name(value)


def _single_name(value: Any, resolver: ObjectResolver) -> str:
    if isinstance(value, dict):
        return str(value.get("name") or value.get("uid") or "")
    if isinstance(value, str):
        return resolver.name(value)
    if isinstance(value, list):
        return resolver.describe_list(value)
    return str(value or "")


def browse_access_rulebase(payload: dict[str, Any]) -> dict[str, Any]:
    """
    Read-only representation of the policy as returned by Check Point.
    This does not calculate shadowing, redundancy, duplicates or score.
    """
    objects = {
        obj["uid"]: obj
        for obj in payload.get("objects-dictionary", [])
        if isinstance(obj, dict) and obj.get("uid")
    }
    resolver = ObjectResolver(objects)

    rows = []
    for section, rule in _walk_rulebase(payload.get("rulebase", [])):
        hits = rule.get("hits") if isinstance(rule.get("hits"), dict) else {}
        rows.append(
            {
                "rule": rule.get("rule-number"),
                "section": section or "",
                "name": rule.get("name") or "",
                "enabled": bool(rule.get("enabled", True)),
                "source": resolver.describe_list(rule.get("source")),
                "destination": resolver.describe_list(rule.get("destination")),
                "vpn": resolver.describe_list(rule.get("vpn")),
                "service": resolver.describe_list(rule.get("service")),
                "action": _action_name(rule, resolver),
                "track": _single_name(rule.get("track"), resolver),
                "install_on": resolver.describe_list(rule.get("install-on")),
                "time": resolver.describe_list(rule.get("time")),
                "inline_layer": _single_name(rule.get("inline-layer"), resolver),
                "comments": rule.get("comments") or "",
                "hits": hits.get("value"),
                "last_hit": hits.get("last-date") or hits.get("last-hit"),
            }
        )

    return {
        "layer": payload.get("layer"),
        "total_rules": len(rows),
        "rules": rows,
        "mode": "raw-policy-browser",
        "analyzed": False,
        "notes": [
            "Policy Browser displays configured Access Control rules without optimizer analysis.",
            "Object names are resolved from the object dictionary returned with the rulebase.",
            "No policy changes are made.",
        ],
    }
