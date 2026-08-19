from __future__ import annotations
from collections import defaultdict
from typing import Any

from .resolver import ObjectResolver


def _nat_rules(items):
    out = []

    def walk(xs):
        for x in xs or []:
            if not isinstance(x, dict):
                continue
            if x.get("type") == "nat-rule":
                out.append(x)
            if isinstance(x.get("rulebase"), list):
                walk(x["rulebase"])

    walk(items)
    return out


def _as_list(value: Any) -> list[Any]:
    """
    Check Point NAT fields can be returned as a single UID/string/object
    rather than an Access-rule-style list. Normalize both forms.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _uid_values(value: Any) -> tuple[str, ...]:
    out = []
    for item in _as_list(value):
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            uid = item.get("uid")
            # Some API responses can embed a name without a uid.
            out.append(str(uid or item.get("name") or ""))
        elif item is not None:
            out.append(str(item))
    return tuple(sorted(x for x in out if x))


def _describe(res: ObjectResolver, value: Any) -> str:
    values = _as_list(value)
    if not values:
        return "—"

    parts = []
    for item in values:
        if isinstance(item, dict):
            uid = item.get("uid")
            name = item.get("name")
            if uid:
                parts.append(res.describe_uid(uid))
            elif name:
                parts.append(str(name))
            else:
                parts.append(str(item))
        elif isinstance(item, str):
            # "Original" is a literal translated-field value in NAT rules.
            if item.lower() == "original":
                parts.append("Original")
            else:
                parts.append(res.describe_uid(item))
        else:
            parts.append(str(item))

    return ", ".join(parts) if parts else "—"


def _is_any(res: ObjectResolver, value: Any) -> bool:
    for item in _as_list(value):
        uid = None
        if isinstance(item, str):
            uid = item
        elif isinstance(item, dict):
            uid = item.get("uid")
            if str(item.get("name", "")).lower() == "any":
                return True
        if uid and res.is_any_uid(uid):
            return True
    return False


def _method(rule: dict[str, Any]) -> str:
    for key in ("method", "nat-method", "translated-source-method"):
        value = rule.get(key)
        if isinstance(value, dict):
            return str(value.get("name") or value.get("uid") or "")
        if value:
            return str(value)
    return ""


def analyze_nat_rulebase(payload: dict[str, Any]) -> dict[str, Any]:
    objects = {
        obj["uid"]: obj
        for obj in payload.get("objects-dictionary", [])
        if isinstance(obj, dict) and obj.get("uid")
    }
    resolver = ObjectResolver(objects)
    rules = _nat_rules(payload.get("rulebase", []))

    rows = []
    signatures = defaultdict(list)
    disabled = []
    broad = []
    no_translation = []

    hits_available = False

    for rule in rules:
        rule_number = rule.get("rule-number")
        enabled = bool(rule.get("enabled", True))
        hits = rule.get("hits") if isinstance(rule.get("hits"), dict) else {}
        hit_value = hits.get("value")
        if hit_value is not None:
            hits_available = True
        if not enabled:
            disabled.append(rule_number)

        original_source = rule.get("original-source")
        original_destination = rule.get("original-destination")
        original_service = rule.get("original-service")
        translated_source = rule.get("translated-source")
        translated_destination = rule.get("translated-destination")
        translated_service = rule.get("translated-service")
        install_on = rule.get("install-on")
        method = _method(rule)

        if (
            _is_any(resolver, original_source)
            and _is_any(resolver, original_destination)
            and _is_any(resolver, original_service)
        ):
            broad.append(rule_number)

        original_desc = (
            _describe(resolver, original_source),
            _describe(resolver, original_destination),
            _describe(resolver, original_service),
        )
        translated_desc = (
            _describe(resolver, translated_source),
            _describe(resolver, translated_destination),
            _describe(resolver, translated_service),
        )

        if all(x in {"—", "Original"} for x in translated_desc):
            no_translation.append(rule_number)

        signature = (
            _uid_values(original_source),
            _uid_values(original_destination),
            _uid_values(original_service),
            _uid_values(translated_source),
            _uid_values(translated_destination),
            _uid_values(translated_service),
            _uid_values(install_on),
            method,
            enabled,
        )
        signatures[signature].append(rule)

        rows.append(
            {
                "rule": rule_number,
                "name": rule.get("name", "") or "",
                "enabled": enabled,
                "original_source": original_desc[0],
                "original_destination": original_desc[1],
                "original_service": original_desc[2],
                "translated_source": translated_desc[0],
                "translated_destination": translated_desc[1],
                "translated_service": translated_desc[2],
                "install_on": _describe(resolver, install_on),
                "method": method or "—",
                # Populated when the Management API build supports
                # show-nat-rulebase + show-hits. Stays None otherwise.
                "hits": hit_value,
                "last_hit": hits.get("last-date") or hits.get("last-hit"),
            }
        )

    duplicates = []
    for group in signatures.values():
        if len(group) < 2:
            continue

        members = []
        for rule in group:
            row = next(
                (x for x in rows if x["rule"] == rule.get("rule-number")),
                None,
            )
            if row:
                members.append(row)

        if members:
            duplicates.append(
                {
                    "group": len(duplicates) + 1,
                    "classification": "Exact NAT Duplicate",
                    "members": members,
                    "rule_numbers": [m["rule"] for m in members],
                    "recommendation": (
                        f"Review later NAT rule(s) "
                        f"{', '.join(str(m['rule']) for m in members[1:])} "
                        f"against earliest Rule {members[0]['rule']} before any change."
                    ),
                }
            )

    return {
        "summary": {
            "total_nat_rules": len(rules),
            "disabled_nat_rules": len(disabled),
            "duplicate_nat_groups": len(duplicates),
            "broad_original_any_any_any": len(broad),
            "possible_no_translation_rules": len(no_translation),
            "nat_hits_available": hits_available,
        },
        "findings": {
            "disabled_rule_numbers": disabled,
            "broad_rule_numbers": broad,
            "possible_no_translation_rule_numbers": no_translation,
            "duplicates": duplicates,
        },
        "rules": rows,
        "notes": [
            "NAT analysis is configuration-based and read-only.",
            "NAT hit count is requested when the Management API build accepts show-hits, and silently omitted when it does not.",
            "Exact duplicate means original match, translated values, install-on, method, and enabled state are equal.",
            "Automatic NAT can also depend on object-level NAT configuration.",
        ],
    }
