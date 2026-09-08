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


def nat_field_values(value: Any) -> list[Any]:
    """
    Check Point NAT fields can be returned as a single UID/string/object
    rather than an Access-rule-style list. Normalize both forms.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _name_index(objects: dict[str, dict[str, Any]]) -> dict[str, str]:
    """name -> uid, but only for names exactly one object carries.

    Chapter 5 homework (c): one rule can send `{"name": "X"}` and another
    `{"uid": "abc", "name": "X"}` for the same object, and the signature then
    reads "X" against "abc" and calls them different rules. The dictionary can
    settle that - but only when the name is unambiguous. Two objects called X
    prove nothing, and announcing a duplicate we cannot prove is a worse
    mistake than missing one.
    """
    seen: dict[str, str | None] = {}
    for uid, obj in objects.items():
        name = str((obj or {}).get("name") or "").strip()
        if not name:
            continue
        seen[name] = None if name in seen else uid
    return {name: uid for name, uid in seen.items() if uid}


def _uid_values(value: Any, names: dict[str, str] | None = None) -> tuple[str, ...]:
    out = []
    for item in nat_field_values(value):
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            uid = item.get("uid")
            # Some API responses can embed a name without a uid. Keep the name
            # rather than dropping the entry - an entry silently missing from a
            # signature makes two different rules look identical - and resolve
            # it to the uid when the dictionary names exactly one object.
            name = str(item.get("name") or "")
            out.append(str(uid or (names or {}).get(name) or name or ""))
        elif item is not None:
            out.append(str(item))
    return tuple(sorted(x for x in out if x))


def describe_nat_field(res: ObjectResolver, value: Any) -> str:
    values = nat_field_values(value)
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
    for item in nat_field_values(value):
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


# "Policy Targets" is the marker for "every gateway this package installs on",
# and "Any" means the same thing here. Neither is the name of a gateway, so
# neither can be missing from the gateway list. Flagging them would put a
# finding on nearly every NAT rule in nearly every policy, which is the
# quickest way to train someone to stop reading the report.
ALL_GATEWAY_MARKERS = {"policy targets", "any", "all", "*"}


def _install_on_targets(res: ObjectResolver, value: Any) -> list[tuple[str, str]]:
    """(uid, label) for each install-on entry, in both field shapes."""
    out: list[tuple[str, str]] = []
    for item in nat_field_values(value):
        if isinstance(item, str):
            out.append((item, str(res.obj(item).get("name") or item)))
        elif isinstance(item, dict):
            uid = str(item.get("uid") or "")
            name = item.get("name") or (res.obj(uid).get("name") if uid else None)
            out.append((uid, str(name or uid or item)))
        elif item is not None:
            out.append(("", str(item)))
    return out


def _known_gateways(gateways: Any) -> tuple[set[str], set[str]]:
    uids, names = set(), set()
    for g in gateways or []:
        if not isinstance(g, dict):
            continue
        if g.get("uid"):
            uids.add(str(g["uid"]))
        if g.get("name"):
            names.add(str(g["name"]).strip().lower())
    return uids, names


def analyze_nat_rulebase(
    payload: dict[str, Any],
    gateways: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Analyse a NAT rulebase.

    `gateways` is what show-gateways-and-servers returned. Pass it and the
    install-on targets are checked against reality; leave it out and the
    result says the check did not run. It must never say zero findings,
    because "nothing wrong" and "nothing to compare against" look the same
    in a summary and only one of them is good news.
    """
    objects = {
        obj["uid"]: obj
        for obj in payload.get("objects-dictionary", [])
        if isinstance(obj, dict) and obj.get("uid")
    }
    resolver = ObjectResolver(objects)
    names = _name_index(objects)
    rules = _nat_rules(payload.get("rulebase", []))

    rows = []
    signatures = defaultdict(list)
    disabled = []
    broad = []
    no_translation = []
    install_on_checked = gateways is not None
    known_uids, known_names = _known_gateways(gateways)
    install_on_unknown: list[Any] = []
    install_on_findings: list[dict[str, Any]] = []

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
            describe_nat_field(resolver, original_source),
            describe_nat_field(resolver, original_destination),
            describe_nat_field(resolver, original_service),
        )
        translated_desc = (
            describe_nat_field(resolver, translated_source),
            describe_nat_field(resolver, translated_destination),
            describe_nat_field(resolver, translated_service),
        )

        if all(x in {"—", "Original"} for x in translated_desc):
            no_translation.append(rule_number)

        if install_on_checked:
            for uid, label in _install_on_targets(resolver, install_on):
                if str(label).strip().lower() in ALL_GATEWAY_MARKERS:
                    continue
                if uid and uid in known_uids:
                    continue
                if str(label).strip().lower() in known_names:
                    continue
                install_on_findings.append({
                    "rule": rule_number,
                    "target": label,
                    "reason": (
                        f"Install-on target '{label}' is not among the gateways "
                        "show-gateways-and-servers returned, so this rule may never "
                        "be installed anywhere."
                    ),
                })
                if rule_number not in install_on_unknown:
                    install_on_unknown.append(rule_number)

        signature = (
            _uid_values(original_source, names),
            _uid_values(original_destination, names),
            _uid_values(original_service, names),
            _uid_values(translated_source, names),
            _uid_values(translated_destination, names),
            _uid_values(translated_service, names),
            _uid_values(install_on, names),
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
                "install_on": describe_nat_field(resolver, install_on),
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
            "install_on_checked": install_on_checked,
            "install_on_unknown_rules": len(install_on_unknown) if install_on_checked else None,
        },
        "findings": {
            "disabled_rule_numbers": disabled,
            "broad_rule_numbers": broad,
            "possible_no_translation_rule_numbers": no_translation,
            "install_on_unknown_rule_numbers": install_on_unknown,
            "install_on_findings": install_on_findings,
            "duplicates": duplicates,
        },
        "rules": rows,
        "notes": [
            "NAT analysis is configuration-based and read-only.",
            "NAT hit count is requested when the Management API build accepts show-hits, and silently omitted when it does not.",
            "Exact duplicate means original match, translated values, install-on, method, and enabled state are equal.",
            "A field sent as a name without a uid is resolved to that uid when the objects-dictionary names exactly one such object; an ambiguous name is left as written.",
            "Automatic NAT can also depend on object-level NAT configuration.",
        ] + ([
            "Install-on targets are compared with show-gateways-and-servers; "
            "'Policy Targets' means every gateway in the package and is not a finding.",
        ] if install_on_checked else [
            "Install-on targets were not checked: the gateway list from "
            "show-gateways-and-servers was not available to this analysis.",
        ]),
    }
