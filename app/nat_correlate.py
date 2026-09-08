"""
NAT correlation for Traffic Path: which NAT rule would act on this flow.

Split out of traffic.py in v4.20. traffic.py owns the tri-state Access
matcher and the inline-layer walk; keeping the NAT half here leaves both
under the 700-line module guard and gives this logic somewhere to grow.

Chapter 4 flagged the design problem this module fixes: correlation was a
boolean. A NAT rule built on an object this static simulator cannot model
answered "does not match", and because NAT is first-match-wins, the next
rule down was then reported as the one that runs. That is not a partial
answer, it is a different rule, presented with no warning.

Correlation is now tri-state, on the same rule as the Access side:

    match     both original-source and original-destination are proven
    unknown   at least one side uses an object with no static model
    no-match  proven not to apply, and skipped in silence

An `unknown` rule that sits ABOVE a proven one is returned FIRST, and the
proven rule below it is marked `blocked_by`, because "rule 7 would translate
this" stops being true the moment rule 3 might have taken the packet.

Deliberately not done here: original-service is not matched. It never was,
and adding it would silently change verdicts this release promised to keep.
The route reports that gap in its limitations rather than hiding it.
"""

from __future__ import annotations

from typing import Any

from .matching import address_match_state
from .nat_analyzer import describe_nat_field, nat_field_values
from .resolver import ObjectResolver


def _nat_rules(items) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

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


def _finding(res: ObjectResolver, rule: dict[str, Any], so: str, do: str) -> dict[str, Any]:
    return {
        "rule": rule.get("rule-number"),
        "name": rule.get("name", "") or "",
        "original_source": so,
        "original_destination": do,
        # describe_nat_field, not describe_list: NAT fields arrive as a bare
        # value as often as a list, and "Original" is a literal the API sends,
        # not a uid to look up.
        "translated_source": describe_nat_field(res, rule.get("translated-source")),
        "translated_destination": describe_nat_field(res, rule.get("translated-destination")),
        "translated_service": describe_nat_field(res, rule.get("translated-service")),
    }


def correlate_nat(
    payload: dict[str, Any],
    src: str,
    dst: str,
    res_extra: dict[str, dict] | None = None,
) -> list[dict[str, Any]]:
    objs = {
        o["uid"]: o
        for o in payload.get("objects-dictionary", [])
        if isinstance(o, dict) and o.get("uid")
    }
    if res_extra:
        objs.update(res_extra)
    res = ObjectResolver(objs)

    blocker: dict[str, Any] | None = None

    for rule in _nat_rules(payload.get("rulebase", [])):
        if not rule.get("enabled", True):
            continue

        ss, so = address_match_state(nat_field_values(rule.get("original-source")), src, res)
        if ss == "no-match":
            continue
        ds, do = address_match_state(
            nat_field_values(rule.get("original-destination")), dst, res
        )
        if ds == "no-match":
            continue

        entry = _finding(res, rule, so, do)
        entry["source_state"] = ss
        entry["destination_state"] = ds
        entry["state"] = "match" if ss == "match" and ds == "match" else "unknown"

        if entry["state"] == "match":
            if blocker is None:
                entry["confidence"] = "exact"
                return [entry]
            entry["confidence"] = "unverified"
            entry["blocked_by"] = blocker.get("rule")
            entry["reason"] = (
                f"NAT Rule {entry['rule']} matches, but earlier NAT Rule "
                f"{blocker.get('rule')} could not be evaluated. NAT is "
                "first-match-wins, so this cannot be declared the rule that runs."
            )
            return [blocker, entry]

        if blocker is None:
            entry["confidence"] = "unverified"
            entry["reason"] = (
                f"NAT Rule {entry['rule']} uses object(s) with no static model, "
                "so whether it takes this flow cannot be decided here."
            )
            blocker = entry

    return [blocker] if blocker else []
