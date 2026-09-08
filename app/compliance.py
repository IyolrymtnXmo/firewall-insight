"""
Compliance as code: the customer writes the standard, this evaluates it.

The question this feature had to answer before a line of it was worth writing
was "why would anyone believe our baseline?" Every firewall estate is
different, so a baseline we invent is our opinion wearing the costume of a
requirement, and an auditor is right to reject it.

So the tool ships no authority. A *profile* is a YAML or JSON file the
customer owns, listing the checks they have decided apply to them, and this
module reports conformance against those. Profiles that ship with the
application are starting points, and each of their checks carries the clause
it came from so a reader can go and disagree with the standard rather than
with us.

Three properties hold the design together:

**Provenance is part of the result.** Every check may declare a `source`. One
without is not rejected - house rules are legitimate and common - but it comes
back labelled `cited: false`, and the summary counts how many there were.
Making an uncited rule look identical to one backed by NIST is how a report
stops being evidence.

**The result is tri-state.** `unverifiable` is a real status and it is never
rounded up to `pass`. A rule whose service cannot be resolved cannot be proven
to exclude telnet, and a compliance report that quietly signs that off is
worse than no report at all, because somebody puts their name on it.

**There is no percentage.** A single score has to decide what an unverifiable
check is worth, and every available answer to that is a lie: count it as a
pass and the report overstates, as a fail and it cries wolf, exclude it and
the denominator moves silently. So the engine reports counts, and
`conformant` is true only when nothing failed AND nothing was unverifiable.
"""

from __future__ import annotations

import json
import re
from ipaddress import ip_network
from pathlib import Path
from typing import Any, Callable

PROFILE_DIR = Path(__file__).resolve().parent / "compliance_profiles"

PASS, FAIL, UNVERIFIABLE, NOT_APPLICABLE = "pass", "fail", "unverifiable", "not_applicable"

UNCITED = {
    "standard": "local",
    "note": "House rule - no external standard cited for this check.",
}


# ---- profile loading --------------------------------------------------

def load_profile(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        import yaml                                   # only needed for YAML
        return yaml.safe_load(text) or {}
    return json.loads(text)


def list_profiles(base: Path | None = None) -> list[dict[str, Any]]:
    directory = Path(base) if base else PROFILE_DIR
    if not directory.is_dir():
        return []
    out = []
    for path in sorted(directory.glob("*")):
        if path.suffix.lower() not in (".yaml", ".yml", ".json"):
            continue
        try:
            data = load_profile(path)
        except Exception:                                         # noqa: BLE001
            continue
        checks = data.get("checks") or []
        out.append({
            "id": path.stem,
            "name": data.get("name") or path.stem,
            "description": data.get("description") or "",
            "checks": len(checks),
            "cited_checks": sum(1 for c in checks if c.get("source")),
            "file": path.name,
        })
    return out


def load_profile_by_id(pid: str, base: Path | None = None) -> dict[str, Any]:
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$", str(pid or "")):
        raise ValueError(f"Not a profile id: {pid!r}")
    directory = Path(base) if base else PROFILE_DIR
    for suffix in (".yaml", ".yml", ".json"):
        candidate = directory / f"{pid}{suffix}"
        if candidate.is_file():
            return load_profile(candidate)
    raise FileNotFoundError(f"No compliance profile named {pid}")


# ---- predicates over one snapshot rule --------------------------------

def _is_any(dimension: dict[str, Any] | None) -> bool:
    return str((dimension or {}).get("text") or "").strip().lower() == "any"


def _address_covers(dimension: dict[str, Any] | None, cidr: str) -> tuple[bool | None, str]:
    """
    Does this dimension reach anything inside `cidr`?

    None means "cannot tell": the dimension has an object with no static model
    and none of the intervals we DO understand overlap. Proving an overlap only
    needs one interval, so a positive answer stays trustworthy even when the
    dimension is incomplete - the same asymmetry the tri-state matcher uses.
    """
    dimension = dimension or {}
    try:
        net = ip_network(str(cidr), strict=False)
    except ValueError:
        return None, f"{cidr!r} is not a network"
    low, high = int(net.network_address), int(net.broadcast_address)

    for atom in dimension.get("atoms") or []:
        try:
            version, start, end = atom[0], int(atom[1]), int(atom[2])
        except (TypeError, ValueError, IndexError):
            continue
        if version != net.version:
            continue
        if not (end < low or start > high):
            return True, "overlaps"
    if not dimension.get("complete", True):
        return None, f"{dimension.get('text')} has no static model"
    return False, "no overlap"


def _service_covers(dimension: dict[str, Any] | None, protocol: str,
                    port: int) -> tuple[bool | None, str]:
    dimension = dimension or {}
    proto = str(protocol or "tcp").lower()
    for atom in dimension.get("atoms") or []:
        try:
            atom_proto, start, end = str(atom[0]).lower(), int(atom[1]), int(atom[2])
        except (TypeError, ValueError, IndexError):
            continue
        if atom_proto not in (proto, "any"):
            continue
        if start <= port <= end:
            return True, "covers"
    if not dimension.get("complete", True):
        return None, f"{dimension.get('text')} has no static model"
    return False, "does not cover"


def _matches(rule: dict[str, Any], where: dict[str, Any]) -> tuple[bool | None, str]:
    """
    True / False / None for one rule against a `where` block.

    None means at least one clause could not be decided, which is what makes a
    whole check unverifiable rather than passing on ignorance.
    """
    reasons: list[str] = []
    matched: list[str] = []

    action = where.get("action")
    if action and str(rule.get("action") or "").strip().lower() != str(action).lower():
        return False, ""

    if "enabled" in where and bool(rule.get("enabled", True)) != bool(where["enabled"]):
        return False, ""

    layer = where.get("layer")
    if layer and str(rule.get("layer") or "") != str(layer):
        return False, ""

    pattern = where.get("name_matches")
    if pattern and not re.search(str(pattern), str(rule.get("name") or "")):
        return False, ""

    if where.get("track_is_none") and str(rule.get("track") or "").lower() not in ("none", ""):
        return False, ""

    for key, field in (("source_is_any", "source"),
                       ("destination_is_any", "destination"),
                       ("service_is_any", "service")):
        if key in where and _is_any(rule.get(field)) != bool(where[key]):
            return False, ""

    for key, field in (("source_covers", "source"), ("destination_covers", "destination")):
        if key not in where:
            continue
        covered, why = _address_covers(rule.get(field), where[key])
        if covered is None:
            reasons.append(f"{field}: {why}")
        elif not covered:
            return False, ""

    if "service_covers" in where:
        spec = where["service_covers"] or {}
        proto, port = str(spec.get("protocol", "tcp")).upper(), int(spec.get("port", 0))
        covered, why = _service_covers(rule.get("service"), proto.lower(), port)
        if covered is None:
            reasons.append(f"service: {why}")
        elif not covered:
            return False, ""
        else:
            # "matches the forbidden condition" is true and unhelpful. On the
            # lab this check fires on a rule whose service is Any, and the
            # reader deserves to be told that is why.
            matched.append(
                f"service {rule.get('service', {}).get('text') or '?'} "
                f"covers {proto}/{port}")

    if reasons:
        return None, "; ".join(reasons)
    return True, "; ".join(matched)


def _offender(rule: dict[str, Any], extra: str = "") -> dict[str, Any]:
    row = {
        "uid": rule.get("uid"),
        "display_rule": rule.get("display_rule"),
        "name": rule.get("name"),
        "layer": rule.get("layer"),
        "action": rule.get("action"),
        "source": (rule.get("source") or {}).get("text"),
        "destination": (rule.get("destination") or {}).get("text"),
        "service": (rule.get("service") or {}).get("text"),
    }
    if extra:
        row["reason"] = extra
    return row


# ---- check types ------------------------------------------------------

FINDING_KEYS = {
    "shadowed": "potential_shadowed_or_redundant",
    "duplicate": "duplicate_groups",
    "any_any_any": "any_any_any_rules",
    "zero_hit": "zero_hit_rules",
    "disabled": "disabled_rules",
}
NAT_FINDING_KEYS = {
    "broad": "broad_original_any_any_any",
    "no_translation": "possible_no_translation_rules",
    "duplicate": "duplicate_nat_groups",
    "install_on_unknown": "install_on_unknown_rules",
}


def _check_no_rule_matches(check, rules, ctx):
    where = check.get("where") or {}
    if not rules:
        return NOT_APPLICABLE, "This package has no rules to test.", [], []
    offenders, unknown = [], []
    for rule in rules:
        verdict, why = _matches(rule, where)
        if verdict is True:
            offenders.append(_offender(rule, why))
        elif verdict is None:
            unknown.append(_offender(rule, why))
    if offenders:
        return FAIL, f"{len(offenders)} rule(s) match a condition this profile forbids.", offenders, unknown
    if unknown:
        return (UNVERIFIABLE,
                f"{len(unknown)} rule(s) could not be decided, so the absence of a "
                "violation is not proven.", [], unknown)
    return PASS, "No rule matches the forbidden condition.", [], []


def _check_all_rules_have(check, rules, ctx):
    field = str(check.get("field") or "")
    if field not in ("track", "comments", "name"):
        return UNVERIFIABLE, f"Unsupported field {field!r} for all_rules_have.", [], []
    if not rules:
        return NOT_APPLICABLE, "This package has no rules to test.", [], []
    offenders = []
    for rule in rules:
        value = str(rule.get(field) or "").strip()
        missing = not value or (field == "track" and value.lower() == "none")
        if missing:
            offenders.append(_offender(rule, f"{field} is empty"))
    if offenders:
        return FAIL, f"{len(offenders)} rule(s) have no {field}.", offenders, []
    return PASS, f"Every rule carries a {field}.", [], []


def _check_no_disabled_rules(check, rules, ctx):
    if not rules:
        return NOT_APPLICABLE, "This package has no rules to test.", [], []
    offenders = [_offender(r, "disabled") for r in rules if not r.get("enabled", True)]
    if offenders:
        return FAIL, f"{len(offenders)} disabled rule(s) remain in the package.", offenders, []
    return PASS, "No disabled rules.", [], []


def _check_cleanup_rule_present(check, rules, ctx):
    if not rules:
        return NOT_APPLICABLE, "This package has no rules to test.", [], []
    by_layer: dict[str, list[dict[str, Any]]] = {}
    for rule in rules:
        by_layer.setdefault(str(rule.get("layer") or ""), []).append(rule)

    offenders = []
    for layer, layer_rules in by_layer.items():
        last = max(layer_rules, key=lambda r: r.get("position") or 0)
        is_cleanup = (
            str(last.get("action") or "").lower() in ("drop", "reject")
            and _is_any(last.get("source")) and _is_any(last.get("destination"))
            and _is_any(last.get("service")))
        if not is_cleanup:
            offenders.append(_offender(last, f"last rule in {layer} is not an explicit cleanup rule"))
            continue
        if check.get("require_log") and str(last.get("track") or "").lower() in ("none", ""):
            offenders.append(_offender(last, f"cleanup rule in {layer} is not logged"))
    if offenders:
        return FAIL, f"{len(offenders)} layer(s) have no explicit logged cleanup rule.", offenders, []
    return PASS, "Every layer ends with an explicit cleanup rule.", [], []


def _check_max_rules(check, rules, ctx):
    try:
        limit = int(check.get("limit"))
    except (TypeError, ValueError):
        return UNVERIFIABLE, "max_rules needs an integer 'limit'.", [], []
    if len(rules) > limit:
        return FAIL, f"{len(rules)} rules exceeds the ceiling of {limit}.", [], []
    return PASS, f"{len(rules)} rules, within the ceiling of {limit}.", [], []


def _finding_check(check, ctx, source_key, keys, label):
    kind = str(check.get("kind") or "")
    field = keys.get(kind)
    if field is None:
        return UNVERIFIABLE, f"Unknown {label} finding kind {kind!r}.", [], []
    summary = ((ctx.get(source_key) or {}).get("summary")) or {}
    if field not in summary:
        return (UNVERIFIABLE,
                f"No {label} analysis was supplied to this run, so {kind!r} could "
                "not be checked. Run it against a live package rather than a "
                "snapshot alone.", [], [])
    count = summary.get(field)
    if count is None:
        return (UNVERIFIABLE,
                f"The {label} analysis reports {field} as not checked.", [], [])
    if count:
        return FAIL, f"{count} {kind} finding(s) reported by the {label} analysis.", [], []
    return PASS, f"No {kind} findings.", [], []


def _check_no_findings(check, rules, ctx):
    return _finding_check(check, ctx, "analysis", FINDING_KEYS, "access")


def _check_nat_no_findings(check, rules, ctx):
    return _finding_check(check, ctx, "nat_analysis", NAT_FINDING_KEYS, "NAT")


CHECK_TYPES: dict[str, Callable] = {
    "no_rule_matches": _check_no_rule_matches,
    "all_rules_have": _check_all_rules_have,
    "no_disabled_rules": _check_no_disabled_rules,
    "cleanup_rule_present": _check_cleanup_rule_present,
    "max_rules": _check_max_rules,
    "no_findings": _check_no_findings,
    "nat_no_findings": _check_nat_no_findings,
}


# ---- the run ----------------------------------------------------------

def evaluate_profile(
    profile: dict[str, Any],
    snapshot: dict[str, Any],
    analysis: dict[str, Any] | None = None,
    nat_analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    rules = ((snapshot.get("access") or {}).get("rules")) or []
    ctx = {"analysis": analysis, "nat_analysis": nat_analysis, "snapshot": snapshot}

    results = []
    for check in profile.get("checks") or []:
        cid = check.get("id")
        if not cid:
            raise ValueError(
                "Every check needs an 'id'. A result nobody can point at by name "
                "cannot be tracked between audits.")

        handler = CHECK_TYPES.get(str(check.get("type") or ""))
        if handler is None:
            status, detail, offenders, unknown = (
                UNVERIFIABLE,
                f"Unknown check type {check.get('type')!r}. Supported: "
                + ", ".join(sorted(CHECK_TYPES)), [], [])
        else:
            status, detail, offenders, unknown = handler(check, rules, ctx)

        source = check.get("source")
        results.append({
            "id": cid,
            "title": check.get("title") or cid,
            "severity": str(check.get("severity") or "medium"),
            "type": check.get("type"),
            "status": status,
            "detail": detail,
            "offenders": offenders,
            "unverifiable_rules": unknown,
            "source": source or dict(UNCITED),
            "cited": bool(source),
        })

    counts = {status: sum(1 for r in results if r["status"] == status)
              for status in (PASS, FAIL, UNVERIFIABLE, NOT_APPLICABLE)}
    summary = {
        "total": len(results),
        "passed": counts[PASS],
        "failed": counts[FAIL],
        "unverifiable": counts[UNVERIFIABLE],
        "not_applicable": counts[NOT_APPLICABLE],
        "uncited_checks": sum(1 for r in results if not r["cited"]),
        # No percentage on purpose. See the module docstring: any single number
        # has to price an unverifiable check, and every price is wrong.
    }

    return {
        "profile": {
            "name": profile.get("name") or "unnamed profile",
            "version": profile.get("version"),
            "description": profile.get("description") or "",
        },
        # Requirements the profile author knows this tool cannot decide -
        # process controls, evidence, interviews. Listed so the report says
        # what it did NOT cover instead of implying the standard is finished.
        "not_checkable": list(profile.get("not_checkable") or []),
        "package": snapshot.get("package"),
        "taken_at": snapshot.get("taken_at"),
        "app_version": snapshot.get("app_version"),
        "summary": summary,
        "conformant": counts[FAIL] == 0 and counts[UNVERIFIABLE] == 0,
        "results": results,
        "notes": [
            "Checks come from the profile file, not from this application. "
            "A check with no cited standard is reported as a house rule.",
            "An unverifiable check is never counted as a pass, and the run is "
            "not conformant while one remains.",
            "No compliance percentage is produced: a single number would have to "
            "price an unverifiable check, and every available price misleads.",
        ],
    }
