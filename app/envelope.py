"""
v4.41 - the supported-policy envelope, enforced by the tool instead of assumed.

The simulator and the shadowing check model Source, Destination and Service
(plus VPN as unknown-only). Three more Access Control columns can change
whether a rule applies, and neither analysis models them:

  * Time        - the rule only applies inside a time window
  * Content     - the rule only applies to some data types (or not, if negated)
  * Install On  - the rule only exists on the listed gateways

v4.40 documented these as preconditions the user had to check. v4.41 checks
them itself, per rule:

  * traffic: a rule whose Time / Content / Install On is not the default
    (Any / Any / Policy Targets) cannot be a proven match, so its state is
    capped at `unknown`. It can still be a proven no-match, because these
    columns only ever narrow a rule. (Kleene: min(state, 1/2).)
  * shadowing: such a rule cannot be the *covering* rule, because outside its
    window, data types or targets it matches nothing. It can still be the
    covered (later) rule - restrictions only shrink its match set.

A package with more than one Ordered Layer is handled in traffic.py: the
decision of one layer is never reported as the gateway's final decision.
Implied rules live in Global Properties, not in the rulebase the API returns;
they cannot be checked from here, so every trace carries a scope note.
"""

from __future__ import annotations

from typing import Any

# Fixed UIDs Check Point uses for these two global objects (seen in every
# show-access-rulebase objects-dictionary); kept as a fallback for payloads
# whose dictionary was trimmed.
ANY_UID = "97aeb369-9aea-11d5-bd16-0090272ccb30"
POLICY_TARGETS_UID = "6c488338-8eec-4103-ad21-cd461ac2c476"

SCOPE_NOTES = [
    "Implied rules (Global Properties) are not part of the rulebase the API "
    "returns and are not modelled; check them before relying on this result.",
]


def _uids(values: Any) -> list[str]:
    if values is None:
        return []
    if isinstance(values, (str, dict)):
        values = [values]
    out = []
    for v in values:
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, dict) and (v.get("uid") or v.get("name")):
            out.append(str(v.get("uid") or v.get("name")))
    return out


def _name(uid: str, res) -> str:
    try:
        return str(res.obj(uid).get("name") or "")
    except Exception:                                           # noqa: BLE001
        return ""


def _is_any(uid: str, res) -> bool:
    if uid == ANY_UID or uid.lower() == "any":
        return True
    try:
        return bool(res.is_any_uid(uid))
    except Exception:                                           # noqa: BLE001
        return _name(uid, res) == "Any"


def _is_policy_targets(uid: str, res) -> bool:
    return uid == POLICY_TARGETS_UID or uid == "Policy Targets" or _name(uid, res) == "Policy Targets"


def unmodelled_columns(rule: dict[str, Any], res) -> list[str]:
    """Columns of `rule` that narrow it in a way neither analysis models.

    An absent field is treated as its default: show-access-rulebase always
    returns these three, so absence only happens in hand-built payloads.
    """
    out = []
    time_uids = _uids(rule.get("time"))
    if time_uids and not all(_is_any(u, res) for u in time_uids):
        out.append("Time")
    content_uids = _uids(rule.get("content"))
    if rule.get("content-negate") or (content_uids and not all(_is_any(u, res) for u in content_uids)):
        out.append("Content")
    install_uids = _uids(rule.get("install-on"))
    if install_uids and not all(_is_policy_targets(u, res) for u in install_uids):
        out.append("Install On")
    return out


def envelope_state(rule: dict[str, Any], res) -> tuple[str, str]:
    """`match` when the rule is inside the modelled envelope, else `unknown`."""
    cols = unmodelled_columns(rule, res)
    if not cols:
        return "match", "Time, Content and Install On are defaults"
    return "unknown", (", ".join(cols) + " not modelled: the rule may not apply to this "
                       "connection, so it cannot be a proven match")


def can_cover(rule: dict[str, Any], res) -> bool:
    """May `rule` be reported as the earlier, covering rule of a shadowing pair?"""
    return not unmodelled_columns(rule, res)
