"""
A cleanup script a person reviews and runs. This module cannot run it.

WHAT IT IS
The analysis says which rules are redundant, duplicated or never hit. Acting on
that means opening SmartConsole and doing it by hand, rule by rule. This turns
the findings into a script - `mgmt_cli` for a shell on the Management Server,
or an Ansible playbook for the `check_point.mgmt` collection - that an engineer
reads, edits and runs themselves.

WHY IT DOES NOT BREAK THE READ-ONLY GUARANTEE
The guarantee is that this application issues no mutating call. It still does
not. This module imports nothing that can reach a network: no client, no httpx,
no socket, no subprocess, and `tests/test_v439_features.py` asserts that from
its imports rather than trusting this paragraph. It returns text. The text
contains mutating commands - that is its purpose - so the acceptance runner's
source scan (tools/acceptance.py) exempts this one file by name and, in the
same breath, checks that it still cannot reach a network.

WHAT IT PROPOSES, AND WHAT IT REFUSES TO
    redundant rule (shadowed, same action)   disable the later rule
    exact duplicate                          disable the later copies
    zero hits              (opt-in)          disable - counters reset on
                                             install and on gateway restart,
                                             so zero hits is weak evidence
    already disabled       (opt-in)          delete
    unused object          (opt-in)          delete - only what the Management
                                             Server itself reports as unused

    shadowed with a DIFFERENT action         no command. The later rule never
                                             fires, but someone meant it to;
                                             that is a question about intent.
    Any/Any/Any                              no command, same reason.

Disable, not delete, wherever a rule is involved: a disabled rule is one
checkbox from being back. Nothing is published unless the person running the
script types PUBLISH, and nothing is ever installed on a gateway.

Never touched, whatever the findings say: a layer's cleanup rule; a rule that
holds an inline layer (disabling it switches off a whole sub-policy); a rule
whose uid is not in the snapshot the script is built from. And if the analysis
behind the findings did not load completely, no script is produced at all - a
rule that looked covered because an object arrived thin is exactly the rule
that must not be switched off.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from .version import APP_VERSION

FORMATS = ("mgmt_cli", "ansible")

# Object types a script may delete, with the mgmt_cli noun and Ansible module.
OBJECT_COMMANDS = {
    "host": ("host", "cp_mgmt_host"),
    "network": ("network", "cp_mgmt_network"),
    "address-range": ("address-range", "cp_mgmt_address_range"),
    "group": ("group", "cp_mgmt_group"),
    "service-tcp": ("service-tcp", "cp_mgmt_service_tcp"),
    "service-udp": ("service-udp", "cp_mgmt_service_udp"),
}


class RefusedIncomplete(ValueError):
    """The analysis did not load completely; a script built on it is unsafe."""


def _key(layer: Any, number: Any) -> tuple[str, str]:
    return (str(layer or ""), str(number))


def build_plan(analysis: dict[str, Any], rules: list[dict[str, Any]], *,
               package: str,
               include_zero_hit: bool = False,
               include_disabled: bool = False,
               unused_objects: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Decide what the script will do, before any text is written.

    *rules* are snapshot rows (they carry the uid the commands need; analysis
    findings identify rules by layer and number only).
    """
    dq = analysis.get("data_quality") or {}
    if dq and not dq.get("complete", False):
        raise RefusedIncomplete(
            "The analysis did not load completely "
            f"({dq.get('failed_inline_layers', 0)} inline layer(s) failed, object "
            f"hydration truncated: {bool(dq.get('object_hydration_truncated'))}). "
            "A cleanup script built on it could switch off a rule that only looked "
            "covered because an object arrived incomplete. Reload the package and "
            "try again.")

    by_key = {_key(r.get("layer"), r.get("rule_number")): r for r in rules}
    findings = analysis.get("findings") or {}
    cleanup = {_key(f.get("layer"), f.get("rule")) for f in findings.get("cleanup_rules") or []}

    actions: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    planned: dict[str, dict[str, Any]] = {}

    def ref(layer, number, display=None):
        return {"layer": layer, "rule": number,
                "display_rule": display or str(number)}

    def propose(layer, number, display, command, reason, evidence):
        k = _key(layer, number)
        row = by_key.get(k)
        where = ref(layer, number, display)
        if row is None or not row.get("uid"):
            skipped.append({**where, "why": "not found in the snapshot this script is "
                            "built from, so there is no uid to address it by"})
            return
        if k in cleanup:
            skipped.append({**where, "name": row.get("name"),
                            "why": "the cleanup rule of its layer is never touched"})
            return
        if row.get("inline_layer"):
            skipped.append({**where, "name": row.get("name"),
                            "why": f"holds inline layer {row['inline_layer']!r}; disabling "
                                   "it would switch off that whole sub-policy"})
            return
        if command == "disable_rule" and not row.get("enabled", True):
            return                       # already off; nothing to propose
        uid = row["uid"]
        if uid in planned:
            planned[uid]["reasons"].append(reason)
            return
        item = {"command": command, "uid": uid, "layer": row.get("layer"),
                "name": row.get("name") or "", "display_rule": row.get("display_rule"),
                "reasons": [reason], "evidence": evidence,
                "hits": row.get("hits"), "track": row.get("track")}
        planned[uid] = item
        actions.append(item)

    for f in findings.get("shadowing") or []:
        layer, n, disp = f.get("layer"), f.get("rule"), f.get("display_rule")
        covered = f.get("display_covered_by") or f.get("covered_by")
        if str(f.get("classification", "")).startswith("Redundant"):
            propose(layer, n, disp, "disable_rule",
                    f"redundant: rule {covered} already matches everything it matches, "
                    "with the same action",
                    {"covered_by": covered, "action": f.get("later_action")})
        else:
            decisions.append({**ref(layer, n, disp), "name": f.get("rule_name"),
                              "why": f"never matches: rule {covered} "
                                     f"({f.get('earlier_action')}) is reached first, but this "
                                     f"rule says {f.get('later_action')}. Removing it changes "
                                     "nothing on the wire; deciding which action was meant is "
                                     "not something a script should do."})

    for g in findings.get("duplicates") or []:
        members = g.get("members") or []
        actions_seen = {m.get("action") for m in members}
        if len(actions_seen) > 1:
            decisions.append({**ref(g.get("layer"), members[0].get("rule") if members else None),
                              "why": "duplicate group with differing actions"})
            continue
        first = members[0] if members else {}
        for m in members[1:]:
            propose(m.get("layer") or g.get("layer"), m.get("rule"), m.get("display_rule"),
                    "disable_rule",
                    f"exact duplicate of rule {first.get('display_rule') or first.get('rule')}",
                    {"duplicate_of": first.get("display_rule") or first.get("rule")})

    for f in findings.get("any_any_any_rules") or []:
        decisions.append({**ref(f.get("layer"), f.get("rule"), f.get("display_rule")),
                          "why": "Any/Any/Any: whether it is too broad depends on what it is "
                                 "for, which the rulebase does not say."})

    if include_zero_hit:
        for f in findings.get("zero_hit_rules") or []:
            propose(f.get("layer"), f.get("rule"), f.get("display_rule"), "disable_rule",
                    "zero hits - counters reset on policy install and on gateway restart, "
                    "so confirm with logs before trusting this",
                    {"hits": 0})

    if include_disabled:
        for f in findings.get("disabled_rules") or []:
            propose(f.get("layer"), f.get("rule"), f.get("display_rule"), "delete_rule",
                    "already disabled", {"enabled": False})

    objects: list[dict[str, Any]] = []
    for o in unused_objects or []:
        kind = o.get("type")
        domain = o.get("domain") or {}
        if kind not in OBJECT_COMMANDS:
            skipped.append({"object": o.get("name"), "type": kind,
                            "why": "object type this script does not delete"})
            continue
        if o.get("read-only") or domain.get("domain-type") == "data domain":
            skipped.append({"object": o.get("name"), "type": kind,
                            "why": "predefined object"})
            continue
        objects.append({"command": "delete_object", "uid": o.get("uid"), "type": kind,
                        "name": o.get("name"),
                        "reasons": ["the Management Server reports it as used nowhere"]})

    return {"package": package, "actions": actions, "objects": objects,
            "decisions": decisions, "skipped": skipped,
            "counts": {"disable": sum(a["command"] == "disable_rule" for a in actions),
                       "delete_rules": sum(a["command"] == "delete_rule" for a in actions),
                       "delete_objects": len(objects),
                       "decisions": len(decisions), "skipped": len(skipped)}}


# ---- rendering ---------------------------------------------------------------

def _sh(value: Any) -> str:
    """A bash double-quoted string. Layer and object names may hold anything."""
    text = str(value if value is not None else "")
    for ch in ("\\", '"', "$", "`"):
        text = text.replace(ch, "\\" + ch)
    return f'"{text}"'


def _comment(text: str) -> str:
    return "# " + " ".join(str(text).split())


def render_mgmt_cli(plan: dict[str, Any], *, domain: str = "",
                    taken_at: str | None = None) -> str:
    now = taken_at or datetime.now().isoformat(timespec="minutes")
    c = plan["counts"]
    total = len(plan["actions"]) + len(plan["objects"])
    lines = [
        "#!/usr/bin/env bash",
        "# ============================================================================",
        f"# Firewall Insight cleanup script - package {plan['package']}",
        f"# Generated {now} by Firewall Insight {APP_VERSION}. READ IT BEFORE RUNNING IT.",
        "#",
        "# Firewall Insight did not run this and cannot: it has no write path to the",
        "# Management Server. Every line below is a proposal for you to check.",
        "#",
        f"#   disable rules   {c['disable']}",
        f"#   delete rules    {c['delete_rules']}",
        f"#   delete objects  {c['delete_objects']}",
        f"#   left to you     {c['decisions']}   (listed at the end, no command)",
        f"#   not touched     {c['skipped']}",
        "#",
        "# Changes go into one session. At the end you are asked to type PUBLISH;",
        "# anything else discards the session. Nothing is installed on a gateway.",
        "# Run it on the Management Server (expert mode), or wherever mgmt_cli can",
        "# reach it. Set MGMT_USER to log in as a named administrator instead of root.",
        "# ============================================================================",
        "set -euo pipefail",
        'command -v mgmt_cli >/dev/null || { echo "mgmt_cli not found" >&2; exit 1; }',
        'SESSION="$(mktemp)"',
        "FINISHED=0",
        "on_exit() {",
        '  if [ "$FINISHED" != 1 ] && [ -s "$SESSION" ]; then',
        '    echo "Stopped before the end - discarding the session so nothing is left locked." >&2',
        '    mgmt_cli discard -s "$SESSION" >/dev/null 2>&1 || true',
        '    mgmt_cli logout -s "$SESSION" >/dev/null 2>&1 || true',
        "  fi",
        '  rm -f "$SESSION"',
        "}",
        "trap on_exit EXIT",
    ]
    dom = f" domain {_sh(domain)}" if domain else ""
    dom_root = f" -d {_sh(domain)}" if domain else ""
    lines += [
        'if [ -n "${MGMT_USER:-}" ]; then',
        f'  mgmt_cli login user "$MGMT_USER"{dom} > "$SESSION"',
        "else",
        f'  mgmt_cli login -r true{dom_root} > "$SESSION"',
        "fi",
        'run() { echo "+ mgmt_cli $*"; mgmt_cli "$@" -s "$SESSION" >/dev/null; }',
        "",
    ]
    for a in plan["actions"]:
        lines.append(_comment(f"Rule {a['display_rule']} {a['name'] or '(unnamed)'} in "
                              f"{a['layer']}: {'; '.join(a['reasons'])}. hits={a['hits']} "
                              f"track={a['track'] or 'unknown'}"))
        if a["command"] == "disable_rule":
            lines.append(f"run set access-rule uid {_sh(a['uid'])} layer {_sh(a['layer'])} enabled false")
        else:
            lines.append(f"run delete access-rule uid {_sh(a['uid'])} layer {_sh(a['layer'])}")
        lines.append("")
    for o in plan["objects"]:
        noun = OBJECT_COMMANDS[o["type"]][0]
        lines.append(_comment(f"{o['type']} {o['name']}: {'; '.join(o['reasons'])}"))
        lines.append(f"run delete {noun} uid {_sh(o['uid'])}")
        lines.append("")
    lines += [
        f'echo "{total} change(s) are in an unpublished session. Review them in SmartConsole if you like."',
        'read -r -p "Type PUBLISH to publish them, anything else discards: " ANSWER',
        'if [ "$ANSWER" = "PUBLISH" ]; then',
        '  mgmt_cli publish -s "$SESSION" && echo "Published. Nothing is installed until you install policy."',
        "else",
        '  mgmt_cli discard -s "$SESSION" >/dev/null && echo "Discarded. Nothing changed."',
        "fi",
        'mgmt_cli logout -s "$SESSION" >/dev/null || true',
        "FINISHED=1",
        "",
    ]
    lines += _tail(plan)
    return "\n".join(lines) + "\n"


def render_ansible(plan: dict[str, Any], *, domain: str = "",
                   taken_at: str | None = None) -> str:
    """A playbook for the check_point.mgmt collection.

    Its access-rule module identifies a rule by `name` and `layer` - it has no
    `uid` parameter - so an unnamed rule cannot be addressed and is listed as
    not handled rather than emitted as a task that might hit the wrong rule.
    """
    now = taken_at or datetime.now().isoformat(timespec="minutes")
    q = json.dumps
    lines = [
        "---",
        f"# Firewall Insight cleanup playbook - package {plan['package']}",
        f"# Generated {now} by Firewall Insight {APP_VERSION}. READ IT BEFORE RUNNING IT.",
        "# Firewall Insight did not run this and cannot. Nothing here publishes on its",
        "# own: auto_publish_session is false on every task, and publishing is the last",
        "# task, tagged `publish`, so `--skip-tags publish` leaves the session unpublished.",
        "#",
        "# Inventory, from the collection's README:",
        "#   [check_point]",
        "#   <management-server>",
        "#   [check_point:vars]",
        "#   ansible_httpapi_use_ssl=True",
        "#   ansible_httpapi_validate_certs=False",
        "#   ansible_user=<user>",
        "#   ansible_password=<password>",
        "#   ansible_network_os=check_point.mgmt.checkpoint",
        "# Check module parameters against the collection version you have installed.",
        f"- name: {q('Firewall Insight cleanup - ' + plan['package'])}",
        "  hosts: check_point",
        "  connection: httpapi",
        "  gather_facts: false",
    ]
    if domain:
        lines += ["  vars:", f"    ansible_checkpoint_domain: {q(domain)}"]
    lines.append("  tasks:")
    unnamed = []
    for a in plan["actions"]:
        if not a["name"]:
            unnamed.append(a)
            continue
        title = f"Rule {a['display_rule']} {a['name']}: {'; '.join(a['reasons'])}"
        lines += [f"    - name: {q(title)}",
                  "      check_point.mgmt.cp_mgmt_access_rule:",
                  f"        name: {q(a['name'])}",
                  f"        layer: {q(a['layer'])}"]
        if a["command"] == "disable_rule":
            lines += ["        enabled: false", "        state: present"]
        else:
            lines += ["        state: absent"]
        lines.append("        auto_publish_session: false")
    for o in plan["objects"]:
        module = OBJECT_COMMANDS[o["type"]][1]
        lines += [f"    - name: {q('Delete unused ' + o['type'] + ' ' + str(o['name']))}",
                  f"      check_point.mgmt.{module}:",
                  f"        name: {q(o['name'])}",
                  "        state: absent",
                  "        auto_publish_session: false"]
    lines += ["    - name: Publish the session",
              "      check_point.mgmt.cp_mgmt_publish:",
              "      tags: [publish]", ""]
    if unnamed:
        lines.append("# Not handled here - the Ansible module addresses rules by name, and these have none.")
        lines.append("# Use the mgmt_cli format for them, or name them first:")
        for a in unnamed:
            lines.append(_comment(f"Rule {a['display_rule']} in {a['layer']} (uid {a['uid']}): "
                                  f"{'; '.join(a['reasons'])}"))
    lines += _tail(plan)
    return "\n".join(lines) + "\n"


def _tail(plan: dict[str, Any]) -> list[str]:
    out = []
    if plan["decisions"]:
        out.append("# ---- Left to you: findings that call for a decision, not a command ----")
        for d in plan["decisions"]:
            out.append(_comment(f"Rule {d.get('display_rule')} in {d.get('layer')}: {d['why']}"))
    if plan["skipped"]:
        out.append("# ---- Not touched, and why ----")
        for s in plan["skipped"]:
            label = (f"Rule {s.get('display_rule')} in {s.get('layer')}"
                     if "layer" in s else f"{s.get('type')} {s.get('object')}")
            out.append(_comment(f"{label}: {s['why']}"))
    return out


def render(plan: dict[str, Any], fmt: str, **kw) -> str:
    if fmt not in FORMATS:
        raise ValueError(f"Unknown format {fmt!r}. Use one of: {', '.join(FORMATS)}.")
    return render_mgmt_cli(plan, **kw) if fmt == "mgmt_cli" else render_ansible(plan, **kw)
