"""
Compare two policy snapshots: what changed between two audits.

Every other page in this application answers "what does the policy say now".
This one answers "what changed since last time", which is the question
periodic review work actually starts from and which SmartConsole does not
present as a view.

Four decisions shape the whole file:

**Identity is the rule uid.** Rule numbers shift the moment anything is
inserted above them, so a number-keyed diff reports a whole rulebase as
rewritten after a one-line change. Check Point gives every rule a uid; that is
the only stable handle, and a rule that arrives without one is counted and
warned about rather than quietly matched by position.

**Moved is its own verdict.** Access Control is first-match-wins, so a rule's
position is part of its meaning. A rule that is byte-identical but now sits
above one it used to sit below has changed behaviour, and calling that
"unchanged" hides a real event - while calling it "modified" claims fields
changed when none did.

**A rule can change without the rule changing.** Add a member to a group and
every rule referencing it permits more traffic, with identical text, identical
uids and an identical rule number. A textual diff sees nothing at all. The
snapshot therefore carries each dimension's resolved intervals, and comparing
those is what catches it. This is the finding that makes the feature worth
having.

**An unresolvable object makes a comparison unavailable, not equal.** The same
rule the tri-state matcher lives by. And because those intervals are produced
by *this application*, two snapshots taken by different versions of it can
differ for reasons that have nothing to do with the policy - so that gets a
warning on the whole diff rather than a quiet assumption.
"""

from __future__ import annotations

from typing import Any

# Fields whose change means somebody edited the rule.
COMPARED_FIELDS = (
    "name", "enabled", "action", "track", "comments", "inline_layer",
    "section", "layer",
)
DIMENSIONS = ("source", "destination", "service", "vpn", "install_on")

# Deliberately NOT compared: hits and last_hit move on their own every day,
# and position, which is reported as a move instead of an edit.
NAT_FIELDS = (
    "name", "enabled", "original_source", "original_destination",
    "original_service", "translated_source", "translated_destination",
    "translated_service", "method", "install_on",
)


def _by_uid(rows: list[dict[str, Any]]) -> tuple[dict[str, dict], int]:
    out, untracked = {}, 0
    for row in rows or []:
        uid = str(row.get("uid") or "")
        if not uid:
            untracked += 1
            continue
        out[uid] = row
    return out, untracked


def _atoms(dimension: dict[str, Any] | None) -> tuple[tuple, ...]:
    values = (dimension or {}).get("atoms") or []
    return tuple(sorted(tuple(a) for a in values))


def _span(atoms: tuple[tuple, ...]) -> int:
    """Total size covered, for saying whether a scope widened or narrowed."""
    total = 0
    for atom in atoms:
        try:
            total += int(atom[-1]) - int(atom[-2]) + 1
        except (TypeError, ValueError, IndexError):
            continue
    return total


def _summarise(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {
        "package": snapshot.get("package"),
        "taken_at": snapshot.get("taken_at"),
        "app_version": snapshot.get("app_version"),
        "id": snapshot.get("id"),
        "access_rules": len((snapshot.get("access") or {}).get("rules") or []),
        "nat_rules": len((snapshot.get("nat") or {}).get("rules") or []),
    }


def _field_changes(before: dict, after: dict, fields) -> list[dict[str, Any]]:
    changes = []
    for field in fields:
        was, now = before.get(field), after.get(field)
        if was != now:
            changes.append({"field": field, "from": was, "to": now})
    return changes


def _dimension_changes(before: dict, after: dict) -> list[dict[str, Any]]:
    """Dimension edits, judged on the uids the rule references."""
    changes = []
    for name in DIMENSIONS:
        was, now = before.get(name) or {}, after.get(name) or {}
        if sorted(was.get("uids") or []) != sorted(now.get("uids") or []):
            changes.append({
                "field": name,
                "from": was.get("text"),
                "to": now.get("text"),
            })
    return changes


def _scope_findings(uid: str, before: dict, after: dict) -> tuple[list, list]:
    """
    Same objects referenced, different resolved reach.

    Only asked when the uids are identical: a different uid means the rule was
    edited, which the field diff already reported, and saying it twice would
    make one change look like two.
    """
    changed, unverifiable = [], []
    for name in DIMENSIONS:
        was, now = before.get(name) or {}, after.get(name) or {}
        if sorted(was.get("uids") or []) != sorted(now.get("uids") or []):
            continue

        if not (was.get("complete", True) and now.get("complete", True)):
            unverifiable.append({
                "uid": uid,
                "display_rule": after.get("display_rule"),
                "name": after.get("name"),
                "dimension": name,
                "text": now.get("text") or was.get("text"),
                "reason": (
                    "At least one object on this dimension has no static model, "
                    "so whether its reach changed cannot be decided here."
                ),
            })
            continue

        old_atoms, new_atoms = _atoms(was), _atoms(now)
        if old_atoms == new_atoms:
            continue

        old_span, new_span = _span(old_atoms), _span(new_atoms)
        direction = ("widened" if new_span > old_span
                     else "narrowed" if new_span < old_span
                     else "redefined")
        changed.append({
            "uid": uid,
            "display_rule": after.get("display_rule"),
            "name": after.get("name"),
            "dimension": name,
            "text": now.get("text") or was.get("text"),
            "direction": direction,
            "from_intervals": len(old_atoms),
            "to_intervals": len(new_atoms),
            "reason": (
                f"The rule is unchanged and still references the same object(s), "
                f"but their contents {direction} between the two snapshots."
            ),
        })
    return changed, unverifiable


def _row(rule: dict[str, Any]) -> dict[str, Any]:
    keep = ("uid", "display_rule", "position", "layer", "name", "enabled",
            "action", "inline_layer")
    row = {k: rule.get(k) for k in keep}
    for name in DIMENSIONS:
        row[name] = (rule.get(name) or {}).get("text")
    return row


def diff_snapshots(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    warnings: list[str] = []

    if a.get("package") != b.get("package"):
        warnings.append(
            f"These snapshots are of different policy packages "
            f"({a.get('package')} and {b.get('package')}). Comparing them is "
            "valid - two firewalls can be compared deliberately - but nothing "
            "below is a change over time.")

    versions = (a.get("app_version"), b.get("app_version"))
    if versions[0] != versions[1]:
        warnings.append(
            f"The snapshots were taken by different versions of this application "
            f"({versions[0]} and {versions[1]}). Resolved-reach differences may "
            "come from a change in this application rather than in the policy. "
            "Re-take both snapshots with one version before acting on a scope "
            "finding.")

    before, untracked_a = _by_uid((a.get("access") or {}).get("rules") or [])
    after, untracked_b = _by_uid((b.get("access") or {}).get("rules") or [])
    untracked = untracked_a + untracked_b
    if untracked:
        warnings.append(
            f"{untracked} rule(s) arrived without a uid and cannot be tracked "
            "across snapshots. They are excluded from every count below.")

    added = [_row(after[uid]) for uid in after if uid not in before]
    removed = [_row(before[uid]) for uid in before if uid not in after]

    modified, moved, scope_changed, scope_unverifiable = [], [], [], []
    unchanged = 0

    for uid, now in after.items():
        was = before.get(uid)
        if was is None:
            continue

        changes = _field_changes(was, now, COMPARED_FIELDS) + _dimension_changes(was, now)
        if changes:
            modified.append({
                "uid": uid,
                "display_rule": now.get("display_rule"),
                "name": now.get("name"),
                "layer": now.get("layer"),
                "changes": changes,
            })

        if was.get("position") != now.get("position"):
            moved.append({
                "uid": uid,
                "display_rule": now.get("display_rule"),
                "name": now.get("name"),
                "from_position": was.get("position"),
                "to_position": now.get("position"),
                "reason": (
                    "Access Control is first match wins, so a rule's position is "
                    "part of what it means, even when nothing in it was edited."
                ),
            })

        widened, unknown = _scope_findings(uid, was, now)
        scope_changed.extend(widened)
        scope_unverifiable.extend(unknown)

        if not changes and was.get("position") == now.get("position") \
                and not widened and not unknown:
            unchanged += 1

    nat_before, _ = _by_uid((a.get("nat") or {}).get("rules") or [])
    nat_after, _ = _by_uid((b.get("nat") or {}).get("rules") or [])
    nat_added = [nat_after[u] for u in nat_after if u not in nat_before]
    nat_removed = [nat_before[u] for u in nat_before if u not in nat_after]
    nat_modified = []
    for uid, now in nat_after.items():
        was = nat_before.get(uid)
        if was is None:
            continue
        changes = _field_changes(was, now, NAT_FIELDS)
        if changes:
            nat_modified.append({
                "uid": uid, "rule": now.get("rule"), "name": now.get("name"),
                "changes": changes,
            })

    summary = {
        "added": len(added), "removed": len(removed), "modified": len(modified),
        "moved": len(moved), "unchanged": unchanged,
        "scope_changed": len(scope_changed),
        "scope_unverifiable": len(scope_unverifiable),
        "untracked_rules": untracked,
        "nat_added": len(nat_added), "nat_removed": len(nat_removed),
        "nat_modified": len(nat_modified),
    }
    # "Nothing to report" has to include the things we could not check. A diff
    # that says "identical" while one dimension was unverifiable is the same
    # confident-wrong-answer failure the tracer refuses to make.
    identical = not any(
        summary[k] for k in
        ("added", "removed", "modified", "moved", "scope_changed",
         "scope_unverifiable", "nat_added", "nat_removed", "nat_modified"))

    return {
        "a": _summarise(a),
        "b": _summarise(b),
        "summary": summary,
        "identical": identical,
        "access": {
            "added": added, "removed": removed, "modified": modified,
            "moved": moved, "scope_changed": scope_changed,
            "scope_unverifiable": scope_unverifiable,
        },
        "nat": {"added": nat_added, "removed": nat_removed, "modified": nat_modified},
        "warnings": warnings,
        "notes": [
            "Rules are matched by uid, so inserting a rule does not report the "
            "rules below it as rewritten.",
            "Hit counts are excluded: they change on their own and would bury "
            "the policy changes.",
            "A move is reported separately from an edit because position is part "
            "of the meaning of an ordered rulebase.",
        ],
    }
