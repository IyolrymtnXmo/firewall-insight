from __future__ import annotations
from typing import Any


def walk_access_rules(items):
    """Yield Access rules recursively through sections contained in one layer."""
    for item in items or []:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "access-rule":
            yield item
        nested = item.get("rulebase")
        if isinstance(nested, list):
            yield from walk_access_rules(nested)


def inline_ref(rule: dict[str, Any], uid_to_name: dict[str, str]) -> tuple[str, str] | None:
    """
    Return (uid, name) for a rule's inline-layer reference.

    Management API responses can return inline-layer as a dict, UID string,
    or (on some builds) a layer name string.
    """
    value = rule.get("inline-layer")
    if not value:
        return None

    if isinstance(value, dict):
        uid = str(value.get("uid") or "")
        name = str(value.get("name") or uid_to_name.get(uid) or "")
        if uid or name:
            return uid, name
        return None

    if isinstance(value, str):
        if value in uid_to_name:
            return value, uid_to_name[value]
        # It may already be the layer name.
        return "", value

    return None


def layer_catalog(layers: list[dict[str, Any]]) -> tuple[dict[str, str], dict[str, str]]:
    uid_to_name = {}
    name_to_uid = {}
    for layer in layers or []:
        if not isinstance(layer, dict):
            continue
        uid = str(layer.get("uid") or "")
        name = str(layer.get("name") or "")
        if uid and name:
            uid_to_name[uid] = name
            name_to_uid[name] = uid
    return uid_to_name, name_to_uid


def annotate_analysis(result: dict[str, Any], node: dict[str, Any]) -> dict[str, Any]:
    """Add layer context to rows and findings produced by the existing analyzer."""
    layer = node["name"]
    path = node["path"]
    depth = node["depth"]
    parent_rule = node.get("parent_rule")

    prefix = str(node.get("display_prefix") or "")

    for row in result.get("rules", []):
        row["layer"] = layer
        row["layer_path"] = path
        row["depth"] = depth
        row["parent_rule"] = parent_rule
        row["display_rule"] = (
            f"{prefix}.{row.get('rule')}" if prefix else str(row.get("rule"))
        )

    for finding in result.get("findings", {}).get("shadowing", []):
        finding["layer"] = layer
        finding["layer_path"] = path
        finding["depth"] = depth
        finding["parent_rule"] = parent_rule
        finding["display_rule"] = (
            f"{prefix}.{finding.get('rule')}" if prefix else str(finding.get("rule"))
        )
        covered = finding.get("covered_by") or finding.get("potentially_shadowed_by")
        if covered is not None:
            finding["display_covered_by"] = (
                f"{prefix}.{covered}" if prefix else str(covered)
            )

    for group in result.get("findings", {}).get("duplicates", []):
        group["layer"] = layer
        group["layer_path"] = path
        group["depth"] = depth
        group["parent_rule"] = parent_rule
        group["display_prefix"] = prefix
        for member in group.get("members", []):
            member["layer"] = layer
            member["layer_path"] = path
            member["display_rule"] = (
                f"{prefix}.{member.get('rule')}" if prefix else str(member.get("rule"))
            )

    return result


def aggregate_analyses(tree: dict[str, Any], analyses: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Analyze every layer, but keep SmartConsole-style Access Rule count separate.

    total_rules      = ordered/top-level rule count shown by SmartConsole
    inline_rules     = rules contained in Inline Layers
    analyzed_rules   = total rules actually inspected by the analyzer
    """
    rows = []
    shadows = []
    duplicate_groups = []
    any_rows = []
    disabled = []
    zero_hit = []
    cleanup_rules = []

    root_layer_names = set(tree.get("root_layers") or [])
    if not root_layer_names and tree.get("layers"):
        root_layer_names.add(tree["layers"][0]["name"])

    top_level_rules = 0
    inline_rules = 0

    for result in analyses:
        layer_name = ""
        if result.get("rules"):
            layer_name = str(result["rules"][0].get("layer") or "")
        else:
            # fallback from findings/layer metadata is not necessary for count
            layer_name = ""

        n = int(result.get("summary", {}).get("total_rules", 0) or 0)
        if layer_name in root_layer_names:
            top_level_rules += n
        else:
            inline_rules += n

        rows.extend(result.get("rules", []))
        shadows.extend(result.get("findings", {}).get("shadowing", []))

        for group in result.get("findings", {}).get("duplicates", []):
            g = dict(group)
            g["group"] = len(duplicate_groups) + 1
            duplicate_groups.append(g)

        broad_nums = {
            str(x)
            for x in result.get("findings", {}).get("any_any_any_rule_numbers", [])
        }
        for row in result.get("rules", []):
            if str(row.get("rule")) in broad_nums:
                any_rows.append(row)

        disabled.extend(
            {"layer": row.get("layer"), "rule": row.get("rule")}
            for row in result.get("rules", [])
            if row.get("enabled") is False
        )

        cleanup_nums = {
            str(x)
            for x in result.get("findings", {}).get("cleanup_rule_numbers", [])
        }
        cleanup_rules.extend(
            {
                "layer": row.get("layer"),
                "rule": row.get("rule"),
                "display_rule": row.get("display_rule"),
                "action": row.get("action"),
            }
            for row in result.get("rules", [])
            if str(row.get("rule")) in cleanup_nums
        )

        zero_nums = {
            str(x)
            for x in result.get("findings", {}).get("zero_hit_rule_numbers", [])
        }
        zero_hit.extend(
            {"layer": row.get("layer"), "rule": row.get("rule")}
            for row in result.get("rules", [])
            if str(row.get("rule")) in zero_nums
        )

    broad_count = len(any_rows)
    dup_count = len(duplicate_groups)
    shadow_count = len(shadows)
    disabled_count = len(disabled)

    inline_shadow_count = sum(
        1 for f in shadows if int(f.get("depth", 0) or 0) > 0
    )
    inline_duplicate_count = sum(
        1 for g in duplicate_groups if int(g.get("depth", 0) or 0) > 0
    )
    inline_any_count = sum(
        1 for r in any_rows if int(r.get("depth", 0) or 0) > 0
    )

    top_shadow_count = shadow_count - inline_shadow_count
    top_duplicate_count = dup_count - inline_duplicate_count
    top_any_count = broad_count - inline_any_count

    score = max(
        0,
        100
        - min(broad_count * 8, 24)
        - min(dup_count * 3, 15)
        - min(shadow_count * 2, 25)
        - min(disabled_count, 10),
    )

    return {
        "summary": {
            "total_rules": top_level_rules,
            "top_level_rules": top_level_rules,
            "inline_rules": inline_rules,
            "analyzed_rules": top_level_rules + inline_rules,
            "inline_layers": max(0, len(tree.get("layers", [])) - len(root_layer_names)),
            "failed_inline_layers": len(tree.get("errors", [])),
            "disabled_rules": disabled_count,
            "zero_hit_rules": len(zero_hit),
            "any_any_any_rules": broad_count,
            "cleanup_rules": len(cleanup_rules),
            "duplicate_groups": dup_count,
            "potential_shadowed_or_redundant": shadow_count,
            "top_level_shadow_findings": top_shadow_count,
            "inline_shadow_findings": inline_shadow_count,
            "top_level_duplicate_groups": top_duplicate_count,
            "inline_duplicate_groups": inline_duplicate_count,
            "top_level_any_any_any_rules": top_any_count,
            "inline_any_any_any_rules": inline_any_count,
            "optimization_score": score,
        },
        "findings": {
            "disabled_rules": disabled,
            "zero_hit_rules": zero_hit,
            "any_any_any_rules": any_rows,
            "any_any_any_rule_numbers": [r.get("rule") for r in any_rows],
            "cleanup_rules": cleanup_rules,
            "duplicates": duplicate_groups,
            "shadowing": shadows,
        },
        "rules": rows,
        "layers": [
            {
                "name": n["name"],
                "uid": n.get("uid", ""),
                "path": n["path"],
                "depth": n["depth"],
                "parent_layer": n.get("parent_layer"),
                "parent_rule": n.get("parent_rule"),
                "display_prefix": n.get("display_prefix", ""),
                "rule_count": n.get("rule_count", 0),
            }
            for n in tree.get("layers", [])
        ],
        "root_layers": list(root_layer_names),
        "notes": [
            "Access Rules matches the ordered/top-level SmartConsole rule count.",
            "Inline rules are analyzed and reported separately.",
            "Shadow and duplicate analysis is isolated per layer.",
            "A trailing Any/Any/Any Drop/Reject rule is counted as a cleanup rule, not an Any/Any/Any finding.",
            "Read-only: no policy changes are made.",
        ],
    }


def aggregate_browser(tree: dict[str, Any], browser_results: list[dict[str, Any]]) -> dict[str, Any]:
    rows = []
    top = 0
    inline = 0

    root_names = set(tree.get("root_layers") or [])
    if not root_names and tree.get("root_layer"):
        root_names.add(tree.get("root_layer"))
    if not root_names and tree.get("layers"):
        root_names.add(tree["layers"][0]["name"])

    for node, result in zip(tree.get("layers", []), browser_results):
        count = int(result.get("total_rules", 0) or 0)
        if node.get("name") in root_names:
            top += count
        else:
            inline += count

        for row in result.get("rules", []):
            row["layer"] = node["name"]
            row["layer_path"] = node["path"]
            row["depth"] = node["depth"]
            row["parent_layer"] = node.get("parent_layer")
            row["parent_rule"] = node.get("parent_rule")
            prefix = str(node.get("display_prefix") or "")
            row["display_rule"] = (
                f"{prefix}.{row.get('rule')}" if prefix else str(row.get("rule"))
            )
            rows.append(row)

    return {
        "layer": tree.get("root_layer"),
        "root_layers": list(root_names),
        "total_rules": top,
        "visible_rules": len(rows),
        "top_level_rules": top,
        "inline_rules": inline,
        "analyzed_rules": top + inline,
        "inline_layers": max(0, len(tree.get("layers", [])) - len(root_names)),
        "failed_inline_layers": len(tree.get("errors", [])),
        "rules": rows,
        "layers": [
            {
                "name": n["name"],
                "path": n["path"],
                "depth": n["depth"],
                "parent_rule": n.get("parent_rule"),
                "display_prefix": n.get("display_prefix", ""),
                "rule_count": n.get("rule_count", 0),
            }
            for n in tree.get("layers", [])
        ],
        "errors": tree.get("errors", []),
        "mode": "raw-policy-browser",
        "analyzed": False,
        "notes": [
            "Access Rules matches the ordered/top-level SmartConsole rule count.",
            "Inline Layer rules are displayed and counted separately.",
            "Layer and parent-rule context is preserved.",
            "No optimizer analysis is performed on this page.",
        ],
    }


def merge_package_trees(package: str, trees: list[dict[str, Any]]) -> dict[str, Any]:
    layers = []
    errors = []
    seen = set()

    for tree in trees:
        errors.extend(tree.get("errors", []))
        for node in tree.get("layers", []):
            key = str(node.get("uid") or node.get("name") or node.get("path"))
            if key in seen:
                continue
            seen.add(key)
            layers.append(node)

    return {
        "package": package,
        "root_layers": [t.get("root_layer") for t in trees if t.get("root_layer")],
        "layers": layers,
        "errors": errors,
        "total_layers": len(layers),
    }
