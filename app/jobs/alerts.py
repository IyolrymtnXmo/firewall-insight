"""
Alerts: tell a team when a review needs looking at.

DESTINATIONS
    slack     an incoming-webhook URL
    teams     a Teams Workflows webhook URL (adaptive card)
    webhook   any URL; receives the alert as JSON
    email     SMTP, optionally with the review's PDF attached

WHEN
Each destination chooses from the three verdicts `store.outcome()` gives a
review, plus two narrower triggers:

    attention      something changed, or a compliance profile is not conformant
    undecided      part of the review could not be read or compared
    clean          nothing moved and nothing was left undecided
    health         a gateway had a high finding or did not answer
    every-run      always

The default is attention + undecided + health. "Undecided" is on by default on
purpose. A review that could not read the gateways is exactly the review whose
silence would be mistaken for good news, and an alerting system that only
speaks when it is sure is one that goes quiet when things break.

WHAT IS SENT
Summary level by default: counts and verdicts, the package name, and no rule
contents or addresses - an alert lands in a chat channel that more people can
read than this application. `findings` adds rule numbers, failed check titles
and gateway addresses, and is a choice made per destination.

SECRETS
A webhook URL is a credential (anyone holding it can post), and so is an SMTP
password. Both are encrypted into credentials.enc under "alerts" and never
returned by the API; the configuration it returns says only whether one is set.

FAILURE
Delivery never raises into the review. Each attempt is recorded on the run -
destination, ok, and the error - because an alert that silently failed to send
is worse than no alerting: it is believed.
"""

from __future__ import annotations

import json
import logging
import re
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from .. import credential_store
from ..version import APP_VERSION
from .store import outcome

log = logging.getLogger(__name__)

CONFIG_FILE = Path(__file__).resolve().parent.parent.parent / "alerts.json"
KINDS = ("slack", "teams", "webhook", "email")
TRIGGERS = ("attention", "undecided", "clean", "health", "every-run")
DEFAULT_TRIGGERS = ["attention", "undecided", "health"]
DETAILS = ("summary", "findings")
SECRET_TYPE = "alerts"

_SAFE_ID = re.compile(r"[^A-Za-z0-9._-]+")


# ---- configuration -----------------------------------------------------------

def _read_file(base: Path | None = None) -> dict[str, Any]:
    path = base or CONFIG_FILE
    if not path.exists():
        return {"public_url": "", "destinations": []}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log.warning("alerts.json could not be read: %s", exc)
        return {"public_url": "", "destinations": [], "error": str(exc)}


def _secrets() -> dict[str, Any]:
    return credential_store.load(SECRET_TYPE) or {}


def normalise(dest: dict[str, Any]) -> dict[str, Any]:
    kind = str(dest.get("kind") or "")
    if kind not in KINDS:
        raise ValueError(f"Unknown destination kind {kind!r}. Use one of: {', '.join(KINDS)}.")
    name = str(dest.get("name") or kind).strip()
    triggers = [t for t in (dest.get("on") or DEFAULT_TRIGGERS) if t in TRIGGERS]
    if not triggers:
        raise ValueError("A destination that fires on nothing would never send.")
    detail = str(dest.get("detail") or "summary")
    if detail not in DETAILS:
        raise ValueError(f"Unknown detail {detail!r}.")
    out = {
        "id": _SAFE_ID.sub("-", str(dest.get("id") or f"{kind}-{name}")).strip("-") or kind,
        "kind": kind, "name": name, "enabled": bool(dest.get("enabled", True)),
        "on": triggers, "detail": detail,
    }
    if kind == "email":
        to = dest.get("to") or []
        if isinstance(to, str):
            to = [x.strip() for x in to.split(",")]
        to = [x for x in to if x]
        if not to:
            raise ValueError("An email destination needs at least one recipient.")
        if not dest.get("smtp_host") or not dest.get("sender"):
            raise ValueError("An email destination needs smtp_host and sender.")
        security = str(dest.get("security") or "starttls")
        if security not in ("starttls", "ssl", "none"):
            raise ValueError("security must be starttls, ssl or none.")
        out.update({"smtp_host": str(dest["smtp_host"]),
                    "smtp_port": int(dest.get("smtp_port") or (465 if security == "ssl" else 587)),
                    "security": security, "username": str(dest.get("username") or ""),
                    "sender": str(dest["sender"]), "to": to,
                    "attach_pdf": bool(dest.get("attach_pdf", True))})
    return out


def check_url(url: str) -> str:
    """HTTPS only - a webhook URL carries a secret. Plain HTTP only to this machine."""
    parsed = urlparse(url or "")
    if parsed.scheme == "https" and parsed.netloc:
        return url
    if parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost", "::1"):
        return url
    raise ValueError("A webhook URL must be https:// (plain http is allowed only to "
                     "this machine, for testing).")


def public_config(base: Path | None = None) -> dict[str, Any]:
    cfg = _read_file(base)
    secrets = _secrets()
    for d in cfg.get("destinations") or []:
        s = secrets.get(d.get("id")) or {}
        d["url_set"] = bool(s.get("url"))
        d["password_set"] = bool(s.get("password"))
    cfg.setdefault("public_url", "")
    cfg["triggers"], cfg["kinds"], cfg["details"] = TRIGGERS, KINDS, DETAILS
    return cfg


def save_destination(dest: dict[str, Any], *, url: str | None = None,
                     password: str | None = None, base: Path | None = None) -> dict[str, Any]:
    clean = normalise(dest)
    secrets = _secrets()
    mine = dict(secrets.get(clean["id"]) or {})
    if clean["kind"] != "email":
        if url is not None and url != "":
            mine["url"] = check_url(url)
        if not mine.get("url"):
            raise ValueError("This destination needs a webhook URL.")
    elif password is not None and password != "":
        mine["password"] = password
    secrets[clean["id"]] = mine
    credential_store.save(SECRET_TYPE, secrets)

    cfg = _read_file(base)
    dests = [d for d in cfg.get("destinations") or [] if d.get("id") != clean["id"]]
    dests.append(clean)
    cfg["destinations"] = dests
    (base or CONFIG_FILE).write_text(json.dumps(cfg, indent=2, ensure_ascii=False),
                                     encoding="utf-8")
    return clean


def remove_destination(did: str, base: Path | None = None) -> bool:
    cfg = _read_file(base)
    before = len(cfg.get("destinations") or [])
    cfg["destinations"] = [d for d in cfg.get("destinations") or [] if d.get("id") != did]
    (base or CONFIG_FILE).write_text(json.dumps(cfg, indent=2, ensure_ascii=False),
                                     encoding="utf-8")
    secrets = _secrets()
    if secrets.pop(did, None) is not None:
        credential_store.save(SECRET_TYPE, secrets)
    return len(cfg["destinations"]) < before


def set_public_url(url: str, base: Path | None = None) -> None:
    cfg = _read_file(base)
    cfg["public_url"] = (url or "").strip()
    (base or CONFIG_FILE).write_text(json.dumps(cfg, indent=2, ensure_ascii=False),
                                     encoding="utf-8")


# ---- the message ---------------------------------------------------------------

def triggers_met(o: dict[str, Any]) -> set[str]:
    met = {"every-run", o["verdict"]}
    if o["health_high"] or o["not_reached"]:
        met.add("health")
    return met


def build_message(run: dict[str, Any], detail: str = "summary",
                  public_url: str = "") -> dict[str, Any]:
    o = outcome(run)
    pkg = run.get("package") or "?"
    headline = {"attention": "needs attention", "undecided": "could not be fully read",
                "clean": "no change"}[o["verdict"]]
    title = f"Firewall Insight - {pkg} - {headline}"

    if o["first_run"]:
        policy = "First review of this package; nothing to compare with yet."
    elif o["changed"]:
        policy = f"{o['changes']} rule change(s) since the previous review."
    else:
        policy = "No rule changed since the previous review."
    if o["could_not_compare"]:
        policy += f" {o['could_not_compare']} rule(s) could not be compared."

    compliance = {
        "conformant": f"Conformant to {o['compliance_profile']}.",
        "not-conformant": (f"Not conformant to {o['compliance_profile']}: "
                           f"{o['compliance_failed']} check(s) failed, "
                           f"{o['compliance_undecided']} could not be decided."),
        "not-requested": "No compliance profile in this review.",
        "failed": "The compliance profile could not be run.",
    }[o["compliance"]]

    health = {
        "clean": "Gateways read, no findings.",
        "findings": (f"Gateways: {o['health_findings']} finding(s), {o['health_high']} high"
                     + (f"; {o['not_reached']} gateway(s) did not answer." if o["not_reached"] else ".")),
        "not-requested": "Gateway health not included.",
        "failed": "Gateway health could not be read.",
    }[o["health"]]

    lines = [policy, compliance, health]
    if o["incomplete"]:
        lines.append("Incomplete: " + ", ".join(o["incomplete"])
                     + " - this review is not evidence that those are clean.")

    if detail == "findings":
        sections = run.get("sections") or {}
        ch = ((sections.get("changed") or {}).get("data") or {})
        for kind in ("added", "removed", "modified", "moved"):
            rows = (ch.get("access") or {}).get(kind) or []
            if rows:
                lines.append(f"{kind.capitalize()}: " + ", ".join(
                    str(r.get("display_rule") or r.get("name")) for r in rows[:15]))
        comp = ((sections.get("compliance") or {}).get("data") or {})
        failed = [r.get("title") for r in comp.get("results") or [] if r.get("status") == "fail"]
        if failed:
            lines.append("Failed checks: " + "; ".join(str(t) for t in failed[:10]))
        gw = ((sections.get("gateways") or {}).get("data") or {})
        for f in (gw.get("findings") or [])[:10]:
            lines.append(f"{str(f.get('severity')).upper()} {f.get('host')}: {f.get('kind')} {f.get('subject') or ''}".strip())

    facts = {"Package": pkg, "Review": str(run.get("started_at") or "")[:16].replace("T", " "),
             "Verdict": headline, "Version": APP_VERSION}
    link = f"{public_url.rstrip('/')}/#runs" if public_url else ""
    return {"title": title, "verdict": o["verdict"], "lines": lines, "facts": facts,
            "link": link, "outcome": o, "run_id": run.get("id")}


def payload(kind: str, msg: dict[str, Any]) -> dict[str, Any]:
    text = "\n".join(msg["lines"])
    if kind == "slack":
        blocks = [{"type": "header", "text": {"type": "plain_text", "text": msg["title"][:150]}},
                  {"type": "section", "text": {"type": "mrkdwn", "text": text[:2900]}},
                  {"type": "context", "elements": [{"type": "mrkdwn", "text": " | ".join(
                      f"*{k}* {v}" for k, v in msg["facts"].items())}]}]
        if msg["link"]:
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                                                       "text": f"<{msg['link']}|Open the review>"}})
        return {"text": f"{msg['title']}\n{text}", "blocks": blocks}
    if kind == "teams":
        body = [{"type": "TextBlock", "size": "Medium", "weight": "Bolder",
                 "text": msg["title"], "wrap": True}]
        body += [{"type": "TextBlock", "text": line, "wrap": True} for line in msg["lines"]]
        body.append({"type": "FactSet", "facts": [{"title": k, "value": v}
                                                  for k, v in msg["facts"].items()]})
        card = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard", "version": "1.4", "body": body}
        if msg["link"]:
            card["actions"] = [{"type": "Action.OpenUrl", "title": "Open the review",
                                "url": msg["link"]}]
        return {"type": "message", "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "contentUrl": None, "content": card}]}
    return {"source": "firewall-insight", "version": APP_VERSION, "title": msg["title"],
            "verdict": msg["verdict"], "lines": msg["lines"], "facts": msg["facts"],
            "link": msg["link"], "run_id": msg["run_id"],
            "outcome": {k: v for k, v in msg["outcome"].items()}}


# ---- delivery ------------------------------------------------------------------

async def _post(url: str, body: dict[str, Any], transport: httpx.AsyncBaseTransport | None):
    async with httpx.AsyncClient(timeout=15, transport=transport) as client:
        r = await client.post(check_url(url), json=body)
        if r.status_code >= 300:
            raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")


def _send_email(dest: dict[str, Any], password: str, msg: dict[str, Any],
                pdf: bytes | None, smtp_factory=None) -> None:
    em = EmailMessage()
    em["Subject"] = msg["title"]
    em["From"] = dest["sender"]
    em["To"] = ", ".join(dest["to"])
    body = "\n\n".join(msg["lines"])
    body += "\n\n" + "\n".join(f"{k}: {v}" for k, v in msg["facts"].items())
    if msg["link"]:
        body += f"\n\nOpen the review: {msg['link']}"
    body += ("\n\nSent by Firewall Insight, a read-only analysis tool. It changed "
             "nothing on any firewall.")
    em.set_content(body)
    if pdf:
        em.add_attachment(pdf, maintype="application", subtype="pdf",
                          filename=f"{msg.get('run_id') or 'review'}.pdf")
    host, port, security = dest["smtp_host"], dest["smtp_port"], dest["security"]
    factory = smtp_factory or (smtplib.SMTP_SSL if security == "ssl" else smtplib.SMTP)
    kwargs = {"timeout": 20}
    if security == "ssl" and smtp_factory is None:
        kwargs["context"] = ssl.create_default_context()
    with factory(host, port, **kwargs) as smtp:
        if security == "starttls":
            smtp.starttls(context=ssl.create_default_context())
        if dest.get("username"):
            smtp.login(dest["username"], password)
        smtp.send_message(em)


async def send(dest: dict[str, Any], msg: dict[str, Any], run: dict[str, Any], *,
               transport=None, smtp_factory=None) -> None:
    """Deliver one message to one destination. Raises on failure; dispatch() catches."""
    secret = _secrets().get(dest["id"]) or {}
    if dest["kind"] == "email":
        pdf = None
        if dest.get("attach_pdf") and run.get("sections"):
            from .report import build_report
            pdf = build_report(run, "summary")
        import asyncio
        await asyncio.to_thread(_send_email, dest, secret.get("password", ""), msg, pdf,
                                smtp_factory)
    else:
        if not secret.get("url"):
            raise RuntimeError("no webhook URL is saved for this destination")
        await _post(secret["url"], payload(dest["kind"], msg), transport)


async def dispatch(run: dict[str, Any], *, only: str | None = None, force: bool = False,
                   base: Path | None = None, transport=None,
                   smtp_factory=None) -> list[dict[str, Any]]:
    """Send *run* wherever its outcome meets a destination's triggers.

    Never raises. Returns one record per destination considered, which the
    caller stores on the run.
    """
    cfg = _read_file(base)
    results = []
    try:
        o = outcome(run)
    except Exception as exc:                                      # noqa: BLE001
        return [{"destination": None, "ok": False, "error": f"could not read the run: {exc}"}]
    met = triggers_met(o)
    for d in cfg.get("destinations") or []:
        if only and d.get("id") != only:
            continue
        rec = {"destination": d.get("id"), "kind": d.get("kind"), "name": d.get("name")}
        if not d.get("enabled", True) and not force:
            results.append({**rec, "ok": None, "skipped": "disabled"})
            continue
        fired = sorted(met & set(d.get("on") or []))
        if not fired and not force:
            results.append({**rec, "ok": None, "skipped": f"verdict {o['verdict']} matches none of "
                                                         f"{', '.join(d.get('on') or [])}"})
            continue
        try:
            msg = build_message(run, d.get("detail", "summary"), cfg.get("public_url", ""))
            await send(d, msg, run, transport=transport, smtp_factory=smtp_factory)
            results.append({**rec, "ok": True, "fired_on": fired or ["test"]})
        except Exception as exc:                                  # noqa: BLE001
            log.warning("Alert to %s failed: %s", d.get("id"), exc)
            results.append({**rec, "ok": False, "error": str(exc)[:300]})
    return results
