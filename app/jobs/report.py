"""
A stored review run, rendered as a PDF somebody senior will actually read.

The audience decides the shape. An executive is not going to read thirteen
rows of a seven-column rulebase table, and printing it does not make the report
more rigorous - it makes the two sentences that matter harder to find. So the
document answers four questions in order:

    where does this stand        the score, the verdict, the counts
    what needs a decision        failed checks, by severity, with the clause
    what changed                 since the previous run of the same package
    what this does NOT cover     the part most compliance reports leave out

That last section is not padding. This tool reads configuration; it cannot see
whether a change went through an approval workflow or whether anybody reads the
logs, and the profiles say so themselves in `not_checkable`. A report to a
decision-maker that omits its own blind spots is worse than no report, because
it converts "we did not look" into "nothing was found".

DETAIL LEVELS
    summary   scores, counts, severities, what changed. No rule identifiers.
    findings  adds rule numbers and names, so an engineer can act on it.
    full      adds the source/destination/service of each offending rule.

The level exists because this file is meant to leave the building eventually.
`summary` is the default for that reason: a PDF that lists which addresses a
firewall permits is a document you have to think about before attaching it to
an email, and the safe choice should be the one you get without asking.
"""

from __future__ import annotations

import io
from datetime import datetime
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph,
                                SimpleDocTemplate, Spacer, Table, TableStyle)

from ..version import APP_VERSION

DETAIL_LEVELS = ("summary", "findings", "full")

INK = colors.HexColor("#12211f")
MUTED = colors.HexColor("#5d6b69")
LINE = colors.HexColor("#d7e0de")
ACCENT = colors.HexColor("#0f766e")
BAD = colors.HexColor("#b4302a")
WARN = colors.HexColor("#8a6100")
GOOD = colors.HexColor("#1a7f5a")

SEVERITY_TONE = {"high": BAD, "critical": BAD, "medium": WARN, "low": MUTED}


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()["BodyText"]
    mk = lambda **kw: ParagraphStyle(kw.pop("name"), parent=base, **kw)
    return {
        "title": mk(name="t", fontName="Helvetica-Bold", fontSize=21, leading=25,
                    textColor=INK, spaceAfter=2),
        "subtitle": mk(name="st", fontSize=10.5, leading=14, textColor=MUTED,
                       spaceAfter=14),
        "h2": mk(name="h2", fontName="Helvetica-Bold", fontSize=13, leading=16,
                 textColor=INK, spaceBefore=16, spaceAfter=6),
        "body": mk(name="b", fontSize=9.5, leading=13.5, textColor=INK,
                   alignment=TA_LEFT, spaceAfter=4),
        "muted": mk(name="m", fontSize=8.5, leading=12, textColor=MUTED,
                    spaceAfter=3),
        "cell": mk(name="c", fontSize=8.5, leading=11.5, textColor=INK),
        "cellmuted": mk(name="cm", fontSize=8, leading=11, textColor=MUTED),
    }


def _fmt_time(value: Any) -> str:
    try:
        return datetime.fromisoformat(str(value)).strftime("%d %b %Y, %H:%M UTC")
    except (TypeError, ValueError):
        return str(value or "unknown")


def _section(run: dict[str, Any], name: str) -> dict[str, Any]:
    return (run.get("sections") or {}).get(name) or {}


def _data(run: dict[str, Any], name: str) -> dict[str, Any]:
    return _section(run, name).get("data") or {}


def _kpi_row(items: list[tuple[str, str, colors.Color]], width: float) -> Table:
    """One band of big numbers, the way the dashboard shows them."""
    st = _styles()
    cells = [[Paragraph(f'<font size="17" color="{v[2].hexval()}">'
                        f'<b>{v[1]}</b></font>', st["cell"]) for v in items],
             [Paragraph(v[0].upper(), st["cellmuted"]) for v in items]]
    t = Table(cells, colWidths=[width / len(items)] * len(items))
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, 0), 8),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 10),
        ("LINEABOVE", (0, 0), (-1, 0), 0.7, LINE),
        ("LINEBELOW", (0, 1), (-1, 1), 0.7, LINE),
    ]))
    return t


def _table(rows: list[list[Any]], widths: list[float], header: bool = True) -> Table:
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
    ]
    if header:
        style += [("LINEBELOW", (0, 0), (-1, 0), 0.9, INK),
                  ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f4f8f7"))]
    t.setStyle(TableStyle(style))
    return t


def build_report(run: dict[str, Any], detail: str = "summary") -> bytes:
    """Render *run* as a PDF and return the bytes.

    Raises ValueError on an unknown detail level rather than quietly falling
    back: a caller that asked for something this does not understand should not
    be handed a document with less in it than they think.
    """
    if detail not in DETAIL_LEVELS:
        raise ValueError(
            f"Unknown detail level '{detail}'. Use one of: {', '.join(DETAIL_LEVELS)}.")

    st = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"Firewall policy review - {run.get('package', '')}",
        author=f"Firewall Insight {APP_VERSION}",
    )
    width = doc.width
    flow: list[Any] = []

    flow += _cover(run, st, width)
    flow += _decisions(run, st, width, detail)
    flow += _changes(run, st, width)
    flow += _gateways(run, st, width, detail)
    flow += _not_covered(run, st, width)

    doc.build(flow, onFirstPage=_furniture(run), onLaterPages=_furniture(run))
    return buf.getvalue()


def _furniture(run: dict[str, Any]):
    label = (f"Firewall Insight {run.get('app_version', APP_VERSION)}  ·  "
             f"{run.get('package', '')}  ·  read-only analysis")

    def draw(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(18 * mm, 10 * mm, label)
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"page {canvas.getPageNumber()}")
        canvas.restoreState()

    return draw


# ---- 1. where this stands --------------------------------------------------

def _cover(run, st, width):
    access = _data(run, "access").get("summary") or {}
    comp = _data(run, "compliance")
    csum = comp.get("summary") or {}
    changed = _data(run, "changed")

    flow = [Paragraph("Firewall policy review", st["title"]),
            Paragraph(f"{run.get('package', 'unknown package')} &nbsp;·&nbsp; "
                      f"{_fmt_time(run.get('started_at'))}", st["subtitle"])]

    score = access.get("optimization_score")
    verdict, tone = _headline(run)
    flow.append(_kpi_row([
        ("Optimizer score", "—" if score is None else f"{score}/100",
         GOOD if (score or 0) >= 90 else WARN),
        ("Rules analysed", str(access.get("analyzed_rules", "—")), INK),
        ("Compliance", verdict, tone),
        ("Checks failed", str(csum.get("failed", "—")),
         BAD if csum.get("failed") else GOOD),
    ], width))

    flow.append(Spacer(1, 12))
    flow.append(Paragraph(_headline_sentence(run, access, csum, changed), st["body"]))

    if run.get("incomplete_sections"):
        flow.append(Spacer(1, 6))
        flow.append(Paragraph(
            "<b>This review is incomplete.</b> " + _incomplete_sentence(run),
            ParagraphStyle("warn", parent=st["body"], textColor=BAD,
                           borderPadding=6, backColor=colors.HexColor("#fdf1f0"))))
    return flow


def _headline(run) -> tuple[str, colors.Color]:
    sec = _section(run, "compliance")
    if not sec.get("requested"):
        return "not run", MUTED
    if not sec.get("ok"):
        return "not read", BAD
    return ("conformant", GOOD) if (sec.get("data") or {}).get("conformant") \
        else ("not conformant", BAD)


def _headline_sentence(run, access, csum, changed) -> str:
    bits = []
    if access:
        bits.append(f"{access.get('analyzed_rules', 0)} rules were analysed across "
                    f"{access.get('inline_layers', 0)} inline layer(s)")
    if csum:
        bits.append(f"{csum.get('passed', 0)} of {csum.get('total', 0)} compliance "
                    f"checks passed")
    if changed.get("first_run"):
        bits.append("this is the first recorded run of this package, so there is "
                    "nothing yet to compare it against")
    elif changed:
        # This is the sentence most likely to be quoted out of the report, so it
        # must not round "one rule could not be compared" down to "nothing
        # changed" - the same flattening the CLI summary was doing.
        cs = changed.get("summary") or {}
        moved = sum(cs.get(k, 0) for k in
                    ("added", "removed", "modified", "moved", "scope_changed",
                     "nat_added", "nat_removed", "nat_modified"))
        undecided = cs.get("scope_unverifiable", 0)
        if moved and undecided:
            bits.append(f"{moved} rule change(s) since the previous run, and "
                        f"{undecided} rule(s) that could not be compared at all")
        elif moved:
            bits.append(f"{moved} rule change(s) since the previous run")
        elif undecided:
            bits.append(f"no rule changed since the previous run, though "
                        f"{undecided} could not be compared and so cannot be "
                        f"reported as unchanged")
        else:
            bits.append("the policy has not changed since the previous run")
    return ". ".join(b[0].upper() + b[1:] for b in bits) + "." if bits else \
        "This run did not produce a summary."


def _incomplete_sentence(run) -> str:
    names = ", ".join(run.get("incomplete_sections") or [])
    return (f"The following could not be read: {names}. Those sections are absent "
            "from this report. Their absence is not evidence that they are clean — "
            "it means nobody looked.")


# ---- 2. what needs a decision ---------------------------------------------

def _decisions(run, st, width, detail):
    sec = _section(run, "compliance")
    flow = [Paragraph("What needs a decision", st["h2"])]

    if not sec.get("requested"):
        flow.append(Paragraph("No compliance profile was evaluated in this run.",
                              st["body"]))
        return flow
    if not sec.get("ok"):
        flow.append(Paragraph(
            f"The profile could not be evaluated: {sec.get('error')}. "
            "Nothing below should be read as a clean result.", st["body"]))
        return flow

    results = (sec.get("data") or {}).get("results") or []
    failed = [r for r in results if r.get("status") == "fail"]
    undecided = [r for r in results if r.get("status") == "unverifiable"]

    if not failed and not undecided:
        flow.append(Paragraph(
            "Every check in this profile passed. The profile is a list of checks "
            "somebody chose; it is not a statement that the estate is secure.",
            st["body"]))
        return flow

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    failed.sort(key=lambda r: order.get(str(r.get("severity", "")).lower(), 9))

    for r in failed + undecided:
        flow.append(_check_block(r, st, width, detail))
    return flow


def _check_block(r, st, width, detail):
    sev = str(r.get("severity", "")).lower()
    tone = SEVERITY_TONE.get(sev, MUTED)
    status = str(r.get("status", "")).upper()
    src = r.get("source") or {}

    head = (f'<font color="{tone.hexval()}"><b>{status}</b></font> &nbsp; '
            f'<b>{r.get("title", "")}</b>')
    parts = [Paragraph(head, st["body"]),
             Paragraph(f'{r.get("id", "")} · severity {sev or "unstated"}',
                       st["muted"]),
             Paragraph(r.get("detail", ""), st["body"])]

    if detail != "summary":
        rows = _offender_rows(r, detail, st)
        if rows:
            parts.append(Spacer(1, 3))
            parts.append(rows if isinstance(rows, Table) else rows)

    provenance = (f'{src.get("standard")} · {src.get("clause")}'
                  if r.get("cited") else "House rule — no external standard cited")
    parts.append(Paragraph(provenance, st["muted"]))
    parts.append(Spacer(1, 9))
    return KeepTogether(parts)


def _offender_rows(r, detail, st):
    items = r.get("offenders") or []
    if not items:
        return None
    shown, extra = items[:8], max(0, len(items) - 8)

    if detail == "findings":
        # Rule names are hyphenated (Lab-Troubleshoot-ICMP) and a narrow column
        # breaks them mid-word, which reads like a typo in a document going to
        # somebody senior.
        head = ["Rule", "Layer", "Why"]
        widths = [125, 105, 210]
        body = [[Paragraph(f'{o.get("display_rule", "")} {o.get("name", "")}', st["cell"]),
                 Paragraph(str(o.get("layer", "")), st["cell"]),
                 Paragraph(str(o.get("reason", "")), st["cell"])] for o in shown]
    else:                                             # full
        head = ["Rule", "Layer", "Source", "Destination", "Service"]
        widths = [105, 80, 85, 85, 85]
        body = [[Paragraph(f'{o.get("display_rule", "")} {o.get("name", "")}', st["cell"]),
                 Paragraph(str(o.get("layer", "")), st["cell"]),
                 Paragraph(str(o.get("source", "")), st["cell"]),
                 Paragraph(str(o.get("destination", "")), st["cell"]),
                 Paragraph(str(o.get("service", "")), st["cell"])] for o in shown]

    rows = [[Paragraph(f"<b>{h}</b>", st["cell"]) for h in head]] + body
    if extra:
        rows.append([Paragraph(f"… and {extra} more, in the application",
                               st["cellmuted"])] + [""] * (len(head) - 1))
    return _table(rows, widths)


# ---- 3. what changed -------------------------------------------------------

def _changes(run, st, width):
    sec = _section(run, "changed")
    flow = [Paragraph("What changed since the previous review", st["h2"])]

    if not sec.get("requested"):
        flow.append(Paragraph("This run did not compare against a previous one.",
                              st["body"]))
        return flow
    if not sec.get("ok"):
        flow.append(Paragraph(f"The comparison could not be made: {sec.get('error')}",
                              st["body"]))
        return flow

    d = sec.get("data") or {}
    if d.get("first_run"):
        flow.append(Paragraph(
            "This is the first recorded review of this package. From the next run "
            "onward this section reports what moved.", st["body"]))
        return flow

    cs = d.get("summary") or {}
    flow.append(Paragraph(
        f'Compared against the review of {_fmt_time(d.get("compared_with_taken_at"))}.',
        st["muted"]))
    flow.append(Spacer(1, 4))
    flow.append(_kpi_row([
        ("Added", str(cs.get("added", 0)), BAD if cs.get("added") else INK),
        ("Removed", str(cs.get("removed", 0)), BAD if cs.get("removed") else INK),
        ("Modified", str(cs.get("modified", 0)), WARN if cs.get("modified") else INK),
        ("Moved", str(cs.get("moved", 0)), WARN if cs.get("moved") else INK),
        ("Unchanged", str(cs.get("unchanged", 0)), MUTED),
    ], width))

    undecided = cs.get("scope_unverifiable", 0)
    if undecided:
        flow.append(Spacer(1, 8))
        flow.append(Paragraph(
            f"<b>{undecided} rule(s) could not be compared.</b> Their reach could "
            "not be resolved in one of the two reviews, so this comparison cannot "
            "state that they are unchanged. That is not the same as a change, and "
            "it is not the same as no change.", st["body"]))

    for w in d.get("warnings") or []:
        flow.append(Paragraph(w, st["muted"]))
    return flow


# ---- 4. gateways -----------------------------------------------------------

def _gateways(run, st, width, detail):
    sec = _section(run, "gateways")
    if not sec.get("requested"):
        return []

    flow = [Paragraph("Gateway state", st["h2"])]
    if not sec.get("ok"):
        flow.append(Paragraph(
            f"Gateway state could not be read: {sec.get('error')}. This is not a "
            "statement that the gateways are healthy — it means they were not "
            "reached.", st["body"]))
        return flow

    d = sec.get("data") or {}
    findings = d.get("findings") or []
    flow.append(Paragraph(
        f'{len(d.get("gateways") or [])} gateway(s) read at one instant. '
        f'{len(findings)} finding(s). This is a reading, not monitoring.',
        st["body"]))

    if findings and detail != "summary":
        rows = [[Paragraph("<b>Severity</b>", st["cell"]),
                 Paragraph("<b>Host</b>", st["cell"]),
                 Paragraph("<b>Finding</b>", st["cell"])]]
        for f in findings[:10]:
            tone = SEVERITY_TONE.get(str(f.get("severity", "")).lower(), MUTED)
            rows.append([
                Paragraph(f'<font color="{tone.hexval()}">'
                          f'{f.get("severity", "")}</font>', st["cell"]),
                Paragraph(str(f.get("host", "")), st["cell"]),
                Paragraph(f'<b>{f.get("subject", "")}</b> — {f.get("detail", "")}',
                          st["cell"])])
        flow.append(Spacer(1, 4))
        flow.append(_table(rows, [55, 85, 300]))
    elif findings:
        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[str(f.get("severity", "unstated"))] = \
                by_sev.get(str(f.get("severity", "unstated")), 0) + 1
        flow.append(Paragraph(
            ", ".join(f"{n} {sev}" for sev, n in sorted(by_sev.items())) + ".",
            st["muted"]))
    return flow


# ---- 5. the blind spots ----------------------------------------------------

def _not_covered(run, st, width):
    flow = [PageBreak(), Paragraph("What this review does not cover", st["h2"]),
            Paragraph(
                "This tool reads configuration. The list below is not a caveat "
                "added for safety — it is the set of questions a configuration "
                "reader cannot answer, and a decision taken from the pages above "
                "should be taken knowing they are open.", st["body"]),
            Spacer(1, 6)]

    comp = _data(run, "compliance")
    items = comp.get("not_checkable") or []
    if items:
        rows = [[Paragraph("<b>Requirement</b>", st["cell"]),
                 Paragraph("<b>Why not</b>", st["cell"])]]
        for it in items:
            rows.append([
                Paragraph(f'<b>{it.get("requirement", "")}</b><br/>'
                          f'<font color="{MUTED.hexval()}" size="7.5">'
                          f'{it.get("clause", "")}</font>', st["cell"]),
                Paragraph(str(it.get("why_not", "")), st["cell"])])
        flow.append(_table(rows, [170, 270]))
        flow.append(Spacer(1, 10))

    flow.append(Paragraph("Also true of every review this tool produces:", st["body"]))
    for line in (
        "Traffic paths are simulated from configuration. No packet is sent, and a "
        "live gateway log can still differ.",
        "A rule this tool cannot model statically is reported as unknown, never as "
        "safe and never as a violation.",
        "There is no compliance percentage. A single number would have to price an "
        "unverifiable check, and every available price misleads.",
        "Hit counts come from the Management API as running totals; this tool does "
        "not interpolate between readings.",
    ):
        flow.append(Paragraph(f"•&nbsp; {line}", st["muted"]))

    flow.append(Spacer(1, 12))
    flow.append(Paragraph(
        f'Generated by Firewall Insight {run.get("app_version", APP_VERSION)} from '
        f'review {run.get("id", "")}, which took {run.get("duration_seconds", "?")}s. '
        f'The evidence behind every figure is stored locally and can be re-read.',
        st["muted"]))
    return flow
