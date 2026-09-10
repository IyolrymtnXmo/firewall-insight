"""
v4.32 - the review run, rendered for somebody who will not open the tool.

These tests assert on the document model rather than on the rendered bytes.
Parsing a PDF back to check it would test reportlab, need a parser this project
does not otherwise want, and still not prove the sentences are right. What
needs proving is what the report *says*, and the strings are built in Python
before any of them reach a page.

Two properties matter more than layout:

  * The detail level is a disclosure boundary, not a verbosity dial. `summary`
    must not carry rule identifiers, because that is the file that will be
    attached to an email once delivery exists.
  * The report must not round "could not be compared" down to "unchanged".
    The headline sentence is the one somebody quotes in a meeting, and the
    live lab produces exactly that case on every single comparison.
"""

from __future__ import annotations

import pytest

from app.jobs import report as R


def _run(**over):
    run = {
        "id": "P-20260910T0900", "package": "P", "app_version": "9.9.9",
        "started_at": "2026-09-10T09:00:00+00:00", "duration_seconds": 80.2,
        "complete": True, "incomplete_sections": [],
        "sections": {
            "access": {"requested": True, "ok": True, "error": None, "data": {
                "summary": {"analyzed_rules": 13, "inline_layers": 1,
                            "optimization_score": 100}}},
            "nat": {"requested": True, "ok": True, "error": None, "data": {}},
            "snapshot": {"requested": True, "ok": True, "error": None,
                         "data": {"snapshot_id": "SNAP-1"}},
            "changed": {"requested": True, "ok": True, "error": None, "data": {
                "first_run": False, "compared_with": "SNAP-0",
                "compared_with_taken_at": "2026-09-09T09:00:00+00:00",
                "identical": False, "warnings": [],
                "summary": {"added": 0, "removed": 0, "modified": 0, "moved": 0,
                            "unchanged": 12, "scope_unverifiable": 1}}},
            "compliance": {"requested": True, "ok": True, "error": None, "data": {
                "conformant": False,
                "summary": {"total": 3, "passed": 1, "failed": 2,
                            "unverifiable": 0, "not_applicable": 0},
                "results": [
                    {"id": "C-HIGH", "title": "A high one", "status": "fail",
                     "severity": "high", "cited": True, "detail": "two layers",
                     "source": {"standard": "NIST SP 800-41", "clause": "S4"},
                     "offenders": [{"display_rule": "9", "name": "Cleanup rule",
                                    "layer": "L", "reason": "not logged",
                                    "source": "10.0.0.0/8", "destination": "Any",
                                    "service": "Any"}]},
                    {"id": "C-MED", "title": "A medium one", "status": "fail",
                     "severity": "medium", "cited": False, "detail": "13 rules",
                     "source": {"note": "House rule"}, "offenders": []},
                    {"id": "C-OK", "title": "A passing one", "status": "pass",
                     "severity": "high", "cited": True, "detail": "fine",
                     "source": {"standard": "NIST SP 800-41", "clause": "S4"}},
                ],
                "not_checkable": [
                    {"requirement": "Change management", "clause": "ES-2",
                     "why_not": "A process control."}]}},
            "gateways": {"requested": True, "ok": True, "error": None, "data": {
                "gateways": [{"host": "10.0.0.1"}],
                "findings": [{"severity": "medium", "host": "10.0.0.1",
                              "subject": "Mgmt", "detail": "administratively down"}]}},
        },
    }
    run["sections"].update(over.pop("sections", {}))
    run.update(over)
    return run


def _text(flowables) -> str:
    """Every string the document model will put on a page."""
    out = []
    for f in flowables:
        for attr in ("text", "_cellvalues"):
            if hasattr(f, attr):
                break
        if hasattr(f, "text"):
            out.append(str(f.text))
        elif hasattr(f, "_cellvalues"):
            for row in f._cellvalues:
                for cell in row:
                    out.append(_text([cell]) if not isinstance(cell, str) else cell)
        elif hasattr(f, "_content"):                       # KeepTogether
            out.append(_text(f._content))
    return " ".join(out)


class TestTheDetailLevelIsADisclosureBoundary:
    """`summary` is the level that will be attached to an email."""

    def test_summary_carries_no_rule_identifiers(self):
        body = _text(R._decisions(_run(), R._styles(), 440, "summary"))
        assert "Cleanup rule" not in body, "a rule name reached the summary report"
        assert "10.0.0.0/8" not in body, "an address reached the summary report"

    def test_summary_still_says_what_failed_and_how_badly(self):
        body = _text(R._decisions(_run(), R._styles(), 440, "summary"))
        assert "A high one" in body
        assert "severity high" in body
        assert "two layers" in body

    def test_findings_adds_rule_identifiers_but_not_addresses(self):
        body = _text(R._decisions(_run(), R._styles(), 440, "findings"))
        assert "Cleanup rule" in body
        assert "10.0.0.0/8" not in body, "findings level leaked an address"

    def test_full_adds_the_addresses(self):
        body = _text(R._decisions(_run(), R._styles(), 440, "full"))
        assert "10.0.0.0/8" in body

    def test_an_unknown_level_is_refused_not_downgraded(self):
        with pytest.raises(ValueError, match="Unknown detail level"):
            R.build_report(_run(), "verbose")

    def test_the_default_is_the_safe_one(self):
        import inspect
        assert inspect.signature(R.build_report).parameters["detail"].default == "summary"


class TestItNeverRoundsUndecidedDownToUnchanged:
    """The live lab produces 0 changes and 1 unverifiable on every comparison."""

    def test_the_headline_says_what_could_not_be_compared(self):
        run = _run()
        sentence = R._headline_sentence(
            run, R._data(run, "access")["summary"],
            R._data(run, "compliance")["summary"], R._data(run, "changed"))
        assert "could not be compared" in sentence
        assert "has not changed" not in sentence, (
            "one rule that could not be compared was reported as no change")

    def test_a_genuinely_unchanged_policy_still_reads_as_unchanged(self):
        run = _run()
        run["sections"]["changed"]["data"]["summary"]["scope_unverifiable"] = 0
        sentence = R._headline_sentence(
            run, R._data(run, "access")["summary"],
            R._data(run, "compliance")["summary"], R._data(run, "changed"))
        assert "has not changed" in sentence

    def test_the_changes_section_calls_it_out_too(self):
        body = _text(R._changes(_run(), R._styles(), 440))
        assert "could not be compared" in body

    def test_a_first_run_does_not_claim_stability(self):
        run = _run()
        run["sections"]["changed"]["data"] = {"first_run": True}
        body = _text(R._changes(run, R._styles(), 440))
        assert "first recorded review" in body


class TestAnAbsentSectionIsNeverACleanOne:
    def test_an_incomplete_run_says_so_on_the_first_page(self):
        run = _run(complete=False, incomplete_sections=["gateways"])
        body = _text(R._cover(run, R._styles(), 440))
        assert "incomplete" in body.lower()
        assert "nobody looked" in body

    def test_unreachable_gateways_are_not_reported_as_healthy(self):
        run = _run()
        run["sections"]["gateways"] = {"requested": True, "ok": False,
                                       "error": "no answer", "data": None}
        body = _text(R._gateways(run, R._styles(), 440, "findings"))
        assert "not a statement that the gateways are healthy" in body

    def test_an_unevaluated_profile_is_not_a_pass(self):
        run = _run()
        run["sections"]["compliance"] = {"requested": True, "ok": False,
                                         "error": "no such profile", "data": None}
        body = _text(R._decisions(run, R._styles(), 440, "summary"))
        assert "no such profile" in body
        assert "clean result" in body


class TestTheBlindSpotsAreInTheDocument:
    def test_the_profiles_own_not_checkable_list_is_printed(self):
        body = _text(R._not_covered(_run(), R._styles(), 440))
        assert "Change management" in body
        assert "A process control." in body

    def test_the_standing_limitations_are_printed(self):
        body = _text(R._not_covered(_run(), R._styles(), 440))
        assert "No packet is sent" in body
        assert "no compliance percentage" in body.lower()
        assert "reported as unknown" in body


class TestItActuallyRenders:
    """Cheap smoke: a real PDF, of a plausible size, for every level."""

    @pytest.mark.parametrize("level", R.DETAIL_LEVELS)
    def test_each_level_produces_a_pdf(self, level):
        pdf = R.build_report(_run(), level)
        assert pdf.startswith(b"%PDF-")
        assert pdf.rstrip().endswith(b"%%EOF")
        assert len(pdf) > 2000

    def test_a_sparse_run_does_not_crash_the_renderer(self):
        """A run where nothing was requested still has to produce a document."""
        bare = {"id": "x", "package": "P", "started_at": "2026-09-10T09:00:00+00:00",
                "app_version": "9.9.9", "complete": True, "incomplete_sections": [],
                "sections": {k: {"requested": False, "ok": False, "error": None,
                                 "data": None}
                             for k in ("access", "nat", "snapshot", "changed",
                                       "compliance", "gateways")}}
        assert R.build_report(bare, "summary").startswith(b"%PDF-")
