"""
v4.28.1 - the frontend has to be RUN, not only parsed.

v4.25 shipped this inside a function whose parameter is `data`:

    const checked=(d.summary||{}).install_on_checked===true;

Valid JavaScript. `node --check` was happy. 668 Python tests passed. The NAT
page and the dashboard both died with "d is not defined" and the first person
to find out was the user, on the lab, with the deadline a week away. It was the
second identifier bug to reach them that way.

Nothing in a source-scanning test can catch this: the assertions here have
always looked for strings in app.js, and the string was there - it just named
something that did not exist at runtime. So this test runs the real file in a
stubbed DOM and calls the renderers.

The stub is deliberately mean. Element ids come out of index.html, because a
browser exposes them as window properties and that is why the code can say
`natResults` instead of a getElementById call. Every OTHER identifier stays
undefined, so a stray one throws here rather than in front of somebody.

Verified against the original defect: with `d.summary` put back, this test
fails with exactly "d is not defined".

Skipped, not failed, where node is unavailable - a Python test suite should not
stop working because a JavaScript runtime is missing.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
HARNESS = ROOT / "tests" / "js" / "scope_check.mjs"


@pytest.mark.skipif(shutil.which("node") is None,
                    reason="node is not installed; the JS renderers cannot be executed here")
def test_every_renderer_runs_without_touching_an_undefined_identifier():
    result = subprocess.run(
        ["node", str(HARNESS), str(ROOT)],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, (
        "a frontend renderer threw when it was actually called:\n"
        + (result.stderr or result.stdout))
    assert "ok -" in result.stdout


def test_the_harness_is_part_of_the_repository():
    """A test that is easy to delete by accident is not a guarantee."""
    assert HARNESS.is_file()
    text = HARNESS.read_text(encoding="utf-8")
    assert "renderNatSpecialViews" in text
    assert "id=\\\"" in text or 'id="' in text, "element ids must come from index.html"


def test_the_harness_covers_the_v430_frontend():
    """v4.30's own code was the part with no runtime coverage at all.

    The Aurora dashboard and the Settings page shipped after this harness was
    written, so the newest code in the application - and the only code that
    writes to disk and talks to a Management Server - was never executed by any
    test. These names are asserted so that coverage cannot quietly disappear.
    """
    text = HARNESS.read_text(encoding="utf-8")
    for name in ("renderHealthGauge", "renderHitBars", "renderTopoPreview",
                 "renderTracePreview", "renderHitTrend", "refreshAuroraDashboard",
                 "loadCredentialStatus", "saveCred", "testCred", "deleteCred",
                 "showTestResult"):
        assert name in text, f"the harness no longer exercises {name}"


def test_async_renderers_are_awaited_not_fire_and_forget():
    """An async function that throws rejects a promise; it does not throw here.

    Calling saveCred() inside a try/catch and never awaiting it would make the
    harness report success on a function that is broken, which is worse than
    not covering it at all.
    """
    text = HARNESS.read_text(encoding="utf-8")
    assert "asyncChecks" in text
    assert "await run()" in text
    assert "asyncChecks.length" in text, "async checks must count towards the total"


def test_the_harness_executes_the_traffic_path_render():
    """The screen the product is judged on has to be RUN, not just parsed.

    Every other check calls a renderer directly. The Traffic Path render lives
    inside `trace()`, behind an await, so nothing executed it - which is how
    `${ARROW_CH}`, an identifier that does not exist, reached the transition
    cell while the whole Python suite and every other renderer stayed green.
    """
    text = HARNESS.read_text(encoding="utf-8")
    assert "TRACE_UNVERIFIED" in text, "the UNVERIFIED payload is gone"
    assert "TRACE_EXACT" in text, "the matched payload is gone"
    assert "context.trace()" in text, "the harness no longer runs trace()"


def test_the_harness_pins_the_honesty_of_the_trace_screen():
    """These assertions are the v4.31 UI fixes. Losing them loses the fixes."""
    text = HARNESS.read_text(encoding="utf-8")
    for claim in ('mustNot(html, "No match"',
                  'mustNot(html, "Final rule"',
                  '"configured: Accept"',
                  '"Policy Path (unverified)"'):
        assert claim in text, f"the harness stopped checking: {claim}"


def test_the_stub_remembers_nodes_by_id():
    """Without this the harness cannot see the DOM change at all.

    getElementById() used to return a fresh object per call, so two calls for
    the same id got two unrelated nodes. notify() appends to
    getElementById('toasts'), so every append landed somewhere different and
    the stacked-toast defect was invisible here.
    """
    text = HARNESS.read_text(encoding="utf-8")
    assert "NODES" in text and "NODES.set" in text
    assert "notify() replaces a repeated toast" in text
