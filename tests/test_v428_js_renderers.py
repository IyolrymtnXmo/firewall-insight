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
