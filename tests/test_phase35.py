from conftest import app_source
from pathlib import Path

def test_nat_rulebase_does_not_request_show_hits():
    source = Path("app/checkpoint.py").read_text(encoding="utf-8")
    block = source.split("async def show_nat_rulebase", 1)[1]
    assert '"show-hits": True' not in block

def test_settings_page_is_confined_to_credentials():
    """Settings came back in v4.30, deliberately, and stayed narrow.

    v4.0 Final removed the Settings menu as a UI simplification - the note in
    CHANGELOG.md reads "Settings menu removed; Network Mapping no longer shows
    policy selectors" - and this test pinned that by asserting the page was
    absent. v4.30 reintroduced it for one reason: an operator should be able to
    enter Management and Gaia credentials without hand-editing .env.

    The old assertion is superseded by that decision, so it is replaced rather
    than deleted. What still needs protecting is the scope: this page manages
    credentials, and must not grow controls that change firewall policy.
    """
    source = app_source()
    section = source.split('<section id="settings"', 1)
    assert len(section) == 2, "the Settings page is missing"
    body = section[1].split("</section>", 1)[0]

    # It is a credential form, and nothing else.
    for expected in ("cpMgmt", "cpUser", "cpPass", "gaiaUser", "gaiaHosts"):
        assert expected in body, f"Settings lost its {expected} field"

    # No control on this page may write policy, install it, or pick a rulebase
    # to act on - the v4.0 concern that removed the page in the first place.
    for forbidden in ("install-policy", "publish", "install_policy",
                      "runAccess(", "runNat(", "takeSnapshot("):
        assert forbidden not in body, f"Settings grew a policy control: {forbidden}"
