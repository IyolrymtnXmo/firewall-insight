"""
v4.8 regression: NAT show-hits is probed per Management API build.

v4.0 hardcoded "no NAT hits" because one lab ran Management API v1.9 and
answered `HTTP 400: Unrecognized parameter [show-hits]`. A newer lab on
API 2.0.1 supports it, so the capability must be detected, not assumed.
"""

import asyncio

import pytest

from app.checkpoint import (
    CheckPointAPIError,
    CheckPointClient,
    CheckPointRateLimitError,
    _is_unsupported_parameter_error,
)
from app.nat_analyzer import analyze_nat_rulebase


def _client_with(responder):
    client = CheckPointClient.__new__(CheckPointClient)
    client.nat_show_hits_supported = None
    client.calls = []

    async def call(command, payload=None):
        client.calls.append((command, dict(payload or {})))
        return responder(command, payload or {})

    client.call = call
    return client


def _empty_page(_command, _payload):
    return {"rulebase": [], "objects-dictionary": [], "total": 0, "to": 0}


def _reject_show_hits(_command, payload):
    if "show-hits" in payload:
        raise CheckPointAPIError("HTTP 400: Unrecognized parameter [show-hits]")
    return _empty_page(_command, payload)


def test_error_matcher_recognises_the_v19_message():
    assert _is_unsupported_parameter_error(
        CheckPointAPIError("HTTP 400: Unrecognized parameter [show-hits]")
    )
    assert not _is_unsupported_parameter_error(
        CheckPointAPIError("HTTP 404: package not found")
    )


def test_show_hits_is_attempted_on_a_supporting_build():
    client = _client_with(_empty_page)
    asyncio.run(client.show_nat_rulebase("Standard"))
    assert client.nat_show_hits_supported is True
    assert client.calls[0][1]["show-hits"] is True


def test_unsupported_build_falls_back_and_does_not_ask_again():
    client = _client_with(_reject_show_hits)
    result = asyncio.run(client.show_nat_rulebase("Standard"))

    assert client.nat_show_hits_supported is False
    assert result["hits_requested"] is False
    # Probe with show-hits, then the same page without it.
    assert "show-hits" in client.calls[0][1]
    assert "show-hits" not in client.calls[1][1]

    client.calls.clear()
    asyncio.run(client.show_nat_rulebase("Standard"))
    assert all("show-hits" not in payload for _, payload in client.calls)


def test_unrelated_api_errors_are_not_swallowed():
    def boom(_command, _payload):
        raise CheckPointAPIError("HTTP 404: Requested object not found")

    client = _client_with(boom)
    with pytest.raises(CheckPointAPIError):
        asyncio.run(client.show_nat_rulebase("Nope"))


def test_rate_limit_is_not_mistaken_for_an_unsupported_parameter():
    def limited(_command, _payload):
        raise CheckPointRateLimitError("HTTP 403: too many requests")

    client = _client_with(limited)
    with pytest.raises(CheckPointRateLimitError):
        asyncio.run(client.show_nat_rulebase("Standard"))
    assert client.nat_show_hits_supported is None


def test_nat_analyzer_surfaces_hits_when_the_api_returns_them():
    payload = {
        "objects-dictionary": [],
        "rulebase": [
            {"type": "nat-rule", "rule-number": 1, "original-source": "a",
             "translated-source": "x",
             "hits": {"value": 581672,
                      "last-date": {"iso-8601": "2026-08-19T12:58+0700"}}},
        ],
    }
    result = analyze_nat_rulebase(payload)
    assert result["summary"]["nat_hits_available"] is True
    assert result["rules"][0]["hits"] == 581672
    assert result["rules"][0]["last_hit"]["iso-8601"].startswith("2026-08-19")


def test_nat_analyzer_still_works_without_hits():
    payload = {
        "objects-dictionary": [],
        "rulebase": [
            {"type": "nat-rule", "rule-number": 1, "original-source": "a",
             "translated-source": "x"},
        ],
    }
    result = analyze_nat_rulebase(payload)
    assert result["summary"]["nat_hits_available"] is False
    assert result["rules"][0]["hits"] is None
