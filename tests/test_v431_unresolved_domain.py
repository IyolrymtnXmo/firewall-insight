"""
v4.31 - a hostname that does not resolve is `unknown`, never `no-match`.

Found by running a trace against the live lab, not by reading the code.

`address_match_state()` resolved the endpoint and then threw the error away:

    resolved, _ = _domain_candidates(raw)

When the name did not resolve, `ips` was empty, so every containment test in
the loop was vacuously false and the function fell through to its final
`return "no-match", "No matching object"`.

That is a confident answer to a question this simulator cannot answer, and it
does not stay contained. With the address condition of every earlier rule
falsely settled as a non-match, the trailing Any/Any/Any cleanup rule matches,
and the trace reports:

    result='Drop'  confidence='exact'  reason='Terminal Access rule matched exactly.'

for a flow whose real path is unknown. On the live lab, tracing
`192.168.10.50 -> no-such-host-xyz.invalid tcp/443` produced exactly that,
while the same trace to a resolvable name matched rule 8 -> 8.1 Accept.

This is the failure mode the whole tri-state design exists to prevent, so it
gets a test of its own.
"""

from __future__ import annotations

import pytest

from app import matching
from app.matching import address_match_state
from app.resolver import ObjectResolver


def _resolver():
    return ObjectResolver({
        "net-lab": {"uid": "net-lab", "name": "LAB-NET", "type": "network",
                    "subnet4": "192.168.20.0", "mask-length4": 24},
        "any": {"uid": "any", "name": "Any", "type": "CpmiAnyObject"},
    })


@pytest.fixture(autouse=True)
def clean_dns_cache():
    matching.dns_cache_clear()
    yield
    matching.dns_cache_clear()


def _unresolvable(monkeypatch):
    def boom(*a, **kw):
        raise OSError("Name or service not known")
    monkeypatch.setattr(matching.socket, "getaddrinfo", boom)


def _resolves_to(monkeypatch, addr):
    monkeypatch.setattr(
        matching.socket, "getaddrinfo",
        lambda *a, **kw: [(None, None, None, "", (addr, 0))])


class TestUnresolvedIsUnknown:
    def test_a_name_that_does_not_resolve_is_unknown(self, monkeypatch):
        _unresolvable(monkeypatch)
        state, why = address_match_state(["net-lab"], "nope.example.invalid", _resolver())
        assert state == "unknown", f"got {state!r} ({why})"
        assert "did not resolve" in why

    def test_the_resolver_error_is_carried_into_the_reason(self, monkeypatch):
        _unresolvable(monkeypatch)
        _, why = address_match_state(["net-lab"], "nope.example.invalid", _resolver())
        assert "Name or service not known" in why, why

    def test_a_name_that_resolves_outside_the_object_is_still_no_match(self, monkeypatch):
        """`unknown` must not swallow a genuine, decidable non-match."""
        _resolves_to(monkeypatch, "203.0.113.9")
        state, _ = address_match_state(["net-lab"], "elsewhere.example.invalid", _resolver())
        assert state == "no-match"

    def test_a_name_that_resolves_inside_the_object_matches(self, monkeypatch):
        _resolves_to(monkeypatch, "192.168.20.7")
        state, _ = address_match_state(["net-lab"], "inside.example.invalid", _resolver())
        assert state == "match"

    def test_any_still_matches_an_unresolvable_name(self, monkeypatch):
        """Any matches every address, so it needs no address to decide."""
        _unresolvable(monkeypatch)
        state, _ = address_match_state(["any"], "nope.example.invalid", _resolver())
        assert state == "match"

    def test_an_ip_literal_is_unaffected(self, monkeypatch):
        def explode(*a, **kw):
            raise AssertionError("an IP literal must not reach the resolver")
        monkeypatch.setattr(matching.socket, "getaddrinfo", explode)
        assert address_match_state(["net-lab"], "192.168.20.5", _resolver())[0] == "match"
        assert address_match_state(["net-lab"], "10.9.9.9", _resolver())[0] == "no-match"


class TestTheVerdictStopsClaimingCertainty:
    def test_a_cleanup_rule_cannot_be_reported_as_exact(self, monkeypatch):
        """The end-to-end shape of the defect, through trace_access_tree().

        Rule 1 sends LAB-NET somewhere; rule 2 is the Any/Any/Any cleanup. With
        an unresolvable destination the old code settled rule 1 as a non-match
        and handed back rule 2 as an exact Drop.
        """
        from app.traffic import trace_access_tree

        _unresolvable(monkeypatch)

        objects = {
            "net-lab": {"uid": "net-lab", "name": "LAB-NET", "type": "network",
                        "subnet4": "192.168.20.0", "mask-length4": 24},
            "any": {"uid": "any", "name": "Any", "type": "CpmiAnyObject"},
            "accept": {"uid": "accept", "name": "Accept", "type": "RulebaseAction"},
            "drop": {"uid": "drop", "name": "Drop", "type": "RulebaseAction"},
            "svc": {"uid": "svc", "name": "https", "type": "service-tcp", "port": "443"},
        }
        payload = {
            "objects-dictionary": list(objects.values()),
            "rulebase": [
                {"type": "access-rule", "rule-number": 1, "name": "to-lab",
                 "enabled": True, "source": ["any"], "destination": ["net-lab"],
                 "service": ["svc"], "action": "accept"},
                {"type": "access-rule", "rule-number": 2, "name": "Cleanup rule",
                 "enabled": True, "source": ["any"], "destination": ["any"],
                 "service": ["any"], "action": "drop"},
            ],
        }
        tree = {
            "root_layers": ["L"],
            "layers": [{"name": "L", "path": "L", "depth": 0, "parent_layer": None,
                        "parent_rule": None, "display_prefix": "", "payload": payload}],
        }
        query = {"protocol": "tcp", "port": 443,
                 "atoms": [("tcp", 443, 443)], "display": "https"}

        out = trace_access_tree(tree, "10.0.0.5", "nope.example.invalid", "tcp", query,
                                selected_root="L")

        assert out.get("confidence") != "exact", (
            f"reported {out.get('result')!r} with confidence "
            f"{out.get('confidence')!r} for an endpoint that never resolved")


def test_the_limitation_is_disclosed_to_the_user():
    """Resolution happens on this host, not on the gateway. Say so."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent
           / "app" / "api" / "traffic.py").read_text(encoding="utf-8")
    assert "resolved by the machine running this" in src
    assert "split-horizon" in src
