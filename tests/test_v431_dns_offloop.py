"""
v4.31 - name resolution must not run on the event loop, or run N times.

`address_match_state()` is called once per rule per direction. Tracing a
hostname endpoint through a 200-rule policy therefore issued ~400 identical
`socket.getaddrinfo()` calls, each of them a blocking call reached from inside
`async def traffic_path`. A resolver that did not answer promptly stalled the
whole process: every other request queued behind it, including the
`/api/progress` poll whose entire job is to show that the request is alive.

Two changes, tested here:

  * `matching._domain_candidates()` memoises with a TTL, so one hostname costs
    one lookup instead of one per rule - and the TTL keeps the answer from
    outliving the record it came from.
  * `api/traffic.py` resolves the endpoints through `loop.getaddrinfo()` before
    the synchronous trace starts, and seeds that cache, so the trace itself
    makes no call at all.

The fallback lookup stays in `matching.py` on purpose: the analysis modules are
called directly by the tests and by `tools/acceptance.py`, with no event loop
in sight, and they have to keep working there.
"""

from __future__ import annotations

import asyncio
import socket

import pytest

from app import matching


@pytest.fixture(autouse=True)
def clean_dns_cache():
    matching.dns_cache_clear()
    yield
    matching.dns_cache_clear()


class TestMemoisation:
    def test_one_hostname_costs_one_lookup(self, monkeypatch):
        calls = []

        def fake_getaddrinfo(host, *a, **kw):
            calls.append(host)
            return [(None, None, None, "", ("10.1.2.3", 0))]

        monkeypatch.setattr(matching.socket, "getaddrinfo", fake_getaddrinfo)

        for _ in range(50):
            ips, err = matching._domain_candidates("host.example.invalid")
            assert ips == ["10.1.2.3"] and err is None

        assert len(calls) == 1, f"resolved {len(calls)} times for one hostname"

    def test_a_failure_is_remembered_too(self, monkeypatch):
        """A rulebase full of misses must not retry a dead resolver per rule."""
        calls = []

        def fake_getaddrinfo(host, *a, **kw):
            calls.append(host)
            raise OSError("no such host")

        monkeypatch.setattr(matching.socket, "getaddrinfo", fake_getaddrinfo)

        for _ in range(20):
            ips, err = matching._domain_candidates("nope.example.invalid")
            assert ips == [] and "no such host" in err

        assert len(calls) == 1

    def test_the_answer_expires(self, monkeypatch):
        """A cache without a TTL would let a trace cite a stale address."""
        calls = []

        def fake_getaddrinfo(host, *a, **kw):
            calls.append(host)
            return [(None, None, None, "", (f"10.0.0.{len(calls)}", 0))]

        monkeypatch.setattr(matching.socket, "getaddrinfo", fake_getaddrinfo)

        clock = [1000.0]
        monkeypatch.setattr(matching.time, "monotonic", lambda: clock[0])

        assert matching._domain_candidates("host.example.invalid")[0] == ["10.0.0.1"]
        clock[0] += matching.DNS_TTL_SECONDS + 1
        assert matching._domain_candidates("host.example.invalid")[0] == ["10.0.0.2"]
        assert len(calls) == 2

    def test_an_address_is_never_resolved(self, monkeypatch):
        def explode(*a, **kw):
            raise AssertionError("an IP literal must not reach the resolver")

        monkeypatch.setattr(matching.socket, "getaddrinfo", explode)
        assert matching._domain_candidates("192.0.2.10") == (["192.0.2.10"], None)


class TestThePrewarmKeepsTheTraceOffTheResolver:
    def test_prewarm_seeds_the_cache_so_the_trace_makes_no_call(self, monkeypatch):
        from app.api.traffic import _prewarm_dns

        # loop.getaddrinfo() hands the work to socket.getaddrinfo in an
        # executor thread, so patching the socket module covers every loop
        # implementation - Windows uses Proactor, POSIX uses a selector loop.
        monkeypatch.setattr(
            socket, "getaddrinfo",
            lambda *a, **kw: [(None, None, None, "", ("198.51.100.7", 0))])

        asyncio.run(_prewarm_dns("web.example.invalid", "192.0.2.1", ""))

        def explode(*a, **kw):
            raise AssertionError("the trace resolved a name on the event loop")

        monkeypatch.setattr(matching.socket, "getaddrinfo", explode)
        assert matching._domain_candidates("web.example.invalid") == (["198.51.100.7"], None)

    def test_a_resolver_failure_is_cached_not_raised(self, monkeypatch):
        from app.api.traffic import _prewarm_dns

        def boom(*a, **kw):
            raise OSError("resolver unreachable")

        monkeypatch.setattr(socket, "getaddrinfo", boom)

        asyncio.run(_prewarm_dns("dead.example.invalid"))

        def explode(*a, **kw):
            raise AssertionError("the trace retried a resolver that had already failed")

        monkeypatch.setattr(matching.socket, "getaddrinfo", explode)
        ips, err = matching._domain_candidates("dead.example.invalid")
        assert ips == [] and "resolver unreachable" in err

    def test_the_route_prewarms_before_it_traces(self):
        """Ordering is the whole point: after the trace it would prove nothing."""
        from pathlib import Path
        src = (Path(__file__).resolve().parent.parent
               / "app" / "api" / "traffic.py").read_text(encoding="utf-8")
        body = src.split("async def traffic_path", 1)[1]
        assert body.index("_prewarm_dns(src, dst)") < body.index("trace_access_tree(")


def test_socket_is_still_available_for_direct_callers():
    """The pure module keeps its own fallback - acceptance.py has no loop."""
    assert hasattr(matching, "socket")
    assert callable(socket.getaddrinfo)
