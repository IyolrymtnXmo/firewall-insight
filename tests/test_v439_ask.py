"""
v4.39 - asking Traffic Path a question in words.

The parser is held to asking back rather than guessing, and the answer to the
trace's own verdict: it may phrase UNVERIFIED in a sentence, but it may never
turn it into a yes or a no.
"""

from __future__ import annotations

from pathlib import Path

from app import ask

APP = Path(__file__).resolve().parent.parent / "app"

OBJECTS = {
    "1": {"uid": "1", "name": "AD-Server_192.168.10.10", "type": "host", "ipv4-address": "192.0.2.10"},
    "2": {"uid": "2", "name": "LAB-VLAN20", "type": "network", "subnet4": "198.51.100.0", "mask-length4": 24},
    "3": {"uid": "3", "name": "Admins", "type": "group"},
    "4": {"uid": "4", "name": "AD-Services", "type": "service-group"},
    "5": {"uid": "5", "name": "Custom-8443", "type": "service-tcp", "port": "8443"},
}


def p(q):
    return ask.parse(q, OBJECTS)


class TestReadingTheQuestion:
    def test_thai(self):
        r = p("ทำไม 203.0.113.5 เข้า AD-Server_192.168.10.10 ด้วย rdp ไม่ได้")
        assert r["lang"] == "th" and r["ready"]
        assert (r["source"]["value"], r["destination"]["value"]) == ("203.0.113.5", "192.0.2.10")
        assert r["service"] == {"input": "3389", "protocol": "tcp", "from": "rdp"}

    def test_english_with_a_hostname(self):
        r = p("can 203.0.113.5 reach web01.example.com on https?")
        assert r["ready"] and r["destination"]["value"] == "web01.example.com"
        assert r["service"]["input"] == "443"

    def test_an_object_name_holding_an_address_is_the_object(self):
        """The name embeds 192.168.10.10; the host's address is 192.0.2.10."""
        r = p("from 203.0.113.9 to AD-Server_192.168.10.10 tcp/389")
        assert r["destination"]["value"] == "192.0.2.10"

    def test_direction_words_decide_the_order(self):
        r = p("to 192.0.2.10 from 203.0.113.5 port 22")
        assert (r["source"]["value"], r["destination"]["value"]) == ("203.0.113.5", "192.0.2.10")

    def test_a_marker_inside_a_word_is_not_a_marker(self):
        """'to' is inside 'cusTOmer'. Matched as a substring, it outranked the
        'from' before it, and source and destination came out swapped."""
        r = p("from customer 203.0.113.5 to 192.0.2.10 port 22")
        assert (r["source"]["value"], r["destination"]["value"]) == ("203.0.113.5", "192.0.2.10")

    def test_a_port_after_the_address(self):
        r = p("192.0.2.1 -> 198.51.100.7:8443")
        assert r["ready"] and r["service"]["input"] == "8443"

    def test_a_check_point_service_object_by_name(self):
        r = p("from 192.0.2.1 to 192.0.2.10 using Custom-8443")
        assert r["service"]["input"] == "Custom-8443"


class TestAskingBackInsteadOfGuessing:
    def test_a_network_is_not_silently_turned_into_one_address(self):
        r = p("from LAB-VLAN20 to 192.0.2.10 port 445")
        assert not r["ready"]
        c = r["clarify"][0]
        assert c["role"] == "source" and "198.51.100.0/24" in c["why"]
        assert c["suggestion"] == "198.51.100.1"

    def test_a_group_has_no_suggestion_invented_for_it(self):
        r = p("from Admins to 192.0.2.10 port 22")
        assert not r["ready"] and r["clarify"][0]["suggestion"] is None

    def test_a_service_group_is_asked_about_not_reported_missing(self):
        """AD-Services is a group with no static model; the trace needs one port."""
        r = p("from 192.0.2.1 to 192.0.2.10 on AD-Services")
        assert not r["ready"] and "service" not in r["missing"]
        assert r["clarify"][0]["role"] == "service" and "service group" in r["clarify"][0]["why"]

    def test_missing_pieces_are_named(self):
        r = p("จาก 203.0.113.5 ไป 192.0.2.10")
        assert r["missing"] == ["service"] and not r["ready"]
        text = " ".join(ask.clarification(r))
        assert "พอร์ต" in text


def _result(access, nat=None, complete=True):
    return {"query": {"source": "203.0.113.5", "destination": "192.0.2.10",
                      "service_display": "TCP/3389"},
            "access": access, "nat": nat or [], "data_quality": {"complete": complete}}


STEP_4 = {"display_rule": "4", "name": "VLAN20-to-AD", "layer": "Net", "action": "Accept",
          "service_state": "unknown", "service_match": "AD-Services has no static model"}
STEP_9 = {"display_rule": "9", "name": "Cleanup rule", "layer": "Net", "action": "Drop"}


class TestTheAnswerIsTheTracesAnswer:
    def test_an_exact_accept(self):
        e = ask.explain(_result({"matched": True, "winner": {**STEP_4, "service_state": "match"},
                                 "result": "Accept", "confidence": "exact"}), {"lang": "en"})
        assert e["verdict"] == "allowed" and e["answer"][0].startswith("Allowed:")

    def test_a_drop_in_thai(self):
        e = ask.explain(_result({"matched": True, "winner": STEP_9, "result": "Drop",
                                 "confidence": "exact"}), {"lang": "th"})
        assert e["verdict"] == "blocked" and e["answer"][0].startswith("ไม่ได้")
        assert " ใน Net" in e["answer"][0] and " in Net" not in e["answer"][0]

    def test_unverified_is_never_turned_into_yes_or_no(self):
        e = ask.explain(_result({"matched": False, "result": "UNVERIFIED", "confidence": "unknown",
                                 "possible_winner": STEP_4, "later_exact_rule": STEP_9,
                                 "reason": "..."}), {"lang": "en"})
        assert e["verdict"] == "unknown"
        text = " ".join(e["answer"])
        assert "Cannot say for certain" in text
        assert "cannot be declared final" in text
        assert "AD-Services has no static model" in text
        assert not text.startswith(("Allowed", "Blocked"))

    def test_an_inferred_match_says_it_is_not_certain(self):
        e = ask.explain(_result({"matched": True, "winner": STEP_9, "result": "Drop",
                                 "confidence": "inferred", "reason": "parent was unknown"}),
                        {"lang": "en"})
        assert "not certain" in e["answer"][0]

    def test_an_incomplete_read_is_disclosed(self):
        e = ask.explain(_result({"matched": True, "winner": STEP_9, "confidence": "exact"},
                                complete=False), {"lang": "en"})
        assert any("did not load completely" in l for l in e["answer"])

    def test_it_always_says_it_is_a_simulation(self):
        e = ask.explain(_result({"matched": True, "winner": STEP_9, "confidence": "exact"}), {"lang": "th"})
        assert "simulation" in e["answer"][-1] or "จำลอง" in e["answer"][-1]


class TestItUsesTheOneTrace:
    def test_the_ask_route_calls_the_same_trace_as_the_form(self):
        src = (APP / "api" / "traffic.py").read_text(encoding="utf-8")
        ask_body = src.split('@router.get("/api/ask")', 1)[1].split("@router.get(", 1)[0]
        assert "run_trace(" in ask_body
        assert "trace_access_tree(" not in ask_body, "a second matcher would drift from the first"

    def test_the_module_sends_nothing_anywhere(self):
        import ast
        tree = ast.parse((APP / "ask.py").read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
        assert imported <= {"__future__", "ipaddress", "re", "typing"}, imported
