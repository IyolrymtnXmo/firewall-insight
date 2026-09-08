"""
v4.23 - Chapter 5 homework (c): the same object, referenced two ways.

The question: if one NAT rule sends `{"name": "X"}` with no uid and another
sends `{"uid": "abc", "name": "X"}`, are they counted as duplicates, and is
that right?

Measured before changing anything, they were not:

    duplicate groups: 0

`_uid_values()` falls back to the name when a uid is absent, so the two rules
got the signatures ("X",) and ("abc",) and looked different. The fallback was
right - without it the entry becomes an empty string and is filtered out,
which corrupts the signature far worse - but stopping there is a false
negative: the two references are the same object, and the objects-dictionary
says so.

So the answer is "no, and it should have been yes, but only where the
dictionary proves it". A name is resolved to a uid when exactly one object in
this payload carries it. Two objects sharing a name prove nothing, so the name
is left as written and the rules stay distinct - reporting a duplicate we
cannot prove is the more expensive mistake.
"""

from app.nat_analyzer import analyze_nat_rulebase

ANY = {"uid": "any", "name": "Any", "type": "CpmiAnyObject"}
HOST = {"uid": "abc", "name": "X", "type": "host", "ipv4-address": "10.0.0.1"}
TWIN = {"uid": "def", "name": "X", "type": "host", "ipv4-address": "10.0.0.2"}


def rule(number, source):
    return {"type": "nat-rule", "rule-number": number, "enabled": True,
            "method": "hide",
            "original-source": source, "original-destination": "any",
            "original-service": "any",
            "translated-source": "any", "translated-destination": "Original",
            "translated-service": "Original", "install-on": ["any"]}


def test_a_name_only_reference_matches_the_uid_the_dictionary_gives_it():
    out = analyze_nat_rulebase({
        "objects-dictionary": [ANY, HOST],
        "rulebase": [rule(1, {"name": "X"}), rule(2, {"uid": "abc", "name": "X"})],
    })
    assert out["summary"]["duplicate_nat_groups"] == 1
    assert out["findings"]["duplicates"][0]["rule_numbers"] == [1, 2]


def test_an_ambiguous_name_is_left_alone_rather_than_guessed():
    """Two objects called X: the dictionary cannot say which one was meant."""
    out = analyze_nat_rulebase({
        "objects-dictionary": [ANY, HOST, TWIN],
        "rulebase": [rule(1, {"name": "X"}), rule(2, {"uid": "abc", "name": "X"})],
    })
    assert out["summary"]["duplicate_nat_groups"] == 0


def test_a_name_with_no_object_behind_it_is_still_kept_in_the_signature():
    """The original reason for the fallback: never drop the entry."""
    out = analyze_nat_rulebase({
        "objects-dictionary": [ANY],
        "rulebase": [rule(1, {"name": "Ghost"}), rule(2, {"name": "Ghost"})],
    })
    assert out["summary"]["duplicate_nat_groups"] == 1


def test_genuinely_different_rules_are_still_not_duplicates():
    out = analyze_nat_rulebase({
        "objects-dictionary": [ANY, HOST, TWIN],
        "rulebase": [rule(1, {"uid": "abc"}), rule(2, {"uid": "def"})],
    })
    assert out["summary"]["duplicate_nat_groups"] == 0
