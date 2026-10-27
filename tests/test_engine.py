"""Unit tests for the Sigma engine itself (modifiers, wildcards, conditions)."""

import pytest

from scripts.detection_engine import ConditionParser, Rule, RuleError, sigma_pattern_to_regex


def make_rule(detection: dict) -> Rule:
    return Rule.from_dict({"title": "test", "detection": detection})


EVENT = {
    "Image": "C:\\Windows\\System32\\cmd.exe",
    "CommandLine": "cmd.exe /c whoami /all",
    "EventID": 4688,
    "User": "CORP\\j.doe",
    "userIdentity": {"type": "Root", "arn": "arn:aws:iam::1:root"},
    "Tags": ["finance", "vip"],
}


@pytest.mark.parametrize(
    ("selection", "expected"),
    [
        ({"Image|endswith": "\\cmd.exe"}, True),
        ({"Image|endswith": "\\CMD.EXE"}, True),  # case-insensitive by default
        ({"Image|endswith|cased": "\\CMD.EXE"}, False),
        ({"Image|startswith": "C:\\Windows\\"}, True),
        ({"CommandLine|contains": "whoami"}, True),
        ({"CommandLine|contains": "net user"}, False),
        ({"CommandLine|contains|all": ["/c", "whoami"]}, True),
        ({"CommandLine|contains|all": ["/c", "ipconfig"]}, False),
        ({"CommandLine|contains": ["ipconfig", "whoami"]}, True),  # list = OR
        ({"CommandLine": "cmd.exe /c whoami*"}, True),  # wildcard
        ({"CommandLine": "cmd.exe /? whoami*"}, True),  # ? wildcard
        ({"CommandLine": "cmd.exe"}, False),  # equality is exact
        ({"CommandLine|re": r"whoami\s+/all$"}, True),
        ({"CommandLine|re": r"WHOAMI"}, False),
        ({"CommandLine|re|i": r"WHOAMI"}, True),
        ({"CommandLine|contains|windash": " -c "}, True),  # matches " /c "
        ({"EventID": 4688}, True),
        ({"EventID": "4688"}, True),
        ({"EventID": [1, 4688]}, True),
        ({"userIdentity.type": "Root"}, True),  # nested field
        ({"Tags": "vip"}, True),  # list value in event
        ({"ParentImage": None}, True),  # null = field missing
        ({"Image": None}, False),
        ({"ParentImage|exists": False}, True),
        ({"Image|exists": True}, True),
        ({"Image|endswith": "\\cmd.exe", "User|startswith": "NT AUTHORITY"}, False),  # AND
    ],
)
def test_field_modifiers(selection, expected):
    rule = make_rule({"sel": selection, "condition": "sel"})
    assert rule.matches(EVENT) is expected


def test_list_of_maps_is_or():
    rule = make_rule(
        {
            "sel": [{"Image|endswith": "\\powershell.exe"}, {"CommandLine|contains": "whoami"}],
            "condition": "sel",
        }
    )
    assert rule.matches(EVENT)


def test_keyword_search():
    rule = make_rule({"keywords": ["*whoami*"], "condition": "keywords"})
    assert rule.matches(EVENT)


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        ("sel_a", True),
        ("sel_a and sel_b", False),
        ("sel_a or sel_b", True),
        ("sel_a and not sel_b", True),
        ("not sel_a", False),
        ("1 of sel_*", True),
        ("all of sel_*", False),
        ("1 of them", True),
        ("all of them", False),
        ("(sel_a or sel_b) and not filter", True),
        ("sel_a and (sel_b or filter)", False),
        ("NOT sel_b AND sel_a", True),  # keywords are case-insensitive
    ],
)
def test_conditions(condition, expected):
    rule = make_rule(
        {
            "sel_a": {"CommandLine|contains": "whoami"},
            "sel_b": {"CommandLine|contains": "mimikatz"},
            "filter": {"User": "NT AUTHORITY\\SYSTEM"},
            "condition": condition,
        }
    )
    assert rule.matches(EVENT) is expected


def test_and_binds_tighter_than_or():
    # a or b and c  ==  a or (b and c)
    parsed = ConditionParser("a or b and c", ["a", "b", "c"]).parse()
    assert parsed == ("or", ("id", "a"), ("and", ("id", "b"), ("id", "c")))


@pytest.mark.parametrize("condition", ["sel and", "sel and unknown", "(sel", "1 of nothing_*", "sel sel"])
def test_invalid_conditions_raise(condition):
    rule = make_rule({"sel": {"Image": "x"}, "condition": condition})
    with pytest.raises(RuleError):
        rule.matches(EVENT)


def test_unknown_modifier_raises():
    rule = make_rule({"sel": {"Image|base64offset": "x"}, "condition": "sel"})
    with pytest.raises(RuleError, match="Unsupported modifier"):
        rule.matches(EVENT)


@pytest.mark.parametrize(
    ("pattern", "text", "expected"),
    [
        ("a*c", "abbbc", True),
        ("a?c", "abc", True),
        ("a\\*c", "a*c", True),
        ("a\\*c", "abc", False),
        ("C:\\Windows\\", "C:\\Windows\\", True),
    ],
)
def test_wildcards_and_escapes(pattern, text, expected):
    import re

    assert bool(re.fullmatch(sigma_pattern_to_regex(pattern), text)) is expected

# --------------------------------------------------------------------------- #
# cidr modifier
# --------------------------------------------------------------------------- #
def test_cidr_matches_ip_inside_network():
    rule = make_rule({"sel": {"SourceIp|cidr": "10.0.0.0/8"}, "condition": "sel"})
    assert rule.matches({"SourceIp": "10.20.30.40"}) is True
    assert rule.matches({"SourceIp": "192.168.1.5"}) is False
    assert rule.matches({"SourceIp": "not-an-ip"}) is False
    assert rule.matches({}) is False  # field missing


def test_cidr_accepts_a_list_of_networks():
    rule = make_rule(
        {"sel": {"SourceIp|cidr": ["192.168.0.0/16", "172.16.0.0/12"]}, "condition": "sel"}
    )
    assert rule.matches({"SourceIp": "172.20.1.1"}) is True
    assert rule.matches({"SourceIp": "8.8.8.8"}) is False


def test_invalid_cidr_is_rejected_when_rule_loads():
    rule = make_rule({"sel": {"SourceIp|cidr": "10.0.0.0/33"}, "condition": "sel"})
    with pytest.raises(RuleError, match="Invalid CIDR"):
        rule.matches({"SourceIp": "10.1.1.1"})
