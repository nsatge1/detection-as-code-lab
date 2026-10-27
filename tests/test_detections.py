"""Every rule is tested against its own true-positive and true-negative events.

Test data lives in tests/events/<rule file name>.json:

    {
      "should_match":     [{"description": "...", "event": {...}}],
      "should_not_match": [{"description": "...", "event": {...}}]
    }
"""

import json
from pathlib import Path

import pytest

from scripts.detection_engine import Rule

ROOT = Path(__file__).resolve().parent.parent
RULES = sorted((ROOT / "detections").rglob("*.yml"))
EVENTS_DIR = ROOT / "tests" / "events"


def _cases():
    for rule_path in RULES:
        test_file = EVENTS_DIR / f"{rule_path.stem}.json"
        data = json.loads(test_file.read_text(encoding="utf-8")) if test_file.exists() else {}
        for expected, key in ((True, "should_match"), (False, "should_not_match")):
            for case in data.get(key, []):
                test_id = f"{rule_path.stem}::{key}::{case['description']}"
                yield pytest.param(rule_path, case["event"], expected, id=test_id)


@pytest.mark.parametrize(("rule_path", "event", "expected"), list(_cases()))
def test_rule_against_event(rule_path, event, expected):
    rule = Rule.from_file(rule_path)
    assert rule.matches(event) is expected


@pytest.mark.parametrize("rule_path", RULES, ids=lambda p: p.stem)
def test_every_rule_has_test_events(rule_path):
    test_file = EVENTS_DIR / f"{rule_path.stem}.json"
    assert test_file.exists(), f"create {test_file.relative_to(ROOT)}"
    data = json.loads(test_file.read_text(encoding="utf-8"))
    assert data.get("should_match"), "add at least one event that must match"
    assert data.get("should_not_match"), "add at least one event that must NOT match"
