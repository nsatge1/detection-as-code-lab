"""Integration test: hunt over the simulated attack day.

* Every rule must fire on the intrusion (no blind spot).
* No rule may fire on normal activity (no false positive).
"""

from pathlib import Path

from scripts.detection_engine import load_rules
from scripts.generate_events import attack, build_dataset, noise
from scripts.hunt import hunt, read_events

ROOT = Path(__file__).resolve().parent.parent
RULES = load_rules(ROOT / "detections")


def test_every_rule_fires_on_the_attack():
    alerts = hunt(RULES, attack())
    fired = {a.rule for a in alerts}
    missing = {r.title for r in RULES} - fired
    assert not missing, f"rules that did not fire: {sorted(missing)}"


def test_no_false_positive_on_normal_activity():
    import random

    alerts = hunt(RULES, noise(random.Random(7), count=2000))
    assert alerts == [], [f"{a.rule}: {a.event.get('CommandLine', a.event)}" for a in alerts]


def test_sample_file_is_up_to_date():
    """samples/attack_simulation.jsonl must be the output of generate_events.py."""
    assert read_events(ROOT / "samples" / "attack_simulation.jsonl") == build_dataset()


def test_attack_chain_order_on_workstation():
    alerts = [a for a in hunt(RULES, build_dataset()) if a.host == "WIN-FIN-07"]
    first, last = alerts[0], alerts[-1]
    assert "Office Application" in first.rule or "PowerShell" in first.rule
    assert last.rule == "Windows Security Audit Log Cleared"
