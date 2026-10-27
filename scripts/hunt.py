"""Run every rule over a log file and print the alerts as a timeline.

This is a tiny "SIEM in a terminal" for the demo dataset:

    python -m scripts.hunt samples/attack_simulation.jsonl
    python -m scripts.hunt samples/attack_simulation.jsonl --min-level high
    python -m scripts.hunt samples/attack_simulation.jsonl --json > alerts.jsonl

Input: one JSON event per line (JSON Lines).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from scripts.detection_engine import Rule, load_rules

ROOT = Path(__file__).resolve().parent.parent
LEVELS = ["informational", "low", "medium", "high", "critical"]


@dataclass
class Alert:
    timestamp: str
    level: str
    host: str
    rule: str
    rule_id: str
    techniques: list[str]
    event: dict[str, Any]


def event_host(event: dict[str, Any]) -> str:
    if "Computer" in event:
        return str(event["Computer"])
    if "recipientAccountId" in event:
        return f"aws:{event['recipientAccountId']}"
    return "-"


def read_events(path: Path) -> list[dict[str, Any]]:
    events = []
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{number}: invalid JSON ({exc})") from exc
    return events


def hunt(rules: list[Rule], events: list[dict[str, Any]], min_level: str = "informational") -> list[Alert]:
    threshold = LEVELS.index(min_level)
    active = [r for r in rules if LEVELS.index(r.level) >= threshold]
    alerts = []
    for event in events:
        for rule in active:
            if rule.applies_to(event) and rule.matches(event):
                alerts.append(
                    Alert(
                        timestamp=str(event.get("@timestamp", "")),
                        level=rule.level,
                        host=event_host(event),
                        rule=rule.title,
                        rule_id=rule.id,
                        techniques=rule.techniques,
                        event=event,
                    )
                )
    return sorted(alerts, key=lambda a: a.timestamp)


def print_timeline(alerts: list[Alert], rule_count: int, event_count: int, source: Path) -> None:
    print(f"Hunting with {rule_count} rules over {event_count} events ({source})\n")
    if not alerts:
        print("No alerts.")
        return
    print(f"{'TIME (UTC)':<20}  {'LEVEL':<8}  {'HOST':<17}  {'ATT&CK':<10}  RULE")
    print("-" * 110)
    for alert in alerts:
        time = alert.timestamp.replace("T", " ").rstrip("Z")
        technique = alert.techniques[0] if alert.techniques else ""
        print(f"{time:<20}  {alert.level:<8}  {alert.host:<17}  {technique:<10}  {alert.rule}")

    levels = Counter(a.level for a in alerts)
    summary = ", ".join(f"{levels[lvl]} {lvl}" for lvl in reversed(LEVELS) if levels[lvl])
    hosts = len({a.host for a in alerts})
    print(f"\n{len(alerts)} alerts | {summary} | {hosts} hosts/accounts")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("events", type=Path, help="JSON Lines file")
    parser.add_argument("--rules", type=Path, default=ROOT / "detections")
    parser.add_argument("--min-level", choices=LEVELS, default="informational")
    parser.add_argument("--json", action="store_true", help="print alerts as JSON Lines")
    args = parser.parse_args(argv)

    rules = load_rules(args.rules)
    events = read_events(args.events)
    alerts = hunt(rules, events, args.min_level)

    if args.json:
        for alert in alerts:
            print(json.dumps(asdict(alert), ensure_ascii=False))
    else:
        print_timeline(alerts, len(rules), len(events), args.events)
    return 0


if __name__ == "__main__":
    sys.exit(main())
