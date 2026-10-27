"""Quality gate for detection rules.

Every rule in ``detections/`` must pass these checks before it can be merged:

1. Valid YAML and valid Sigma (parsed by pySigma)
2. Required metadata is present (title, id, author, date, level, tags, ...)
3. ``id`` is a UUID and is unique; ``title`` is unique
4. At least one MITRE ATT&CK technique tag (attack.tXXXX[.XXX])
5. The condition only uses identifiers that exist, and only supported modifiers
6. A test file ``tests/events/<rule>.json`` exists with at least one event that
   must match and one event that must NOT match

Usage:
    python -m scripts.validate_rules            # validate detections/
    python -m scripts.validate_rules path/to/rule.yml
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import yaml

from scripts.detection_engine import Rule, RuleError, referenced_identifiers

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "detections"
EVENTS_DIR = ROOT / "tests" / "events"

REQUIRED_FIELDS = (
    "title",
    "id",
    "status",
    "description",
    "author",
    "date",
    "tags",
    "logsource",
    "detection",
    "falsepositives",
    "level",
)
VALID_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
TECHNIQUE_TAG = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
TAG_FORMAT = re.compile(r"^[a-z0-9_.-]+$")
FILENAME_FORMAT = re.compile(r"^[a-z0-9_]+\.yml$")


@dataclass
class Report:
    path: Path
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def _check_with_pysigma(text: str, report: Report) -> None:
    try:
        from sigma.collection import SigmaCollection
        from sigma.exceptions import SigmaError
    except ImportError:  # pragma: no cover - pySigma is in requirements.txt
        report.warnings.append("pySigma not installed: skipped official Sigma parsing")
        return
    try:
        collection = SigmaCollection.from_yaml(text, collect_errors=True)
    except SigmaError as exc:
        report.errors.append(f"pySigma: {exc}")
        return
    for rule in collection.rules:
        for error in rule.errors:
            report.errors.append(f"pySigma: {error}")


def _check_metadata(data: dict, report: Report) -> None:
    for key in REQUIRED_FIELDS:
        if key not in data or data[key] in (None, "", []):
            report.errors.append(f"missing required field '{key}'")

    try:
        uuid.UUID(str(data.get("id", "")))
    except ValueError:
        report.errors.append(f"id '{data.get('id')}' is not a valid UUID")

    if data.get("status") not in VALID_STATUS:
        report.errors.append(f"status must be one of {sorted(VALID_STATUS)}")

    if data.get("level") not in VALID_LEVELS:
        report.errors.append(f"level must be one of {sorted(VALID_LEVELS)}")

    rule_date = data.get("date")
    if rule_date is not None and not isinstance(rule_date, date):
        try:
            date.fromisoformat(str(rule_date))
        except ValueError:
            report.errors.append("date must use the format YYYY-MM-DD")

    tags = data.get("tags") or []
    if not any(TECHNIQUE_TAG.match(str(tag)) for tag in tags):
        report.errors.append("needs at least one ATT&CK technique tag, e.g. attack.t1059.001")
    for tag in tags:
        if not TAG_FORMAT.match(str(tag)):
            report.errors.append(f"tag '{tag}' must be lower case without spaces")

    if len(str(data.get("title", ""))) > 110:
        report.warnings.append("title is longer than 110 characters")


def _check_detection_logic(rule: Rule, report: Report) -> None:
    try:
        _ = rule.conditions  # parses the condition and every selection
        _ = rule.searches
    except RuleError as exc:
        report.errors.append(f"detection: {exc}")
        return

    used = set().union(*(referenced_identifiers(c) for c in rule.conditions))
    unused = set(rule.searches) - used
    for name in sorted(unused):
        report.warnings.append(f"search identifier '{name}' is never used in the condition")


def _check_tests(path: Path, report: Report) -> None:
    test_file = EVENTS_DIR / f"{path.stem}.json"
    if not test_file.exists():
        report.errors.append(f"no test events: create tests/events/{path.stem}.json")
        return
    try:
        data = json.loads(test_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        report.errors.append(f"{test_file.name} is not valid JSON: {exc}")
        return
    for key in ("should_match", "should_not_match"):
        cases = data.get(key) or []
        if not cases:
            report.errors.append(f"{test_file.name} needs at least one '{key}' event")
        for index, case in enumerate(cases):
            if not isinstance(case, dict) or "event" not in case or "description" not in case:
                report.errors.append(f"{test_file.name}: {key}[{index}] needs 'description' and 'event'")


def validate_file(path: Path) -> Report:
    report = Report(path)
    if not FILENAME_FORMAT.match(path.name):
        report.errors.append("file name must be snake_case and end with .yml")

    text = path.read_text(encoding="utf-8")
    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        report.errors.append(f"invalid YAML: {exc}")
        return report
    if len(documents) != 1 or not isinstance(documents[0], dict):
        report.errors.append("file must contain exactly one YAML document (one rule)")
        return report

    data = documents[0]
    _check_metadata(data, report)
    _check_with_pysigma(text, report)
    _check_detection_logic(Rule(path=path, data=data), report)
    _check_tests(path, report)
    return report


def validate_all(paths: list[Path]) -> list[Report]:
    reports = [validate_file(p) for p in paths]

    # Cross-rule checks: unique ids and titles.
    seen_ids: dict[str, Path] = {}
    seen_titles: dict[str, Path] = {}
    for report in reports:
        try:
            data = yaml.safe_load(report.path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            continue
        if not isinstance(data, dict):
            continue
        rule_id, title = str(data.get("id")), str(data.get("title"))
        if rule_id in seen_ids:
            report.errors.append(f"duplicate id, already used by {seen_ids[rule_id].name}")
        seen_ids.setdefault(rule_id, report.path)
        if title in seen_titles:
            report.errors.append(f"duplicate title, already used by {seen_titles[title].name}")
        seen_titles.setdefault(title, report.path)

    return reports


def find_orphan_tests(rule_paths: list[Path]) -> list[Path]:
    """Test files in tests/events/ that do not belong to any rule."""
    stems = {p.stem for p in rule_paths}
    return [f for f in sorted(EVENTS_DIR.glob("*.json")) if f.stem not in stems]


def collect_rules(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    return sorted(target.rglob("*.yml"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("targets", nargs="*", type=Path, default=[RULES_DIR])
    args = parser.parse_args(argv)

    paths = [p.resolve() for target in args.targets for p in collect_rules(target)]
    if not paths:
        print("No rules found.")
        return 1

    reports = validate_all(paths)
    failed = 0
    for report in reports:
        name = report.path.relative_to(ROOT) if ROOT in report.path.parents else report.path
        status = "OK  " if report.ok else "FAIL"
        print(f"{status}  {name}")
        for error in report.errors:
            print(f"        ERROR    {error}")
        for warning in report.warnings:
            print(f"        WARNING  {warning}")
        failed += not report.ok

    if args.targets == [RULES_DIR]:
        for orphan in find_orphan_tests(paths):
            print(f"FAIL  tests/events/{orphan.name}\n        ERROR    no rule with this name")
            failed += 1

    print(f"\n{len(reports) - failed}/{len(reports)} rules passed validation.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
