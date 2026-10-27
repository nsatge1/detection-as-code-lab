"""The quality gate (scripts/validate_rules.py) must pass on every rule."""

from pathlib import Path

import pytest

from scripts.validate_rules import find_orphan_tests, validate_all

ROOT = Path(__file__).resolve().parent.parent
RULES = sorted((ROOT / "detections").rglob("*.yml"))


@pytest.mark.parametrize("report", validate_all(RULES), ids=lambda r: r.path.stem)
def test_rule_passes_validation(report):
    assert report.ok, "\n".join(report.errors)


def test_no_orphan_test_files():
    assert find_orphan_tests(RULES) == []


def test_validator_rejects_a_bad_rule(tmp_path):
    bad = tmp_path / "bad_rule.yml"
    bad.write_text(
        "title: Bad\n"
        "id: not-a-uuid\n"
        "status: experimental\n"
        "logsource: {product: windows}\n"
        "detection:\n"
        "  selection: {Image|endswith: x.exe}\n"
        "  condition: selection and missing\n"
        "level: high\n"
        "tags: [attack.execution]\n",
        encoding="utf-8",
    )
    [report] = validate_all([bad])
    text = "\n".join(report.errors)
    assert not report.ok
    assert "not a valid UUID" in text
    assert "ATT&CK technique tag" in text
    assert "unknown identifier 'missing'" in text
    assert "missing required field 'author'" in text
