"""A small Sigma rule engine.

It evaluates Sigma rules directly against JSON events, so every detection can be
unit-tested in CI without a SIEM. It supports the subset of the Sigma
specification used in this repository:

* field modifiers: contains, startswith, endswith, all, re (+ i/m/s flags),
  windash, cased, exists
* wildcards in values (``*`` and ``?``) and ``\\`` escapes
* nested fields with dots (``userIdentity.type``)
* conditions: and / or / not, parentheses, ``1 of x*``, ``all of x*``,
  ``1 of them``, ``all of them``

Production conversion to SIEM queries is done with pySigma
(see ``scripts/convert_rules.py``). This engine only answers one question:
"does this event match this rule?".
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Any

import yaml

SUPPORTED_MODIFIERS = {
    "contains",
    "startswith",
    "endswith",
    "all",
    "re",
    "i",
    "m",
    "s",
    "windash",
    "cased",
    "exists",
    "cidr",
}

# Characters that Windows command-line tools accept in place of "-".
WINDASH_CHARS = ("-", "/", "–", "—", "―")

_MISSING = object()


class RuleError(ValueError):
    """Raised when a rule uses a feature this engine does not support."""


# --------------------------------------------------------------------------- #
# Value matching
# --------------------------------------------------------------------------- #
def sigma_pattern_to_regex(value: str) -> str:
    """Translate a Sigma string (with * and ? wildcards) into a regex."""
    out: list[str] = []
    i = 0
    while i < len(value):
        char = value[i]
        if char == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        if char == "*":
            out.append(".*")
        elif char == "?":
            out.append(".")
        else:
            out.append(re.escape(char))
        i += 1
    return "".join(out)


def windash_variants(value: str) -> list[str]:
    """Return the value with every "-" replaced by each Windows dash variant."""
    if "-" not in value:
        return [value]
    return [value.replace("-", dash) for dash in WINDASH_CHARS]


def get_field(event: dict[str, Any], name: str) -> Any:
    """Read a field. Dots go into nested objects (``a.b.c``)."""
    if name in event:
        return event[name]
    current: Any = event
    for part in name.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return _MISSING
    return current


def _iter_values(actual: Any) -> list[Any]:
    if isinstance(actual, list):
        return actual
    return [actual]


def _to_text(value: Any) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)


@dataclass(frozen=True)
class FieldMatcher:
    """One ``Field|modifier1|modifier2: value(s)`` line of a selection."""

    field: str
    modifiers: tuple[str, ...]
    values: tuple[Any, ...]

    @classmethod
    def parse(cls, key: str, raw_value: Any) -> FieldMatcher:
        field, *modifiers = key.split("|")
        unknown = set(modifiers) - SUPPORTED_MODIFIERS
        if unknown:
            raise RuleError(f"Unsupported modifier(s) {sorted(unknown)} on field '{field}'")
        values = tuple(raw_value) if isinstance(raw_value, list) else (raw_value,)
        if "cidr" in modifiers:
            for value in values:
                try:
                    ipaddress.ip_network(str(value), strict=False)
                except ValueError as exc:
                    raise RuleError(f"Invalid CIDR '{value}' on field '{field}'") from exc
        return cls(field=field, modifiers=tuple(modifiers), values=values)

    @cached_property
    def _compiled(self) -> list[re.Pattern[str] | None]:
        """Pre-compile one regex per expected value (None = match "field is null")."""
        mods = set(self.modifiers)
        flags = 0 if "cased" in mods else re.IGNORECASE
        flags |= re.DOTALL
        patterns: list[re.Pattern[str] | None] = []

        for value in self.values:
            if value is None:
                patterns.append(None)
                continue

            if "re" in mods:
                re_flags = 0
                re_flags |= re.IGNORECASE if "i" in mods else 0
                re_flags |= re.MULTILINE if "m" in mods else 0
                re_flags |= re.DOTALL if "s" in mods else 0
                patterns.append(re.compile(str(value), re_flags))
                continue

            text = _to_text(value)
            variants = windash_variants(text) if "windash" in mods else [text]
            regexes = []
            for variant in variants:
                body = sigma_pattern_to_regex(variant)
                if "contains" in mods:
                    body = f".*{body}.*"
                elif "startswith" in mods:
                    body = f"{body}.*"
                elif "endswith" in mods:
                    body = f".*{body}"
                regexes.append(f"(?:{body})")
            patterns.append(re.compile("|".join(regexes), flags))
        return patterns

    def _cidr_matches(self, actual: Any) -> bool:
        """True when an IP address in the event is inside one of the networks."""
        if actual is _MISSING or actual is None:
            return False
        networks = [ipaddress.ip_network(str(v), strict=False) for v in self.values]
        for item in _iter_values(actual):
            try:
                ip = ipaddress.ip_address(_to_text(item))
            except ValueError:
                continue  # not an IP address, so it cannot be in a network
            if any(ip in network for network in networks):  # IPv4 never matches IPv6
                return True
        return False

    def _value_matches(self, pattern: re.Pattern[str] | None, actual: Any) -> bool:
        if pattern is None:
            return actual is _MISSING or actual is None
        if actual is _MISSING or actual is None:
            return False
        for item in _iter_values(actual):
            text = _to_text(item)
            if "re" in self.modifiers:
                if pattern.search(text):
                    return True
            elif pattern.fullmatch(text):
                return True
        return False

    def matches(self, event: dict[str, Any]) -> bool:
        actual = get_field(event, self.field)

        if "exists" in self.modifiers:
            expected = bool(self.values[0])
            return (actual is not _MISSING) == expected

        if "cidr" in self.modifiers:
            return self._cidr_matches(actual)

        results = (self._value_matches(p, actual) for p in self._compiled)
        if "all" in self.modifiers:
            return all(results)
        return any(results)


# --------------------------------------------------------------------------- #
# Search identifiers (selection_xxx / filter_xxx)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class SearchIdentifier:
    """A named block under ``detection`` (for example ``selection_img``)."""

    name: str
    # OR of groups, each group is an AND of field matchers.
    groups: tuple[tuple[FieldMatcher, ...], ...]
    keywords: tuple[re.Pattern[str], ...] = ()

    @classmethod
    def parse(cls, name: str, definition: Any) -> SearchIdentifier:
        if isinstance(definition, dict):
            return cls(name, (cls._parse_map(definition),))

        if isinstance(definition, list) and all(isinstance(d, dict) for d in definition):
            return cls(name, tuple(cls._parse_map(d) for d in definition))

        if isinstance(definition, list) and all(isinstance(d, str) for d in definition):
            keywords = tuple(
                re.compile(f".*{sigma_pattern_to_regex(k)}.*", re.IGNORECASE | re.DOTALL) for k in definition
            )
            return cls(name, (), keywords)

        raise RuleError(f"Search identifier '{name}' has an unsupported format")

    @staticmethod
    def _parse_map(mapping: dict[str, Any]) -> tuple[FieldMatcher, ...]:
        return tuple(FieldMatcher.parse(key, value) for key, value in mapping.items())

    def matches(self, event: dict[str, Any]) -> bool:
        if self.keywords:
            texts = [_to_text(v) for v in _flatten_values(event)]
            return any(k.fullmatch(t) for k in self.keywords for t in texts)
        return any(all(m.matches(event) for m in group) for group in self.groups)


def _flatten_values(obj: Any) -> list[Any]:
    if isinstance(obj, dict):
        return [v for value in obj.values() for v in _flatten_values(value)]
    if isinstance(obj, list):
        return [v for value in obj for v in _flatten_values(value)]
    return [obj]


# --------------------------------------------------------------------------- #
# Condition parser (recursive descent)
#   expr     := and_expr ("or" and_expr)*
#   and_expr := not_expr ("and" not_expr)*
#   not_expr := "not" not_expr | primary
#   primary  := "(" expr ")" | ("1"|"any"|"all") "of" (pattern|"them") | name
# --------------------------------------------------------------------------- #
_TOKEN_RE = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")


def tokenize(condition: str) -> list[str]:
    tokens: list[str] = []
    position = 0
    condition = condition.strip()
    while position < len(condition):
        match = _TOKEN_RE.match(condition, position)
        if not match:
            raise RuleError(f"Cannot parse condition near: '{condition[position:]}'")
        tokens.append(match.group(1))
        position = match.end()
    return tokens


class ConditionParser:
    def __init__(self, condition: str, identifiers: list[str]) -> None:
        self.tokens = tokenize(condition)
        self.position = 0
        self.identifiers = identifiers

    def parse(self) -> tuple:
        node = self._expr()
        if self.position != len(self.tokens):
            raise RuleError(f"Unexpected token '{self.tokens[self.position]}' in condition")
        return node

    # -- helpers ---------------------------------------------------------- #
    def _peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def _next(self) -> str:
        token = self._peek()
        if token is None:
            raise RuleError("Condition ended too early")
        self.position += 1
        return token

    # -- grammar ---------------------------------------------------------- #
    def _expr(self) -> tuple:
        node = self._and()
        while (self._peek() or "").lower() == "or":
            self._next()
            node = ("or", node, self._and())
        return node

    def _and(self) -> tuple:
        node = self._not()
        while (self._peek() or "").lower() == "and":
            self._next()
            node = ("and", node, self._not())
        return node

    def _not(self) -> tuple:
        if (self._peek() or "").lower() == "not":
            self._next()
            return ("not", self._not())
        return self._primary()

    def _primary(self) -> tuple:
        token = self._next()
        if token == "(":
            node = self._expr()
            if self._next() != ")":
                raise RuleError("Missing closing parenthesis in condition")
            return node

        if token.lower() in {"1", "any", "all"} and (self._peek() or "").lower() == "of":
            self._next()
            target = self._next()
            names = self._expand(target)
            quantifier = "all" if token.lower() == "all" else "any"
            return (quantifier, tuple(names))

        if token not in self.identifiers:
            raise RuleError(f"Condition uses unknown identifier '{token}'")
        return ("id", token)

    def _expand(self, target: str) -> list[str]:
        if target.lower() == "them":
            names = [n for n in self.identifiers if not n.startswith("_")]
        else:
            names = [n for n in self.identifiers if fnmatch.fnmatchcase(n, target)]
        if not names:
            raise RuleError(f"Pattern '{target}' does not match any identifier")
        return names


def evaluate(node: tuple, results: dict[str, bool]) -> bool:
    kind = node[0]
    if kind == "id":
        return results[node[1]]
    if kind == "and":
        return evaluate(node[1], results) and evaluate(node[2], results)
    if kind == "or":
        return evaluate(node[1], results) or evaluate(node[2], results)
    if kind == "not":
        return not evaluate(node[1], results)
    if kind == "any":
        return any(results[name] for name in node[1])
    if kind == "all":
        return all(results[name] for name in node[1])
    raise RuleError(f"Unknown condition node: {kind}")


def referenced_identifiers(node: tuple) -> set[str]:
    kind = node[0]
    if kind == "id":
        return {node[1]}
    if kind in {"any", "all"}:
        return set(node[1])
    return set().union(*(referenced_identifiers(child) for child in node[1:]))


# --------------------------------------------------------------------------- #
# Rule
# --------------------------------------------------------------------------- #
class _LazyResults(dict):
    """Evaluate a search identifier only when the condition needs it."""

    def __init__(self, searches: dict[str, SearchIdentifier], event: dict[str, Any]) -> None:
        super().__init__()
        self._searches = searches
        self._event = event

    def __missing__(self, name: str) -> bool:
        value = self._searches[name].matches(self._event)
        self[name] = value
        return value


@dataclass
class Rule:
    path: Path
    data: dict[str, Any]

    @classmethod
    def from_file(cls, path: str | Path) -> Rule:
        path = Path(path)
        with path.open(encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
        if not isinstance(data, dict):
            raise RuleError(f"{path} is not a single YAML mapping")
        return cls(path=path, data=data)

    @classmethod
    def from_dict(cls, data: dict[str, Any], name: str = "inline_rule") -> Rule:
        return cls(path=Path(f"{name}.yml"), data=data)

    # -- metadata --------------------------------------------------------- #
    @property
    def title(self) -> str:
        return self.data.get("title", self.path.stem)

    @property
    def id(self) -> str:
        return str(self.data.get("id", ""))

    @property
    def level(self) -> str:
        return self.data.get("level", "medium")

    @property
    def tags(self) -> list[str]:
        return list(self.data.get("tags", []))

    @property
    def logsource(self) -> dict[str, str]:
        return dict(self.data.get("logsource", {}))

    @property
    def techniques(self) -> list[str]:
        return [
            tag.split(".", 1)[1].upper()
            for tag in self.tags
            if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", tag)
        ]

    # -- detection logic -------------------------------------------------- #
    @cached_property
    def searches(self) -> dict[str, SearchIdentifier]:
        detection = self.data.get("detection") or {}
        return {
            name: SearchIdentifier.parse(name, definition)
            for name, definition in detection.items()
            if name != "condition"
        }

    @cached_property
    def conditions(self) -> list[tuple]:
        raw = (self.data.get("detection") or {}).get("condition")
        if raw is None:
            raise RuleError(f"{self.path} has no detection.condition")
        raw_list = raw if isinstance(raw, list) else [raw]
        names = list(self.searches)
        return [ConditionParser(str(c), names).parse() for c in raw_list]

    def applies_to(self, event: dict[str, Any]) -> bool:
        """Check the optional ``logsource`` tag that ingestion adds to an event."""
        event_source = event.get("logsource")
        if not isinstance(event_source, dict):
            return True
        for key in ("product", "category", "service"):
            if key in self.logsource and self.logsource[key] != event_source.get(key):
                return False
        return True

    def matches(self, event: dict[str, Any]) -> bool:
        results = _LazyResults(self.searches, event)
        return any(evaluate(condition, results) for condition in self.conditions)


# --------------------------------------------------------------------------- #
# Public helpers
# --------------------------------------------------------------------------- #
def load_rule(rule_path: str | Path) -> Rule:
    return Rule.from_file(rule_path)


def load_rules(directory: str | Path = "detections") -> list[Rule]:
    return [Rule.from_file(path) for path in sorted(Path(directory).rglob("*.yml"))]


def detect(event: dict[str, Any], rule_path: str | Path) -> bool:
    """Return True if ``event`` matches the rule stored at ``rule_path``."""
    return load_rule(rule_path).matches(event)
