"""Sigma-subset evaluator for the custom log source `sentinel_soc/android_install` (Stage 6 section 5.4).

Supported: field equality (case-insensitive), value lists (OR), the modifiers contains / startswith / endswith /
all, selections joined with and / or / not / parentheses, and `1 of <pattern>` / `all of <pattern>`.
Anything else (regex, cidr, timeframes, aggregations) raises UnsupportedSigma, and the rule is kept as export-only.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

import yaml

LOGSOURCE = {"product": "sentinel_soc", "service": "android_install"}
FIELDS = {"package_name", "app_label", "version_name", "installer_package", "requested_permissions",
          "apk_sha256", "signer_sha256", "device_name"}
MODIFIERS = {"contains", "startswith", "endswith", "all"}


class UnsupportedSigma(Exception):
    pass


@dataclass
class Sigma:
    title: str
    rule_id: str
    level: str
    detection: dict
    condition: str


def load(text: str) -> Sigma:
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise UnsupportedSigma("rule is not a mapping")
    for key in ("title", "id", "logsource", "detection", "level"):
        if key not in data:
            raise UnsupportedSigma(f"missing key {key}")
    if data["logsource"] != LOGSOURCE:
        raise UnsupportedSigma("logsource must be sentinel_soc/android_install")
    det = data["detection"]
    condition = det.get("condition")
    if not isinstance(condition, str):
        raise UnsupportedSigma("detection.condition is required")
    for name, sel in det.items():
        if name == "condition":
            continue
        if not isinstance(sel, dict):
            raise UnsupportedSigma(f"selection {name} must be a mapping")
        for key in sel:
            parts = key.split("|")
            if parts[0] not in FIELDS:
                raise UnsupportedSigma(f"unknown field {parts[0]}")
            if any(p not in MODIFIERS for p in parts[1:]):
                raise UnsupportedSigma(f"unsupported modifier in {key}")
    _parse_condition(condition, [k for k in det if k != "condition"])  # raises when not supported
    return Sigma(title=data["title"], rule_id=str(data["id"]), level=data["level"], detection=det,
                 condition=condition)


def _test(value, op: str, expected: str) -> bool:
    v, e = str(value).lower(), str(expected).lower()
    if op == "contains":
        return e in v
    if op == "startswith":
        return v.startswith(e)
    if op == "endswith":
        return v.endswith(e)
    return v == e


def _field_matches(event_value, key_parts: list[str], expected_values) -> bool:
    op = next((p for p in key_parts[1:] if p in ("contains", "startswith", "endswith")), "equals")
    require_all = "all" in key_parts[1:]
    values = expected_values if isinstance(expected_values, list) else [expected_values]
    items = event_value if isinstance(event_value, list) else [event_value]
    if event_value is None:
        return False
    results = []
    for expected in values:
        results.append(any(_test(item, op, expected) for item in items))
    return all(results) if require_all else any(results)


def _selection_matches(event: dict, sel: dict) -> bool:
    for key, expected in sel.items():
        parts = key.split("|")
        if not _field_matches(event.get(parts[0]), parts, expected):
            return False
    return True


def _parse_condition(text: str, names: list[str]):
    tokens = re.findall(r"\(|\)|[A-Za-z0-9_*]+", text)
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def take():
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    def expr():
        node = term()
        while peek() == "or":
            take()
            node = ("or", node, term())
        return node

    def term():
        node = factor()
        while peek() == "and":
            take()
            node = ("and", node, factor())
        return node

    def factor():
        tok = peek()
        if tok is None:
            raise UnsupportedSigma("condition ends unexpectedly")
        if tok == "not":
            take()
            return ("not", factor())
        if tok == "(":
            take()
            node = expr()
            if peek() != ")":
                raise UnsupportedSigma("unbalanced parentheses")
            take()
            return node
        if tok in ("1", "all"):
            take()
            if peek() != "of":
                raise UnsupportedSigma("expected 'of'")
            take()
            pattern = take()
            return ("of", tok, pattern)
        take()
        if tok not in names and not (tok.endswith("*")):
            raise UnsupportedSigma(f"unknown selection {tok}")
        return ("sel", tok)

    tree = expr()
    if pos != len(tokens):
        raise UnsupportedSigma("trailing tokens in condition")
    return tree


def _eval(node, event: dict, selections: dict) -> bool:
    kind = node[0]
    if kind == "or":
        return _eval(node[1], event, selections) or _eval(node[2], event, selections)
    if kind == "and":
        return _eval(node[1], event, selections) and _eval(node[2], event, selections)
    if kind == "not":
        return not _eval(node[1], event, selections)
    if kind == "sel":
        return _selection_matches(event, selections[node[1]])
    _, quant, pattern = node
    prefix = pattern.rstrip("*")
    chosen = [name for name in selections if name.startswith(prefix)]
    results = [_selection_matches(event, selections[name]) for name in chosen]
    if quant == "1":
        return any(results)
    return bool(results) and all(results)


def evaluate(sigma: Sigma, event: dict) -> bool:
    selections = {k: v for k, v in sigma.detection.items() if k != "condition"}
    tree = _parse_condition(sigma.condition, list(selections))
    return _eval(tree, event, selections)
