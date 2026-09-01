from __future__ import annotations

import re
import time
from dataclasses import dataclass

ENGINE = "osint-tools-yara-subset"
ENGINE_VERSION = "1"
RULE = re.compile(r"rule\s+([A-Za-z_]\w*)\s*(?::\s*([^\{]+))?\s*\{(.*?)\}", re.S)
STRING = re.compile(r"\$([A-Za-z_]\w*)\s*=\s*\"((?:\\.|[^\"\\])*)\"\s*([^\n\r]*)")
META = re.compile(r"([A-Za-z_]\w*)\s*=\s*(\"(?:\\.|[^\"\\])*\"|-?\d+|true|false)", re.I)


class RuleError(Exception):
    pass


@dataclass(frozen=True)
class YaraLimits:
    timeout_seconds: float = 5.0
    max_matches: int = 100
    max_string_matches: int = 100
    max_rule_bytes: int = 256 * 1024
    max_pack_bytes: int = 1024 * 1024


def _section(body: str, name: str, following: tuple[str, ...]) -> str:
    match = re.search(rf"\b{name}\s*:\s*", body, re.I)
    if not match:
        return ""
    end = len(body)
    for other in following:
        found = re.search(rf"\b{other}\s*:\s*", body[match.end():], re.I)
        if found:
            end = min(end, match.end() + found.start())
    return body[match.end():end]


def compile_rules(source: str, limits: YaraLimits) -> list[dict]:
    raw = source.encode("utf-8")
    if len(raw) > limits.max_pack_bytes:
        raise RuleError("rule pack exceeds maximum size")
    found_rules = list(RULE.finditer(source))
    residue = source
    for start, end in reversed([match.span() for match in found_rules]):
        residue = residue[:start] + residue[end:]
    if not found_rules or residue.strip():
        raise RuleError("malformed or unsupported YARA source")
    rules = []
    for match in found_rules:
        identifier, tag_text, body = match.groups()
        if len(match.group(0).encode()) > limits.max_rule_bytes:
            raise RuleError("rule exceeds maximum size")
        strings_text = _section(body, "strings", ("condition",))
        condition = _section(body, "condition", ()).strip().lower()
        if condition not in {"any of them", "all of them"}:
            raise RuleError("only 'any of them' and 'all of them' conditions are supported")
        strings = []
        for item in STRING.finditer(strings_text):
            string_id, escaped, modifiers = item.groups()
            try:
                value = bytes(escaped, "utf-8").decode("unicode_escape").encode("latin-1")
            except (UnicodeError, ValueError):
                raise RuleError("invalid literal string") from None
            if not value or len(value) > 4096:
                raise RuleError("literal string length is invalid")
            words = set(modifiers.split())
            if words - {"ascii", "wide", "nocase"}:
                raise RuleError("unsupported string modifier")
            strings.append({"id": "$" + string_id, "value": value, "wide": "wide" in words, "nocase": "nocase" in words})
        if not strings:
            raise RuleError("rule requires a literal string")
        meta = {}
        for item in META.finditer(_section(body, "meta", ("strings", "condition"))):
            key, value = item.groups()
            if value.startswith('"'):
                value = bytes(value[1:-1], "utf-8").decode("unicode_escape")[:1024]
            elif value.lower() in ("true", "false"):
                value = value.lower() == "true"
            else:
                value = int(value)
            meta[key] = value
            if len(meta) >= 32:
                break
        rules.append({"identifier": identifier, "tags": (tag_text or "").split()[:32], "metadata": meta, "strings": strings, "condition": condition})
    return rules


def match_rules(data: bytes, rules: list[dict], limits: YaraLimits) -> tuple[str, list[dict], bool]:
    deadline = time.monotonic() + max(0.0, limits.timeout_seconds)
    lowercase_data = data.lower()
    matches = []
    for rule in rules:
        if time.monotonic() >= deadline:
            return "timeout", matches, True
        evidence, states = [], []
        for spec in rule["strings"]:
            needles = [spec["value"]]
            if spec["wide"]:
                needles.append(b"".join(bytes((byte, 0)) for byte in spec["value"]))
            offsets = []
            for needle in needles:
                haystack = lowercase_data if spec["nocase"] else data
                needle = needle.lower() if spec["nocase"] else needle
                start = 0
                while len(evidence) < limits.max_string_matches:
                    if time.monotonic() >= deadline:
                        return "timeout", matches, True
                    found = haystack.find(needle, start)
                    if found < 0:
                        if time.monotonic() >= deadline: return "timeout", matches, True
                        break
                    offsets.append(found); evidence.append({"identifier": spec["id"], "offset": found})
                    start = found + max(1, len(needle))
            states.append(bool(offsets))
        matched = any(states) if rule["condition"] == "any of them" else all(states)
        if matched:
            matches.append({"rule_identifier": rule["identifier"], "tags": rule["tags"], "metadata": rule["metadata"], "string_matches": evidence[:limits.max_string_matches]})
            if len(matches) >= limits.max_matches:
                return "success", matches, True
    return "success", matches, False
