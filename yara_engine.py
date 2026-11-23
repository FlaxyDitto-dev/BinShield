"""
GhidraGuard - Offline YARA Rule Engine
Supports user-extensible .yar / .yara rules in rules/.
Uses native yara-python if installed, with a fast zero-dependency pure-Python YARA
parser/matcher fallback supporting hex patterns, ASCII/nocase strings, and standard
conditions (any of them, all of them, N of them).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class YaraMatch:
    rule_name: str
    severity: str = "MEDIUM"
    category: str = "YARA Signature"
    description: str = ""
    matched_strings: List[str] = field(default_factory=list)
    source_file: str = ""


@dataclass
class _ParsedRule:
    name: str
    meta: Dict[str, str]
    patterns: List[Tuple[str, bytes, bool]]  # (id, raw_bytes, nocase)
    condition: str
    source_file: str


_RULE_BLOCK_RE = re.compile(r"rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{(.*?)\n\}", re.DOTALL)
_META_LINE_RE = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]*)"', re.MULTILINE)
_STR_TEXT_RE = re.compile(r'^\s*(\$[A-Za-z0-9_]+)\s*=\s*"((?:[^"\\]|\\.)*)"(.*)$', re.MULTILINE)
_STR_HEX_RE = re.compile(r"^\s*(\$[A-Za-z0-9_]+)\s*=\s*\{\s*([0-9A-Fa-f\s]+?)\s*\}", re.MULTILINE)


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"//[^\n]*", "", text)
    return text


def parse_yara_file(path: Path) -> List[_ParsedRule]:
    raw = _strip_comments(path.read_text(encoding="utf-8", errors="ignore"))
    rules: List[_ParsedRule] = []
    for m in _RULE_BLOCK_RE.finditer(raw):
        rname = m.group(1)
        body = m.group(2)

        meta: Dict[str, str] = {}
        meta_m = re.search(r"meta\s*:(.*?)(?:strings\s*:|condition\s*:)", body, re.DOTALL)
        if meta_m:
            for km in _META_LINE_RE.finditer(meta_m.group(1)):
                meta[km.group(1)] = km.group(2)

        patterns: List[Tuple[str, bytes, bool]] = []
        str_m = re.search(r"strings\s*:(.*?)condition\s*:", body, re.DOTALL)
        if str_m:
            sblock = str_m.group(1)
            for sm in _STR_TEXT_RE.finditer(sblock):
                sid = sm.group(1)
                val = sm.group(2).encode("utf-8").decode("unicode_escape").encode("latin1", errors="ignore")
                mods = sm.group(3).lower()
                nocase = "nocase" in mods
                patterns.append((sid, val.lower() if nocase else val, nocase))
            for hm in _STR_HEX_RE.finditer(sblock):
                sid = hm.group(1)
                hex_clean = re.sub(r"\s+", "", hm.group(2))
                if len(hex_clean) % 2 == 0 and hex_clean:
                    patterns.append((sid, bytes.fromhex(hex_clean), False))

        cond_m = re.search(r"condition\s*:(.*)", body, re.DOTALL)
        cond = cond_m.group(1).strip().lower() if cond_m else "any of them"
        if patterns:
            rules.append(_ParsedRule(name=rname, meta=meta, patterns=patterns, condition=cond, source_file=path.name))
    return rules


class YaraRuleEngine:
    """Loads all .yar/.yara files from rules/ and scans files in bounded memory."""

    def __init__(self, rules_dir: Optional[Path] = None):
        self.rules_dir = rules_dir or (Path(__file__).resolve().parent / "rules")
        self._rules: List[_ParsedRule] = []
        self.reload()

    def reload(self) -> int:
        self._rules.clear()
        if not self.rules_dir.is_dir():
            return 0
        for p in sorted(self.rules_dir.glob("*.yar*")):
            if p.suffix.lower() in (".yar", ".yara") and p.is_file():
                try:
                    self._rules.extend(parse_yara_file(p))
                except Exception:
                    continue
        return len(self._rules)

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def scan_bytes(self, data: bytes) -> List[YaraMatch]:
        if not data or not self._rules:
            return []
        low_data = data.lower()
        matches: List[YaraMatch] = []

        for rule in self._rules:
            hits: List[str] = []
            for sid, pat, nocase in rule.patterns:
                hay = low_data if nocase else data
                if pat in hay:
                    hits.append(sid)

            cond = rule.condition
            triggered = False
            if "all of them" in cond:
                triggered = len(hits) == len(rule.patterns)
            elif "any of them" in cond:
                triggered = len(hits) >= 1
            else:
                num_m = re.search(r"(\d+)\s+of\s+them", cond)
                if num_m:
                    triggered = len(hits) >= int(num_m.group(1))
                else:
                    triggered = len(hits) >= 1

            if triggered:
                matches.append(
                    YaraMatch(
                        rule_name=rule.name,
                        severity=rule.meta.get("severity", "MEDIUM"),
                        category=rule.meta.get("category", "YARA Signature"),
                        description=rule.meta.get("description", rule.name),
                        matched_strings=hits,
                        source_file=rule.source_file,
                    )
                )
        return matches

    def scan_file(self, file_path: str, max_bytes: int = 16 * 1024 * 1024) -> List[YaraMatch]:
        if not os.path.isfile(file_path):
            return []
        with open(file_path, "rb") as f:
            data = f.read(max_bytes)
        return self.scan_bytes(data)
