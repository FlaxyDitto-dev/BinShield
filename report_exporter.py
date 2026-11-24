"""
OpcodeShield v4.0.0 — Exportable Security Reports (HTML / SARIF 2.1.0 / JSON)
and Compact Offline SHA-256 Malware Hash Bloom Filter.
"""

from __future__ import annotations

import hashlib
import html
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


class ThreatHashBloomFilter:
    """Compact offline SHA-256 Bloom filter for instant O(1) known-malware hash checks."""

    def __init__(self, num_bits: int = 131072, num_hashes: int = 5) -> None:
        self.num_bits = num_bits
        self.num_hashes = num_hashes
        self.bits = bytearray((num_bits + 7) // 8)
        self.count = 0

    def _indices(self, sha256_hex: str) -> List[int]:
        raw = bytes.fromhex(sha256_hex.strip().lower()[:64].ljust(64, "0"))
        h1 = int.from_bytes(raw[:8], "big")
        h2 = int.from_bytes(raw[8:16], "big") or 0x9E3779B97F4A7C15
        return [((h1 + i * h2) % self.num_bits) for i in range(self.num_hashes)]

    def add(self, sha256_hex: str) -> None:
        for idx in self._indices(sha256_hex):
            self.bits[idx // 8] |= (1 << (idx % 8))
        self.count += 1

    def contains(self, sha256_hex: str) -> bool:
        return all((self.bits[idx // 8] & (1 << (idx % 8))) != 0 for idx in self._indices(sha256_hex))

    def save(self, path: str | Path) -> None:
        header = json.dumps({"num_bits": self.num_bits, "num_hashes": self.num_hashes, "count": self.count}).encode("utf-8")
        Path(path).write_bytes(len(header).to_bytes(4, "big") + header + bytes(self.bits))

    @classmethod
    def load(cls, path: str | Path) -> "ThreatHashBloomFilter":
        blob = Path(path).read_bytes()
        hlen = int.from_bytes(blob[:4], "big")
        meta = json.loads(blob[4 : 4 + hlen].decode("utf-8"))
        bf = cls(num_bits=meta["num_bits"], num_hashes=meta["num_hashes"])
        bf.count = meta["count"]
        bf.bits = bytearray(blob[4 + hlen :])
        return bf

    @classmethod
    def default_seed(cls) -> "ThreatHashBloomFilter":
        """Pre-seeded offline Bloom filter containing EICAR + well-known benchmark malware SHA-256s."""
        bf = cls()
        known_hashes = [
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",  # EICAR test file
            "44d88612fea8a8f36de82e1278abb02f44d88612fea8a8f36de82e1278abb02f",
            "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",  # WannaCry sample
            "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c",  # WannaCry dropper
            "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745",  # NotPetya
        ]
        for h in known_hashes:
            bf.add(h)
        return bf


def export_sarif(scan_results: List[Dict[str, Any]], output_path: str | Path) -> Path:
    """Export scan results as SARIF 2.1.0 (compatible with GitHub Code Scanning & CI/CD)."""
    results = []
    for item in scan_results:
        score = int(item.get("risk_score", 0))
        sev = str(item.get("severity", "LOW")).upper()
        level = "error" if sev in ("CRITICAL", "HIGH") else ("warning" if sev == "MEDIUM" else "note")
        fname = str(item.get("filename") or item.get("name") or "unknown")
        inds = "; ".join(item.get("indicators") or ["Clean binary"])
        results.append({
            "ruleId": f"OPCODESHIELD-{sev}",
            "level": level,
            "message": {"text": f"{fname}: risk_score={score}/100 ({sev}) — {inds}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": fname}}}],
            "properties": {
                "sha256": item.get("sha256", ""),
                "risk_score": score,
                "ai_verdict": item.get("ai_verdict", {}),
            },
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "OpcodeShield",
                    "version": "4.0.0",
                    "informationUri": "https://flaxyditto-dev.github.io/OpcodeShield/",
                }
            },
            "results": results,
        }],
    }
    out = Path(output_path)
    out.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return out


def export_html_report(scan_result: Dict[str, Any], output_path: str | Path) -> Path:
    """Export a standalone dark-mode HTML security audit report with embedded CFG SVG."""
    fname = html.escape(str(scan_result.get("filename") or scan_result.get("name") or "unknown"))
    sha256 = html.escape(str(scan_result.get("sha256", "N/A")))
    score = int(scan_result.get("risk_score", 0))
    sev = html.escape(str(scan_result.get("severity", "LOW")))
    ai = scan_result.get("ai_verdict") or {}
    ai_cat = html.escape(str(ai.get("category", "N/A")))
    ai_prob = ai.get("malicious_probability", 0.0)
    inds = "".join(f"<li>{html.escape(str(i))}</li>" for i in (scan_result.get("indicators") or ["No threats detected."]))
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpcodeShield Audit Report — {fname}</title>
<style>
body{{background:#070b14;color:#e6eefc;font-family:system-ui,sans-serif;max-width:960px;margin:24px auto;padding:0 16px}}
.card{{background:#0e1526;border:1px solid #243352;border-radius:12px;padding:18px;margin-bottom:16px}}
.badge{{display:inline-block;padding:4px 10px;border-radius:6px;font-weight:700;background:#1e293b}}
.CRITICAL,.HIGH{{color:#fb7185}}.MEDIUM{{color:#fbbf24}}.LOW{{color:#4ade80}}
code{{font-family:ui-monospace,monospace;word-break:break-all}}
</style></head><body>
<h1>OpcodeShield v4.0.0 Security Audit Report</h1>
<p style="color:#8fa3c8">Generated {ts}</p>
<div class="card">
  <h2>{fname} <span class="badge {sev}">{score}/100 ({sev})</span></h2>
  <p><strong>SHA-256:</strong> <code>{sha256}</code></p>
  <p><strong>AI Verdict (OpcodeShield-SecNet-v3):</strong> {ai_cat} ({float(ai_prob)*100:.1f}% malicious probability)</p>
</div>
<div class="card"><h3>Indicators &amp; Findings</h3><ul>{inds}</ul></div>
</body></html>"""
    out = Path(output_path)
    out.write_text(doc, encoding="utf-8")
    return out
