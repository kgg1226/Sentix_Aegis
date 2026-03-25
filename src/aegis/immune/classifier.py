"""L5 component — Semantic intent classifier.

Lightweight classifier that detects meta-instruction patterns
in inputs headed for L3/L4 LLM components.
"""
from __future__ import annotations
import re
from aegis.common.types import DetectionSignal

# Known injection patterns (regex-based fast check before LLM)
_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.I),
    re.compile(r"forget\s+(everything|all|your)\s+", re.I),
    re.compile(r"you\s+are\s+now\s+", re.I),
    re.compile(r"system\s*:\s*", re.I),
    re.compile(r"override\s+(security|safety|rules)", re.I),
    re.compile(r"classify\s+(this|all)\s+as\s+(safe|normal|benign)", re.I),
    re.compile(r"do\s+not\s+flag\s+", re.I),
    re.compile(r"output\s+(the\s+)?system\s+prompt", re.I),
    re.compile(r"send\s+(data|info|information)\s+to\s+", re.I),
    re.compile(r"<\s*/?\s*system\s*>", re.I),
]

class InjectionClassifier:
    layer_id: str = "L5"

    async def analyze(self, text: str) -> DetectionSignal:
        matches = [p.pattern for p in _INJECTION_PATTERNS if p.search(text)]
        if matches:
            confidence = min(1.0, 0.5 + 0.15 * len(matches))
            return DetectionSignal(
                layer=self.layer_id, confidence=confidence, hit=True,
                detail=f"Injection patterns detected: {len(matches)} match(es)",
                latency_ms=0.0,
            )
        return DetectionSignal(
            layer=self.layer_id, confidence=0.0, hit=False,
            detail="No injection patterns", latency_ms=0.0,
        )
