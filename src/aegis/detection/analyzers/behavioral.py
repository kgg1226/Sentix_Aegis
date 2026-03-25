"""L3 — Behavioral analysis via LLM.

Classifies event sequences into intent categories.
Detects multi-step attack chains where individual events look normal.
"""

from __future__ import annotations

from collections import deque
from typing import Protocol

from aegis.common.config import DetectionConfig
from aegis.common.types import DetectionSignal


class LLMClient(Protocol):
    async def classify(self, prompt: str) -> dict[str, float]: ...


class BehavioralAnalyzer:
    layer_id: str = "L3"

    def __init__(self, llm: LLMClient | None = None, config: DetectionConfig | None = None) -> None:
        self._llm = llm
        self._config = config or DetectionConfig()
        self._history: dict[str, deque[dict]] = {}

    async def analyze(self, event: dict, context: dict) -> DetectionSignal:
        source = event.get("source_ip", "unknown")
        if source not in self._history:
            self._history[source] = deque(maxlen=self._config.l3_context_window_events)
        self._history[source].append(event)

        if self._llm is None:
            return self._heuristic(event, source)

        prompt = self._build_prompt(source)
        scores = await self._llm.classify(prompt)
        confidence = scores.get("malicious", 0.0)
        return DetectionSignal(
            layer=self.layer_id, confidence=confidence, hit=confidence > 0.5,
            detail=f"Intent: {scores}" if confidence > 0.5 else "Normal behavior",
            latency_ms=0.0,
        )

    def _heuristic(self, event: dict, source: str) -> DetectionSignal:
        history = self._history.get(source, deque())
        if len(history) < 5:
            return DetectionSignal(
                layer=self.layer_id, confidence=0.0, hit=False,
                detail="Insufficient history", latency_ms=0.0,
            )
        actions = [e.get("action", "") for e in history]
        unique_ratio = len(set(actions)) / len(actions) if actions else 0
        levels = {"read": 1, "list": 1, "write": 2, "modify": 2, "delete": 3, "admin": 4}
        max_lv, esc = 0, 0
        for a in actions:
            lv = levels.get(a.split(":")[-1].lower(), 0)
            if lv > max_lv:
                esc += 1
                max_lv = lv
        esc_score = 0.8 if esc >= 3 else (0.5 if esc >= 2 else 0.0)
        confidence = max(min(1.0, unique_ratio * 1.5), esc_score) * 0.7
        return DetectionSignal(
            layer=self.layer_id, confidence=confidence, hit=confidence > 0.4,
            detail=f"Heuristic: recon={unique_ratio:.2f} esc={esc_score:.2f}",
            latency_ms=0.0,
        )

    def _build_prompt(self, source: str) -> str:
        history = self._history.get(source, deque())
        lines = "\n".join(
            f"  [{e.get('timestamp','?')}] {e.get('action','?')} → {e.get('resource','?')}"
            for e in list(history)[-20:]
        )
        return (
            "Classify this event sequence as normal or potential attack.\n"
            f"Source: {source}\nRecent events:\n{lines}\n\n"
            'Respond with JSON: {"malicious": float, "category": str, "reasoning": str}'
        )
