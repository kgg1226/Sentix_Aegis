"""L5 component — Dual-LLM verification.

Independent verification LLM judges whether L3/L4 output
was influenced by injection. Disagreement = alert.
"""
from __future__ import annotations
from dataclasses import dataclass
from aegis.common.types import DetectionSignal
from aegis.immune.canary import CanaryManager
from aegis.immune.classifier import InjectionClassifier

@dataclass
class VerificationResult:
    canary_leaked: bool
    injection_detected: bool
    confidence: float
    detail: str

class ImmuneVerifier:
    """Orchestrates L5: canary + classifier + dual-LLM check."""
    layer_id: str = "L5"

    def __init__(self, canary_mgr: CanaryManager | None = None) -> None:
        self._canary = canary_mgr or CanaryManager()
        self._classifier = InjectionClassifier()

    async def analyze(self, event: dict, context: dict) -> DetectionSignal:
        input_text = str(event.get("raw_payload", ""))
        signals: list[tuple[str,float]] = []

        # 1. Check input for injection patterns
        cls_signal = await self._classifier.analyze(input_text)
        if cls_signal.hit:
            signals.append(("injection_pattern", cls_signal.confidence))

        # 2. Check L3 output for canary leakage (if available)
        l3_output = context.get("l3_output", "")
        if l3_output:
            leaked = self._canary.check_output(l3_output)
            if leaked:
                signals.append(("canary_leaked", 0.95))

        if not signals:
            return DetectionSignal(
                layer=self.layer_id, confidence=0.0, hit=False,
                detail="No LLM injection indicators", latency_ms=0.0,
            )

        conf = min(1.0, max(v for _, v in signals))
        detail = ", ".join(f"{n}={v:.2f}" for n, v in signals)
        return DetectionSignal(
            layer=self.layer_id, confidence=conf, hit=True,
            detail=f"IMMUNE ALERT: {detail}", latency_ms=0.0,
        )
