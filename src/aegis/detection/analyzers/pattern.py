"""L1 — Pattern matching analyzer (fast path).

Sub-millisecond hash/signature lookup against known threat database.
Uses in-memory hash set for IOC matching. No ML, no learning.
"""

from __future__ import annotations

from aegis.common.types import DetectionSignal


class PatternAnalyzer:
    """L1 signature-based detection."""

    layer_id: str = "L1"

    def __init__(self, signatures: set[str] | None = None) -> None:
        self._signatures = signatures or set()

    def load_signatures(self, sigs: set[str]) -> None:
        """Hot-reload signature database."""
        self._signatures = sigs

    async def analyze(self, event: dict, context: dict) -> DetectionSignal:
        """Check event against known signatures."""
        # Extract matchable indicators from event
        indicators = self._extract_indicators(event)

        matches = indicators & self._signatures
        if matches:
            confidence = min(1.0, 0.7 + 0.1 * len(matches))
            return DetectionSignal(
                layer=self.layer_id,
                confidence=confidence,
                hit=True,
                detail=f"Matched {len(matches)} known signature(s)",
                latency_ms=0.0,
            )

        return DetectionSignal(
            layer=self.layer_id,
            confidence=0.0,
            hit=False,
            detail="No known signatures matched",
            latency_ms=0.0,
        )

    def _extract_indicators(self, event: dict) -> set[str]:
        """Extract hashable indicators from an event."""
        indicators: set[str] = set()
        for key in ("sha256", "md5", "ip", "domain", "url", "user_agent"):
            val = event.get(key)
            if val:
                indicators.add(str(val))
        return indicators
