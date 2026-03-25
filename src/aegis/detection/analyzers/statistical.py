"""L2 — Statistical anomaly detection.

Rolling-window statistics: request rate, error rate, payload size.
Z-score against baseline. Catches volume-based attacks.
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field
from time import monotonic

from aegis.common.config import DetectionConfig
from aegis.common.types import DetectionSignal


@dataclass
class _Baseline:
    """Rolling window statistics for a single metric."""

    values: deque[float] = field(default_factory=lambda: deque(maxlen=10000))
    _sum: float = 0.0
    _sum_sq: float = 0.0

    def add(self, value: float) -> None:
        if len(self.values) == self.values.maxlen:
            old = self.values[0]
            self._sum -= old
            self._sum_sq -= old * old
        self.values.append(value)
        self._sum += value
        self._sum_sq += value * value

    @property
    def mean(self) -> float:
        n = len(self.values)
        return self._sum / n if n > 0 else 0.0

    @property
    def std(self) -> float:
        n = len(self.values)
        if n < 2:
            return 0.0
        variance = (self._sum_sq / n) - (self.mean ** 2)
        return math.sqrt(max(0.0, variance))

    def zscore(self, value: float) -> float:
        s = self.std
        if s < 1e-10:
            return 0.0
        return abs(value - self.mean) / s


class StatisticalAnalyzer:
    """L2 statistical anomaly detector."""

    layer_id: str = "L2"

    def __init__(self, config: DetectionConfig | None = None) -> None:
        self._config = config or DetectionConfig()
        self._baselines: dict[str, _Baseline] = {
            "request_rate": _Baseline(),
            "error_rate": _Baseline(),
            "payload_size": _Baseline(),
        }

    async def analyze(self, event: dict, context: dict) -> DetectionSignal:
        """Compute Z-scores for event metrics against rolling baselines."""
        max_z = 0.0
        anomalies: list[str] = []

        for metric_name, baseline in self._baselines.items():
            value = event.get(metric_name, 0.0)
            if not isinstance(value, (int, float)):
                continue

            z = baseline.zscore(float(value))
            baseline.add(float(value))

            if z > self._config.l2_zscore_threshold:
                anomalies.append(f"{metric_name} z={z:.1f}")
                max_z = max(max_z, z)

        if anomalies:
            # Convert z-score to confidence: z=3 → 0.5, z=6 → 0.8, z=10+ → 0.95
            confidence = min(0.95, 0.3 + 0.1 * max_z)
            return DetectionSignal(
                layer=self.layer_id,
                confidence=confidence,
                hit=True,
                detail=f"Anomaly: {', '.join(anomalies)}",
                latency_ms=0.0,
            )

        return DetectionSignal(
            layer=self.layer_id,
            confidence=0.0,
            hit=False,
            detail="Within baseline bounds",
            latency_ms=0.0,
        )
