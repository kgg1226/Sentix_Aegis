"""L4 — Cross-cloud contextual correlation.

Connects dots across AWS/Azure/Oracle: impossible travel, credential reuse,
coordinated multi-cloud attacks. Highest accuracy, highest cost.
"""
from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass
from time import time as now
from aegis.common.config import DetectionConfig
from aegis.common.types import DetectionSignal

@dataclass
class _IdentityEvent:
    identity: str
    cloud: str
    region: str
    timestamp: float
    action: str

class CorrelationAnalyzer:
    layer_id: str = "L4"
    def __init__(self, config: DetectionConfig | None = None) -> None:
        self._config = config or DetectionConfig()
        self._log: dict[str, list[_IdentityEvent]] = defaultdict(list)

    async def analyze(self, event: dict, context: dict) -> DetectionSignal:
        identity = event.get("identity", "")
        if not identity:
            return DetectionSignal(layer=self.layer_id, confidence=0.0, hit=False,
                                   detail="No identity to correlate", latency_ms=0.0)
        ie = _IdentityEvent(identity=identity, cloud=event.get("cloud","unknown"),
                            region=event.get("region","unknown"),
                            timestamp=event.get("timestamp", now()),
                            action=event.get("action",""))
        self._log[identity].append(ie)
        signals: list[tuple[str,float]] = []
        travel = self._impossible_travel(identity)
        if travel > 0: signals.append(("impossible_travel", travel))
        cross = self._cross_cloud(identity)
        if cross > 0: signals.append(("cross_cloud", cross))
        if not signals:
            return DetectionSignal(layer=self.layer_id, confidence=0.0, hit=False,
                                   detail="No cross-cloud anomalies", latency_ms=0.0)
        conf = min(1.0, max(v for _, v in signals))
        return DetectionSignal(layer=self.layer_id, confidence=conf, hit=conf>0.5,
                               detail=str(signals), latency_ms=0.0)

    def _impossible_travel(self, identity: str) -> float:
        evts = self._log[identity]
        if len(evts) < 2: return 0.0
        a, b = evts[-2], evts[-1]
        dt = abs(b.timestamp - a.timestamp)
        if a.region != b.region and dt < 60: return min(1.0, 0.7 + (60-dt)/60*0.3)
        if a.cloud != b.cloud and dt < 120: return min(1.0, 0.6 + (120-dt)/120*0.3)
        return 0.0

    def _cross_cloud(self, identity: str) -> float:
        evts = self._log[identity]
        window = self._config.l4_correlation_window_sec
        cutoff = (evts[-1].timestamp if evts else now()) - window
        recent = [e for e in evts if e.timestamp >= cutoff]
        clouds = {e.cloud for e in recent}
        if len(clouds) >= 3: return 0.85
        if len(clouds) >= 2: return 0.55
        return 0.0
