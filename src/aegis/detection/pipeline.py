"""Detection pipeline orchestrator.

Routes events through L0-L5 with progressive escalation.
Each layer only activates if prior layers exceed its trigger threshold.
L5 (LLM immune) runs in parallel with L1-L4.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Protocol

from aegis.common.config import AegisConfig, CollectorConfig, DetectionConfig
from aegis.common.types import CloudEvent, DetectionSignal, ThreatAssessment, ThreatCategory

logger = logging.getLogger(__name__)


class Analyzer(Protocol):
    """Interface for detection layer analyzers."""

    layer_id: str

    async def analyze(self, event: dict, context: dict) -> DetectionSignal: ...


class DetectionPipeline:
    """Orchestrates the 6-layer detection pipeline.

    Flow:
        L0 (collect) → L1 (pattern) → L2 (statistical) → L3 (behavioral) → L4 (correlation)
        L5 (immune) runs in parallel, monitoring L3/L4 inputs and outputs.

    Progressive escalation: L3 only fires if max(L1, L2) > l3_trigger_threshold.
    L4 only fires if L3 > l4_trigger_threshold.
    """

    def __init__(
        self,
        analyzers: dict[str, Analyzer],
        config: DetectionConfig | None = None,
    ) -> None:
        self._analyzers = analyzers
        self._config = config or DetectionConfig()

    async def process(self, event: dict) -> ThreatAssessment:
        """Run an event through the full detection pipeline."""
        correlation_id = str(uuid.uuid4())
        context: dict = {"correlation_id": correlation_id, "event": event}
        signals: list[DetectionSignal] = []

        # L5 immune layer runs in parallel with everything else
        l5_task: asyncio.Task | None = None
        if "L5" in self._analyzers:
            l5_task = asyncio.create_task(
                self._analyzers["L5"].analyze(event, context)
            )

        # L1: pattern matching (always runs, fast path)
        l1_signal = await self._run_layer("L1", event, context)
        signals.append(l1_signal)

        # L2: statistical anomaly (always runs)
        l2_signal = await self._run_layer("L2", event, context)
        signals.append(l2_signal)

        # L3: behavioral analysis (conditional)
        max_early = max(l1_signal.confidence, l2_signal.confidence)
        if max_early >= self._config.l3_trigger_threshold and "L3" in self._analyzers:
            context["prior_signals"] = [l1_signal, l2_signal]
            l3_signal = await self._run_layer("L3", event, context)
            signals.append(l3_signal)

            # L4: cross-cloud correlation (conditional on L3)
            if l3_signal.confidence >= self._config.l4_trigger_threshold and "L4" in self._analyzers:
                context["prior_signals"].append(l3_signal)
                l4_signal = await self._run_layer("L4", event, context)
                signals.append(l4_signal)

        # Collect L5 result
        if l5_task is not None:
            l5_signal = await l5_task
            signals.append(l5_signal)

        return self._aggregate(signals, correlation_id)

    async def _run_layer(self, layer_id: str, event: dict, context: dict) -> DetectionSignal:
        """Run a single analyzer with timing."""
        analyzer = self._analyzers.get(layer_id)
        if analyzer is None:
            return DetectionSignal(
                layer=layer_id, confidence=0.0, hit=False,
                detail=f"{layer_id} not configured", latency_ms=0.0,
            )
        start = time.monotonic()
        signal = await analyzer.analyze(event, context)
        elapsed = (time.monotonic() - start) * 1000
        return DetectionSignal(
            layer=signal.layer,
            confidence=signal.confidence,
            hit=signal.hit,
            detail=signal.detail,
            latency_ms=round(elapsed, 2),
        )

    def _aggregate(self, signals: list[DetectionSignal], correlation_id: str) -> ThreatAssessment:
        """Combine signals into a single threat assessment."""
        if not signals:
            return ThreatAssessment(
                signals=(), final_confidence=0.0,
                category=ThreatCategory.COMMODITY,
                classification="No signals",
                recommended_action="monitor",
                correlation_id=correlation_id,
            )

        # Final confidence = max of all layer confidences
        # (conservative: any strong signal is enough to trigger)
        final_conf = max(s.confidence for s in signals)
        hit_signals = [s for s in signals if s.hit]

        # Check if L5 flagged LLM injection
        l5_hit = any(s.layer == "L5" and s.hit for s in signals)
        if l5_hit:
            category = ThreatCategory.META_ATTACK
            classification = "LLM injection detected"
        else:
            category = self._classify(signals)
            classification = self._label(category, final_conf)

        action = self._recommend_action(final_conf)

        return ThreatAssessment(
            signals=tuple(signals),
            final_confidence=final_conf,
            category=category,
            classification=classification,
            recommended_action=action,
            correlation_id=correlation_id,
        )

    def _classify(self, signals: list[DetectionSignal]) -> ThreatCategory:
        """Determine threat category from signal pattern."""
        l1 = next((s for s in signals if s.layer == "L1"), None)
        l2 = next((s for s in signals if s.layer == "L2"), None)

        if l1 and l1.confidence > 0.8:
            return ThreatCategory.COMMODITY
        if l2 and l2.confidence > 0.8:
            return ThreatCategory.VOLUME
        # If L3/L4 are the primary detectors → advanced threat
        l3 = next((s for s in signals if s.layer == "L3"), None)
        l4 = next((s for s in signals if s.layer == "L4"), None)
        if l4 and l4.confidence > 0.6:
            return ThreatCategory.APT
        if l3 and l3.confidence > 0.5:
            return ThreatCategory.ZERO_DAY
        return ThreatCategory.COMMODITY

    def _label(self, category: ThreatCategory, confidence: float) -> str:
        """Generate human-readable classification label."""
        conf_label = "high" if confidence > 0.8 else "medium" if confidence > 0.5 else "low"
        return f"{category.name.lower()} ({conf_label} confidence)"

    def _recommend_action(self, confidence: float) -> str:
        """Map confidence to recommended action per ResponsePolicy."""
        cfg = AegisConfig().response
        if confidence >= cfg.auto_block_min:
            return "block"
        if confidence >= cfg.isolate_min:
            return "isolate"
        if confidence >= cfg.enhanced_monitor_min:
            return "enhanced_monitor"
        return "monitor"


class CollectorOrchestrator:
    """Runs all enabled cloud collectors and feeds events into the pipeline.

    Usage:
        orchestrator = CollectorOrchestrator(pipeline, config)
        assessments = await orchestrator.collect_and_process()
    """

    def __init__(
        self,
        pipeline: DetectionPipeline,
        config: CollectorConfig | None = None,
    ) -> None:
        self._pipeline = pipeline
        self._config = config or CollectorConfig()
        self._collectors = self._build_collectors()

    def _build_collectors(self) -> list:
        from aegis.detection.collectors.aws import AwsCollector
        from aegis.detection.collectors.azure import AzureCollector
        from aegis.detection.collectors.oracle import OracleCollector

        collectors = []
        if self._config.aws_enabled:
            collectors.append(AwsCollector(self._config))
        if self._config.azure_enabled:
            collectors.append(AzureCollector(self._config))
        if self._config.oracle_enabled:
            collectors.append(OracleCollector(self._config))
        return collectors

    async def collect_and_process(self) -> list[ThreatAssessment]:
        """Run all collectors, then process each event through the pipeline."""
        # L0: collect from all clouds in parallel
        tasks = [c.collect() for c in self._collectors]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_events: list[CloudEvent] = []
        for result in results:
            if isinstance(result, Exception):
                logger.error("Collector failed: %s", result)
            else:
                all_events.extend(result)

        logger.info("Collected %d events from %d collectors", len(all_events), len(self._collectors))

        # L1-L5: process each event
        assessments: list[ThreatAssessment] = []
        for event in all_events:
            assessment = await self._pipeline.process(event.to_pipeline_dict())
            assessments.append(assessment)
        return assessments

    async def healthcheck(self) -> dict[str, bool]:
        """Check connectivity for all configured collectors."""
        results: dict[str, bool] = {}
        for collector in self._collectors:
            results[collector.provider] = await collector.healthcheck()
        return results
