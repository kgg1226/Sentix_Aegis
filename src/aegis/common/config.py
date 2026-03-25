"""Runtime configuration for AEGIS.

All thresholds, model IDs, and tunable parameters live here.
NO magic numbers in business logic — everything references this config.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Environment(Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


@dataclass(frozen=True, slots=True)
class DetectionConfig:
    """Thresholds for the detection pipeline."""

    # L1: pattern matching
    l1_bloom_filter_fp_rate: float = 0.001

    # L2: statistical anomaly
    l2_zscore_threshold: float = 3.0
    l2_baseline_window_hours: int = 24

    # L3: behavioral analysis (LLM)
    l3_trigger_threshold: float = 0.15      # Min L1+L2 signal to activate L3
    l3_context_window_events: int = 100     # Events per source IP
    l3_model_id: str = "claude-haiku-4-5-20251001"

    # L4: contextual correlation
    l4_trigger_threshold: float = 0.30      # Min L3 signal to activate L4
    l4_correlation_window_sec: int = 300    # 5-minute cross-cloud window
    l4_model_id: str = "claude-sonnet-4-6"

    # L5: LLM injection immune layer
    l5_canary_count: int = 3                # Canary tokens per system prompt
    l5_semantic_threshold: float = 0.70     # Intent classifier confidence


@dataclass(frozen=True, slots=True)
class ResponsePolicy:
    """Confidence → action mapping thresholds.

    These are the DEFAULTS. Homeostasis adjusts them based on threat context.
    """

    auto_block_min: float = 0.90
    isolate_min: float = 0.70
    enhanced_monitor_min: float = 0.50
    # Below enhanced_monitor_min → standard logging only


@dataclass(frozen=True, slots=True)
class GenomeConfig:
    """Genome engine parameters."""

    # Fitness function weights (default — overridden by context)
    w_coverage: float = 0.30
    w_efficiency: float = 0.15
    w_adaptability: float = 0.20
    w_synergy: float = 0.15
    w_threat_match: float = 0.20

    # Homeostasis
    damping_base: float = 0.25
    damping_nonlinear_alpha: float = 1.5

    # Mutation
    burst_mutation_bits: int = 5
    crossover_segment_count: int = 1


@dataclass(frozen=True, slots=True)
class AegisConfig:
    """Top-level AEGIS configuration."""

    env: Environment = Environment.DEVELOPMENT
    aws_region: str = "ap-northeast-2"
    eventbridge_bus: str = "aegis-events"
    pgvector_url: str = ""

    detection: DetectionConfig = field(default_factory=DetectionConfig)
    response: ResponsePolicy = field(default_factory=ResponsePolicy)
    genome: GenomeConfig = field(default_factory=GenomeConfig)
