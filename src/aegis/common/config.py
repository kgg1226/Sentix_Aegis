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
    l1_bloom_filter_fp_rate: float = 0.000328  # Battle-tuned: L1 targeted 31% of attacks

    # L2: statistical anomaly
    l2_zscore_threshold: float = 1.56  # Battle-tuned: L2 targeted 59% of attacks
    l2_baseline_window_hours: int = 24

    # L3: behavioral analysis (LLM)
    l3_trigger_threshold: float = 0.05      # Min L1+L2 signal to activate L3 (battle-tuned: was 0.15)
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

    # Fitness function weights (rebalanced: adaptability + threat_match restored)
    # Coverage/efficiency = core defense, synergy = pair bonus,
    # adaptability = segment diversity (prevents dump-all-into-one),
    # threat_match = context alignment (right defense for right threat)
    w_coverage: float = 0.28
    w_efficiency: float = 0.25
    w_adaptability: float = 0.12
    w_synergy: float = 0.23
    w_threat_match: float = 0.12

    # Homeostasis (damping raised: battle-tuned for faster recovery)
    damping_base: float = 0.45
    damping_nonlinear_alpha: float = 2.0

    # Mutation
    burst_mutation_bits: int = 5
    crossover_segment_count: int = 1


@dataclass(frozen=True, slots=True)
class CollectorConfig:
    """Cloud collector parameters."""

    # AWS
    aws_enabled: bool = True
    aws_region: str = "ap-northeast-2"
    aws_cloudtrail_trails: tuple[str, ...] = ()     # Empty = default trail
    aws_guardduty_detector_ids: tuple[str, ...] = ()
    aws_securityhub_enabled: bool = True
    aws_poll_interval_sec: int = 60

    # Azure
    azure_enabled: bool = False
    azure_subscription_id: str = ""
    azure_workspace_id: str = ""                     # Log Analytics workspace
    azure_poll_interval_sec: int = 60

    # Oracle
    oracle_enabled: bool = False
    oracle_compartment_id: str = ""
    oracle_poll_interval_sec: int = 60

    # Common
    batch_size: int = 100
    max_event_age_hours: int = 1


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
    collectors: CollectorConfig = field(default_factory=CollectorConfig)
