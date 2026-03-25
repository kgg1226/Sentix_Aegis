"""Core data models for AEGIS.

All domain types are defined here as frozen dataclasses or Pydantic models.
Genome is immutable — mutations return new instances.
Confidence is always float [0.0, 1.0] internally.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Sequence


# ---------------------------------------------------------------------------
# Genome
# ---------------------------------------------------------------------------

GENOME_BITS = 144

# Segment layout: name, offset, length
SEGMENTS: list[tuple[str, int, int]] = [
    ("HDR", 0, 8),      # Header: form ID, version, parity
    ("RTG", 8, 32),      # Routing topology
    ("ISO", 40, 16),     # Micro-segmentation policy
    ("ATH", 56, 16),     # Authentication levels per zone
    ("DTX", 72, 32),     # Sensor placement & sensitivity
    ("DCP", 104, 16),    # Deception / honeypot config
    ("RSP", 120, 16),    # Auto-response actions
    ("CHK", 136, 8),     # CRC-8 checksum
]


class DefenseForm(Enum):
    """Four metamorphic defense forms."""

    ALPHA = 0   # Layered defense — low overhead, peacetime default
    BETA = 1    # Distributed mesh — no single point of failure
    GAMMA = 2   # Deception grid — honeypot-first, intel gathering
    DELTA = 3   # Zero-trust fortress — max isolation, wartime


@dataclass(frozen=True, slots=True)
class Genome:
    """Immutable 144-bit defense genome.

    Mutations, crossover, and any modification return a NEW Genome instance.
    Direct bit manipulation is only allowed via operators in genome.operators.
    """

    bits: tuple[int, ...]  # Length must equal GENOME_BITS

    def __post_init__(self) -> None:
        if len(self.bits) != GENOME_BITS:
            msg = f"Genome must be exactly {GENOME_BITS} bits, got {len(self.bits)}"
            raise ValueError(msg)
        if any(b not in (0, 1) for b in self.bits):
            msg = "Genome bits must be 0 or 1"
            raise ValueError(msg)

    def segment(self, name: str) -> tuple[int, ...]:
        """Extract a named segment's bits."""
        for seg_name, offset, length in SEGMENTS:
            if seg_name == name:
                return self.bits[offset : offset + length]
        msg = f"Unknown segment: {name}"
        raise KeyError(msg)

    def density(self, name: str) -> float:
        """Fraction of 1-bits in a segment, range [0.0, 1.0]."""
        seg = self.segment(name)
        return sum(seg) / len(seg) if seg else 0.0

    @property
    def form_id(self) -> DefenseForm:
        """Decode form ID from HDR segment (bits 0-1)."""
        hdr = self.segment("HDR")
        value = (hdr[0] << 1) | hdr[1]
        return DefenseForm(value)

    @property
    def version(self) -> int:
        """Decode version from HDR segment (bits 2-5)."""
        hdr = self.segment("HDR")
        return (hdr[2] << 3) | (hdr[3] << 2) | (hdr[4] << 1) | hdr[5]


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

class ThreatCategory(Enum):
    """Top-level attack classification."""

    COMMODITY = auto()     # Known signatures, script-kiddie level
    VOLUME = auto()        # DDoS, credential stuffing, brute force
    APT = auto()           # Advanced persistent threat, low-and-slow
    ZERO_DAY = auto()      # Exploiting unknown vulnerabilities
    META_ATTACK = auto()   # Attacking AEGIS itself (LLM injection)
    INSIDER = auto()       # Authorized user acting maliciously


@dataclass(frozen=True, slots=True)
class DetectionSignal:
    """Output of a single detection layer."""

    layer: str                 # L0-L5 identifier
    confidence: float          # [0.0, 1.0] — NEVER percentage
    hit: bool                  # Did this layer flag the event?
    detail: str                # Human-readable explanation
    latency_ms: float          # Processing time


@dataclass(frozen=True, slots=True)
class ThreatAssessment:
    """Aggregated assessment from all detection layers."""

    signals: tuple[DetectionSignal, ...]
    final_confidence: float          # [0.0, 1.0]
    category: ThreatCategory
    classification: str              # Human-readable label
    recommended_action: str          # monitor | rate_limit | isolate | block
    correlation_id: str              # Unique event trace ID


# ---------------------------------------------------------------------------
# Threat context (input to fitness function + homeostasis)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class ThreatContext:
    """Current threat landscape parameters.

    These drive genome evolution direction and homeostasis target.
    Values are [0.0, 1.0]. Pressure + diversity + novelty need NOT sum to 1.0
    but fitness function normalizes them internally.
    """

    pressure: float     # Overall attack volume / intensity
    diversity: float    # How many different attack vectors active
    novelty: float      # Proportion of unknown/zero-day patterns


# ---------------------------------------------------------------------------
# Fitness
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class FitnessResult:
    """Output of the multi-objective fitness evaluation."""

    scores: dict[str, float]   # Per-objective scores {name: [0.0, 1.0]}
    raw: float                 # Weighted sum before penalty
    penalty: float             # Structural deficiency penalty
    final: float               # max(0, raw - penalty)
    confidence_interval: float # ± range based on test rounds (0 if untested)
