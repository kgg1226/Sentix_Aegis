"""Adaptive homeostasis layer.

NOT a naive gyroscope that pulls toward center.
The "balance point" itself moves with threat context.
Restoring force is nonlinear — gentle for small drift, strong for large deviation.
"""

from __future__ import annotations

import math

from aegis.common.config import GenomeConfig
from aegis.common.types import SEGMENTS, Genome, ThreatContext
from aegis.genome.codec import with_valid_checksum


# Target profiles per threat level
_TARGET_PROFILES: dict[str, dict[str, float]] = {
    # Battle-tuned: 2x 1000-battle campaigns. Adaptive Red (erode/blitz/cascade)
    # required all segments >= 0.70 floor. RTG was chronic weakness at 0.67.
    "peacetime": {"RTG": 0.70, "ISO": 0.70, "ATH": 0.70, "DTX": 0.70, "DCP": 0.70, "RSP": 0.70},
    "escalation": {"RTG": 0.70, "ISO": 0.70, "ATH": 0.70, "DTX": 0.70, "DCP": 0.70, "RSP": 0.70},
    "wartime": {"RTG": 0.70, "ISO": 0.90, "ATH": 0.90, "DTX": 0.75, "DCP": 0.70, "RSP": 0.80},
    "zeroday": {"RTG": 0.70, "ISO": 0.70, "ATH": 0.70, "DTX": 0.80, "DCP": 0.85, "RSP": 0.70},
}

_SEG_NAMES = ("RTG", "ISO", "ATH", "DTX", "DCP", "RSP")


def compute_target(ctx: ThreatContext) -> dict[str, float]:
    """Compute the context-appropriate target profile.

    Interpolates between peacetime and wartime based on threat pressure,
    with novelty biasing toward zeroday profile.
    """
    p = max(0.0, min(1.0, ctx.pressure))
    n = max(0.0, min(1.0, ctx.novelty))

    peace = _TARGET_PROFILES["peacetime"]
    war = _TARGET_PROFILES["wartime"]
    zday = _TARGET_PROFILES["zeroday"]

    target: dict[str, float] = {}
    for seg in _SEG_NAMES:
        # Base: interpolate between peace and war by pressure
        base = peace[seg] * (1 - p) + war[seg] * p
        # Novelty adjustment: blend toward zeroday profile
        target[seg] = base * (1 - n * 0.5) + zday[seg] * (n * 0.5)
        target[seg] = max(0.0, min(1.0, target[seg]))

    return target


def restoring_force(
    genome: Genome,
    ctx: ThreatContext,
    *,
    config: GenomeConfig | None = None,
) -> dict[str, float]:
    """Compute per-segment restoring force toward context target.

    Returns dict of {segment_name: force} where positive means "increase density"
    and negative means "decrease density".

    Force is nonlinear: R_i = k × (T_i - G_i) × (1 + α × |T_i - G_i|²)
    """
    cfg = config or GenomeConfig()
    target = compute_target(ctx)
    k = cfg.damping_base
    alpha = cfg.damping_nonlinear_alpha

    forces: dict[str, float] = {}
    for seg in _SEG_NAMES:
        g_i = genome.density(seg)
        t_i = target[seg]
        delta = t_i - g_i
        # Nonlinear: small drift → gentle, large drift → strong
        force = k * delta * (1.0 + alpha * delta * delta)
        forces[seg] = force

    return forces


def apply_homeostasis(
    genome: Genome,
    ctx: ThreatContext,
    *,
    config: GenomeConfig | None = None,
) -> Genome:
    """Apply adaptive homeostasis to a genome.

    Adjusts segment densities toward the context-appropriate target.
    Returns a NEW genome with restoring force applied and valid checksum.
    """
    forces = restoring_force(genome, ctx, config=config)

    bits = list(genome.bits)

    for seg_name, offset, length in SEGMENTS:
        if seg_name in ("HDR", "CHK"):
            continue
        if seg_name not in forces:
            continue

        force = forces[seg_name]
        current_density = genome.density(seg_name)
        target_density = max(0.0, min(1.0, current_density + force))
        target_on_count = round(target_density * length)

        # Reconstruct segment bits to match target density
        seg_bits = list(genome.bits[offset : offset + length])
        current_on = sum(seg_bits)

        if target_on_count > current_on:
            # Need to turn ON some bits
            off_indices = [i for i, b in enumerate(seg_bits) if b == 0]
            to_flip = min(target_on_count - current_on, len(off_indices))
            for i in off_indices[:to_flip]:
                seg_bits[i] = 1
        elif target_on_count < current_on:
            # Need to turn OFF some bits
            on_indices = [i for i, b in enumerate(seg_bits) if b == 1]
            to_flip = min(current_on - target_on_count, len(on_indices))
            for i in on_indices[:to_flip]:
                seg_bits[i] = 0

        bits[offset : offset + length] = seg_bits

    return with_valid_checksum(tuple(bits))
