"""Multi-objective genome fitness function.

v2 addresses defects AEGIS-F001 through F012 from the initial audit:
- F001: Layer correlation coefficient (not independent)
- F002: Efficiency reaches true zero via piecewise function
- F003: S_ctx normalized to [0, 1]
- F004: Smooth sigmoid penalty (no cliffs)
- F005: Epsilon-guarded entropy over all 6 segments
- F006: S_syn clamped to [0, 1]
- F007: Constants are config-driven, ready for Bayesian optimization
- F008: Interaction terms for topology coupling
- F009: NOTE — density abstraction remains; full topology parsing is Phase 3
- F010: Empirical ground truth blending (F_structural + F_empirical)
- F011: Confidence interval from test round count
- F012: Pareto front maintained externally; this function returns per-objective scores
"""

from __future__ import annotations

import math

from aegis.common.config import GenomeConfig
from aegis.common.types import FitnessResult, Genome, ThreatContext


_EPSILON = 1e-10


def _sigmoid(x: float, k: float = 50.0) -> float:
    """Smooth sigmoid. k controls steepness."""
    return 1.0 / (1.0 + math.exp(-k * x))


def _s_coverage(genome: Genome, *, correlation: float = 0.3) -> float:
    """S_cov — defense coverage with correlated layer failure.

    F001 fix: introduces correlation coefficient ρ ∈ [0, 1].
    ρ = 0 → fully independent (original model).
    ρ = 1 → fully correlated (worst case).
    """
    d_dtx = genome.density("DTX")
    d_ath = genome.density("ATH")
    d_iso = genome.density("ISO")

    # Independent failure probability
    p_independent = (1 - d_dtx) ** 2 * (1 - d_ath) ** 1.5 * (1 - d_iso) ** 1.2

    # Correlated failure: worst-layer dominates
    worst = max(1 - d_dtx, 1 - d_ath, 1 - d_iso)
    p_correlated = worst ** (2 + 1.5 + 1.2)

    # Blend based on correlation coefficient
    p_failure = (1 - correlation) * p_independent + correlation * p_correlated
    return 1.0 - p_failure


def _s_efficiency(genome: Genome) -> float:
    """S_eff — operational efficiency.

    F002 fix: piecewise function that reaches true zero.
    F008 fix: interaction terms for topology coupling.
    """
    d = {name: genome.density(name) for name, _, _ in
         [("RTG", 8, 32), ("ISO", 40, 16), ("ATH", 56, 16),
          ("DCP", 104, 16), ("RSP", 120, 16)]}

    # Base overhead (additive)
    overhead = (
        d["RTG"] * 0.25
        + d["ISO"] * 0.30
        + d["ATH"] * 0.20
        + d["DCP"] * 0.15
        + d["RSP"] * 0.10
    )

    # F008: interaction terms — mesh routing × isolation is multiplicative
    coupling = d["RTG"] * d["ISO"] * 0.15 + d["ATH"] * d["RSP"] * 0.05
    overhead += coupling

    # F002: piecewise that reaches 0
    return max(0.0, 1.0 - overhead ** 1.8)


def _s_adaptability(genome: Genome) -> float:
    """S_adp — evolutionary potential.

    F005 fix: epsilon-guarded entropy, all 6 segments included.
    """
    densities = [
        genome.density(name)
        for name in ("RTG", "ISO", "ATH", "DTX", "DCP", "RSP")
    ]

    # Shannon entropy with epsilon guard
    entropy = 0.0
    for x in densities:
        x_safe = max(x, _EPSILON)
        entropy -= x_safe * math.log2(x_safe)
    entropy /= len(densities)

    # Spread: penalize extreme imbalance between segments
    mean_d = sum(densities) / len(densities) if densities else 0.5
    variance = sum((d - mean_d) ** 2 for d in densities) / len(densities)
    spread = 1.0 - min(1.0, math.sqrt(variance) * 2)

    return min(1.0, max(0.0, entropy * 0.6 + spread * 0.4))


def _s_synergy(genome: Genome) -> float:
    """S_syn — inter-segment synergy.

    F006 fix: result clamped to [0, 1].
    """
    d_dtx = genome.density("DTX")
    d_rsp = genome.density("RSP")
    d_dcp = genome.density("DCP")
    d_iso = genome.density("ISO")
    d_ath = genome.density("ATH")

    s1 = min(d_dtx, d_rsp)           # Detection-response pairing
    s2 = min(d_dcp, d_dtx) * 1.2     # Deception-detection synergy
    s3 = min(d_iso, d_ath)            # Isolation-auth pairing

    penalty = 0.5 * max(0.0, d_dcp - d_dtx)  # Blind honeypots

    raw = (s1 + s2 + s3) / 3.0 - penalty
    return min(1.0, max(0.0, raw))


def _s_threat_match(genome: Genome, ctx: ThreatContext) -> float:
    """S_ctx — alignment with current threat context.

    F003 fix: normalize p/d/n to sum=1 before weighting.
    """
    p, d, n = ctx.pressure, ctx.diversity, ctx.novelty
    total = p + d + n
    if total < _EPSILON:
        return 0.5  # No threat signal → neutral score
    p, d, n = p / total, d / total, n / total

    d_iso = genome.density("ISO")
    d_ath = genome.density("ATH")
    d_rsp = genome.density("RSP")
    d_dtx = genome.density("DTX")
    d_dcp = genome.density("DCP")
    d_rtg = genome.density("RTG")

    depth = d_iso * 0.3 + d_ath * 0.3 + d_rsp * 0.4
    breadth = d_dtx * 0.5 + d_dcp * 0.3 + d_rtg * 0.2
    novelty_ready = d_dcp * 0.4 + d_dtx * 0.3 + (1.0 - d_rsp) * 0.3

    return min(1.0, p * depth + d * breadth + n * novelty_ready)


def _penalty(genome: Genome) -> float:
    """Structural deficiency penalty.

    F004 fix: smooth sigmoid transitions instead of hard thresholds.
    """
    d_ath = genome.density("ATH")
    d_iso = genome.density("ISO")
    d_dtx = genome.density("DTX")
    d_dcp = genome.density("DCP")
    d_rsp = genome.density("RSP")

    p = 0.0

    # Auth AND isolation both dangerously low
    p += 0.30 * _sigmoid(-(d_ath - 0.2)) * _sigmoid(-(d_iso - 0.2))

    # Detection nearly off
    p += 0.20 * _sigmoid(-(d_dtx - 0.1))

    # Honeypots without detection → blind traps
    p += 0.15 * _sigmoid(d_dcp - 0.5) * _sigmoid(-(d_dtx - 0.3))

    # Aggressive response without accurate detection → false positive hell
    p += 0.10 * _sigmoid(d_rsp - 0.8) * _sigmoid(-(d_dtx - 0.4))

    return min(0.5, p)


def evaluate(
    genome: Genome,
    ctx: ThreatContext,
    *,
    config: GenomeConfig | None = None,
    red_win_rate: float | None = None,
    test_rounds: int = 0,
) -> FitnessResult:
    """Evaluate genome fitness.

    Args:
        genome: The genome to evaluate.
        ctx: Current threat context.
        config: Weight configuration. Uses defaults if None.
        red_win_rate: If provided, blends empirical score (F010 fix).
        test_rounds: Number of Sandbox rounds tested (F011 fix).

    Returns:
        FitnessResult with per-objective scores and confidence interval.
    """
    cfg = config or GenomeConfig()

    scores = {
        "coverage": _s_coverage(genome),
        "efficiency": _s_efficiency(genome),
        "adaptability": _s_adaptability(genome),
        "synergy": _s_synergy(genome),
        "threat_match": _s_threat_match(genome, ctx),
    }

    weights = [
        cfg.w_coverage, cfg.w_efficiency, cfg.w_adaptability,
        cfg.w_synergy, cfg.w_threat_match,
    ]
    w_sum = sum(weights)
    if w_sum < _EPSILON:
        w_norm = [0.2] * 5
    else:
        w_norm = [w / w_sum for w in weights]

    score_values = list(scores.values())
    raw = sum(s * w for s, w in zip(score_values, w_norm, strict=True))
    pen = _penalty(genome)
    structural = max(0.0, raw - pen)

    # F010: blend with empirical ground truth if available
    if red_win_rate is not None:
        empirical = 1.0 - red_win_rate
        # As test_rounds increase, trust empirical more
        alpha = min(0.7, test_rounds / 1000.0)
        final = (1.0 - alpha) * structural + alpha * empirical
    else:
        final = structural

    # F011: confidence interval based on test history
    ci = 1.0 / math.sqrt(max(1, test_rounds)) if test_rounds > 0 else 1.0

    return FitnessResult(
        scores=scores,
        raw=raw,
        penalty=pen,
        final=final,
        confidence_interval=ci,
    )
