"""Breach determination model -- per-category attack success logic.

Each category has a fundamentally different breach mechanic:
  COMMODITY:   density check -- basic attacks blocked by solid defense
  VOLUME:      fatigue model -- sustained pressure degrades defense over time
  APT:         penetration model -- slow cumulative progress, breach at threshold
  ZERO_DAY:    probabilistic -- can breach even strong defense (the wildcard)
  INSIDER:     auth bypass -- ATH effectiveness halved (authorized user)
  META_ATTACK: pipeline target -- attacks detection itself, synergy-dependent

Key design principle: HIGH DENSITY SHOULD MEAN SOMETHING.
  - At 85%+ density, COMMODITY/VOLUME should almost never breach
  - APT can breach high density, but ONLY with sustained erosion
  - ZERO_DAY is the only pure probability path through high defense
  - INSIDER bypasses ATH but still faces other defenses
  - META_ATTACK is rare but devastating when it lands

Intensity scales attack power but has diminishing returns above 2.0x.
This prevents mathematical impossibility of defense.

Segment synergy provides defense bonus:
  - DTX+RSP: detection-response coordination
  - ISO+ATH: isolation-authentication layering
  - DCP+DTX: deception-detection amplification
  - RTG+ISO: network segmentation
  - ATH+RSP: rapid lockout
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass

from aegis.common.types import Genome, ThreatCategory


@dataclass(frozen=True, slots=True)
class BreachResult:
    """Detailed outcome of a breach attempt."""

    breached: bool
    category: ThreatCategory
    target_segment: str
    effective_defense: float
    attack_power: float
    synergy_bonus: float
    reason: str


# Segment synergy pairs
_SYNERGY_PAIRS: list[tuple[str, str, float]] = [
    ("DTX", "RSP", 0.08),
    ("ISO", "ATH", 0.06),
    ("DCP", "DTX", 0.05),
    ("RTG", "ISO", 0.04),
    ("ATH", "RSP", 0.03),
]


def compute_synergy_bonus(genome: Genome) -> float:
    """Defense bonus from segment pair synergies. Range [0.0, ~0.20]."""
    bonus = 0.0
    for seg_a, seg_b, weight in _SYNERGY_PAIRS:
        pair_strength = math.sqrt(genome.density(seg_a) * genome.density(seg_b))
        bonus += pair_strength * weight
    return bonus


def _effective_intensity(raw_intensity: float) -> float:
    """Apply diminishing returns to attack intensity.

    Raw intensity can grow to 3.5x, but effective intensity caps at ~2.0x.
    This prevents defense from being mathematically impossible.

    Formula: eff = 1.0 + ln(raw_intensity) * 0.8
    At raw=1.0 → eff=1.0, raw=2.0 → eff=1.55, raw=3.5 → eff=2.0
    """
    if raw_intensity <= 1.0:
        return raw_intensity
    return 1.0 + math.log(raw_intensity) * 0.8


def evaluate_breach(
    genome: Genome,
    target_segment: str,
    category: ThreatCategory,
    intensity: float,
    base_threshold: float,
    *,
    multi_targets: tuple[str, ...] = (),
    rng: random.Random | None = None,
    erosion_pressure: float = 0.0,
) -> BreachResult:
    """Determine if an attack breaches the defense."""
    rng = rng or random.Random()
    targets = multi_targets if multi_targets else (target_segment,)
    synergy = compute_synergy_bonus(genome)
    eff_intensity = _effective_intensity(intensity)

    dispatch = {
        ThreatCategory.COMMODITY: _breach_commodity,
        ThreatCategory.VOLUME: _breach_volume,
        ThreatCategory.APT: _breach_apt,
        ThreatCategory.ZERO_DAY: _breach_zeroday,
        ThreatCategory.INSIDER: _breach_insider,
        ThreatCategory.META_ATTACK: _breach_meta,
    }
    model = dispatch.get(category, _breach_commodity)

    for seg in targets:
        result = model(
            genome=genome,
            segment=seg,
            intensity=eff_intensity,
            base_threshold=base_threshold,
            synergy_bonus=synergy,
            rng=rng,
            erosion_pressure=erosion_pressure,
        )
        if result.breached:
            return result

    density = genome.density(target_segment)
    return BreachResult(
        breached=False,
        category=category,
        target_segment=target_segment,
        effective_defense=density + synergy,
        attack_power=eff_intensity * base_threshold,
        synergy_bonus=synergy,
        reason=f"{target_segment} held: defense {density:.2f} + synergy {synergy:.2f}",
    )


# ------------------------------------------------------------------
# Category-specific breach models
# ------------------------------------------------------------------

def _breach_commodity(
    genome: Genome,
    segment: str,
    intensity: float,
    base_threshold: float,
    synergy_bonus: float,
    rng: random.Random,
    erosion_pressure: float,
) -> BreachResult:
    """COMMODITY: density check. High density = near-impenetrable.

    Script-kiddie attacks. At 80%+ density with synergy, these should
    almost always fail. Red needs to use smarter categories.
    """
    density = genome.density(segment)
    defense = density + synergy_bonus * 0.5

    # Commodity attack power: low ceiling
    attack = base_threshold * intensity * 0.65
    attack = min(attack, 0.70)  # Hard cap: commodity can't breach 70%+ defense

    breached = defense < attack
    return BreachResult(
        breached=breached,
        category=ThreatCategory.COMMODITY,
        target_segment=segment,
        effective_defense=defense,
        attack_power=attack,
        synergy_bonus=synergy_bonus,
        reason=f"COMMODITY: {'breached' if breached else 'blocked'} "
               f"(defense {defense:.2f} vs attack {attack:.2f})",
    )


def _breach_volume(
    genome: Genome,
    segment: str,
    intensity: float,
    base_threshold: float,
    synergy_bonus: float,
    rng: random.Random,
    erosion_pressure: float,
) -> BreachResult:
    """VOLUME: fatigue model. Erosion is the real weapon here.

    DDoS / credential stuffing. Base attacks are weak, but sustained
    erosion pressure degrades defense. RTG absorbs, RSP counters.
    This is the SLOW GRIND — powerful when Red is patient.
    """
    density = genome.density(segment)
    rtg_absorb = genome.density("RTG") * 0.10
    rsp_counter = genome.density("RSP") * 0.08

    defense = density + synergy_bonus * 0.3 + rtg_absorb + rsp_counter
    # Erosion degrades defense (the key mechanic for VOLUME)
    erosion_damage = erosion_pressure * 0.25
    defense -= erosion_damage
    defense = max(0.0, defense)

    # Volume attack power: moderate, capped
    attack = base_threshold * intensity * 0.75
    attack = min(attack, 0.85)  # Can breach moderate defense with erosion

    breached = defense < attack
    return BreachResult(
        breached=breached,
        category=ThreatCategory.VOLUME,
        target_segment=segment,
        effective_defense=defense,
        attack_power=attack,
        synergy_bonus=synergy_bonus,
        reason=f"VOLUME: {'breached' if breached else 'blocked'} "
               f"(defense {defense:.2f} vs attack {attack:.2f}, "
               f"erosion={erosion_pressure:.2f})",
    )


def _breach_apt(
    genome: Genome,
    segment: str,
    intensity: float,
    base_threshold: float,
    synergy_bonus: float,
    rng: random.Random,
    erosion_pressure: float,
) -> BreachResult:
    """APT: penetration model. Erosion + probabilistic breakthrough.

    Advanced persistent threats are patient and methodical.
    High erosion = they've mapped the network. DCP confuses them.
    DTX catches slow movement. But even good defense can fall to
    a well-planned APT with enough accumulated intelligence.
    """
    density = genome.density(segment)
    dcp_counter = genome.density("DCP") * 0.12
    dtx_counter = genome.density("DTX") * 0.08

    defense = density + synergy_bonus * 0.4 + dcp_counter + dtx_counter
    # APT accumulates penetration progress
    penetration = erosion_pressure * 0.40
    defense -= penetration
    defense = max(0.0, defense)

    # APT base attack: moderate but enhanced by penetration
    attack = base_threshold * intensity * 0.60
    # APT gets bonus from high erosion (intelligence gathering pays off)
    if erosion_pressure > 0.3:
        apt_intel_bonus = min(0.15, (erosion_pressure - 0.3) * 0.3)
        attack += apt_intel_bonus

    attack = min(attack, 0.90)  # Can breach strong defense with enough prep

    # Probabilistic element: even without erosion, APT can get lucky
    lucky_roll = rng.random()
    apt_luck_prob = 0.03 + erosion_pressure * 0.08  # 3% base, scales with erosion
    apt_luck_prob = min(0.20, apt_luck_prob)

    breached = defense < attack or lucky_roll < apt_luck_prob
    return BreachResult(
        breached=breached,
        category=ThreatCategory.APT,
        target_segment=segment,
        effective_defense=defense,
        attack_power=attack,
        synergy_bonus=synergy_bonus,
        reason=f"APT: {'breached' if breached else 'blocked'} "
               f"(defense {defense:.2f} vs attack {attack:.2f}, "
               f"penetration={penetration:.2f}, luck_prob={apt_luck_prob:.2f})",
    )


def _breach_zeroday(
    genome: Genome,
    segment: str,
    intensity: float,
    base_threshold: float,
    synergy_bonus: float,
    rng: random.Random,
    erosion_pressure: float,
) -> BreachResult:
    """ZERO_DAY: probabilistic. The WILDCARD.

    Unknown vulnerabilities bypass pattern-based defense entirely.
    DTX (behavioral detection) is the primary counter — it catches
    anomalies regardless of signatures. Even 95% density has a chance.

    This is Red's most reliable path through high defense, but it's
    inherently random — Red can't control when it works.
    """
    density = genome.density(segment)
    dtx = genome.density("DTX")

    # Base breach probability scales with intensity
    base_prob = 0.08 + intensity * 0.06
    # DTX reduces probability (behavioral detection catches anomalies)
    dtx_reduction = dtx * 0.12
    # Synergy reduces further
    synergy_reduction = synergy_bonus * 0.25
    # High density provides some resistance
    density_resistance = density * 0.05

    breach_prob = max(0.03, base_prob - dtx_reduction - synergy_reduction - density_resistance)
    breach_prob = min(0.45, breach_prob)  # Cap at 45%

    roll = rng.random()
    breached = roll < breach_prob

    return BreachResult(
        breached=breached,
        category=ThreatCategory.ZERO_DAY,
        target_segment=segment,
        effective_defense=density + synergy_bonus,
        attack_power=breach_prob,
        synergy_bonus=synergy_bonus,
        reason=f"ZERO_DAY: {'breached' if breached else 'blocked'} "
               f"(prob={breach_prob:.2f}, roll={roll:.2f}, dtx={dtx:.2f})",
    )


def _breach_insider(
    genome: Genome,
    segment: str,
    intensity: float,
    base_threshold: float,
    synergy_bonus: float,
    rng: random.Random,
    erosion_pressure: float,
) -> BreachResult:
    """INSIDER: auth bypass. The TRAITOR.

    Authorized users already passed authentication. ATH is halved.
    ISO limits blast radius. DCP catches abnormal authorized behavior.
    This category is dangerous because it bypasses the outer defense
    layer entirely.
    """
    density = genome.density(segment)
    ath = genome.density("ATH")
    iso = genome.density("ISO")
    dcp = genome.density("DCP")

    # ATH halved — insider has credentials
    ath_contribution = ath * 0.05
    # ISO is critical — limits blast radius
    iso_counter = iso * 0.13
    # DCP catches abnormal behavior
    dcp_counter = dcp * 0.08

    defense = density + synergy_bonus * 0.35 + ath_contribution + iso_counter + dcp_counter

    # Insider attack: fairly strong (they know the system)
    attack = base_threshold * intensity * 0.70
    attack = min(attack, 0.85)

    # Probabilistic element: insider knowledge gives random advantage
    insider_luck = rng.random()
    insider_prob = 0.05 + intensity * 0.03
    insider_prob = min(0.15, insider_prob)

    breached = defense < attack or insider_luck < insider_prob
    return BreachResult(
        breached=breached,
        category=ThreatCategory.INSIDER,
        target_segment=segment,
        effective_defense=defense,
        attack_power=attack,
        synergy_bonus=synergy_bonus,
        reason=f"INSIDER: {'breached' if breached else 'blocked'} "
               f"(defense {defense:.2f} vs attack {attack:.2f}, "
               f"ATH halved, ISO={iso:.2f})",
    )


def _breach_meta(
    genome: Genome,
    segment: str,
    intensity: float,
    base_threshold: float,
    synergy_bonus: float,
    rng: random.Random,
    erosion_pressure: float,
) -> BreachResult:
    """META_ATTACK: targets detection pipeline. The SABOTEUR.

    Attempts to compromise L3/L4 (LLM layers) via injection.
    DTX integrity is the main defense. Synergy is critical —
    isolated sensors are vulnerable to meta-attacks.
    Primarily probabilistic: sophisticated meta-attacks bypass
    conventional defense measures.
    """
    density = genome.density(segment)
    dtx = genome.density("DTX")

    dtx_defense = dtx * 0.18
    defense = density + synergy_bonus * 0.5 + dtx_defense

    # Meta-attacks have probabilistic bypass (injection success)
    base_prob = 0.04 + intensity * 0.04
    bypass_prob = max(0.02, base_prob - synergy_bonus * 0.35)
    bypass_prob = min(0.25, bypass_prob)

    roll = rng.random()
    if roll < bypass_prob:
        return BreachResult(
            breached=True,
            category=ThreatCategory.META_ATTACK,
            target_segment=segment,
            effective_defense=defense,
            attack_power=bypass_prob,
            synergy_bonus=synergy_bonus,
            reason=f"META_ATTACK: pipeline compromised "
                   f"(bypass prob={bypass_prob:.2f}, roll={roll:.2f})",
        )

    attack = base_threshold * intensity * 0.60
    attack = min(attack, 0.80)

    breached = defense < attack
    return BreachResult(
        breached=breached,
        category=ThreatCategory.META_ATTACK,
        target_segment=segment,
        effective_defense=defense,
        attack_power=attack,
        synergy_bonus=synergy_bonus,
        reason=f"META_ATTACK: {'breached' if breached else 'blocked'} "
               f"(defense {defense:.2f} vs attack {attack:.2f})",
    )
