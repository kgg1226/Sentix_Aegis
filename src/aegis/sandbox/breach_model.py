"""Breach determination model -- per-category attack success logic.

Replaces the naive `density < threshold` with category-specific models
that reflect how real attacks succeed or fail.

Each category has a different success condition:
  COMMODITY:   density check -- basic attacks blocked by basic defense
  VOLUME:      fatigue model -- sustained pressure degrades defense over time
  APT:         penetration model -- slow cumulative progress, breach at threshold
  ZERO_DAY:    probabilistic -- can breach even strong defense, DTX reduces odds
  INSIDER:     auth bypass -- ATH effectiveness halved (authorized user)
  META_ATTACK: pipeline target -- attacks detection itself, L5-dependent

Additionally, segment synergy provides a defense bonus:
  - DTX+RSP pair: detection-response coordination
  - ISO+ATH pair: isolation-authentication layering
  - DCP+DTX pair: deception-detection amplification
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
    effective_defense: float    # Final defense score after all modifiers
    attack_power: float         # Final attack power after all modifiers
    synergy_bonus: float        # Defense bonus from segment synergy
    reason: str                 # Human-readable explanation


# Segment synergy pairs: (seg_a, seg_b) -> bonus_weight
# When both segments are strong, they amplify each other's defense
_SYNERGY_PAIRS: list[tuple[str, str, float]] = [
    ("DTX", "RSP", 0.08),   # Detection + Response = coordinated defense
    ("ISO", "ATH", 0.06),   # Isolation + Auth = layered access control
    ("DCP", "DTX", 0.05),   # Deception + Detection = attacker confusion
    ("RTG", "ISO", 0.04),   # Routing + Isolation = network segmentation
    ("ATH", "RSP", 0.03),   # Auth + Response = rapid lockout
]


def compute_synergy_bonus(genome: Genome) -> float:
    """Compute defense bonus from segment pair synergies.

    Returns a value in [0.0, ~0.20] that reduces breach probability.
    Both segments must be strong for the bonus to matter.
    """
    bonus = 0.0
    for seg_a, seg_b, weight in _SYNERGY_PAIRS:
        # Synergy = geometric mean of both densities * weight
        # Both need to be strong; one weak segment kills the pair
        pair_strength = math.sqrt(genome.density(seg_a) * genome.density(seg_b))
        bonus += pair_strength * weight
    return bonus


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
    """Determine if an attack breaches the defense.

    Args:
        genome: Current defense genome
        target_segment: Primary attack target
        category: Type of attack (determines breach model)
        intensity: Red agent's attack power multiplier
        base_threshold: Campaign's current breach threshold
        multi_targets: Additional targets for blitz/cascade attacks
        rng: Random number generator for probabilistic models
        erosion_pressure: Accumulated pressure on target segment (erode attacks)
    """
    rng = rng or random.Random()
    targets = multi_targets if multi_targets else (target_segment,)
    synergy = compute_synergy_bonus(genome)

    # Dispatch to category-specific model
    dispatch = {
        ThreatCategory.COMMODITY: _breach_commodity,
        ThreatCategory.VOLUME: _breach_volume,
        ThreatCategory.APT: _breach_apt,
        ThreatCategory.ZERO_DAY: _breach_zeroday,
        ThreatCategory.INSIDER: _breach_insider,
        ThreatCategory.META_ATTACK: _breach_meta,
    }
    model = dispatch.get(category, _breach_commodity)

    # Check each target -- any breach = Red wins
    for seg in targets:
        result = model(
            genome=genome,
            segment=seg,
            intensity=intensity,
            base_threshold=base_threshold,
            synergy_bonus=synergy,
            rng=rng,
            erosion_pressure=erosion_pressure,
        )
        if result.breached:
            return result

    # All targets held
    density = genome.density(target_segment)
    return BreachResult(
        breached=False,
        category=category,
        target_segment=target_segment,
        effective_defense=density + synergy,
        attack_power=intensity * base_threshold,
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
    """COMMODITY: Simple density check with synergy defense.

    Script-kiddie attacks. Blocked by basic density.
    Intensity matters but synergy provides a clear counter.
    """
    density = genome.density(segment)
    defense = density + synergy_bonus * 0.5  # Synergy helps moderately
    attack = base_threshold * intensity * 0.8  # Commodity attacks are weak

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
    """VOLUME: Fatigue model -- sustained pressure wears down defense.

    DDoS, credential stuffing. Each round of pressure accumulates.
    RTG (routing) and RSP (response) are key defenders.
    Erosion pressure directly degrades effective defense.
    """
    density = genome.density(segment)
    # RTG helps absorb volume (routing can redistribute load)
    rtg_absorb = genome.density("RTG") * 0.10
    # RSP helps with automated response to volume
    rsp_counter = genome.density("RSP") * 0.08

    defense = density + synergy_bonus * 0.3 + rtg_absorb + rsp_counter
    # Erosion directly weakens: sustained volume degrades defense
    defense -= erosion_pressure * 0.3
    defense = max(0.0, defense)

    attack = base_threshold * intensity * 0.9

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
    """APT: Penetration model -- slow cumulative progress.

    Advanced persistent threats are patient. They probe, map, then strike.
    High erosion_pressure = they've been at this for a while.
    DCP (deception) is the primary counter -- confuses APT reconnaissance.
    DTX (detection) catches slow lateral movement.
    """
    density = genome.density(segment)
    # DCP is critical against APT -- honeypots waste attacker time
    dcp_counter = genome.density("DCP") * 0.15
    # DTX catches slow movement
    dtx_counter = genome.density("DTX") * 0.10

    defense = density + synergy_bonus * 0.5 + dcp_counter + dtx_counter
    # APT accumulates progress -- erosion is their primary weapon
    penetration = erosion_pressure * 0.5 + intensity * 0.1
    defense -= penetration
    defense = max(0.0, defense)

    attack = base_threshold * intensity * 0.7  # Lower base but erosion-amplified

    breached = defense < attack
    return BreachResult(
        breached=breached,
        category=ThreatCategory.APT,
        target_segment=segment,
        effective_defense=defense,
        attack_power=attack,
        synergy_bonus=synergy_bonus,
        reason=f"APT: {'breached' if breached else 'blocked'} "
               f"(defense {defense:.2f} vs attack {attack:.2f}, "
               f"penetration={penetration:.2f})",
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
    """ZERO_DAY: Probabilistic -- can breach even high density.

    Unknown vulnerabilities bypass pattern-based defense.
    DTX density reduces probability but can't eliminate it.
    Even 95% density has a chance of being breached.
    This is the only model where "defense > attack" can still lose.
    """
    density = genome.density(segment)
    dtx = genome.density("DTX")

    # Base breach probability: higher intensity = higher chance
    # DTX (detection sensors) is the primary counter
    base_prob = 0.05 + intensity * 0.08  # 5% base + intensity scaling
    # DTX reduces probability (behavioral detection catches anomalies)
    dtx_reduction = dtx * 0.15
    # Synergy further reduces
    synergy_reduction = synergy_bonus * 0.3

    breach_prob = max(0.02, base_prob - dtx_reduction - synergy_reduction)
    breach_prob = min(0.60, breach_prob)  # Cap at 60%

    # Roll the dice
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
    """INSIDER: Auth bypass -- ATH effectiveness halved.

    Authorized users already passed authentication.
    ATH segment's defense is cut in half against insiders.
    ISO (isolation) becomes the primary counter -- limits blast radius.
    DCP (deception) helps detect abnormal authorized behavior.
    """
    density = genome.density(segment)
    ath = genome.density("ATH")
    iso = genome.density("ISO")
    dcp = genome.density("DCP")

    # ATH is halved -- insider already has credentials
    ath_contribution = ath * 0.05  # Normally ~0.10, halved
    # ISO is critical -- limits what insider can reach
    iso_counter = iso * 0.15
    # DCP catches abnormal behavior from authorized users
    dcp_counter = dcp * 0.10

    defense = density + synergy_bonus * 0.4 + ath_contribution + iso_counter + dcp_counter
    attack = base_threshold * intensity * 0.85

    breached = defense < attack
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
    """META_ATTACK: Targets the detection pipeline itself.

    Attempts to compromise L3/L4 (LLM layers) via injection.
    DTX is the primary defense (sensor integrity).
    Synergy bonus is critical -- isolated sensors are vulnerable.
    Probabilistic element: sophisticated meta-attacks can bypass.
    """
    density = genome.density(segment)
    dtx = genome.density("DTX")

    # DTX integrity is the main defense
    dtx_defense = dtx * 0.20
    defense = density + synergy_bonus * 0.6 + dtx_defense

    # Meta-attacks have probabilistic bypass
    base_prob = 0.03 + intensity * 0.05
    bypass_prob = max(0.01, base_prob - synergy_bonus * 0.4)

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

    attack = base_threshold * intensity * 0.75
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
