"""Blue agent -- Desperate defender fighting for survival.

Blue is under CONSTANT siege from a relentless Red team. Every round
could be the round defense crumbles. Blue must be smart, fast, and
willing to make hard tradeoffs.

Defense arsenal:
  - Repair: emergency fix on breached segment (triage)
  - Fortify: proactively strengthen vulnerable segments
  - Diversify: crossover with reference genome to break predictability
  - Harden: incremental tuning when situation is stable
  - Rotate: redistribute density to disrupt Red's targeting model
  - Reinforce: mass strengthening when breach rate spikes
  - Synergize: optimize synergy pairs for multiplicative defense
  - Counter-intel: predict Red's next move and pre-empt it
  - Lockdown: emergency all-hands defense when under extreme pressure

Adaptive mechanics:
  - Tracks Red's attack patterns to predict next target
  - Dynamic safety margin rises under pressure (survival instinct)
  - Counter-intelligence: analyzes Red's strategy preferences
  - Emergency lockdown when breach rate exceeds critical threshold
  - Synergy-aware: strengthens segment pairs, not just individuals
"""

from __future__ import annotations

import math
import random
from collections import Counter
from typing import Literal

from aegis.common.types import DefenseForm, Genome, ThreatContext
from aegis.genome.codec import build_form_genome, with_valid_checksum
from aegis.genome.fitness import evaluate
from aegis.genome.homeostasis import apply_homeostasis
from aegis.genome.operators import burst_mutation, crossover, point_mutation

DEFENSE_SEGMENTS = ["RTG", "ISO", "ATH", "DTX", "DCP", "RSP"]
BASE_SAFETY_MARGIN = 0.40

# Synergy pairs: strengthening BOTH gives disproportionate defense
SYNERGY_PRIORITY = {
    "DTX": ["RSP", "DCP"],
    "DCP": ["DTX", "ISO"],
    "RTG": ["ISO", "DCP"],
    "ISO": ["ATH", "RTG"],
    "ATH": ["RSP", "ISO"],
    "RSP": ["DTX", "ATH"],
}

Strategy = Literal[
    "repair", "fortify", "diversify", "harden", "rotate",
    "reinforce", "synergize", "counter_intel", "lockdown",
]


class BlueAgent:
    """Desperate defender — will do ANYTHING to keep the system alive.

    Blue has personality: it's vigilant, adaptive, and resilient. It tracks
    Red's every move, predicts the next attack, and pre-empts it. When
    things get dire, Blue activates emergency protocols.
    """

    def __init__(self, max_mutations: int = 15) -> None:
        self._max_mutations = max_mutations
        self._breached_segments: list[str] = []
        self._attack_history: list[str] = []
        self._round = 0

        # --- Adaptive defense state ---
        self._consecutive_attacks: dict[str, int] = {s: 0 for s in DEFENSE_SEGMENTS}
        self._recent_breaches: dict[str, int] = {s: 0 for s in DEFENSE_SEGMENTS}
        self._breach_history: list[bool] = []
        self._safety_margin: float = BASE_SAFETY_MARGIN

        # --- Counter-intelligence state ---
        # Track Red's strategy patterns
        self._red_strategy_history: list[str] = []
        # Track Red's category choices per segment
        self._red_category_history: list[str] = []
        # Track which segments Red attacks in sequence
        self._attack_sequence: list[str] = []
        # Breach rate in last N rounds (for emergency detection)
        self._emergency_threshold: float = 0.45
        # Recovery tracker: rounds since last breach
        self._rounds_since_breach: int = 0
        # Defense effectiveness per strategy
        self._defense_outcomes: dict[str, list[bool]] = {}

    @property
    def safety_margin(self) -> float:
        return self._safety_margin

    @property
    def is_emergency(self) -> bool:
        """Are we in emergency mode? (breach rate critically high)"""
        window = 15
        recent = self._breach_history[-window:]
        if len(recent) < 5:
            return False
        return sum(recent) / len(recent) > self._emergency_threshold

    def respond(
        self,
        genome: Genome,
        ctx: ThreatContext,
        red_win: bool,
        attacked_segment: str = "",
        red_strategy: str = "",
        attack_category: str = "",
    ) -> Genome:
        """Evolve genome in response to Red's attack. FIGHT FOR SURVIVAL."""
        self._round += 1

        # --- Track Red's behavior (intelligence gathering) ---
        if attacked_segment:
            self._attack_history.append(attacked_segment)
            self._attack_sequence.append(attacked_segment)
            for seg in DEFENSE_SEGMENTS:
                if seg == attacked_segment:
                    self._consecutive_attacks[seg] += 1
                else:
                    self._consecutive_attacks[seg] = max(0, self._consecutive_attacks[seg] - 1)

        if red_strategy:
            self._red_strategy_history.append(red_strategy)
        if attack_category:
            self._red_category_history.append(attack_category)

        if red_win and attacked_segment:
            self._breached_segments.append(attacked_segment)
            self._recent_breaches[attacked_segment] += 1
            self._rounds_since_breach = 0
        else:
            self._rounds_since_breach += 1

        self._breach_history.append(red_win)
        self._adapt_safety_margin()

        strategy = self._pick_strategy(genome, red_win, attacked_segment)

        # Execute strategy
        result = self._execute_strategy(strategy, genome, ctx, attacked_segment)

        # Track defense effectiveness
        self._defense_outcomes.setdefault(strategy, []).append(not red_win)

        # POST-STRATEGY SAFETY NET
        result = self._enforce_density_floor(result, ctx)
        return result

    def _execute_strategy(
        self, strategy: Strategy, genome: Genome, ctx: ThreatContext, target: str,
    ) -> Genome:
        dispatch = {
            "repair": lambda: self._strategy_repair(genome, ctx, target),
            "fortify": lambda: self._strategy_fortify(genome, ctx),
            "diversify": lambda: self._strategy_diversify(genome, ctx),
            "harden": lambda: self._strategy_harden(genome, ctx),
            "rotate": lambda: self._strategy_rotate(genome, ctx, target),
            "reinforce": lambda: self._strategy_reinforce(genome, ctx),
            "synergize": lambda: self._strategy_synergize(genome, ctx),
            "counter_intel": lambda: self._strategy_counter_intel(genome, ctx),
            "lockdown": lambda: self._strategy_lockdown(genome, ctx),
        }
        return dispatch[strategy]()

    # ------------------------------------------------------------------
    # Adaptive safety margin
    # ------------------------------------------------------------------

    def _adapt_safety_margin(self) -> None:
        """Safety margin rises FAST under pressure, relaxes slowly."""
        window = 25
        recent = self._breach_history[-window:]
        if len(recent) < 5:
            return
        breach_rate = sum(recent) / len(recent)

        # AGGRESSIVE escalation under pressure
        if breach_rate > 0.5:
            self._safety_margin = min(0.90, self._safety_margin + 0.03)
        elif breach_rate > 0.35:
            self._safety_margin = min(0.85, self._safety_margin + 0.02)
        elif breach_rate > 0.2:
            self._safety_margin = min(0.80, self._safety_margin + 0.01)
        elif breach_rate < 0.05 and self._rounds_since_breach > 10:
            # Only relax when truly safe for a sustained period
            self._safety_margin = max(BASE_SAFETY_MARGIN, self._safety_margin - 0.003)

    # ------------------------------------------------------------------
    # Strategy selection — SURVIVAL FIRST
    # ------------------------------------------------------------------

    def _pick_strategy(self, genome: Genome, red_win: bool, attacked_seg: str) -> Strategy:
        """Choose defense strategy. Survival is the ONLY priority."""

        # EMERGENCY LOCKDOWN: breach rate critically high
        if self.is_emergency and red_win:
            return "lockdown"

        # Breach → always repair first (triage)
        if red_win:
            return "repair"

        # Detect sustained pressure → counter it
        if attacked_seg and self._consecutive_attacks.get(attacked_seg, 0) >= 3:
            # Alternate between counter-intel, rotate, synergize
            r = self._round % 3
            if r == 0:
                return "counter_intel"
            elif r == 1:
                return "rotate"
            return "synergize"

        # High recent breach rate → aggressive defense
        recent_window = self._breach_history[-20:]
        if len(recent_window) >= 10:
            breach_rate = sum(recent_window) / len(recent_window)
            if breach_rate > 0.35:
                return "lockdown"
            if breach_rate > 0.25:
                r = self._round % 3
                if r == 0:
                    return "reinforce"
                elif r == 1:
                    return "synergize"
                return "counter_intel"

        # Predict Red's next target and pre-empt
        predicted_target = self._predict_next_target()
        if predicted_target:
            predicted_density = genome.density(predicted_target)
            if predicted_density < self._safety_margin + 0.05:
                return "counter_intel"

        # Vulnerable segments → fortify
        vulnerable = self._find_vulnerable_segments(genome)
        if vulnerable:
            return "fortify"

        # Periodically diversify
        if self._round % 5 == 0 and self._round > 3:
            return "diversify"

        # Synergize periodically (build pair defense)
        if self._round % 4 == 0:
            return "synergize"

        return "harden"

    def _find_vulnerable_segments(self, genome: Genome) -> list[str]:
        """Find segments in danger zone."""
        return [
            seg for seg in DEFENSE_SEGMENTS
            if genome.density(seg) < self._safety_margin
        ]

    def _predict_next_target(self) -> str | None:
        """Counter-intelligence: predict where Red will attack next.

        Analyzes Red's attack patterns to predict the next target.
        Red tends to: (1) repeat successful targets, (2) erode specific
        segments persistently, (3) follow adjacency chains.
        """
        if len(self._attack_sequence) < 3:
            return None

        recent = self._attack_sequence[-10:]
        counts = Counter(recent)

        # Most attacked segment is likely target for erode
        most_common = counts.most_common(1)[0]
        if most_common[1] >= 3:
            return most_common[0]

        # Check for alternating pattern (feint detection)
        if len(recent) >= 4:
            last_two = recent[-2:]
            if last_two[0] != last_two[1]:
                # Red might be alternating — predict it continues
                return last_two[-1]

        return None

    # ------------------------------------------------------------------
    # Strategies
    # ------------------------------------------------------------------

    def _strategy_repair(self, genome: Genome, ctx: ThreatContext, target: str) -> Genome:
        """EMERGENCY triage: fix the breach NOW."""
        best = genome
        best_fitness = evaluate(genome, ctx).final

        for _ in range(self._max_mutations):
            candidate = self._targeted_strengthen(genome, target, n_bits=5)  # Aggressive
            # Shore up other vulnerable segments
            for seg in self._find_vulnerable_segments(candidate):
                if seg != target:
                    candidate = self._targeted_strengthen(candidate, seg, n_bits=2)
            # Also strengthen predicted next target
            predicted = self._predict_next_target()
            if predicted and predicted != target:
                candidate = self._targeted_strengthen(candidate, predicted, n_bits=2)
            candidate = apply_homeostasis(candidate, ctx)
            f = evaluate(candidate, ctx).final
            if f > best_fitness:
                best = candidate
                best_fitness = f

        return best

    def _strategy_fortify(self, genome: Genome, ctx: ThreatContext) -> Genome:
        """Proactively strengthen vulnerable segments."""
        vulnerable = self._find_vulnerable_segments(genome)
        freq_attacked = self._most_attacked_segments(top_k=2)
        # Also include predicted target
        predicted = self._predict_next_target()
        priority = list(set(vulnerable + freq_attacked + ([predicted] if predicted else [])))

        best = genome
        best_fitness = evaluate(genome, ctx).final

        for _ in range(self._max_mutations):
            candidate = genome
            for seg in priority:
                if candidate.density(seg) < self._safety_margin:
                    candidate = self._targeted_strengthen(candidate, seg, n_bits=3)
            candidate = point_mutation(candidate)
            candidate = apply_homeostasis(candidate, ctx)
            f = evaluate(candidate, ctx).final
            if f > best_fitness:
                best = candidate
                best_fitness = f

        return best

    def _strategy_diversify(self, genome: Genome, ctx: ThreatContext) -> Genome:
        """Crossover for structural diversity. SAFE: reject weakening."""
        current_form = genome.form_id
        other_forms = [f for f in DefenseForm if f != current_form]
        donor_form = random.choice(other_forms)
        donor = build_form_genome(donor_form)

        best = genome
        best_fitness = evaluate(genome, ctx).final

        for _ in range(self._max_mutations):
            candidate = crossover(genome, donor)
            candidate = apply_homeostasis(candidate, ctx)
            if any(candidate.density(s) < self._safety_margin - 0.05
                   for s in DEFENSE_SEGMENTS):
                continue
            f = evaluate(candidate, ctx).final
            if f > best_fitness:
                best = candidate
                best_fitness = f

        return best

    def _strategy_harden(self, genome: Genome, ctx: ThreatContext) -> Genome:
        """Incremental hardening. SAFE: reject weakening."""
        best = genome
        best_fitness = evaluate(genome, ctx).final

        attempts = min(self._max_mutations // 3, 5)
        for _ in range(attempts):
            candidate = point_mutation(genome)
            candidate = apply_homeostasis(candidate, ctx)
            if any(candidate.density(s) < self._safety_margin - 0.05
                   for s in DEFENSE_SEGMENTS):
                continue
            f = evaluate(candidate, ctx).final
            if f > best_fitness:
                best = candidate
                best_fitness = f

        if best is genome:
            best = apply_homeostasis(genome, ctx)
        return best

    def _strategy_rotate(self, genome: Genome, ctx: ThreatContext, target_seg: str) -> Genome:
        """Redistribute density to invalidate Red's mental model."""
        best = genome
        best_fitness = evaluate(genome, ctx).final

        for _ in range(self._max_mutations):
            candidate = genome
            candidate = self._targeted_strengthen(candidate, target_seg, n_bits=4)
            # Strengthen random OTHER segments (unpredictable)
            others = [s for s in DEFENSE_SEGMENTS if s != target_seg]
            for other in random.sample(others, min(2, len(others))):
                candidate = self._targeted_strengthen(candidate, other, n_bits=2)
            candidate = burst_mutation(candidate)
            candidate = apply_homeostasis(candidate, ctx)
            f = evaluate(candidate, ctx).final
            if f > best_fitness:
                best = candidate
                best_fitness = f

        return best

    def _strategy_reinforce(self, genome: Genome, ctx: ThreatContext) -> Genome:
        """Mass reinforcement: raise ALL segments."""
        best = genome
        best_fitness = evaluate(genome, ctx).final

        for _ in range(self._max_mutations):
            candidate = genome
            for seg in DEFENSE_SEGMENTS:
                if candidate.density(seg) < self._safety_margin:
                    candidate = self._targeted_strengthen(candidate, seg, n_bits=4)
            for seg in DEFENSE_SEGMENTS:
                if candidate.density(seg) < 0.85 and random.random() < 0.4:
                    candidate = self._targeted_strengthen(candidate, seg, n_bits=2)
            candidate = apply_homeostasis(candidate, ctx)
            f = evaluate(candidate, ctx).final
            if f > best_fitness:
                best = candidate
                best_fitness = f

        return best

    def _strategy_synergize(self, genome: Genome, ctx: ThreatContext) -> Genome:
        """Strengthen synergy pairs for multiplicative defense."""
        from aegis.sandbox.breach_model import compute_synergy_bonus, _SYNERGY_PAIRS

        best = genome
        best_synergy = compute_synergy_bonus(genome)
        best_fitness = evaluate(genome, ctx).final

        # Find weakest synergy pair
        weakest_pair = None
        weakest_strength = float("inf")
        for seg_a, seg_b, weight in _SYNERGY_PAIRS:
            pair_strength = math.sqrt(genome.density(seg_a) * genome.density(seg_b))
            if pair_strength < weakest_strength:
                weakest_strength = pair_strength
                weakest_pair = (seg_a, seg_b)

        for _ in range(self._max_mutations):
            candidate = genome
            if weakest_pair:
                candidate = self._targeted_strengthen(candidate, weakest_pair[0], n_bits=3)
                candidate = self._targeted_strengthen(candidate, weakest_pair[1], n_bits=3)

            most_attacked = self._most_attacked_segments(top_k=1)
            if most_attacked:
                partners = SYNERGY_PRIORITY.get(most_attacked[0], [])
                for partner in partners[:2]:
                    candidate = self._targeted_strengthen(candidate, partner, n_bits=2)

            candidate = apply_homeostasis(candidate, ctx)
            new_synergy = compute_synergy_bonus(candidate)
            f = evaluate(candidate, ctx).final

            if new_synergy > best_synergy or (new_synergy >= best_synergy and f > best_fitness):
                best = candidate
                best_synergy = new_synergy
                best_fitness = f

        return best

    def _strategy_counter_intel(self, genome: Genome, ctx: ThreatContext) -> Genome:
        """COUNTER-INTELLIGENCE: predict Red's next move and pre-empt.

        Analyzes Red's patterns to determine:
        1. Which segment Red will target next
        2. What strategy Red prefers
        3. Where Red has been building erosion pressure

        Then pre-emptively strengthens those segments BEFORE the attack.
        """
        best = genome
        best_fitness = evaluate(genome, ctx).final

        # Predict targets
        predicted_target = self._predict_next_target()
        most_attacked = self._most_attacked_segments(top_k=3)
        most_breached = sorted(
            self._recent_breaches.items(),
            key=lambda x: x[1],
            reverse=True,
        )
        priority_segments = []

        # Priority 1: predicted next target
        if predicted_target:
            priority_segments.append(predicted_target)

        # Priority 2: most breached segments
        for seg, count in most_breached[:2]:
            if count > 0 and seg not in priority_segments:
                priority_segments.append(seg)

        # Priority 3: most attacked (even if not breached)
        for seg in most_attacked:
            if seg not in priority_segments:
                priority_segments.append(seg)

        # Fallback: all vulnerable segments
        if not priority_segments:
            priority_segments = self._find_vulnerable_segments(genome)

        for _ in range(self._max_mutations):
            candidate = genome

            # Aggressively strengthen predicted targets
            for i, seg in enumerate(priority_segments[:3]):
                n_bits = max(2, 5 - i)  # More bits for higher priority
                candidate = self._targeted_strengthen(candidate, seg, n_bits=n_bits)

            # Also strengthen synergy partners of predicted targets
            for seg in priority_segments[:2]:
                partners = SYNERGY_PRIORITY.get(seg, [])
                for partner in partners[:1]:
                    candidate = self._targeted_strengthen(candidate, partner, n_bits=2)

            candidate = apply_homeostasis(candidate, ctx)
            f = evaluate(candidate, ctx).final
            if f > best_fitness:
                best = candidate
                best_fitness = f

        return best

    def _strategy_lockdown(self, genome: Genome, ctx: ThreatContext) -> Genome:
        """EMERGENCY LOCKDOWN: all resources to defense. Survival mode.

        When breach rate exceeds critical threshold, Blue activates
        lockdown: EVERY segment gets maximum strengthening. No subtlety,
        no optimization — just raw defensive power everywhere.

        This is the "pull every fire alarm" response.
        """
        best = genome
        best_fitness = evaluate(genome, ctx).final

        # Double mutation budget in emergency
        budget = self._max_mutations * 2

        for _ in range(budget):
            candidate = genome

            # Strengthen EVERY segment aggressively
            for seg in DEFENSE_SEGMENTS:
                target = max(self._safety_margin + 0.10, 0.80)
                while candidate.density(seg) < target:
                    candidate = self._targeted_strengthen(candidate, seg, n_bits=5)
                    if candidate.density(seg) >= target:
                        break

            # Apply homeostasis
            candidate = apply_homeostasis(candidate, ctx)
            f = evaluate(candidate, ctx).final
            if f > best_fitness:
                best = candidate
                best_fitness = f

        return best

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _targeted_strengthen(
        self, genome: Genome, segment_name: str, n_bits: int = 3,
    ) -> Genome:
        """Flip 0-bits to 1 in a specific segment."""
        from aegis.common.types import SEGMENTS

        offset, length = 0, 0
        for name, seg_offset, seg_length in SEGMENTS:
            if name == segment_name:
                offset, length = seg_offset, seg_length
                break

        bits = list(genome.bits)
        zero_indices = [offset + i for i in range(length) if bits[offset + i] == 0]
        if not zero_indices:
            return genome

        n_flip = min(random.randint(1, n_bits), len(zero_indices))
        for idx in random.sample(zero_indices, n_flip):
            bits[idx] = 1

        return with_valid_checksum(tuple(bits))

    def _enforce_density_floor(self, genome: Genome, ctx: ThreatContext) -> Genome:
        """Safety net: NEVER return a genome with dangerously low segments."""
        floor = max(self._safety_margin - 0.05, BASE_SAFETY_MARGIN)
        needs_repair = [s for s in DEFENSE_SEGMENTS if genome.density(s) < floor]
        if not needs_repair:
            return genome

        candidate = genome
        for seg in needs_repair:
            attempts = 0
            while candidate.density(seg) < floor and attempts < 12:
                candidate = self._targeted_strengthen(candidate, seg, n_bits=4)
                attempts += 1

        return apply_homeostasis(candidate, ctx)

    def _most_attacked_segments(self, top_k: int = 2) -> list[str]:
        if not self._attack_history:
            return []
        counts = Counter(self._attack_history)
        return [seg for seg, _ in counts.most_common(top_k)]
