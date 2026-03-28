"""Blue agent -- Defensive AI for the sandbox arena.

Responds to Red agent attacks by evolving the genome.
Winning mutations are promoted to the live system.

Defense strategies:
  - Repair: targeted mutation on the breached segment
  - Fortify: proactively strengthen segments near the breach threshold
  - Diversify: crossover with a reference genome to break predictability
  - Harden: homeostasis + minor tuning when no breach occurred
  - Rotate: shift density between segments to disrupt sustained targeting
  - Reinforce: massive burst strengthening when under sustained pressure

Adaptive mechanics:
  - Tracks per-segment attack frequency to detect sustained pressure (erode)
  - Raises safety margin dynamically when Red intensity escalates
  - Rotation strategy breaks erode patterns by redistributing density
"""

from __future__ import annotations

import random
from collections import Counter
from typing import Literal

from aegis.common.types import DefenseForm, Genome, ThreatContext
from aegis.genome.codec import build_form_genome, with_valid_checksum
from aegis.genome.fitness import evaluate
from aegis.genome.homeostasis import apply_homeostasis
from aegis.genome.operators import burst_mutation, crossover, point_mutation

DEFENSE_SEGMENTS = ["RTG", "ISO", "ATH", "DTX", "DCP", "RSP"]
BASE_SAFETY_MARGIN = 0.40  # Target density above breach threshold (0.30)

# Synergy pairs: strengthening BOTH segments gives disproportionate defense bonus
# Against APT: DCP+DTX is critical (deception confuses reconnaissance)
# Against ZERO_DAY: DTX is primary (behavioral detection catches anomalies)
# Against VOLUME: RTG+RSP is critical (routing absorbs, response counters)
# Against INSIDER: ISO+DCP is critical (isolation limits blast, deception detects)
SYNERGY_PRIORITY = {
    "DTX": ["RSP", "DCP"],   # Detection needs response and deception partners
    "DCP": ["DTX", "ISO"],   # Deception needs detection and isolation
    "RTG": ["ISO", "DCP"],   # Routing needs isolation and deception
    "ISO": ["ATH", "RTG"],   # Isolation needs auth and routing
    "ATH": ["RSP", "ISO"],   # Auth needs response and isolation
    "RSP": ["DTX", "ATH"],   # Response needs detection and auth
}

Strategy = Literal["repair", "fortify", "diversify", "harden", "rotate", "reinforce", "synergize"]


class BlueAgent:
    """Defensive AI that adapts its strategy based on attack history."""

    def __init__(self, max_mutations: int = 15) -> None:
        self._max_mutations = max_mutations
        self._breached_segments: list[str] = []
        self._attack_history: list[str] = []  # segments attacked (win or lose)
        self._round = 0

        # --- Adaptive defense state ---
        # Per-segment consecutive attack counter (detects erode patterns)
        self._consecutive_attacks: dict[str, int] = {s: 0 for s in DEFENSE_SEGMENTS}
        # Per-segment breach counter (rolling window)
        self._recent_breaches: dict[str, int] = {s: 0 for s in DEFENSE_SEGMENTS}
        # Track breach rate trend
        self._breach_history: list[bool] = []
        # Dynamic safety margin (rises under pressure)
        self._safety_margin: float = BASE_SAFETY_MARGIN

    @property
    def safety_margin(self) -> float:
        """Dynamic safety margin that rises when breach rate increases."""
        return self._safety_margin

    def respond(
        self,
        genome: Genome,
        ctx: ThreatContext,
        red_win: bool,
        attacked_segment: str = "",
    ) -> Genome:
        """Evolve genome in response to Red agent's attack outcome."""
        self._round += 1
        if attacked_segment:
            self._attack_history.append(attacked_segment)
            # Track consecutive attacks on same segment
            for seg in DEFENSE_SEGMENTS:
                if seg == attacked_segment:
                    self._consecutive_attacks[seg] += 1
                else:
                    # Decay (not reset) -- Red might alternate targets
                    self._consecutive_attacks[seg] = max(0, self._consecutive_attacks[seg] - 1)

        if red_win and attacked_segment:
            self._breached_segments.append(attacked_segment)
            self._recent_breaches[attacked_segment] += 1

        # Track overall breach trend
        self._breach_history.append(red_win)

        # Adapt safety margin based on recent breach rate
        self._adapt_safety_margin()

        strategy = self._pick_strategy(genome, red_win, attacked_segment)

        if strategy == "repair":
            result = self._strategy_repair(genome, ctx, attacked_segment)
        elif strategy == "fortify":
            result = self._strategy_fortify(genome, ctx)
        elif strategy == "diversify":
            result = self._strategy_diversify(genome, ctx)
        elif strategy == "rotate":
            result = self._strategy_rotate(genome, ctx, attacked_segment)
        elif strategy == "reinforce":
            result = self._strategy_reinforce(genome, ctx)
        elif strategy == "synergize":
            result = self._strategy_synergize(genome, ctx)
        else:
            result = self._strategy_harden(genome, ctx)

        # POST-STRATEGY SAFETY NET: ensure no segment falls below floor
        # This prevents homeostasis/crossover/mutation from silently weakening segments
        result = self._enforce_density_floor(result, ctx)
        return result

    # ------------------------------------------------------------------
    # Adaptive safety margin
    # ------------------------------------------------------------------

    def _adapt_safety_margin(self) -> None:
        """Raise safety margin when breach rate trends upward."""
        window = 30
        recent = self._breach_history[-window:]
        if len(recent) < 5:
            return
        breach_rate = sum(recent) / len(recent)

        # Escalate margin under pressure
        if breach_rate > 0.4:
            self._safety_margin = min(0.85, self._safety_margin + 0.02)
        elif breach_rate > 0.2:
            self._safety_margin = min(0.80, self._safety_margin + 0.01)
        elif breach_rate < 0.05:
            # Slowly relax when safe (don't over-invest)
            self._safety_margin = max(BASE_SAFETY_MARGIN, self._safety_margin - 0.005)

    # ------------------------------------------------------------------
    # Strategy selection
    # ------------------------------------------------------------------

    def _pick_strategy(self, genome: Genome, red_win: bool, attacked_seg: str) -> Strategy:
        """Choose defense strategy based on situation."""
        # Breach -> always repair first
        if red_win:
            return "repair"

        # Detect sustained pressure (erode pattern): same segment hit 3+ times in a row
        if attacked_seg and self._consecutive_attacks.get(attacked_seg, 0) >= 3:
            # Alternate between rotate and synergize to counter erode
            if self._round % 2 == 0:
                return "rotate"
            return "synergize"

        # High recent breach rate -> synergize (not just reinforce)
        recent_window = self._breach_history[-20:]
        if len(recent_window) >= 10 and sum(recent_window) / len(recent_window) > 0.3:
            # Alternate: synergize builds pair defense, reinforce raises floor
            if self._round % 3 == 0:
                return "reinforce"
            return "synergize"

        # Check if any segment is dangerously close to threshold
        vulnerable = self._find_vulnerable_segments(genome)
        if vulnerable:
            return "fortify"

        # Periodically diversify to avoid predictability
        if self._round % 5 == 0 and self._round > 3:
            return "diversify"

        # Default: incremental hardening
        return "harden"

    def _find_vulnerable_segments(self, genome: Genome) -> list[str]:
        """Find segments within danger zone (below dynamic safety margin)."""
        return [
            seg for seg in DEFENSE_SEGMENTS
            if genome.density(seg) < self._safety_margin
        ]

    # ------------------------------------------------------------------
    # Strategies
    # ------------------------------------------------------------------

    def _strategy_repair(self, genome: Genome, ctx: ThreatContext, target: str) -> Genome:
        """Emergency repair: aggressively strengthen the breached segment."""
        best = genome
        best_fitness = evaluate(genome, ctx).final

        for _ in range(self._max_mutations):
            candidate = self._targeted_strengthen(genome, target, n_bits=4)
            # Also shore up other vulnerable segments
            for seg in self._find_vulnerable_segments(candidate):
                if seg != target:
                    candidate = self._targeted_strengthen(candidate, seg)
            candidate = apply_homeostasis(candidate, ctx)
            f = evaluate(candidate, ctx).final
            if f > best_fitness:
                best = candidate
                best_fitness = f

        return best

    def _strategy_fortify(self, genome: Genome, ctx: ThreatContext) -> Genome:
        """Proactively strengthen vulnerable segments before they get breached."""
        vulnerable = self._find_vulnerable_segments(genome)

        # Also consider frequently attacked segments (even if above threshold)
        freq_attacked = self._most_attacked_segments(top_k=2)
        priority = list(set(vulnerable + freq_attacked))

        best = genome
        best_fitness = evaluate(genome, ctx).final

        for _ in range(self._max_mutations):
            candidate = genome
            for seg in priority:
                if candidate.density(seg) < self._safety_margin:
                    candidate = self._targeted_strengthen(candidate, seg)
            candidate = point_mutation(candidate)
            candidate = apply_homeostasis(candidate, ctx)
            f = evaluate(candidate, ctx).final
            if f > best_fitness:
                best = candidate
                best_fitness = f

        return best

    def _strategy_diversify(self, genome: Genome, ctx: ThreatContext) -> Genome:
        """Crossover with a reference genome to introduce structural diversity.

        SAFETY: reject candidates that lower any segment below safety margin.
        """
        current_form = genome.form_id
        other_forms = [f for f in DefenseForm if f != current_form]
        donor_form = random.choice(other_forms)
        donor = build_form_genome(donor_form)

        best = genome
        best_fitness = evaluate(genome, ctx).final

        for _ in range(self._max_mutations):
            candidate = crossover(genome, donor)
            candidate = apply_homeostasis(candidate, ctx)
            # Safety check: don't accept if it weakens any segment below margin
            if any(candidate.density(s) < self._safety_margin - 0.05
                   for s in DEFENSE_SEGMENTS):
                continue
            f = evaluate(candidate, ctx).final
            if f > best_fitness:
                best = candidate
                best_fitness = f

        return best

    def _strategy_harden(self, genome: Genome, ctx: ThreatContext) -> Genome:
        """Incremental hardening: minor tuning + homeostasis.

        SAFETY: reject mutations that weaken any segment below margin.
        """
        best = genome
        best_fitness = evaluate(genome, ctx).final

        attempts = min(self._max_mutations // 3, 5)
        for _ in range(attempts):
            candidate = point_mutation(genome)
            candidate = apply_homeostasis(candidate, ctx)
            # Reject if any segment dropped dangerously
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
        """Rotation: shift density pattern to break sustained targeting.

        When Red uses erode (sustained pressure on one segment), simply
        repairing that segment is predictable. Rotation redistributes
        density across ALL segments, making the next erode attack hit
        a different density landscape.

        Key insight: erode works by building a mental model of the target's
        density. Rotation invalidates that model.
        """
        best = genome
        best_fitness = evaluate(genome, ctx).final

        for _ in range(self._max_mutations):
            candidate = genome

            # Strengthen the targeted segment aggressively
            candidate = self._targeted_strengthen(candidate, target_seg, n_bits=3)

            # Also strengthen a random other segment (unpredictable)
            other = random.choice([s for s in DEFENSE_SEGMENTS if s != target_seg])
            candidate = self._targeted_strengthen(candidate, other, n_bits=2)

            # Apply burst mutation for structural unpredictability
            candidate = burst_mutation(candidate)
            candidate = apply_homeostasis(candidate, ctx)

            f = evaluate(candidate, ctx).final
            if f > best_fitness:
                best = candidate
                best_fitness = f

        return best

    def _strategy_reinforce(self, genome: Genome, ctx: ThreatContext) -> Genome:
        """Mass reinforcement: raise ALL segments toward safety margin.

        Used when breach rate is trending up -- indicates Red's intensity
        is growing faster than Blue's per-segment repairs.
        """
        best = genome
        best_fitness = evaluate(genome, ctx).final

        for _ in range(self._max_mutations):
            candidate = genome

            # Strengthen every segment that's below safety margin
            for seg in DEFENSE_SEGMENTS:
                if candidate.density(seg) < self._safety_margin:
                    candidate = self._targeted_strengthen(candidate, seg, n_bits=3)

            # Even segments above margin get a small boost
            for seg in DEFENSE_SEGMENTS:
                if candidate.density(seg) < 0.85 and random.random() < 0.3:
                    candidate = self._targeted_strengthen(candidate, seg, n_bits=1)

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
        """Flip 0-bits to 1 in a specific segment to raise its density."""
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

    def _strategy_synergize(self, genome: Genome, ctx: ThreatContext) -> Genome:
        """Strengthen synergy pairs to boost the synergy defense bonus.

        The breach model gives a defense bonus when BOTH segments in a pair
        are strong. This strategy identifies the weakest synergy pair and
        strengthens both members simultaneously.

        Key insight: raising one segment from 60% to 80% is less effective
        than raising BOTH segments of a pair from 70% to 80% each.
        """
        from aegis.sandbox.breach_model import compute_synergy_bonus, _SYNERGY_PAIRS
        import math

        best = genome
        best_synergy = compute_synergy_bonus(genome)
        best_fitness = evaluate(genome, ctx).final

        # Find the weakest synergy pair
        weakest_pair = None
        weakest_strength = float("inf")
        for seg_a, seg_b, weight in _SYNERGY_PAIRS:
            pair_strength = math.sqrt(genome.density(seg_a) * genome.density(seg_b))
            if pair_strength < weakest_strength:
                weakest_strength = pair_strength
                weakest_pair = (seg_a, seg_b)

        for _ in range(self._max_mutations):
            candidate = genome

            # Strengthen both segments of the weakest pair
            if weakest_pair:
                candidate = self._targeted_strengthen(candidate, weakest_pair[0], n_bits=3)
                candidate = self._targeted_strengthen(candidate, weakest_pair[1], n_bits=3)

            # Also strengthen the most-attacked segment's synergy partners
            most_attacked = self._most_attacked_segments(top_k=1)
            if most_attacked:
                partners = SYNERGY_PRIORITY.get(most_attacked[0], [])
                for partner in partners[:2]:
                    candidate = self._targeted_strengthen(candidate, partner, n_bits=2)

            candidate = apply_homeostasis(candidate, ctx)
            new_synergy = compute_synergy_bonus(candidate)
            f = evaluate(candidate, ctx).final

            # Prefer candidates that improve BOTH synergy AND fitness
            if new_synergy > best_synergy or (new_synergy >= best_synergy and f > best_fitness):
                best = candidate
                best_synergy = new_synergy
                best_fitness = f

        return best

    def _enforce_density_floor(self, genome: Genome, ctx: ThreatContext) -> Genome:
        """Post-strategy safety net: raise any segment below dynamic floor.

        This is the LAST line of defense — no matter what strategy was used,
        we never return a genome with dangerously low segments.
        """
        floor = max(self._safety_margin - 0.05, BASE_SAFETY_MARGIN)
        needs_repair = [s for s in DEFENSE_SEGMENTS if genome.density(s) < floor]
        if not needs_repair:
            return genome

        candidate = genome
        for seg in needs_repair:
            # Aggressively strengthen until above floor
            attempts = 0
            while candidate.density(seg) < floor and attempts < 10:
                candidate = self._targeted_strengthen(candidate, seg, n_bits=3)
                attempts += 1

        return apply_homeostasis(candidate, ctx)

    def _most_attacked_segments(self, top_k: int = 2) -> list[str]:
        """Return segments most frequently attacked by Red."""
        if not self._attack_history:
            return []
        counts = Counter(self._attack_history)
        return [seg for seg, _ in counts.most_common(top_k)]
