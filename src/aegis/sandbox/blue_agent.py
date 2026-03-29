"""Blue agent -- Desperate defender with revolutionary defense systems.

Blue fights Red with EVERYTHING — traditional defense + novel systems
never seen before in conventional security architectures.

Strategy arsenal (14 total):
  CLASSIC:
  - Repair:        emergency fix on breached segment
  - Fortify:       proactively strengthen vulnerable segments
  - Diversify:     crossover with reference genome for structural diversity
  - Harden:        incremental tuning when stable
  - Rotate:        redistribute density to disrupt Red's targeting
  - Reinforce:     mass strengthening when breach rate spikes
  - Synergize:     optimize synergy pairs for multiplicative defense
  - Counter-intel: predict Red's next move and pre-empt
  - Lockdown:      emergency all-hands defense

  REVOLUTIONARY (NEW):
  - Immune response:  deploy antibodies for recognized attack patterns
  - Moving target:    shift defense surface to stale Red's intelligence
  - Self-heal:        autonomous recovery + scar tissue hardening
  - Honeypot deploy:  trap attackers and gather intelligence
  - Threat hunt:      proactively search for Red's attack infrastructure

Novel defense systems:
  - ImmuneMemory:        biological immune model (antibodies + memory cells)
  - MovingTargetDefense: constantly shifting attack surface
  - SelfHealingEngine:   autonomous segment recovery with scar tissue
  - HoneypotNetwork:     dynamic decoys for trapping + intel gathering
  - ThreatHunter:        proactive detection through pattern analysis
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
from aegis.sandbox.defense_systems import (
    HoneypotNetwork,
    ImmuneMemory,
    MovingTargetDefense,
    SelfHealingEngine,
    ThreatHunter,
)

DEFENSE_SEGMENTS = ["RTG", "ISO", "ATH", "DTX", "DCP", "RSP"]
BASE_SAFETY_MARGIN = 0.40

SYNERGY_PRIORITY = {
    "DTX": ["RSP", "DCP"], "DCP": ["DTX", "ISO"], "RTG": ["ISO", "DCP"],
    "ISO": ["ATH", "RTG"], "ATH": ["RSP", "ISO"], "RSP": ["DTX", "ATH"],
}

Strategy = Literal[
    "repair", "fortify", "diversify", "harden", "rotate",
    "reinforce", "synergize", "counter_intel", "lockdown",
    "immune_response", "moving_target", "self_heal",
    "honeypot_deploy", "threat_hunt",
]


class BlueAgent:
    """Desperate defender with revolutionary defense systems.

    Blue has access to:
    - Adaptive immune system (antibody defense against known patterns)
    - Moving target defense (topology rotation to stale Red intel)
    - Self-healing engine (autonomous recovery with scar tissue)
    - Honeypot network (decoys that trap and study Red)
    - Threat hunter (proactive search for Red infrastructure)
    """

    def __init__(self, max_mutations: int = 15) -> None:
        self._max_mutations = max_mutations
        self._breached_segments: list[str] = []
        self._attack_history: list[str] = []
        self._round = 0

        # --- Classic adaptive state ---
        self._consecutive_attacks: dict[str, int] = {s: 0 for s in DEFENSE_SEGMENTS}
        self._recent_breaches: dict[str, int] = {s: 0 for s in DEFENSE_SEGMENTS}
        self._breach_history: list[bool] = []
        self._safety_margin: float = BASE_SAFETY_MARGIN
        self._red_strategy_history: list[str] = []
        self._red_category_history: list[str] = []
        self._attack_sequence: list[str] = []
        self._emergency_threshold: float = 0.45
        self._rounds_since_breach: int = 0
        self._defense_outcomes: dict[str, list[bool]] = {}

        # --- Revolutionary defense systems ---
        self._immune = ImmuneMemory()
        self._mtd = MovingTargetDefense(rotation_interval=8)
        self._healer = SelfHealingEngine()
        self._honeypots = HoneypotNetwork()
        self._hunter = ThreatHunter()

    @property
    def safety_margin(self) -> float:
        return self._safety_margin

    @property
    def is_emergency(self) -> bool:
        window = 15
        recent = self._breach_history[-window:]
        if len(recent) < 5:
            return False
        return sum(recent) / len(recent) > self._emergency_threshold

    @property
    def immune_system(self) -> ImmuneMemory:
        return self._immune

    @property
    def honeypot_network(self) -> HoneypotNetwork:
        return self._honeypots

    def respond(
        self,
        genome: Genome,
        ctx: ThreatContext,
        red_win: bool,
        attacked_segment: str = "",
        red_strategy: str = "",
        attack_category: str = "",
    ) -> Genome:
        """Evolve genome in response. FIGHT WITH EVERYTHING."""
        self._round += 1

        # --- Feed all defense systems ---

        # 1. Immune system: learn from every encounter
        if attacked_segment and attack_category:
            self._immune.encounter_attack(
                category=attack_category,
                segment=attacked_segment,
                red_won=red_win,
                red_strategy=red_strategy,
            )

        # 2. Threat hunter: ingest attack data
        if attacked_segment:
            self._hunter.ingest_attack_data(
                segment=attacked_segment,
                category=attack_category,
                strategy=red_strategy,
            )

        # 3. Self-healer: register breaches
        if red_win and attacked_segment:
            self._healer.register_breach(attacked_segment)

        # 4. Deploy honeypots on frequently attacked segments
        if attacked_segment and self._consecutive_attacks.get(attacked_segment, 0) >= 2:
            attractiveness = min(0.8, 0.3 + self._consecutive_attacks[attacked_segment] * 0.1)
            self._honeypots.deploy_honeypot(attacked_segment, attractiveness)

        # --- Track Red's behavior ---
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

        # --- PASSIVE SYSTEMS (run every round) ---

        # Self-healing tick (autonomous recovery)
        heal_adjustments = self._healer.heal_tick()

        # Apply heal adjustments to genome BEFORE strategy
        if heal_adjustments:
            genome = self._apply_density_adjustments(genome, heal_adjustments)

        # --- Active strategy ---
        strategy = self._pick_strategy(genome, red_win, attacked_segment)
        result = self._execute_strategy(strategy, genome, ctx, attacked_segment)

        self._defense_outcomes.setdefault(strategy, []).append(not red_win)

        # POST-STRATEGY: enforce density floor + scar tissue bonus
        result = self._apply_scar_tissue(result)
        result = self._enforce_density_floor(result, ctx)
        return result

    def _execute_strategy(self, strategy, genome, ctx, target):
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
            "immune_response": lambda: self._strategy_immune_response(genome, ctx),
            "moving_target": lambda: self._strategy_moving_target(genome, ctx),
            "self_heal": lambda: self._strategy_self_heal(genome, ctx),
            "honeypot_deploy": lambda: self._strategy_honeypot_deploy(genome, ctx),
            "threat_hunt": lambda: self._strategy_threat_hunt(genome, ctx),
        }
        return dispatch[strategy]()

    # ------------------------------------------------------------------
    # Adaptive safety margin
    # ------------------------------------------------------------------

    def _adapt_safety_margin(self) -> None:
        window = 25
        recent = self._breach_history[-window:]
        if len(recent) < 5:
            return
        breach_rate = sum(recent) / len(recent)

        if breach_rate > 0.5:
            self._safety_margin = min(0.90, self._safety_margin + 0.03)
        elif breach_rate > 0.35:
            self._safety_margin = min(0.85, self._safety_margin + 0.02)
        elif breach_rate > 0.2:
            self._safety_margin = min(0.80, self._safety_margin + 0.01)
        elif breach_rate < 0.05 and self._rounds_since_breach > 10:
            self._safety_margin = max(BASE_SAFETY_MARGIN, self._safety_margin - 0.003)

    # ------------------------------------------------------------------
    # Strategy selection
    # ------------------------------------------------------------------

    def _pick_strategy(self, genome: Genome, red_win: bool, attacked_seg: str) -> Strategy:
        # EMERGENCY LOCKDOWN
        if self.is_emergency and red_win:
            return "lockdown"

        # Breach → immune response if we have antibodies, else repair
        if red_win:
            if attacked_seg:
                cat = self._red_category_history[-1] if self._red_category_history else ""
                immunity = self._immune.get_defense_bonus(cat, attacked_seg)
                if immunity > 0.10:
                    return "immune_response"
            return "repair"

        # Moving target defense rotation check
        if self._mtd.should_rotate():
            return "moving_target"

        # Self-healing active
        if self._healer.is_healing:
            return "self_heal"

        # Sustained pressure → use advanced defense
        if attacked_seg and self._consecutive_attacks.get(attacked_seg, 0) >= 3:
            # Cycle through advanced strategies
            cycle = self._round % 5
            if cycle == 0:
                return "counter_intel"
            elif cycle == 1:
                return "honeypot_deploy"
            elif cycle == 2:
                return "threat_hunt"
            elif cycle == 3:
                return "moving_target"
            return "synergize"

        # High breach rate → aggressive defense
        recent_window = self._breach_history[-20:]
        if len(recent_window) >= 10:
            breach_rate = sum(recent_window) / len(recent_window)
            if breach_rate > 0.35:
                return "lockdown"
            if breach_rate > 0.25:
                cycle = self._round % 4
                if cycle == 0:
                    return "reinforce"
                elif cycle == 1:
                    return "immune_response"
                elif cycle == 2:
                    return "threat_hunt"
                return "counter_intel"

        # Prediction-based defense
        predicted_target = self._predict_next_target()
        if predicted_target:
            if genome.density(predicted_target) < self._safety_margin + 0.05:
                return "counter_intel"

        # Vulnerable segments
        vulnerable = self._find_vulnerable_segments(genome)
        if vulnerable:
            return "fortify"

        # Periodic advanced defense rotation
        if self._round % 6 == 0 and self._round > 5:
            return "threat_hunt"
        if self._round % 5 == 0 and self._round > 3:
            return "diversify"
        if self._round % 4 == 0:
            return "synergize"
        if self._round % 7 == 0:
            return "honeypot_deploy"

        return "harden"

    def _find_vulnerable_segments(self, genome: Genome) -> list[str]:
        return [s for s in DEFENSE_SEGMENTS if genome.density(s) < self._safety_margin]

    def _predict_next_target(self) -> str | None:
        if len(self._attack_sequence) < 3:
            return None
        recent = self._attack_sequence[-10:]
        counts = Counter(recent)
        most_common = counts.most_common(1)[0]
        if most_common[1] >= 3:
            return most_common[0]
        if len(recent) >= 4:
            last_two = recent[-2:]
            if last_two[0] != last_two[1]:
                return last_two[-1]
        return None

    # ------------------------------------------------------------------
    # CLASSIC strategies (9)
    # ------------------------------------------------------------------

    def _strategy_repair(self, genome, ctx, target):
        best, best_f = genome, evaluate(genome, ctx).final
        for _ in range(self._max_mutations):
            c = self._targeted_strengthen(genome, target, n_bits=5)
            for seg in self._find_vulnerable_segments(c):
                if seg != target:
                    c = self._targeted_strengthen(c, seg, n_bits=2)
            predicted = self._predict_next_target()
            if predicted and predicted != target:
                c = self._targeted_strengthen(c, predicted, n_bits=2)
            c = apply_homeostasis(c, ctx)
            f = evaluate(c, ctx).final
            if f > best_f:
                best, best_f = c, f
        return best

    def _strategy_fortify(self, genome, ctx):
        vulnerable = self._find_vulnerable_segments(genome)
        freq = self._most_attacked_segments(top_k=2)
        predicted = self._predict_next_target()
        priority = list(set(vulnerable + freq + ([predicted] if predicted else [])))
        best, best_f = genome, evaluate(genome, ctx).final
        for _ in range(self._max_mutations):
            c = genome
            for seg in priority:
                if c.density(seg) < self._safety_margin:
                    c = self._targeted_strengthen(c, seg, n_bits=3)
            c = point_mutation(c)
            c = apply_homeostasis(c, ctx)
            f = evaluate(c, ctx).final
            if f > best_f:
                best, best_f = c, f
        return best

    def _strategy_diversify(self, genome, ctx):
        current_form = genome.form_id
        other_forms = [f for f in DefenseForm if f != current_form]
        donor = build_form_genome(random.choice(other_forms))
        best, best_f = genome, evaluate(genome, ctx).final
        for _ in range(self._max_mutations):
            c = crossover(genome, donor)
            c = apply_homeostasis(c, ctx)
            if any(c.density(s) < self._safety_margin - 0.05 for s in DEFENSE_SEGMENTS):
                continue
            f = evaluate(c, ctx).final
            if f > best_f:
                best, best_f = c, f
        return best

    def _strategy_harden(self, genome, ctx):
        best, best_f = genome, evaluate(genome, ctx).final
        for _ in range(min(self._max_mutations // 3, 5)):
            c = point_mutation(genome)
            c = apply_homeostasis(c, ctx)
            if any(c.density(s) < self._safety_margin - 0.05 for s in DEFENSE_SEGMENTS):
                continue
            f = evaluate(c, ctx).final
            if f > best_f:
                best, best_f = c, f
        if best is genome:
            best = apply_homeostasis(genome, ctx)
        return best

    def _strategy_rotate(self, genome, ctx, target_seg):
        best, best_f = genome, evaluate(genome, ctx).final
        for _ in range(self._max_mutations):
            c = self._targeted_strengthen(genome, target_seg, n_bits=4)
            others = [s for s in DEFENSE_SEGMENTS if s != target_seg]
            for o in random.sample(others, min(2, len(others))):
                c = self._targeted_strengthen(c, o, n_bits=2)
            c = burst_mutation(c)
            c = apply_homeostasis(c, ctx)
            f = evaluate(c, ctx).final
            if f > best_f:
                best, best_f = c, f
        return best

    def _strategy_reinforce(self, genome, ctx):
        best, best_f = genome, evaluate(genome, ctx).final
        for _ in range(self._max_mutations):
            c = genome
            for seg in DEFENSE_SEGMENTS:
                if c.density(seg) < self._safety_margin:
                    c = self._targeted_strengthen(c, seg, n_bits=4)
            for seg in DEFENSE_SEGMENTS:
                if c.density(seg) < 0.85 and random.random() < 0.4:
                    c = self._targeted_strengthen(c, seg, n_bits=2)
            c = apply_homeostasis(c, ctx)
            f = evaluate(c, ctx).final
            if f > best_f:
                best, best_f = c, f
        return best

    def _strategy_synergize(self, genome, ctx):
        from aegis.sandbox.breach_model import compute_synergy_bonus, _SYNERGY_PAIRS
        best, best_syn = genome, compute_synergy_bonus(genome)
        best_f = evaluate(genome, ctx).final
        weakest_pair = None
        weakest_str = float("inf")
        for a, b, w in _SYNERGY_PAIRS:
            s = math.sqrt(genome.density(a) * genome.density(b))
            if s < weakest_str:
                weakest_str = s
                weakest_pair = (a, b)
        for _ in range(self._max_mutations):
            c = genome
            if weakest_pair:
                c = self._targeted_strengthen(c, weakest_pair[0], n_bits=3)
                c = self._targeted_strengthen(c, weakest_pair[1], n_bits=3)
            most_attacked = self._most_attacked_segments(top_k=1)
            if most_attacked:
                for p in SYNERGY_PRIORITY.get(most_attacked[0], [])[:2]:
                    c = self._targeted_strengthen(c, p, n_bits=2)
            c = apply_homeostasis(c, ctx)
            ns = compute_synergy_bonus(c)
            f = evaluate(c, ctx).final
            if ns > best_syn or (ns >= best_syn and f > best_f):
                best, best_syn, best_f = c, ns, f
        return best

    def _strategy_counter_intel(self, genome, ctx):
        best, best_f = genome, evaluate(genome, ctx).final
        predicted = self._predict_next_target()
        most_attacked = self._most_attacked_segments(top_k=3)
        most_breached = sorted(self._recent_breaches.items(), key=lambda x: x[1], reverse=True)
        priority = []
        if predicted:
            priority.append(predicted)
        for seg, cnt in most_breached[:2]:
            if cnt > 0 and seg not in priority:
                priority.append(seg)
        for seg in most_attacked:
            if seg not in priority:
                priority.append(seg)
        if not priority:
            priority = self._find_vulnerable_segments(genome)
        for _ in range(self._max_mutations):
            c = genome
            for i, seg in enumerate(priority[:3]):
                c = self._targeted_strengthen(c, seg, n_bits=max(2, 5 - i))
            for seg in priority[:2]:
                for p in SYNERGY_PRIORITY.get(seg, [])[:1]:
                    c = self._targeted_strengthen(c, p, n_bits=2)
            c = apply_homeostasis(c, ctx)
            f = evaluate(c, ctx).final
            if f > best_f:
                best, best_f = c, f
        return best

    def _strategy_lockdown(self, genome, ctx):
        best, best_f = genome, evaluate(genome, ctx).final
        for _ in range(self._max_mutations * 2):
            c = genome
            for seg in DEFENSE_SEGMENTS:
                target = max(self._safety_margin + 0.10, 0.80)
                while c.density(seg) < target:
                    c = self._targeted_strengthen(c, seg, n_bits=5)
                    if c.density(seg) >= target:
                        break
            c = apply_homeostasis(c, ctx)
            f = evaluate(c, ctx).final
            if f > best_f:
                best, best_f = c, f
        return best

    # ------------------------------------------------------------------
    # REVOLUTIONARY strategies (5) — NEW
    # ------------------------------------------------------------------

    def _strategy_immune_response(self, genome: Genome, ctx: ThreatContext) -> Genome:
        """Deploy antibodies against recognized attack patterns.

        The immune system remembers every attack. When a known pattern
        returns, Blue activates targeted antibodies — faster and more
        effective than generic defense.

        Antibody defense: strengthen the specific segments that the
        immune system has identified as targets for this attack category.
        """
        best, best_f = genome, evaluate(genome, ctx).final

        # Get immune intelligence: which categories are most dangerous?
        dangerous_categories: list[tuple[str, float]] = []
        for cat_name in ["COMMODITY", "VOLUME", "APT", "ZERO_DAY", "INSIDER", "META_ATTACK"]:
            immunity = self._immune.get_category_immunity(cat_name)
            # Counter-intuitive: HIGH immunity means we've been hit often
            # — antibodies are strong but the threat is persistent
            if immunity > 0.1:
                dangerous_categories.append((cat_name, immunity))

        # Priority segments: where immune system has recorded breaches
        immune_priority = []
        for seg in DEFENSE_SEGMENTS:
            total_bonus = sum(
                self._immune.get_defense_bonus(cat, seg)
                for cat in ["COMMODITY", "VOLUME", "APT", "ZERO_DAY", "INSIDER", "META_ATTACK"]
            )
            if total_bonus > 0.15:
                immune_priority.append(seg)

        # If no immune priority, fall back to most attacked
        if not immune_priority:
            immune_priority = self._most_attacked_segments(top_k=3)

        for _ in range(self._max_mutations):
            c = genome
            # Strengthen segments where immune system detected threats
            for seg in immune_priority[:3]:
                c = self._targeted_strengthen(c, seg, n_bits=4)
            # Strengthen synergy partners of immunized segments
            for seg in immune_priority[:2]:
                for partner in SYNERGY_PRIORITY.get(seg, [])[:1]:
                    c = self._targeted_strengthen(c, partner, n_bits=2)
            c = apply_homeostasis(c, ctx)
            f = evaluate(c, ctx).final
            if f > best_f:
                best, best_f = c, f

        return best

    def _strategy_moving_target(self, genome: Genome, ctx: ThreatContext) -> Genome:
        """Shift defense topology to invalidate Red's intelligence.

        Moving Target Defense: rotate what Red thinks it knows.
        After rotation, Red's erosion pressure, vulnerability scores,
        and segment intelligence become partially stale.
        """
        # Get current densities
        current = {s: genome.density(s) for s in DEFENSE_SEGMENTS}

        # Get threatened segments from threat hunter
        threatened = self._hunter.get_priority_segments(top_k=3)
        if not threatened:
            threatened = self._most_attacked_segments(top_k=2)

        # Compute redistribution
        adjustments = self._mtd.compute_redistribution(current, threatened)

        # Apply adjustments to genome
        best = self._apply_density_adjustments(genome, adjustments)

        # Additional strengthening on threatened segments
        for seg in threatened[:2]:
            best = self._targeted_strengthen(best, seg, n_bits=3)

        # Diversify (crossover with random form) to further confuse Red
        current_form = genome.form_id
        other_forms = [f for f in DefenseForm if f != current_form]
        if other_forms:
            donor = build_form_genome(random.choice(other_forms))
            candidate = crossover(best, donor)
            candidate = apply_homeostasis(candidate, ctx)
            if evaluate(candidate, ctx).final > evaluate(best, ctx).final:
                if not any(candidate.density(s) < self._safety_margin - 0.05
                           for s in DEFENSE_SEGMENTS):
                    best = candidate

        return apply_homeostasis(best, ctx)

    def _strategy_self_heal(self, genome: Genome, ctx: ThreatContext) -> Genome:
        """Actively assist the self-healing engine.

        While the healer runs passively every round, this strategy
        allocates extra resources to accelerate recovery.
        Also applies scar tissue reinforcement.
        """
        best, best_f = genome, evaluate(genome, ctx).final

        healing_segs = self._healer.healing_segments

        for _ in range(self._max_mutations):
            c = genome
            # Prioritize healing segments
            for seg in healing_segs:
                c = self._targeted_strengthen(c, seg, n_bits=5)
            # Also strengthen scar tissue segments (they've been attacked before)
            for seg in DEFENSE_SEGMENTS:
                scar = self._healer.get_scar_bonus(seg)
                if scar > 0.02:
                    c = self._targeted_strengthen(c, seg, n_bits=2)
            c = apply_homeostasis(c, ctx)
            f = evaluate(c, ctx).final
            if f > best_f:
                best, best_f = c, f

        return best

    def _strategy_honeypot_deploy(self, genome: Genome, ctx: ThreatContext) -> Genome:
        """Deploy and optimize the honeypot network.

        Honeypots serve two purposes:
        1. Waste Red's attacks (misdirection)
        2. Gather intelligence on Red's methods

        This strategy deploys honeypots on the most attacked segments
        and strengthens the REAL defense behind them.
        """
        best, best_f = genome, evaluate(genome, ctx).final

        # Deploy honeypots on most attacked segments
        most_attacked = self._most_attacked_segments(top_k=3)
        for seg in most_attacked:
            attacks = self._consecutive_attacks.get(seg, 0)
            attractiveness = min(0.80, 0.40 + attacks * 0.08)
            self._honeypots.deploy_honeypot(seg, attractiveness)

        # Strengthen the REAL defense behind honeypots
        for _ in range(self._max_mutations):
            c = genome
            for seg in most_attacked:
                c = self._targeted_strengthen(c, seg, n_bits=3)
                # Also strengthen DCP (deception) to make honeypots more convincing
                c = self._targeted_strengthen(c, "DCP", n_bits=2)
            c = apply_homeostasis(c, ctx)
            f = evaluate(c, ctx).final
            if f > best_f:
                best, best_f = c, f

        return best

    def _strategy_threat_hunt(self, genome: Genome, ctx: ThreatContext) -> Genome:
        """Proactive threat hunting — find Red before Red finds us.

        Instead of reacting to attacks, Blue actively hunts for
        Red's attack infrastructure by analyzing patterns.
        """
        best, best_f = genome, evaluate(genome, ctx).final

        # Execute hunt
        threat_scores = self._hunter.hunt()
        priority = self._hunter.get_priority_segments(top_k=3)

        for _ in range(self._max_mutations):
            c = genome
            # Pre-emptively strengthen high-threat segments
            for i, seg in enumerate(priority):
                n_bits = max(2, 4 - i)
                c = self._targeted_strengthen(c, seg, n_bits=n_bits)
            # Strengthen DTX (detection) to improve hunting capability
            c = self._targeted_strengthen(c, "DTX", n_bits=3)
            # Strengthen DCP (deception) to confuse Red's recon
            c = self._targeted_strengthen(c, "DCP", n_bits=2)
            c = apply_homeostasis(c, ctx)
            f = evaluate(c, ctx).final
            if f > best_f:
                best, best_f = c, f

        return best

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _targeted_strengthen(self, genome: Genome, segment_name: str, n_bits: int = 3) -> Genome:
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

    def _apply_density_adjustments(
        self, genome: Genome, adjustments: dict[str, float],
    ) -> Genome:
        """Apply density adjustments from defense systems (healing, MTD)."""
        from aegis.common.types import SEGMENTS

        bits = list(genome.bits)
        for seg_name, seg_offset, seg_length in SEGMENTS:
            if seg_name in ("HDR", "CHK"):
                continue
            adj = adjustments.get(seg_name, 0.0)
            if abs(adj) < 0.001:
                continue

            current_on = sum(bits[seg_offset:seg_offset + seg_length])
            target_on = max(0, min(seg_length, round(current_on + adj * seg_length)))

            seg_bits = list(bits[seg_offset:seg_offset + seg_length])
            if target_on > current_on:
                off_indices = [i for i, b in enumerate(seg_bits) if b == 0]
                to_flip = min(target_on - current_on, len(off_indices))
                for i in random.sample(off_indices, to_flip) if off_indices else []:
                    seg_bits[i] = 1
            elif target_on < current_on:
                on_indices = [i for i, b in enumerate(seg_bits) if b == 1]
                to_flip = min(current_on - target_on, len(on_indices))
                for i in random.sample(on_indices, to_flip) if on_indices else []:
                    seg_bits[i] = 0
            bits[seg_offset:seg_offset + seg_length] = seg_bits

        return with_valid_checksum(tuple(bits))

    def _apply_scar_tissue(self, genome: Genome) -> Genome:
        """Apply scar tissue bonus from healed segments."""
        for seg in DEFENSE_SEGMENTS:
            scar = self._healer.get_scar_bonus(seg)
            if scar > 0.03:
                # Small permanent strengthening from scar tissue
                genome = self._targeted_strengthen(genome, seg, n_bits=1)
        return genome

    def _enforce_density_floor(self, genome: Genome, ctx: ThreatContext) -> Genome:
        floor = max(self._safety_margin - 0.05, BASE_SAFETY_MARGIN)
        needs_repair = [s for s in DEFENSE_SEGMENTS if genome.density(s) < floor]
        if not needs_repair:
            return genome
        c = genome
        for seg in needs_repair:
            attempts = 0
            while c.density(seg) < floor and attempts < 12:
                c = self._targeted_strengthen(c, seg, n_bits=4)
                attempts += 1
        return apply_homeostasis(c, ctx)

    def _most_attacked_segments(self, top_k: int = 2) -> list[str]:
        if not self._attack_history:
            return []
        return [seg for seg, _ in Counter(self._attack_history).most_common(top_k)]
