"""Sandbox battle arena -- Red vs Blue continuous evolution loop.

The arena orchestrates attack-defense cycles with advanced systems:
  1. Red generates attack (using kill chains, zero-day discovery, etc.)
  2. Honeypot network checks if Red stumbles into a trap
  3. Immune system provides defense bonus for known attack patterns
  4. Breach model evaluates success per attack category
  5. Blue evolves genome using all defense systems
  6. Both sides learn from the outcome
"""

from __future__ import annotations

from dataclasses import dataclass

from aegis.common.types import Genome, ThreatContext
from aegis.sandbox.battle_log import BattleLog
from aegis.sandbox.breach_model import evaluate_breach
from aegis.sandbox.red_agent import AttackScenario, RedAgent
from aegis.sandbox.blue_agent import BlueAgent


@dataclass
class BattleResult:
    """Outcome of a single battle round."""

    round_num: int
    attack: AttackScenario
    red_won: bool
    genome_before: Genome
    genome_after: Genome
    fitness_delta: float
    honeypot_trapped: bool = False   # Did Red hit a honeypot?
    immune_bonus: float = 0.0        # Immune system defense bonus


BREACH_THRESHOLD = 0.3


class Arena:
    """Orchestrates Red vs Blue battles with advanced defense systems."""

    def __init__(
        self,
        red: RedAgent | None = None,
        blue: BlueAgent | None = None,
        breach_threshold: float = BREACH_THRESHOLD,
    ) -> None:
        self._red = red or RedAgent()
        self._blue = blue or BlueAgent()
        self._breach_threshold = breach_threshold
        self._round = 0
        self._history: list[BattleResult] = []
        self._battle_log = BattleLog()

    def battle(self, genome: Genome, ctx: ThreatContext) -> BattleResult:
        """Run one Red vs Blue battle round."""
        self._round += 1
        attack = self._red.generate_attack(genome)

        honeypot_trapped = False
        immune_bonus = 0.0

        # --- HONEYPOT CHECK ---
        # If Blue has deployed honeypots, Red might attack a decoy
        honeypot_trapped = self._blue.honeypot_network.check_trap(
            target_segment=attack.target_segment,
            red_intensity=getattr(attack, "intensity", 1.0),
            rng=self._red._rng,
        )

        if honeypot_trapped:
            # Red attacked a honeypot — attack is wasted
            red_won = False
            # Honeypot reduces erosion on the real segment
            hp_reduction = self._blue.honeypot_network.erosion_reduction(
                attack.target_segment
            )
            self._red._erosion_pressure[attack.target_segment] = max(
                0.0,
                self._red._erosion_pressure.get(attack.target_segment, 0.0) - hp_reduction,
            )
        else:
            # --- IMMUNE SYSTEM BONUS ---
            immune_bonus = self._blue.immune_system.get_defense_bonus(
                category=attack.category.name,
                segment=attack.target_segment,
            )

            # Category-specific breach evaluation
            breach_result = evaluate_breach(
                genome=genome,
                target_segment=attack.target_segment,
                category=attack.category,
                intensity=getattr(attack, "intensity", 1.0),
                base_threshold=self._breach_threshold,
                multi_targets=attack.multi_targets,
                rng=self._red._rng,
                erosion_pressure=self._red._erosion_pressure.get(
                    attack.target_segment, 0.0
                ),
                immune_bonus=immune_bonus,
                stealth_rating=getattr(attack, "stealth_rating", 0.0),
            )
            red_won = breach_result.breached

        # Red learns from outcome
        self._red.record_outcome(attack, red_won)

        # Blue defense decay on Red's erosion
        if not red_won and not honeypot_trapped:
            seg = attack.target_segment
            decay = 0.05
            self._red._erosion_pressure[seg] = max(
                0.0, self._red._erosion_pressure.get(seg, 0.0) - decay
            )
            for other_seg in ["RTG", "ISO", "ATH", "DTX", "DCP", "RSP"]:
                if other_seg != seg:
                    self._red._erosion_pressure[other_seg] = max(
                        0.0, self._red._erosion_pressure.get(other_seg, 0.0) - 0.01
                    )

        # Feed Red's strategy to Red's defense pattern tracker
        # (Red also analyzes Blue's responses)
        # Blue responds
        evolved = self._blue.respond(
            genome, ctx, red_won,
            attacked_segment=attack.target_segment,
            red_strategy=attack.strategy,
            attack_category=attack.category.name,
        )

        # Let Red track Blue's defense patterns
        # (Blue's strategy choice is visible through genome changes)
        if hasattr(self._red, 'record_blue_strategy'):
            # Infer Blue's strategy from density changes
            density_changes = sum(
                abs(evolved.density(s) - genome.density(s))
                for s in ["RTG", "ISO", "ATH", "DTX", "DCP", "RSP"]
            )
            # Large changes → Blue is panicking (lockdown/reinforce)
            # Small changes → Blue is calm (harden/synergize)
            if density_changes > 0.3:
                self._red.record_blue_strategy("aggressive_defense")
            elif density_changes > 0.1:
                self._red.record_blue_strategy("moderate_defense")
            else:
                self._red.record_blue_strategy("passive_defense")

        from aegis.genome.fitness import evaluate

        f_before = evaluate(genome, ctx).final
        f_after = evaluate(evolved, ctx).final

        result = BattleResult(
            round_num=self._round,
            attack=attack,
            red_won=red_won,
            genome_before=genome,
            genome_after=evolved,
            fitness_delta=f_after - f_before,
            honeypot_trapped=honeypot_trapped,
            immune_bonus=immune_bonus,
        )
        self._history.append(result)

        self._battle_log.record(
            round_num=self._round,
            attack=attack,
            red_won=red_won,
            genome_before=genome,
            genome_after=evolved,
            fitness_before=f_before,
            fitness_after=f_after,
            ctx=ctx,
        )

        return result

    @property
    def history(self) -> list[BattleResult]:
        return list(self._history)

    @property
    def win_rate(self) -> float:
        if not self._history:
            return 0.0
        return sum(1 for r in self._history if r.red_won) / len(self._history)

    @property
    def round_count(self) -> int:
        return self._round

    @property
    def battle_log(self) -> BattleLog:
        return self._battle_log
