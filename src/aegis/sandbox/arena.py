"""Sandbox battle arena -- Red vs Blue continuous evolution loop.

The arena orchestrates attack-defense cycles:
  1. Red generates an attack targeting genome weaknesses
  2. Attack success is determined by segment density vs effective threshold
  3. Blue evolves the genome in response
  4. Red learns from outcome for next round

Breach mechanic:
  breach when density < threshold * intensity
  - threshold: base difficulty (0.3 -> 0.5 over campaign)
  - intensity: Red's attack power (1.0x -> 2.5x as Red adapts)
  This means a fortified 70% segment CAN be breached by a 2.0x intensity attack
  when threshold is 0.40 (effective = 0.80 > 0.70 = breach).
"""

from __future__ import annotations

from dataclasses import dataclass

from aegis.common.types import Genome, ThreatContext
from aegis.sandbox.battle_log import BattleLog
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


BREACH_THRESHOLD = 0.3


class Arena:
    """Orchestrates Red vs Blue battles with adaptive difficulty."""

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

        # Effective threshold = base * intensity
        # A 2.0x intensity attack against 0.40 threshold -> effective 0.80
        # If segment density < 0.80 -> breach
        effective_threshold = min(
            0.95,  # Hard cap: even max intensity can't breach >95%
            self._breach_threshold * getattr(attack, "intensity", 1.0),
        )

        # Determine breach: check all targets for multi-target attacks
        if attack.multi_targets:
            red_won = any(
                genome.density(seg) < effective_threshold
                for seg in attack.multi_targets
            )
        else:
            red_won = genome.density(attack.target_segment) < effective_threshold

        # Red learns from outcome
        self._red.record_outcome(attack, red_won)

        # Blue responds (pass attack details for learning)
        evolved = self._blue.respond(
            genome, ctx, red_won,
            attacked_segment=attack.target_segment,
        )

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
        )
        self._history.append(result)

        # Record in structured battle log
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
        """Red win rate across all rounds."""
        if not self._history:
            return 0.0
        return sum(1 for r in self._history if r.red_won) / len(self._history)

    @property
    def round_count(self) -> int:
        return self._round

    @property
    def battle_log(self) -> BattleLog:
        """Access the structured battle log for analysis."""
        return self._battle_log
