"""Sandbox battle arena -- Red vs Blue continuous evolution loop.

The arena orchestrates attack-defense cycles:
  1. Red generates an attack targeting genome weaknesses
  2. Breach model evaluates success per attack category
  3. Blue evolves the genome in response
  4. Red learns from outcome for next round

Breach models (category-specific):
  COMMODITY:   density check -- basic defense blocks basic attacks
  VOLUME:      fatigue model -- sustained pressure degrades defense
  APT:         penetration model -- slow cumulative progress
  ZERO_DAY:    probabilistic -- can breach even strong defense
  INSIDER:     auth bypass -- ATH effectiveness halved
  META_ATTACK: pipeline target -- attacks detection itself
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
        )
        red_won = breach_result.breached

        # Red learns from outcome
        self._red.record_outcome(attack, red_won)

        # Blue successful defense partially decays Red's erosion
        # Models real-world: key rotation, topology change, honeypot redeployment
        # Decay is less than erosion gain (0.05/fail) -- attacker has initiative
        if not red_won:
            seg = attack.target_segment
            decay = 0.03  # Modest: defense is harder than attack
            self._red._erosion_pressure[seg] = max(
                0.0, self._red._erosion_pressure.get(seg, 0.0) - decay
            )

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
