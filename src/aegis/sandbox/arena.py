"""Sandbox battle arena — Red vs Blue continuous evolution loop."""
from __future__ import annotations
from dataclasses import dataclass
from aegis.common.types import Genome, ThreatContext
from aegis.sandbox.red_agent import RedAgent, AttackScenario
from aegis.sandbox.blue_agent import BlueAgent

@dataclass
class BattleResult:
    round_num: int
    attack: AttackScenario
    red_won: bool
    genome_before: Genome
    genome_after: Genome
    fitness_delta: float

class Arena:
    def __init__(self, red: RedAgent | None = None, blue: BlueAgent | None = None) -> None:
        self._red = red or RedAgent()
        self._blue = blue or BlueAgent()
        self._round = 0
        self._history: list[BattleResult] = []

    def battle(self, genome: Genome, ctx: ThreatContext) -> BattleResult:
        """Run one Red vs Blue battle round."""
        self._round += 1
        attack = self._red.generate_attack(genome)
        # Simulate: Red wins if target segment density is below threshold
        target_density = genome.density(attack.target_segment)
        red_won = target_density < 0.3
        evolved = self._blue.respond(genome, ctx, red_won)
        from aegis.genome.fitness import evaluate
        f_before = evaluate(genome, ctx).final
        f_after = evaluate(evolved, ctx).final
        result = BattleResult(
            round_num=self._round, attack=attack, red_won=red_won,
            genome_before=genome, genome_after=evolved,
            fitness_delta=f_after - f_before,
        )
        self._history.append(result)
        return result

    @property
    def win_rate(self) -> float:
        if not self._history: return 0.0
        return sum(1 for r in self._history if r.red_won) / len(self._history)
