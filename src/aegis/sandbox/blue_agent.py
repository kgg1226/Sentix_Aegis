"""Blue agent — Defensive AI for the sandbox arena.

Responds to Red agent attacks by mutating the genome.
Winning mutations are promoted to the live system.
"""
from __future__ import annotations
from aegis.common.types import Genome, ThreatContext
from aegis.genome.operators import point_mutation, burst_mutation
from aegis.genome.fitness import evaluate
from aegis.genome.homeostasis import apply_homeostasis

class BlueAgent:
    def __init__(self, max_mutations: int = 10) -> None:
        self._max_mutations = max_mutations

    def respond(self, genome: Genome, ctx: ThreatContext, red_win: bool) -> Genome:
        """Evolve genome in response to Red agent's attack outcome."""
        if not red_win:
            return apply_homeostasis(genome, ctx)
        best = genome
        best_fitness = evaluate(genome, ctx).final
        for _ in range(self._max_mutations):
            candidate = burst_mutation(genome, count=3)
            candidate = apply_homeostasis(candidate, ctx)
            f = evaluate(candidate, ctx).final
            if f > best_fitness:
                best = candidate
                best_fitness = f
        return best
