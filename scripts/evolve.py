"""AEGIS Evolutionary Feedback Loop.

Runs multiple generations of Red vs Blue battles.
After each generation, analyzes the battle log and applies model
improvements to the next generation's config.

    Generation 1: battle -> log -> analyze -> adapt
    Generation 2: battle (with improved config) -> log -> analyze -> adapt
    ...

Usage:
    python scripts/evolve.py [--generations N] [--rounds N] [--seed N]
"""

from __future__ import annotations

import argparse

from aegis.common.config import DetectionConfig, GenomeConfig
from aegis.common.types import DefenseForm, Genome, ThreatContext
from aegis.genome.codec import build_form_genome
from aegis.genome.fitness import evaluate
from aegis.sandbox.arena import Arena
from aegis.sandbox.battle_log import BattleLog
from aegis.sandbox.blue_agent import BlueAgent
from aegis.sandbox.memory import MemoryBank
from aegis.sandbox.model_adapter import ModelAdapter
from aegis.sandbox.red_agent import RedAgent


def run_generation(
    gen: int,
    genome: Genome,
    ctx: ThreatContext,
    genome_config: GenomeConfig,
    detection_config: DetectionConfig,
    rounds: int,
    seed: int | None,
    breach_threshold: float = 0.3,
) -> tuple[Genome, BattleLog]:
    """Run one generation of battles and return evolved genome + log."""
    red = RedAgent(seed=(seed + gen * 1000) if seed is not None else None)
    blue = BlueAgent(max_mutations=15)
    arena = Arena(red=red, blue=blue, breach_threshold=breach_threshold)
    battle_log = BattleLog()

    for rnd in range(1, rounds + 1):
        # Escalate threat over time
        escalation = min(rnd / rounds, 1.0)
        dynamic_ctx = ThreatContext(
            pressure=min(ctx.pressure + escalation * 0.3, 1.0),
            diversity=min(ctx.diversity + escalation * 0.2, 1.0),
            novelty=min(ctx.novelty + escalation * 0.2, 1.0),
        )

        f_before = evaluate(genome, dynamic_ctx, config=genome_config).final
        result = arena.battle(genome, dynamic_ctx)
        f_after = evaluate(result.genome_after, dynamic_ctx, config=genome_config).final

        battle_log.record(
            round_num=rnd,
            attack=result.attack,
            red_won=result.red_won,
            genome_before=result.genome_before,
            genome_after=result.genome_after,
            fitness_before=f_before,
            fitness_after=f_after,
            ctx=dynamic_ctx,
        )

        genome = result.genome_after

    return genome, battle_log


def print_analysis(gen: int, analysis) -> None:
    """Print battle analysis summary."""
    print(f"\n  {'─' * 62}")
    print(f"  GENERATION {gen} ANALYSIS")
    print(f"  {'─' * 62}")
    print(f"  Rounds: {analysis.total_rounds}  |  "
          f"Red wins: {analysis.red_wins} ({analysis.red_win_rate:.0%})  |  "
          f"Blue wins: {analysis.blue_wins}")
    print(f"  Fitness: {analysis.fitness_start:.4f} -> {analysis.fitness_end:.4f}  "
          f"(peak: {analysis.fitness_peak:.4f})")

    print(f"\n  Segment vulnerabilities:")
    for seg, v in analysis.segment_vulnerabilities.items():
        if v.times_attacked == 0:
            continue
        status = "BREACHED" if v.times_breached > 0 else "HELD"
        print(f"    {seg}: attacked {v.times_attacked}x, breached {v.times_breached}x "
              f"({v.breach_rate:.0%}) -{status}")

    if analysis.chronic_weaknesses:
        print(f"\n  Chronic weaknesses: {', '.join(analysis.chronic_weaknesses)}")

    print(f"\n  Red strategy effectiveness:")
    for strat, rate in analysis.strategy_effectiveness.items():
        bar = "#" * int(rate * 20) + "." * (20 - int(rate * 20))
        print(f"    {strat:>8}: [{bar}] {rate:.0%}")

    print(f"\n  Recommendations:")
    for i, rec in enumerate(analysis.recommendations, 1):
        print(f"    {i}. {rec}")


def print_patch(patch) -> None:
    """Print model adjustments."""
    if not patch.adjustments:
        print(f"\n  No model adjustments needed.")
        return

    print(f"\n  MODEL ADJUSTMENTS ({len(patch.adjustments)} changes):")
    for adj in patch.adjustments:
        print(f"    [{adj.target}] {adj.old_value} -> {adj.new_value}")
        print(f"      Reason: {adj.reason}")

    if any(v > 0.30 for v in patch.min_density_floors.values()):
        elevated = {s: f for s, f in patch.min_density_floors.items() if f > 0.30}
        print(f"\n  Density floors raised: {elevated}")


def main() -> None:
    parser = argparse.ArgumentParser(description="AEGIS Evolutionary Feedback Loop")
    parser.add_argument("--generations", type=int, default=3, help="Number of generations")
    parser.add_argument("--rounds", type=int, default=20, help="Rounds per generation")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--form", type=str, default="ALPHA",
                        choices=["ALPHA", "BETA", "GAMMA", "DELTA"])
    args = parser.parse_args()

    form = DefenseForm[args.form]
    genome = build_form_genome(form)
    ctx = ThreatContext(pressure=0.5, diversity=0.4, novelty=0.3)
    genome_config = GenomeConfig()
    detection_config = DetectionConfig()

    print("=" * 66)
    print("  AEGIS EVOLUTIONARY FEEDBACK LOOP")
    print("=" * 66)
    print(f"  Generations: {args.generations}  |  Rounds/gen: {args.rounds}  |  Seed: {args.seed}")
    print(f"  Initial form: {form.name}  |  Initial fitness: {evaluate(genome, ctx).final:.4f}")

    all_logs: list[BattleLog] = []

    for gen in range(1, args.generations + 1):
        # Red escalation: breach threshold rises each generation
        # Gen 1: 0.30, Gen 2: 0.35, Gen 3: 0.40, ...
        breach_threshold = min(0.30 + (gen - 1) * 0.05, 0.55)

        print(f"\n{'*' * 66}")
        print(f"  GENERATION {gen}  (breach threshold: {breach_threshold:.2f})")
        print(f"{'*' * 66}")

        # Run battles
        genome, battle_log = run_generation(
            gen=gen,
            genome=genome,
            ctx=ctx,
            genome_config=genome_config,
            detection_config=detection_config,
            rounds=args.rounds,
            seed=args.seed,
            breach_threshold=breach_threshold,
        )
        all_logs.append(battle_log)

        # Analyze
        analysis = battle_log.analyze()
        print_analysis(gen, analysis)

        # Adapt model
        adapter = ModelAdapter(genome_config, detection_config)
        patch = adapter.adapt(analysis)
        print_patch(patch)

        # Apply improvements for next generation
        genome_config = patch.genome_config
        detection_config = patch.detection_config

        # Show current state
        f = evaluate(genome, ctx, config=genome_config).final
        print(f"\n  Post-adaptation fitness: {f:.4f}")
        print(f"  Genome densities: ", end="")
        for seg in ["RTG", "ISO", "ATH", "DTX", "DCP", "RSP"]:
            print(f"{seg}={genome.density(seg):.0%} ", end="")
        print()

    # Final summary
    print(f"\n{'=' * 66}")
    print(f"  EVOLUTION COMPLETE -{args.generations} GENERATIONS")
    print(f"  {'─' * 62}")
    initial_f = evaluate(build_form_genome(form), ctx).final
    final_f = evaluate(genome, ctx, config=genome_config).final
    print(f"  Fitness:  {initial_f:.4f} -> {final_f:.4f}  ({final_f - initial_f:+.4f})")
    print(f"  Red win rate by generation:")
    for i, log in enumerate(all_logs, 1):
        a = log.analyze()
        bar = "#" * int(a.red_win_rate * 30) + "." * (30 - int(a.red_win_rate * 30))
        print(f"    Gen {i}: [{bar}] {a.red_win_rate:.0%}")

    print(f"\n  Final config adjustments persisted:")
    print(f"    Fitness weights: cov={genome_config.w_coverage:.2f} eff={genome_config.w_efficiency:.2f} "
          f"adapt={genome_config.w_adaptability:.2f} syn={genome_config.w_synergy:.2f} "
          f"ctx={genome_config.w_threat_match:.2f}")
    print(f"    L3 trigger: {detection_config.l3_trigger_threshold}")
    print(f"    L5 semantic: {detection_config.l5_semantic_threshold}")
    print(f"  {'=' * 62}")


if __name__ == "__main__":
    main()
