"""AEGIS 1000-Battle Campaign — 3 rounds per battle, mutual escalation.

Each battle (3 rounds):
  Round 1: Red probes, Blue defends
  Round 2: Both adapt from Round 1 outcome
  Round 3: Full escalation — Red uses best-known vector, Blue at max effort

Between battles: learnings persist (Red's memory, Blue's history).
Every 100 battles: checkpoint analysis + model adaptation.

After 1000 battles: generate final ModelPatch and apply to source code.

Usage:
    python scripts/campaign.py [--battles 1000] [--seed 42]
"""

from __future__ import annotations

import argparse
import sys
import time
from collections import Counter
from dataclasses import dataclass

from aegis.common.config import DetectionConfig, GenomeConfig
from aegis.common.types import DefenseForm, Genome, ThreatContext
from aegis.genome.codec import build_form_genome
from aegis.genome.fitness import evaluate
from aegis.sandbox.arena import Arena
from aegis.sandbox.battle_log import BattleLog
from aegis.sandbox.blue_agent import BlueAgent
from aegis.sandbox.model_adapter import ModelAdapter
from aegis.sandbox.red_agent import RedAgent


@dataclass
class BattleOutcome:
    battle_num: int
    red_round_wins: int       # 0-3
    blue_round_wins: int      # 0-3
    winner: str               # "red" | "blue" | "draw"
    fitness_start: float
    fitness_end: float
    segments_breached: list[str]


def run_campaign(
    n_battles: int = 1000,
    rounds_per_battle: int = 3,
    seed: int = 42,
    form: DefenseForm = DefenseForm.ALPHA,
) -> None:
    # Persistent agents — learnings carry across all battles
    red = RedAgent(seed=seed)
    blue = BlueAgent(max_mutations=15)

    genome = build_form_genome(form)
    genome_config = GenomeConfig()
    detection_config = DetectionConfig()

    cumulative_log = BattleLog()
    outcomes: list[BattleOutcome] = []

    # Tracking
    red_battle_wins = 0
    blue_battle_wins = 0
    draws = 0

    print("=" * 70)
    print("  AEGIS 1000-BATTLE CAMPAIGN (3 rounds/battle)")
    print("=" * 70)
    print(f"  Battles: {n_battles}  |  Rounds/battle: {rounds_per_battle}  |  Seed: {seed}")
    print(f"  Initial form: {form.name}  |  Fitness: {evaluate(genome, ThreatContext(0.5, 0.4, 0.3)).final:.4f}")
    t0 = time.monotonic()

    checkpoint_interval = max(n_battles // 10, 1)

    for battle in range(1, n_battles + 1):
        # Threat escalates over the campaign
        progress = battle / n_battles
        ctx = ThreatContext(
            pressure=min(0.3 + progress * 0.5, 0.95),
            diversity=min(0.3 + progress * 0.3, 0.80),
            novelty=min(0.2 + progress * 0.3, 0.70),
        )

        # Breach threshold escalates: starts easy, gets harder
        breach_threshold = 0.30 + progress * 0.20  # 0.30 -> 0.50

        arena = Arena(red=red, blue=blue, breach_threshold=breach_threshold)
        f_start = evaluate(genome, ctx, config=genome_config).final

        red_rw = 0
        blue_rw = 0
        breached_segs: list[str] = []

        # --- 3 rounds within this battle ---
        for rnd in range(1, rounds_per_battle + 1):
            # Intra-battle escalation
            rnd_ctx = ThreatContext(
                pressure=min(ctx.pressure + (rnd - 1) * 0.05, 1.0),
                diversity=min(ctx.diversity + (rnd - 1) * 0.03, 1.0),
                novelty=min(ctx.novelty + (rnd - 1) * 0.05, 1.0),
            )

            result = arena.battle(genome, rnd_ctx)

            # Record in cumulative log
            f_b = evaluate(result.genome_before, rnd_ctx, config=genome_config).final
            f_a = evaluate(result.genome_after, rnd_ctx, config=genome_config).final
            cumulative_log.record(
                round_num=(battle - 1) * rounds_per_battle + rnd,
                attack=result.attack,
                red_won=result.red_won,
                genome_before=result.genome_before,
                genome_after=result.genome_after,
                fitness_before=f_b,
                fitness_after=f_a,
                ctx=rnd_ctx,
            )

            if result.red_won:
                red_rw += 1
                breached_segs.append(result.attack.target_segment)
            else:
                blue_rw += 1

            genome = result.genome_after

        # Determine battle winner (best of 3)
        if red_rw > blue_rw:
            winner = "red"
            red_battle_wins += 1
        elif blue_rw > red_rw:
            winner = "blue"
            blue_battle_wins += 1
        else:
            winner = "draw"
            draws += 1

        f_end = evaluate(genome, ctx, config=genome_config).final

        outcomes.append(BattleOutcome(
            battle_num=battle, red_round_wins=red_rw, blue_round_wins=blue_rw,
            winner=winner, fitness_start=f_start, fitness_end=f_end,
            segments_breached=breached_segs,
        ))

        # --- Checkpoint every N battles ---
        if battle % checkpoint_interval == 0:
            elapsed = time.monotonic() - t0
            recent = outcomes[-checkpoint_interval:]
            recent_red = sum(1 for o in recent if o.winner == "red")
            recent_blue = sum(1 for o in recent if o.winner == "blue")
            recent_draws = sum(1 for o in recent if o.winner == "draw")
            recent_breaches = Counter(
                seg for o in recent for seg in o.segments_breached
            )

            print(f"\n  --- Checkpoint: Battle {battle}/{n_battles} "
                  f"({elapsed:.1f}s) threshold={breach_threshold:.2f} ---")
            print(f"  Last {checkpoint_interval}: "
                  f"Red {recent_red} | Blue {recent_blue} | Draw {recent_draws}")
            print(f"  Breaches: {dict(recent_breaches) if recent_breaches else 'none'}")
            print(f"  Fitness: {f_end:.4f}  |  "
                  f"Genome: ", end="")
            for seg in ["RTG", "ISO", "ATH", "DTX", "DCP", "RSP"]:
                print(f"{seg}={genome.density(seg):.0%} ", end="")
            print()

            # Mid-campaign adaptation
            if battle % (checkpoint_interval * 2) == 0 and battle < n_battles:
                analysis = cumulative_log.analyze()
                adapter = ModelAdapter(genome_config, detection_config)
                patch = adapter.adapt(analysis)
                genome_config = patch.genome_config
                detection_config = patch.detection_config
                n_adj = len(patch.adjustments)
                if n_adj > 0:
                    print(f"  >> Mid-campaign adaptation: {n_adj} adjustments applied")

    # =================================================================
    # FINAL ANALYSIS
    # =================================================================
    elapsed_total = time.monotonic() - t0
    analysis = cumulative_log.analyze()
    adapter = ModelAdapter(genome_config, detection_config)
    final_patch = adapter.adapt(analysis)

    print(f"\n{'=' * 70}")
    print(f"  CAMPAIGN COMPLETE - {n_battles} battles, "
          f"{n_battles * rounds_per_battle} rounds ({elapsed_total:.1f}s)")
    print(f"{'=' * 70}")

    print(f"\n  BATTLE RECORD:")
    print(f"    Red wins:  {red_battle_wins:>4}  ({red_battle_wins/n_battles:.0%})")
    print(f"    Blue wins: {blue_battle_wins:>4}  ({blue_battle_wins/n_battles:.0%})")
    print(f"    Draws:     {draws:>4}  ({draws/n_battles:.0%})")

    print(f"\n  FITNESS TRAJECTORY:")
    print(f"    Start:  {outcomes[0].fitness_start:.4f}")
    print(f"    End:    {outcomes[-1].fitness_end:.4f}")
    print(f"    Peak:   {max(o.fitness_end for o in outcomes):.4f}")
    print(f"    Delta:  {outcomes[-1].fitness_end - outcomes[0].fitness_start:+.4f}")

    # Win rate over time (quartiles)
    q = n_battles // 4
    for i, label in enumerate(["Q1 (early)", "Q2", "Q3", "Q4 (late)"]):
        chunk = outcomes[i * q:(i + 1) * q]
        rw = sum(1 for o in chunk if o.winner == "red")
        bw = sum(1 for o in chunk if o.winner == "blue")
        bar_r = "#" * (rw * 20 // len(chunk))
        bar_b = "#" * (bw * 20 // len(chunk))
        print(f"    {label:>12}: Red [{bar_r:<20}] {rw/len(chunk):.0%}  "
              f"Blue [{bar_b:<20}] {bw/len(chunk):.0%}")

    print(f"\n  SEGMENT VULNERABILITY (cumulative {analysis.total_rounds} rounds):")
    for seg, v in analysis.segment_vulnerabilities.items():
        if v.times_attacked == 0:
            continue
        bar = "#" * int(v.breach_rate * 30)
        print(f"    {seg}: attacked {v.times_attacked:>4}x  "
              f"breached {v.times_breached:>4}x  [{bar:<30}] {v.breach_rate:.0%}")

    if analysis.chronic_weaknesses:
        print(f"\n  CHRONIC WEAKNESSES: {', '.join(analysis.chronic_weaknesses)}")

    print(f"\n  RED STRATEGY EFFECTIVENESS:")
    for strat, rate in sorted(analysis.strategy_effectiveness.items(), key=lambda x: -x[1]):
        bar = "#" * int(rate * 30)
        print(f"    {strat:>8}: [{bar:<30}] {rate:.0%}")

    print(f"\n  EVASION LAYER TARGETING:")
    for layer, count in sorted(analysis.evasion_hotspots.items(), key=lambda x: -x[1]):
        print(f"    {layer}: {count} attacks ({count/analysis.total_rounds:.0%})")

    print(f"\n  RECOMMENDATIONS:")
    for i, rec in enumerate(analysis.recommendations, 1):
        print(f"    {i}. {rec}")

    # Final model patch
    print(f"\n  FINAL MODEL PATCH ({len(final_patch.adjustments)} adjustments):")
    for adj in final_patch.adjustments:
        print(f"    {adj.target}: {adj.old_value} -> {adj.new_value}")

    print(f"\n  DENSITY FLOORS:")
    for seg in ["RTG", "ISO", "ATH", "DTX", "DCP", "RSP"]:
        floor = final_patch.min_density_floors.get(seg, 0.30)
        current = genome.density(seg)
        status = "OK" if current >= floor else "BELOW"
        print(f"    {seg}: floor={floor:.2f}  current={current:.0%}  [{status}]")

    print(f"\n  FINAL CONFIG:")
    gc = final_patch.genome_config
    dc = final_patch.detection_config
    print(f"    Fitness weights: cov={gc.w_coverage:.3f} eff={gc.w_efficiency:.3f} "
          f"adapt={gc.w_adaptability:.3f} syn={gc.w_synergy:.3f} ctx={gc.w_threat_match:.3f}")
    print(f"    L3 trigger: {dc.l3_trigger_threshold}")
    print(f"    L2 z-score: {dc.l2_zscore_threshold}")
    print(f"    L5 semantic: {dc.l5_semantic_threshold}")
    print(f"  {'=' * 66}")

    # Write patch data for code application
    _write_patch_summary(final_patch, analysis, genome)


def _write_patch_summary(patch, analysis, genome) -> None:
    """Write machine-readable patch for code application."""
    import json
    from pathlib import Path

    data = {
        "genome_config": {
            "w_coverage": patch.genome_config.w_coverage,
            "w_efficiency": patch.genome_config.w_efficiency,
            "w_adaptability": patch.genome_config.w_adaptability,
            "w_synergy": patch.genome_config.w_synergy,
            "w_threat_match": patch.genome_config.w_threat_match,
        },
        "detection_config": {
            "l3_trigger_threshold": patch.detection_config.l3_trigger_threshold,
            "l2_zscore_threshold": patch.detection_config.l2_zscore_threshold,
            "l5_semantic_threshold": patch.detection_config.l5_semantic_threshold,
        },
        "density_floors": patch.min_density_floors,
        "homeostasis_overrides": patch.homeostasis_overrides,
        "chronic_weaknesses": analysis.chronic_weaknesses,
        "adjustments": [
            {"target": a.target, "old": a.old_value, "new": a.new_value, "reason": a.reason}
            for a in patch.adjustments
        ],
    }
    out = Path("campaign_patch.json")
    out.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    print(f"\n  Patch written to {out.resolve()}")


def main() -> None:
    parser = argparse.ArgumentParser(description="AEGIS 1000-Battle Campaign")
    parser.add_argument("--battles", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--form", type=str, default="ALPHA",
                        choices=["ALPHA", "BETA", "GAMMA", "DELTA"])
    args = parser.parse_args()

    run_campaign(
        n_battles=args.battles,
        seed=args.seed,
        form=DefenseForm[args.form],
    )


if __name__ == "__main__":
    main()
