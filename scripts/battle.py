"""AEGIS Red vs Blue Battle Simulator.

Runs a configurable number of rounds where:
  - Red Agent probes the genome's weakest segments
  - Blue Agent evolves the genome in response to breaches
  - Memory Bank records all attack fingerprints

Usage:
    python scripts/battle.py [--rounds N] [--form ALPHA|BETA|GAMMA|DELTA] [--seed N]
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass

from aegis.common.types import DefenseForm, Genome, ThreatContext
from aegis.genome.codec import build_form_genome, validate_checksum
from aegis.genome.fitness import evaluate
from aegis.sandbox.arena import Arena
from aegis.sandbox.red_agent import RedAgent
from aegis.sandbox.blue_agent import BlueAgent
from aegis.sandbox.memory import MemoryBank


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

FORM_ICONS = {
    DefenseForm.ALPHA: "Alpha (layered)",
    DefenseForm.BETA: "Beta (mesh)",
    DefenseForm.GAMMA: "Gamma (deception)",
    DefenseForm.DELTA: "Delta (fortress)",
}

CATEGORY_ICONS = {
    "COMMODITY": "Script kiddie",
    "VOLUME": "DDoS / Brute",
    "APT": "APT (low-and-slow)",
    "ZERO_DAY": "Zero-day exploit",
    "META_ATTACK": "Meta (anti-AEGIS)",
    "INSIDER": "Insider threat",
}


def segment_bar(genome: Genome, name: str, width: int = 20) -> str:
    density = genome.density(name)
    filled = int(density * width)
    return f"{name} [{'#' * filled}{'.' * (width - filled)}] {density:.0%}"


def print_genome_state(genome: Genome, ctx: ThreatContext, label: str = "") -> None:
    result = evaluate(genome, ctx)
    form = FORM_ICONS.get(genome.form_id, str(genome.form_id))
    print(f"\n  {'=' * 58}")
    if label:
        print(f"  {label}")
    print(f"  Form: {form}  |  Fitness: {result.final:.4f}  |  CRC: {'OK' if validate_checksum(genome) else 'FAIL'}")
    print(f"  Scores: cov={result.scores['coverage']:.2f}  eff={result.scores['efficiency']:.2f}  "
          f"adapt={result.scores['adaptability']:.2f}  syn={result.scores['synergy']:.2f}  "
          f"ctx={result.scores['threat_match']:.2f}")
    print(f"  {'─' * 58}")
    for seg in ["RTG", "ISO", "ATH", "DTX", "DCP", "RSP"]:
        print(f"    {segment_bar(genome, seg)}")
    print(f"  {'=' * 58}")


STRATEGY_LABELS = {
    "exploit": "EXPLOIT (weakest point)",
    "probe": "PROBE (recon)",
    "blitz": "BLITZ (multi-vector)",
    "pivot": "PIVOT (repeat success)",
}


def print_round(rnd: int, total: int, result, memory: MemoryBank) -> None:
    cat_name = result.attack.category.name
    cat_desc = CATEGORY_ICONS.get(cat_name, cat_name)
    status = "RED WINS" if result.red_won else "BLUE HOLDS"
    delta_sign = "+" if result.fitness_delta >= 0 else ""
    strat = STRATEGY_LABELS.get(result.attack.strategy, result.attack.strategy)

    print(f"\n  Round {rnd:>3}/{total}  |  {status}")
    print(f"  Strategy: {strat}")
    if result.attack.multi_targets:
        targets = ", ".join(result.attack.multi_targets)
        print(f"  Attack: {cat_desc}  ->  segments [{targets}]  "
              f"(evading {result.attack.expected_evasion_layer})")
    else:
        print(f"  Attack: {cat_desc}  ->  segment {result.attack.target_segment}  "
              f"(evading {result.attack.expected_evasion_layer})")
    print(f"  Target density: {result.genome_before.density(result.attack.target_segment):.2f}  "
          f"(threshold: 0.30)")
    # Show vulnerable segments after this round
    vulnerable = [
        seg for seg in ["RTG", "ISO", "ATH", "DTX", "DCP", "RSP"]
        if result.genome_after.density(seg) < 0.40
    ]
    vuln_str = ", ".join(f"{s}({result.genome_after.density(s):.0%})" for s in vulnerable) if vulnerable else "none"
    print(f"  Fitness delta: {delta_sign}{result.fitness_delta:.4f}  "
          f"|  Memory bank: {memory.size} fingerprints")
    print(f"  Vulnerable: {vuln_str}")


# ---------------------------------------------------------------------------
# Battle loop
# ---------------------------------------------------------------------------


def run_battle(
    rounds: int = 20,
    form: DefenseForm = DefenseForm.ALPHA,
    seed: int | None = None,
    threat_pressure: float = 0.5,
    threat_diversity: float = 0.4,
    threat_novelty: float = 0.3,
) -> None:
    ctx = ThreatContext(
        pressure=threat_pressure,
        diversity=threat_diversity,
        novelty=threat_novelty,
    )
    red = RedAgent(seed=seed)
    blue = BlueAgent(max_mutations=15)
    arena = Arena(red=red, blue=blue)
    memory = MemoryBank()

    genome = build_form_genome(form)

    print("\n" + "=" * 62)
    print("  AEGIS Red vs Blue Battle Arena")
    print("=" * 62)
    print(f"  Rounds: {rounds}  |  Seed: {seed or 'random'}")
    print(f"  Threat context: pressure={ctx.pressure}  diversity={ctx.diversity}  novelty={ctx.novelty}")

    print_genome_state(genome, ctx, "INITIAL GENOME")

    # Track stats
    red_wins = 0
    blue_wins = 0
    fitness_history: list[float] = [evaluate(genome, ctx).final]

    # Phase markers
    phases = [
        (1, "PHASE 1: RECONNAISSANCE"),
        (rounds // 3, "PHASE 2: ESCALATION"),
        (2 * rounds // 3, "PHASE 3: ADAPTATION"),
    ]
    phase_idx = 0

    for rnd in range(1, rounds + 1):
        # Phase announcements
        if phase_idx < len(phases) and rnd == phases[phase_idx][0]:
            print(f"\n  {'*' * 58}")
            print(f"  {phases[phase_idx][1]}")
            print(f"  {'*' * 58}")
            phase_idx += 1

        # Escalate threat over time
        escalation = min(rnd / rounds, 1.0)
        dynamic_ctx = ThreatContext(
            pressure=min(ctx.pressure + escalation * 0.3, 1.0),
            diversity=min(ctx.diversity + escalation * 0.2, 1.0),
            novelty=min(ctx.novelty + escalation * 0.2, 1.0),
        )

        result = arena.battle(genome, dynamic_ctx)

        # Record in memory bank
        attack_data = {
            "category": result.attack.category.name,
            "target_segment": result.attack.target_segment,
            "vector": result.attack.vector,
        }
        memory.record(attack_data, success=result.red_won, round_num=rnd)

        if result.red_won:
            red_wins += 1
        else:
            blue_wins += 1

        print_round(rnd, rounds, result, memory)

        # Blue evolves
        genome = result.genome_after
        fitness_history.append(evaluate(genome, dynamic_ctx).final)

    # Final report
    final_ctx = ThreatContext(
        pressure=min(ctx.pressure + 0.3, 1.0),
        diversity=min(ctx.diversity + 0.2, 1.0),
        novelty=min(ctx.novelty + 0.2, 1.0),
    )
    print_genome_state(genome, final_ctx, "FINAL EVOLVED GENOME")

    print(f"\n  {'=' * 58}")
    print(f"  BATTLE REPORT")
    print(f"  {'─' * 58}")
    print(f"  Total rounds: {rounds}")
    print(f"  Red wins:  {red_wins:>3}  ({red_wins/rounds:.0%})")
    print(f"  Blue wins: {blue_wins:>3}  ({blue_wins/rounds:.0%})")
    print(f"  {'─' * 58}")
    print(f"  Starting fitness: {fitness_history[0]:.4f}")
    print(f"  Final fitness:    {fitness_history[-1]:.4f}")
    print(f"  Peak fitness:     {max(fitness_history):.4f}")
    print(f"  Fitness delta:    {fitness_history[-1] - fitness_history[0]:+.4f}")
    print(f"  {'─' * 58}")
    print(f"  Memory bank: {memory.size} attack fingerprints recorded")
    print(f"  CRC integrity: {'VALID' if validate_checksum(genome) else 'CORRUPTED'}")
    print(f"  {'=' * 58}")

    # Segment evolution summary
    initial = build_form_genome(form)
    print(f"\n  Segment evolution (initial -> final):")
    for seg in ["RTG", "ISO", "ATH", "DTX", "DCP", "RSP"]:
        d0 = initial.density(seg)
        d1 = genome.density(seg)
        arrow = "+" if d1 > d0 else "-" if d1 < d0 else "="
        print(f"    {seg}: {d0:.2f} -> {d1:.2f}  ({arrow}{abs(d1-d0):.2f})")
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="AEGIS Red vs Blue Battle Simulator")
    parser.add_argument("--rounds", type=int, default=20, help="Number of battle rounds")
    parser.add_argument("--form", type=str, default="ALPHA",
                        choices=["ALPHA", "BETA", "GAMMA", "DELTA"],
                        help="Initial defense form")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility")
    parser.add_argument("--pressure", type=float, default=0.5, help="Threat pressure [0-1]")
    parser.add_argument("--diversity", type=float, default=0.4, help="Threat diversity [0-1]")
    parser.add_argument("--novelty", type=float, default=0.3, help="Threat novelty [0-1]")

    args = parser.parse_args()
    form = DefenseForm[args.form]

    run_battle(
        rounds=args.rounds,
        form=form,
        seed=args.seed,
        threat_pressure=args.pressure,
        threat_diversity=args.diversity,
        threat_novelty=args.novelty,
    )


if __name__ == "__main__":
    main()
