"""Structured battle log — persistent record of all Red vs Blue outcomes.

Records every round with full context, then supports querying for
vulnerability patterns, breach frequency, and segment-level statistics.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence


@dataclass(frozen=True, slots=True)
class BattleRecord:
    """Single round in the battle log."""

    round_num: int
    timestamp: str                     # ISO 8601
    red_strategy: str                  # exploit / probe / blitz / pivot
    attack_category: str               # ThreatCategory name
    target_segment: str                # Primary target
    multi_targets: tuple[str, ...]     # All targets (blitz)
    evasion_layer: str                 # Detection layer the attack aims to bypass
    target_density_before: float       # Density of target segment before attack
    red_won: bool
    fitness_before: float
    fitness_after: float
    fitness_delta: float
    genome_densities_before: dict[str, float]
    genome_densities_after: dict[str, float]
    threat_pressure: float
    threat_diversity: float
    threat_novelty: float


@dataclass
class SegmentVulnerability:
    """Aggregated vulnerability profile for one segment."""

    segment: str
    times_attacked: int
    times_breached: int
    breach_rate: float                 # breached / attacked
    avg_density_at_breach: float       # mean density when breach occurred
    min_density_observed: float
    attack_categories: dict[str, int]  # category -> count


@dataclass
class BattleAnalysis:
    """Full analysis output from a battle log."""

    total_rounds: int
    red_wins: int
    blue_wins: int
    red_win_rate: float
    fitness_start: float
    fitness_end: float
    fitness_peak: float
    fitness_improvement: float

    segment_vulnerabilities: dict[str, SegmentVulnerability]
    chronic_weaknesses: list[str]      # Segments breached 2+ times
    evasion_hotspots: dict[str, int]   # Detection layer -> times targeted
    strategy_effectiveness: dict[str, float]  # Red strategy -> success rate

    recommendations: list[str]         # Human-readable improvement actions


class BattleLog:
    """Accumulates battle records and produces vulnerability analyses."""

    def __init__(self) -> None:
        self._records: list[BattleRecord] = []

    def record(
        self,
        round_num: int,
        attack,  # AttackScenario
        red_won: bool,
        genome_before,  # Genome
        genome_after,  # Genome
        fitness_before: float,
        fitness_after: float,
        ctx,  # ThreatContext
    ) -> BattleRecord:
        """Record a single battle round."""
        seg_names = ["RTG", "ISO", "ATH", "DTX", "DCP", "RSP"]

        entry = BattleRecord(
            round_num=round_num,
            timestamp=datetime.now(timezone.utc).isoformat(),
            red_strategy=getattr(attack, "strategy", "unknown"),
            attack_category=attack.category.name,
            target_segment=attack.target_segment,
            multi_targets=getattr(attack, "multi_targets", ()),
            evasion_layer=attack.expected_evasion_layer,
            target_density_before=genome_before.density(attack.target_segment),
            red_won=red_won,
            fitness_before=fitness_before,
            fitness_after=fitness_after,
            fitness_delta=fitness_after - fitness_before,
            genome_densities_before={s: genome_before.density(s) for s in seg_names},
            genome_densities_after={s: genome_after.density(s) for s in seg_names},
            threat_pressure=ctx.pressure,
            threat_diversity=ctx.diversity,
            threat_novelty=ctx.novelty,
        )
        self._records.append(entry)
        return entry

    @property
    def records(self) -> list[BattleRecord]:
        return list(self._records)

    @property
    def size(self) -> int:
        return len(self._records)

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def analyze(self) -> BattleAnalysis:
        """Produce a full vulnerability analysis from the battle log."""
        if not self._records:
            return BattleAnalysis(
                total_rounds=0, red_wins=0, blue_wins=0, red_win_rate=0.0,
                fitness_start=0.0, fitness_end=0.0, fitness_peak=0.0,
                fitness_improvement=0.0, segment_vulnerabilities={},
                chronic_weaknesses=[], evasion_hotspots={},
                strategy_effectiveness={}, recommendations=[],
            )

        red_wins = sum(1 for r in self._records if r.red_won)
        total = len(self._records)
        fitnesses = [self._records[0].fitness_before] + [
            r.fitness_after for r in self._records
        ]

        # Per-segment analysis
        seg_vulns = self._analyze_segments()

        # Chronic weaknesses: breached 2+ times
        chronic = [
            s for s, v in seg_vulns.items()
            if v.times_breached >= 2
        ]

        # Evasion hotspots
        evasion: dict[str, int] = Counter()
        for r in self._records:
            evasion[r.evasion_layer] += 1

        # Red strategy effectiveness
        strat_eff = self._analyze_strategy_effectiveness()

        # Generate recommendations
        recs = self._generate_recommendations(seg_vulns, chronic, evasion, strat_eff)

        return BattleAnalysis(
            total_rounds=total,
            red_wins=red_wins,
            blue_wins=total - red_wins,
            red_win_rate=red_wins / total if total else 0.0,
            fitness_start=fitnesses[0],
            fitness_end=fitnesses[-1],
            fitness_peak=max(fitnesses),
            fitness_improvement=fitnesses[-1] - fitnesses[0],
            segment_vulnerabilities=seg_vulns,
            chronic_weaknesses=chronic,
            evasion_hotspots=dict(evasion),
            strategy_effectiveness=strat_eff,
            recommendations=recs,
        )

    def _analyze_segments(self) -> dict[str, SegmentVulnerability]:
        seg_names = ["RTG", "ISO", "ATH", "DTX", "DCP", "RSP"]
        result: dict[str, SegmentVulnerability] = {}

        for seg in seg_names:
            attacked = [r for r in self._records if seg in self._targets_of(r)]
            breached = [r for r in attacked if r.red_won]
            categories: dict[str, int] = Counter()
            for r in attacked:
                categories[r.attack_category] += 1

            densities_at_breach = [
                r.genome_densities_before[seg] for r in breached
            ]
            all_densities = [
                r.genome_densities_before[seg] for r in self._records
            ]

            result[seg] = SegmentVulnerability(
                segment=seg,
                times_attacked=len(attacked),
                times_breached=len(breached),
                breach_rate=len(breached) / len(attacked) if attacked else 0.0,
                avg_density_at_breach=(
                    sum(densities_at_breach) / len(densities_at_breach)
                    if densities_at_breach else 0.0
                ),
                min_density_observed=min(all_densities) if all_densities else 0.0,
                attack_categories=dict(categories),
            )

        return result

    def _analyze_strategy_effectiveness(self) -> dict[str, float]:
        strat_groups: dict[str, list[bool]] = {}
        for r in self._records:
            strat_groups.setdefault(r.red_strategy, []).append(r.red_won)
        return {
            strat: sum(wins) / len(wins) if wins else 0.0
            for strat, wins in strat_groups.items()
        }

    def _targets_of(self, record: BattleRecord) -> list[str]:
        if record.multi_targets:
            return list(record.multi_targets)
        return [record.target_segment]

    # ------------------------------------------------------------------
    # Recommendations
    # ------------------------------------------------------------------

    def _generate_recommendations(
        self,
        seg_vulns: dict[str, SegmentVulnerability],
        chronic: list[str],
        evasion: dict[str, int],
        strat_eff: dict[str, float],
    ) -> list[str]:
        recs: list[str] = []

        # Chronic weaknesses
        for seg in chronic:
            v = seg_vulns[seg]
            recs.append(
                f"CRITICAL: {seg} breached {v.times_breached} times "
                f"(avg density at breach: {v.avg_density_at_breach:.2f}). "
                f"Raise minimum density floor to {max(0.45, v.avg_density_at_breach + 0.20):.2f}."
            )

        # High breach-rate segments (even if not chronic)
        for seg, v in seg_vulns.items():
            if v.breach_rate > 0.3 and seg not in chronic:
                recs.append(
                    f"WARNING: {seg} has {v.breach_rate:.0%} breach rate. "
                    f"Consider increasing {seg} weight in homeostasis target."
                )

        # Segments never attacked but low density
        for seg, v in seg_vulns.items():
            if v.times_attacked == 0 and v.min_density_observed < 0.30:
                recs.append(
                    f"BLIND SPOT: {seg} never attacked but density as low as "
                    f"{v.min_density_observed:.2f}. Red may not have discovered it yet."
                )

        # Detection layer evasion patterns
        most_targeted_layer = max(evasion, key=evasion.get) if evasion else None
        if most_targeted_layer:
            count = evasion[most_targeted_layer]
            recs.append(
                f"EVASION PATTERN: {most_targeted_layer} targeted {count} times "
                f"({count / len(self._records):.0%} of attacks). "
                f"Strengthen {most_targeted_layer} detection sensitivity."
            )

        # Effective Red strategies
        for strat, rate in strat_eff.items():
            if rate > 0.3:
                recs.append(
                    f"RED STRATEGY: '{strat}' has {rate:.0%} success rate. "
                    f"Blue needs counter-strategy for {strat} attacks."
                )

        if not recs:
            recs.append("No critical vulnerabilities detected. Continue monitoring.")

        return recs

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str | Path) -> None:
        """Save battle log to JSON file."""
        data = [
            {
                **{k: v for k, v in asdict(r).items() if k != "multi_targets"},
                "multi_targets": list(r.multi_targets),
            }
            for r in self._records
        ]
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> BattleLog:
        """Load battle log from JSON file."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        log = cls()
        for d in data:
            d["multi_targets"] = tuple(d["multi_targets"])
            log._records.append(BattleRecord(**d))
        return log
