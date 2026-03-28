"""Red agent -- Offensive AI for the sandbox arena.

Generates attack scenarios targeting the current genome's weaknesses.
Learns from every outcome and adapts strategy, intensity, and targeting.

Strategy mix:
  - Exploit: target the weakest segment (highest success probability)
  - Probe: target a random segment to find new weaknesses
  - Blitz: multi-segment coordinated attack
  - Pivot: re-attack a previously successful vector
  - Erode: sustained pressure on a single segment to wear it down
  - Cascade: chain attacks across related segments

Adaptive mechanics:
  - Attack intensity scales with consecutive failures
  - Per-segment success tracking drives targeting
  - Strategy weights shift based on win/loss patterns
  - Breach power accumulates from repeated probing
"""

from __future__ import annotations

import math
import random
from collections import Counter
from dataclasses import dataclass, field
from typing import Literal

from aegis.common.types import Genome, ThreatCategory

ATTACK_SEGMENTS = ["RTG", "ISO", "ATH", "DTX", "DCP", "RSP"]

Strategy = Literal["exploit", "probe", "blitz", "pivot", "erode", "cascade"]


@dataclass(frozen=True, slots=True)
class AttackScenario:
    """A single Red agent attack plan."""

    category: ThreatCategory
    vector: str
    target_segment: str
    events: list[dict]
    expected_evasion_layer: str  # Which detection layer this aims to bypass
    strategy: Strategy = "exploit"
    multi_targets: tuple[str, ...] = ()  # For blitz attacks
    intensity: float = 1.0  # Attack power multiplier (1.0 = baseline)


class RedAgent:
    """Offensive AI that adapts its strategy based on battle history."""

    def __init__(self, seed: int | None = None) -> None:
        self._rng = random.Random(seed)
        self._successful_vectors: list[str] = []
        self._failed_segments: list[str] = []
        self._round = 0

        # --- Adaptive learning state ---
        # Per-segment attack history: segment -> [True/False, ...]
        self._segment_outcomes: dict[str, list[bool]] = {s: [] for s in ATTACK_SEGMENTS}
        # Consecutive failure counter (resets on any win)
        self._consecutive_failures: int = 0
        # Per-strategy win tracking
        self._strategy_outcomes: dict[str, list[bool]] = {}
        # Accumulated "erosion" pressure per segment
        self._erosion_pressure: dict[str, float] = {s: 0.0 for s in ATTACK_SEGMENTS}
        # Last attack info for chaining
        self._last_target: str = ""
        self._last_won: bool = False

    @property
    def intensity(self) -> float:
        """Current attack intensity based on failure frustration.

        Starts at 1.0, grows with consecutive failures up to 2.5x.
        Models a real attacker who escalates tools and effort.
        """
        # Logarithmic growth: intensity = 1.0 + 0.3 * ln(1 + failures)
        return 1.0 + 0.3 * math.log1p(self._consecutive_failures)

    def generate_attack(self, genome: Genome) -> AttackScenario:
        """Generate attack using adaptive strategy selection."""
        self._round += 1
        strategy = self._pick_strategy(genome)
        attack = self._dispatch_strategy(strategy, genome)
        return attack

    def record_outcome(self, attack: AttackScenario, red_won: bool) -> None:
        """Learn from battle outcome to inform future strategy."""
        # Basic history
        if red_won:
            self._successful_vectors.append(attack.vector)
            self._consecutive_failures = 0
        else:
            self._failed_segments.append(attack.target_segment)
            self._consecutive_failures += 1

        # Per-segment tracking
        self._segment_outcomes[attack.target_segment].append(red_won)
        for seg in attack.multi_targets:
            if seg != attack.target_segment:
                self._segment_outcomes[seg].append(red_won)

        # Per-strategy tracking
        strat = attack.strategy
        self._strategy_outcomes.setdefault(strat, []).append(red_won)

        # Erosion: even failed attacks accumulate pressure
        erosion_gain = 0.15 if red_won else 0.05
        self._erosion_pressure[attack.target_segment] += erosion_gain
        for seg in attack.multi_targets:
            self._erosion_pressure[seg] += erosion_gain * 0.5

        # Decay erosion on non-attacked segments (Blue repairs them)
        for seg in ATTACK_SEGMENTS:
            if seg != attack.target_segment and seg not in attack.multi_targets:
                self._erosion_pressure[seg] = max(0, self._erosion_pressure[seg] - 0.02)

        self._last_target = attack.target_segment
        self._last_won = red_won

    # ------------------------------------------------------------------
    # Strategy selection
    # ------------------------------------------------------------------

    def _pick_strategy(self, genome: Genome) -> Strategy:
        """Weighted random strategy based on battle phase, history, and state."""
        base_weights: dict[str, float] = {
            "exploit": 0.25,
            "probe": 0.15,
            "blitz": 0.20,
            "pivot": 0.10,
            "erode": 0.15,
            "cascade": 0.15,
        }

        # Phase adjustment: early = probe, late = blitz + cascade
        if self._round <= 5:
            base_weights["probe"] += 0.20
            base_weights["blitz"] -= 0.10
            base_weights["cascade"] -= 0.10
        elif self._round > 20:
            base_weights["blitz"] += 0.10
            base_weights["cascade"] += 0.10
            base_weights["probe"] -= 0.10

        # Frustration: many consecutive failures -> prefer blitz and erode
        if self._consecutive_failures > 5:
            frustration_boost = min(0.25, self._consecutive_failures * 0.03)
            base_weights["blitz"] += frustration_boost
            base_weights["erode"] += frustration_boost * 0.8
            base_weights["exploit"] -= frustration_boost * 0.5

        # If last attack won, boost pivot
        if self._last_won and self._successful_vectors:
            base_weights["pivot"] += 0.20
            base_weights["probe"] = max(0.05, base_weights["probe"] - 0.10)

        # If we have high erosion on any segment, boost erode
        max_erosion = max(self._erosion_pressure.values()) if self._erosion_pressure else 0
        if max_erosion > 0.3:
            base_weights["erode"] += 0.15

        # Strategy-specific win rate boosts
        for strat, outcomes in self._strategy_outcomes.items():
            if len(outcomes) >= 3:
                win_rate = sum(outcomes[-10:]) / len(outcomes[-10:])
                if win_rate > 0.3:
                    base_weights[strat] = base_weights.get(strat, 0.1) + 0.15

        # Normalize and select
        strategies = list(base_weights.keys())
        probs = [max(0.02, w) for w in base_weights.values()]
        total = sum(probs)
        probs = [p / total for p in probs]
        return self._rng.choices(strategies, weights=probs, k=1)[0]  # type: ignore[return-value]

    def _dispatch_strategy(self, strategy: Strategy, genome: Genome) -> AttackScenario:
        dispatch = {
            "exploit": self._attack_exploit,
            "probe": self._attack_probe,
            "blitz": self._attack_blitz,
            "pivot": self._attack_pivot,
            "erode": self._attack_erode,
            "cascade": self._attack_cascade,
        }
        return dispatch[strategy](genome)

    # ------------------------------------------------------------------
    # Attack strategies
    # ------------------------------------------------------------------

    def _attack_exploit(self, genome: Genome) -> AttackScenario:
        """Target the weakest segment, factoring in erosion pressure."""
        # Score = low density + high erosion -> better target
        scores = {
            seg: (1.0 - genome.density(seg)) + self._erosion_pressure.get(seg, 0) * 0.5
            for seg in ATTACK_SEGMENTS
        }
        ranked = sorted(scores, key=scores.get, reverse=True)  # type: ignore[arg-type]
        target = self._rng.choice(ranked[:2])
        return self._build_scenario(genome, target, "exploit")

    def _attack_probe(self, genome: Genome) -> AttackScenario:
        """Randomly probe to discover weaknesses, avoiding recent failures."""
        # Prefer segments we haven't attacked much
        attack_counts = {s: len(v) for s, v in self._segment_outcomes.items()}
        min_count = min(attack_counts.values()) if attack_counts else 0
        # Under-explored segments
        candidates = [s for s, c in attack_counts.items() if c <= min_count + 2]
        if not candidates:
            candidates = ATTACK_SEGMENTS
        # Avoid segments that recently failed
        recent_fails = self._failed_segments[-3:]
        filtered = [s for s in candidates if s not in recent_fails]
        target = self._rng.choice(filtered or candidates)
        return self._build_scenario(genome, target, "probe")

    def _attack_blitz(self, genome: Genome) -> AttackScenario:
        """Coordinated multi-segment attack at higher intensity."""
        n_targets = self._rng.randint(2, min(4, 2 + self._consecutive_failures // 5))
        ranked = sorted(ATTACK_SEGMENTS, key=lambda s: genome.density(s))
        targets = ranked[:n_targets]
        primary = targets[0]

        scenario = self._build_scenario(genome, primary, "blitz")
        extra_events: list[dict] = []
        for t in targets[1:]:
            extra_events.extend(self._build_events(self._pick_category(t), t))
        return AttackScenario(
            category=scenario.category,
            vector=f"blitz_{'_'.join(t.lower() for t in targets)}",
            target_segment=primary,
            events=scenario.events + extra_events,
            expected_evasion_layer=scenario.expected_evasion_layer,
            strategy="blitz",
            multi_targets=tuple(targets),
            intensity=self.intensity * 1.2,  # Blitz gets bonus intensity
        )

    def _attack_pivot(self, genome: Genome) -> AttackScenario:
        """Re-use a previously successful attack vector with escalation."""
        if not self._successful_vectors:
            return self._attack_exploit(genome)

        past = self._rng.choice(self._successful_vectors[-10:])  # Prefer recent successes
        parts = past.split("_")
        target = parts[-1].upper() if parts[-1].upper() in ATTACK_SEGMENTS else self._rng.choice(ATTACK_SEGMENTS)
        scenario = self._build_scenario(genome, target, "pivot")
        # Pivot attacks get extra intensity from accumulated knowledge
        return AttackScenario(
            category=scenario.category,
            vector=scenario.vector,
            target_segment=scenario.target_segment,
            events=scenario.events,
            expected_evasion_layer=scenario.expected_evasion_layer,
            strategy="pivot",
            intensity=self.intensity * 1.1,
        )

    def _attack_erode(self, genome: Genome) -> AttackScenario:
        """Sustained pressure on highest-erosion segment to wear it down.

        Models APT-style persistent attacks that chip away at defenses.
        """
        # Target the segment with most accumulated erosion
        target = max(self._erosion_pressure, key=self._erosion_pressure.get)  # type: ignore[arg-type]
        scenario = self._build_scenario(genome, target, "erode")
        # Erode intensity scales with accumulated pressure on this segment
        erode_bonus = min(0.5, self._erosion_pressure[target] * 0.3)
        return AttackScenario(
            category=scenario.category,
            vector=f"erode_{target.lower()}",
            target_segment=target,
            events=scenario.events,
            expected_evasion_layer=scenario.expected_evasion_layer,
            strategy="erode",
            intensity=self.intensity * (1.0 + erode_bonus),
        )

    def _attack_cascade(self, genome: Genome) -> AttackScenario:
        """Chain attack: hit a segment, then exploit the disruption to hit neighbors.

        Models real-world attack chains where compromising one system
        gives leverage against adjacent systems.
        """
        # Segment adjacency (defense dependencies)
        adjacency: dict[str, list[str]] = {
            "RTG": ["ISO", "DCP"],    # Routing compromise -> isolation/deception exposed
            "ISO": ["ATH", "RTG"],    # Isolation failure -> auth/routing exposed
            "ATH": ["DTX", "ISO"],    # Auth breach -> detection/isolation exposed
            "DTX": ["ATH", "RSP"],    # Detection blind -> auth/response exposed
            "DCP": ["RTG", "RSP"],    # Deception failure -> routing/response exposed
            "RSP": ["DCP", "DTX"],    # Response delay -> deception/detection exposed
        }

        # Start with weakest segment
        ranked = sorted(ATTACK_SEGMENTS, key=lambda s: genome.density(s))
        primary = ranked[0]
        neighbors = adjacency.get(primary, [])
        # Chain to neighbor with lowest density
        if neighbors:
            secondary = min(neighbors, key=lambda s: genome.density(s))
            targets = (primary, secondary)
        else:
            targets = (primary,)

        scenario = self._build_scenario(genome, primary, "cascade")
        extra_events: list[dict] = []
        for t in targets[1:]:
            extra_events.extend(self._build_events(self._pick_category(t), t))

        return AttackScenario(
            category=scenario.category,
            vector=f"cascade_{'_'.join(t.lower() for t in targets)}",
            target_segment=primary,
            events=scenario.events + extra_events,
            expected_evasion_layer=scenario.expected_evasion_layer,
            strategy="cascade",
            multi_targets=tuple(targets),
            intensity=self.intensity * 1.15,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_scenario(self, genome: Genome, target: str, strategy: Strategy) -> AttackScenario:
        category = self._pick_category(target)
        events = self._build_events(category, target)
        evasion = self._pick_evasion_target(category)
        return AttackScenario(
            category=category,
            vector=f"{category.name.lower()}_{target.lower()}",
            target_segment=target,
            events=events,
            expected_evasion_layer=evasion,
            strategy=strategy,
            intensity=self.intensity,
        )

    def _pick_category(self, weak_seg: str) -> ThreatCategory:
        mapping = {
            "DTX": ThreatCategory.ZERO_DAY,
            "DCP": ThreatCategory.APT,
            "ATH": ThreatCategory.INSIDER,
            "ISO": ThreatCategory.VOLUME,
            "RTG": ThreatCategory.APT,
            "RSP": ThreatCategory.COMMODITY,
        }
        return mapping.get(weak_seg, ThreatCategory.COMMODITY)

    def _build_events(self, cat: ThreatCategory, target: str) -> list[dict]:
        base = {
            "source_ip": f"10.{self._rng.randint(0, 255)}.{self._rng.randint(0, 255)}.1",
            "cloud": self._rng.choice(["aws", "azure", "oracle"]),
            "identity": f"attacker-{self._rng.randint(1000, 9999)}",
        }
        n_steps = self._rng.randint(3, 8)
        return [base | {"action": f"probe_{target.lower()}", "step": i} for i in range(n_steps)]

    def _pick_evasion_target(self, cat: ThreatCategory) -> str:
        return {
            ThreatCategory.COMMODITY: "L1",
            ThreatCategory.VOLUME: "L2",
            ThreatCategory.APT: "L3",
            ThreatCategory.ZERO_DAY: "L1",
            ThreatCategory.META_ATTACK: "L5",
            ThreatCategory.INSIDER: "L3",
        }.get(cat, "L1")
