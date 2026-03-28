"""Red agent -- Relentless offensive AI hell-bent on overthrowing Blue.

Red is OBSESSED with breaching defense. It will probe, feint, erode,
and unleash fury when frustrated. Every failure makes it angrier and
more creative. Every success feeds its hunger for more.

Strategy arsenal:
  - Exploit: target the weakest segment with surgical precision
  - Probe: reconnaissance to discover new attack surfaces
  - Blitz: coordinated multi-segment assault (shock & awe)
  - Pivot: re-exploit a known vulnerability with escalation
  - Erode: relentless sustained pressure to wear down defenses
  - Cascade: chain attacks through segment dependencies
  - Fury: all-out desperate assault when frustrated (kamikaze mode)
  - Feint: misdirection — fake one target, hit another

Adaptive mechanics:
  - Intensity escalates FAST with consecutive failures (rage mode)
  - Per-segment × per-category win tracking (intelligence dossier)
  - Strategy weights shift aggressively based on what works
  - Erosion accumulates relentlessly — Red NEVER forgets
  - Category learning: discovers which attack type kills which segment
"""

from __future__ import annotations

import math
import random
from collections import Counter
from dataclasses import dataclass, field
from typing import Literal

from aegis.common.types import Genome, ThreatCategory

ATTACK_SEGMENTS = ["RTG", "ISO", "ATH", "DTX", "DCP", "RSP"]

Strategy = Literal[
    "exploit", "probe", "blitz", "pivot",
    "erode", "cascade", "fury", "feint",
]


@dataclass(frozen=True, slots=True)
class AttackScenario:
    """A single Red agent attack plan."""

    category: ThreatCategory
    vector: str
    target_segment: str
    events: list[dict]
    expected_evasion_layer: str
    strategy: Strategy = "exploit"
    multi_targets: tuple[str, ...] = ()
    intensity: float = 1.0


class RedAgent:
    """Relentless offensive AI — will do ANYTHING to breach Blue's defense.

    Red has personality: it gets frustrated, angry, obsessive. It holds
    grudges against segments that resisted it. It celebrates breaches
    and doubles down on what works.
    """

    def __init__(self, seed: int | None = None) -> None:
        self._rng = random.Random(seed)
        self._successful_vectors: list[str] = []
        self._failed_segments: list[str] = []
        self._round = 0

        # --- Adaptive intelligence state ---
        # Per-segment outcome tracking
        self._segment_outcomes: dict[str, list[bool]] = {s: [] for s in ATTACK_SEGMENTS}

        # Per-segment × per-category success rates (the intelligence dossier)
        # Key: (segment, category) -> [True/False, ...]
        self._intel_dossier: dict[tuple[str, str], list[bool]] = {}

        # Consecutive failure rage counter
        self._consecutive_failures: int = 0
        self._max_consecutive_failures: int = 0  # All-time record

        # Per-strategy tracking
        self._strategy_outcomes: dict[str, list[bool]] = {}

        # Erosion pressure (Red's persistent grinding on each segment)
        self._erosion_pressure: dict[str, float] = {s: 0.0 for s in ATTACK_SEGMENTS}

        # Grudge list: segments that resisted Red get targeted more
        self._grudge_score: dict[str, float] = {s: 0.0 for s in ATTACK_SEGMENTS}

        # Last attack context for chaining
        self._last_target: str = ""
        self._last_won: bool = False
        self._last_category: ThreatCategory | None = None

        # Kill streak: consecutive wins make Red bolder
        self._kill_streak: int = 0

    @property
    def intensity(self) -> float:
        """Attack intensity based on frustration + kill streak.

        Grows FAST with failures (rage). Also grows with consecutive wins
        (confidence boost). Red is always escalating, never relaxing.

        Range: 1.0 → 3.5x
        """
        # Rage from failures: logarithmic growth
        rage = 0.4 * math.log1p(self._consecutive_failures)
        # Confidence from wins: smaller boost but stacks
        confidence = 0.15 * math.log1p(self._kill_streak)
        # Base intensity always climbs slightly with experience
        experience = min(0.3, self._round * 0.003)

        return min(3.5, 1.0 + rage + confidence + experience)

    @property
    def fury_available(self) -> bool:
        """Fury unlocks after 4+ consecutive failures (Red snaps)."""
        return self._consecutive_failures >= 4

    def generate_attack(self, genome: Genome) -> AttackScenario:
        """Generate attack using adaptive strategy selection."""
        self._round += 1
        strategy = self._pick_strategy(genome)
        return self._dispatch_strategy(strategy, genome)

    def record_outcome(self, attack: AttackScenario, red_won: bool) -> None:
        """Learn from battle. Red NEVER forgets."""
        # Basic history
        if red_won:
            self._successful_vectors.append(attack.vector)
            self._consecutive_failures = 0
            self._kill_streak += 1
        else:
            self._failed_segments.append(attack.target_segment)
            self._consecutive_failures += 1
            self._max_consecutive_failures = max(
                self._max_consecutive_failures, self._consecutive_failures
            )
            self._kill_streak = 0

        # Per-segment tracking
        self._segment_outcomes[attack.target_segment].append(red_won)
        for seg in attack.multi_targets:
            if seg != attack.target_segment:
                self._segment_outcomes[seg].append(red_won)

        # Intelligence dossier: segment × category
        key = (attack.target_segment, attack.category.name)
        self._intel_dossier.setdefault(key, []).append(red_won)

        # Per-strategy tracking
        self._strategy_outcomes.setdefault(attack.strategy, []).append(red_won)

        # Erosion: persistent accumulation with ceiling
        # Red's erosion builds over time but caps at 1.5 (diminishing returns)
        erosion_gain = 0.18 if red_won else 0.06
        self._erosion_pressure[attack.target_segment] = min(
            1.5, self._erosion_pressure[attack.target_segment] + erosion_gain,
        )
        for seg in attack.multi_targets:
            self._erosion_pressure[seg] = min(
                1.5, self._erosion_pressure[seg] + erosion_gain * 0.5,
            )

        # Slower decay on non-attacked (Red's pressure lingers)
        for seg in ATTACK_SEGMENTS:
            if seg != attack.target_segment and seg not in attack.multi_targets:
                self._erosion_pressure[seg] = max(0, self._erosion_pressure[seg] - 0.02)

        # Grudge system: segments that resist Red get grudge points
        if not red_won:
            self._grudge_score[attack.target_segment] += 0.15
            # Grudge spreads to adjacent segments (anger displacement)
            for seg in ATTACK_SEGMENTS:
                if seg != attack.target_segment:
                    self._grudge_score[seg] += 0.02
        else:
            # Success reduces grudge (satisfaction)
            self._grudge_score[attack.target_segment] = max(
                0, self._grudge_score[attack.target_segment] - 0.10
            )

        self._last_target = attack.target_segment
        self._last_won = red_won
        self._last_category = attack.category

    # ------------------------------------------------------------------
    # Intelligence: what Red has learned
    # ------------------------------------------------------------------

    def _best_category_for_segment(self, segment: str) -> ThreatCategory | None:
        """Query intel dossier: which attack category works best here?"""
        best_cat = None
        best_rate = 0.0
        for cat in ThreatCategory:
            key = (segment, cat.name)
            outcomes = self._intel_dossier.get(key, [])
            if len(outcomes) >= 2:
                rate = sum(outcomes[-10:]) / len(outcomes[-10:])
                if rate > best_rate:
                    best_rate = rate
                    best_cat = cat
        return best_cat if best_rate > 0.15 else None

    def _segment_vulnerability_score(self, genome: Genome, seg: str) -> float:
        """How vulnerable is this segment? Higher = better target."""
        density_weakness = 1.0 - genome.density(seg)
        erosion = self._erosion_pressure.get(seg, 0) * 0.4
        grudge = self._grudge_score.get(seg, 0) * 0.2

        # Intelligence bonus: if we know a good category for this segment
        intel_bonus = 0.0
        best_cat = self._best_category_for_segment(seg)
        if best_cat:
            key = (seg, best_cat.name)
            outcomes = self._intel_dossier.get(key, [])
            if outcomes:
                intel_bonus = sum(outcomes[-5:]) / len(outcomes[-5:]) * 0.3

        return density_weakness + erosion + grudge + intel_bonus

    # ------------------------------------------------------------------
    # Strategy selection — Red is AGGRESSIVE
    # ------------------------------------------------------------------

    def _pick_strategy(self, genome: Genome) -> Strategy:
        """Choose attack strategy. Red ALWAYS escalates."""
        base_weights: dict[str, float] = {
            "exploit": 0.20,
            "probe": 0.12,
            "blitz": 0.18,
            "pivot": 0.10,
            "erode": 0.15,
            "cascade": 0.15,
            "fury": 0.00,   # Unlocked by frustration
            "feint": 0.10,
        }

        # --- Phase: early game = recon, late game = all-out war ---
        if self._round <= 5:
            base_weights["probe"] += 0.25
            base_weights["feint"] += 0.10
            base_weights["blitz"] -= 0.10
        elif self._round <= 15:
            base_weights["exploit"] += 0.10
            base_weights["erode"] += 0.10
        else:
            # Late game: Red is experienced and aggressive
            base_weights["blitz"] += 0.15
            base_weights["cascade"] += 0.15
            base_weights["erode"] += 0.10
            base_weights["probe"] -= 0.08

        # --- Frustration rage: failures make Red desperate and creative ---
        if self._consecutive_failures >= 2:
            frustration = min(0.40, self._consecutive_failures * 0.05)
            base_weights["blitz"] += frustration
            base_weights["erode"] += frustration * 0.8
            base_weights["feint"] += frustration * 0.6  # Try misdirection
            base_weights["exploit"] -= frustration * 0.3

        # Fury unlocks at 4+ failures: Red SNAPS
        if self.fury_available:
            base_weights["fury"] = 0.30 + self._consecutive_failures * 0.05

        # --- Kill streak confidence: wins make Red bold ---
        if self._kill_streak >= 2:
            base_weights["pivot"] += 0.25  # Keep exploiting what works
            base_weights["cascade"] += 0.15  # Chain the momentum
            base_weights["probe"] -= 0.08

        # --- Last attack won → double down ---
        if self._last_won and self._successful_vectors:
            base_weights["pivot"] += 0.20
            base_weights["erode"] += 0.10

        # --- High erosion somewhere → press the advantage ---
        max_erosion_seg = max(self._erosion_pressure, key=self._erosion_pressure.get)  # type: ignore[arg-type]
        max_erosion = self._erosion_pressure[max_erosion_seg]
        if max_erosion > 0.3:
            base_weights["erode"] += 0.20
        if max_erosion > 0.5:
            base_weights["erode"] += 0.15  # OBSESSIVE grinding

        # --- Strategy-specific learning: boost what works ---
        for strat, outcomes in self._strategy_outcomes.items():
            if len(outcomes) >= 3:
                recent = outcomes[-15:]
                win_rate = sum(recent) / len(recent)
                if win_rate > 0.25:
                    base_weights[strat] = base_weights.get(strat, 0.1) + win_rate * 0.3
                elif win_rate < 0.05 and len(outcomes) >= 10:
                    # Abandon strategies that consistently fail
                    base_weights[strat] = max(0.02, base_weights.get(strat, 0.1) - 0.10)

        # --- Grudge targeting: if a segment resists, Red gets creative ---
        max_grudge = max(self._grudge_score.values())
        if max_grudge > 0.5:
            base_weights["feint"] += 0.15  # Misdirection against stubborn defense

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
            "fury": self._attack_fury,
            "feint": self._attack_feint,
        }
        return dispatch[strategy](genome)

    # ------------------------------------------------------------------
    # Attack strategies
    # ------------------------------------------------------------------

    def _attack_exploit(self, genome: Genome) -> AttackScenario:
        """Surgical strike on the most vulnerable segment."""
        scores = {
            seg: self._segment_vulnerability_score(genome, seg)
            for seg in ATTACK_SEGMENTS
        }
        ranked = sorted(scores, key=scores.get, reverse=True)  # type: ignore[arg-type]
        target = self._rng.choice(ranked[:2])

        # Use intelligence: pick best known category if available
        category = self._best_category_for_segment(target)
        if category:
            return self._build_scenario(genome, target, "exploit", force_category=category)
        return self._build_scenario(genome, target, "exploit")

    def _attack_probe(self, genome: Genome) -> AttackScenario:
        """Reconnaissance: find undiscovered weaknesses."""
        # Prefer under-explored segments
        attack_counts = {s: len(v) for s, v in self._segment_outcomes.items()}
        min_count = min(attack_counts.values()) if attack_counts else 0
        candidates = [s for s, c in attack_counts.items() if c <= min_count + 2]
        if not candidates:
            candidates = ATTACK_SEGMENTS

        # Avoid recent failures (but not forever — Red is persistent)
        recent_fails = self._failed_segments[-3:]
        filtered = [s for s in candidates if s not in recent_fails]
        target = self._rng.choice(filtered or candidates)

        # Probes try different categories to build intel
        cats = list(ThreatCategory)
        category = self._rng.choice(cats)
        return self._build_scenario(genome, target, "probe", force_category=category)

    def _attack_blitz(self, genome: Genome) -> AttackScenario:
        """Coordinated multi-segment assault — overwhelm defense."""
        # More targets when frustrated (desperation blitz)
        max_targets = min(5, 2 + self._consecutive_failures // 3)
        n_targets = self._rng.randint(2, max_targets)

        # Target by vulnerability score (not just density)
        ranked = sorted(
            ATTACK_SEGMENTS,
            key=lambda s: self._segment_vulnerability_score(genome, s),
            reverse=True,
        )
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
            intensity=self.intensity * 1.3,  # Blitz hits HARD
        )

    def _attack_pivot(self, genome: Genome) -> AttackScenario:
        """Re-exploit known vulnerabilities with escalation."""
        if not self._successful_vectors:
            return self._attack_exploit(genome)

        # Prefer recent successes (they might still work)
        past = self._rng.choice(self._successful_vectors[-10:])
        parts = past.split("_")
        target = parts[-1].upper() if parts[-1].upper() in ATTACK_SEGMENTS else self._rng.choice(ATTACK_SEGMENTS)

        # Use the category that worked before
        best_cat = self._best_category_for_segment(target)
        scenario = self._build_scenario(
            genome, target, "pivot",
            force_category=best_cat,
        )
        return AttackScenario(
            category=scenario.category,
            vector=scenario.vector,
            target_segment=scenario.target_segment,
            events=scenario.events,
            expected_evasion_layer=scenario.expected_evasion_layer,
            strategy="pivot",
            intensity=self.intensity * 1.2,  # Pivot with escalation
        )

    def _attack_erode(self, genome: Genome) -> AttackScenario:
        """Relentless sustained pressure — NEVER give up on a target.

        Models APT-style grinding: "I will wear you down eventually."
        Red accumulates erosion pressure that degrades defense over time.
        """
        # Target the segment with most accumulated erosion
        target = max(self._erosion_pressure, key=self._erosion_pressure.get)  # type: ignore[arg-type]

        # Use best known category or APT (patient attacker)
        best_cat = self._best_category_for_segment(target) or ThreatCategory.APT
        scenario = self._build_scenario(genome, target, "erode", force_category=best_cat)

        erode_bonus = min(0.7, self._erosion_pressure[target] * 0.35)
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
        """Chain attack: breach one system → leverage against neighbors.

        Real-world: compromise the router → own the network → bypass auth.
        """
        adjacency: dict[str, list[str]] = {
            "RTG": ["ISO", "DCP"],
            "ISO": ["ATH", "RTG"],
            "ATH": ["DTX", "ISO"],
            "DTX": ["ATH", "RSP"],
            "DCP": ["RTG", "RSP"],
            "RSP": ["DCP", "DTX"],
        }

        # Start with most vulnerable segment
        ranked = sorted(
            ATTACK_SEGMENTS,
            key=lambda s: self._segment_vulnerability_score(genome, s),
            reverse=True,
        )
        primary = ranked[0]
        neighbors = adjacency.get(primary, [])

        # Chain to weakest neighbor (or multiple if frustrated)
        if neighbors:
            chain = sorted(neighbors, key=lambda s: genome.density(s))
            n_chain = min(len(chain), 1 + self._consecutive_failures // 4)
            targets = (primary, *chain[:n_chain])
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
            intensity=self.intensity * 1.25,
        )

    def _attack_fury(self, genome: Genome) -> AttackScenario:
        """ALL-OUT ASSAULT — Red has SNAPPED.

        When frustrated beyond breaking point, Red attacks EVERY segment
        simultaneously with maximum intensity. Kamikaze mode: if even ONE
        segment falls, Red wins.

        This is the nuclear option. Expensive but devastating.
        """
        # Attack ALL segments
        targets = list(ATTACK_SEGMENTS)
        # Primary = absolute weakest
        primary = min(targets, key=lambda s: genome.density(s))

        # Build massive event payload
        events: list[dict] = []
        for t in targets:
            cat = self._pick_category(t)
            events.extend(self._build_events(cat, t))

        # Fury intensity is MASSIVE
        fury_multiplier = 1.5 + 0.1 * self._consecutive_failures

        return AttackScenario(
            category=ThreatCategory.ZERO_DAY,  # Use most dangerous category
            vector=f"fury_all_segments",
            target_segment=primary,
            events=events,
            expected_evasion_layer="L1",  # Bypass everything
            strategy="fury",
            multi_targets=tuple(targets),
            intensity=self.intensity * fury_multiplier,
        )

    def _attack_feint(self, genome: Genome) -> AttackScenario:
        """Misdirection: make Blue think we're attacking X, actually attack Y.

        Red attacks the segment Blue is LEAST expecting. This counters
        Blue's pattern matching — if Blue fortifies based on Red's
        recent targets, the feint hits somewhere else entirely.
        """
        # Find where Blue expects us to attack (most attacked recently)
        recent_targets = self._failed_segments[-5:] + [
            v.split("_")[-1].upper() for v in self._successful_vectors[-5:]
            if v.split("_")[-1].upper() in ATTACK_SEGMENTS
        ]
        target_counts = Counter(recent_targets)

        # Attack the LEAST expected segment (where Blue isn't looking)
        if target_counts:
            # Segments we haven't been attacking much
            least_attacked = min(
                ATTACK_SEGMENTS,
                key=lambda s: target_counts.get(s, 0),
            )
            target = least_attacked
        else:
            # No history — pick randomly
            target = self._rng.choice(ATTACK_SEGMENTS)

        # Feints use INSIDER or META_ATTACK (unexpected categories)
        feint_categories = [ThreatCategory.INSIDER, ThreatCategory.META_ATTACK, ThreatCategory.ZERO_DAY]
        category = self._rng.choice(feint_categories)

        scenario = self._build_scenario(genome, target, "feint", force_category=category)
        return AttackScenario(
            category=scenario.category,
            vector=f"feint_{target.lower()}",
            target_segment=target,
            events=scenario.events,
            expected_evasion_layer=scenario.expected_evasion_layer,
            strategy="feint",
            intensity=self.intensity * 1.15,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_scenario(
        self,
        genome: Genome,
        target: str,
        strategy: Strategy,
        *,
        force_category: ThreatCategory | None = None,
    ) -> AttackScenario:
        category = force_category or self._pick_category(target)
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
        """Pick attack category using intelligence dossier.

        Early game: use natural mapping.
        Late game: use what WORKS (learned from intel dossier).
        """
        # Check intel first — use proven effective categories
        if self._round > 8:
            best = self._best_category_for_segment(weak_seg)
            if best and self._rng.random() < 0.5:  # 50% use intel
                return best

        # Base mapping
        mapping = {
            "DTX": ThreatCategory.ZERO_DAY,
            "DCP": ThreatCategory.APT,
            "ATH": ThreatCategory.INSIDER,
            "ISO": ThreatCategory.VOLUME,
            "RTG": ThreatCategory.APT,
            "RSP": ThreatCategory.COMMODITY,
        }
        base = mapping.get(weak_seg, ThreatCategory.COMMODITY)

        # Exploration: try random categories to build intel (25% after round 8)
        if self._round > 8 and self._rng.random() < 0.25:
            return self._rng.choice(list(ThreatCategory))

        return base

    def _build_events(self, cat: ThreatCategory, target: str) -> list[dict]:
        base = {
            "source_ip": f"10.{self._rng.randint(0, 255)}.{self._rng.randint(0, 255)}.1",
            "cloud": self._rng.choice(["aws", "azure", "oracle"]),
            "identity": f"attacker-{self._rng.randint(1000, 9999)}",
        }
        # More steps when intensity is high (more sophisticated attack)
        n_steps = self._rng.randint(3, max(8, int(self.intensity * 5)))
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
