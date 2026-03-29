"""Red agent -- Relentless offensive AI hell-bent on overthrowing Blue.

Red draws from humanity's COMPLETE offensive cyber history and actively
discovers new attack vectors. It uses real-world kill chains, supply
chain attacks, living-off-the-land techniques, and zero-day discovery.

Strategy arsenal (13 total):
  CLASSIC:
  - Exploit:       target weakest segment with surgical precision
  - Probe:         reconnaissance to discover new attack surfaces
  - Blitz:         coordinated multi-segment assault (shock & awe)
  - Pivot:         re-exploit known vulnerability with escalation
  - Erode:         relentless sustained pressure to wear down defenses
  - Cascade:       chain attacks through segment dependencies
  - Fury:          all-out desperate assault when frustrated
  - Feint:         misdirection — fake one target, hit another

  ADVANCED (NEW):
  - Kill chain:    multi-stage attack following real APT kill chains
  - Supply chain:  exploit trust between segments
  - Living-off-land: weaponize Blue's own defense mechanisms
  - Zero-day hunt: discover unknown vulnerabilities through probing
  - Social engineer: manipulate the human factor (ATH bypass)

Intelligence systems:
  - Attack Knowledge Base: 22+ real-world techniques (MITRE ATT&CK inspired)
  - Kill Chain Composer: multi-phase attack planning with combo bonuses
  - Zero-Day Discovery: algorithmic vulnerability probing + mutation
  - Per-segment × per-category win tracking (intelligence dossier)
  - Defense pattern analysis: detect predictable Blue responses
"""

from __future__ import annotations

import math
import random
from collections import Counter
from dataclasses import dataclass, field
from typing import Literal

from aegis.common.types import Genome, ThreatCategory
from aegis.sandbox.attack_knowledge import (
    TECHNIQUE_LIBRARY,
    KillChainComposer,
    KillChainPhase,
    ZeroDayDiscovery,
)

ATTACK_SEGMENTS = ["RTG", "ISO", "ATH", "DTX", "DCP", "RSP"]

Strategy = Literal[
    "exploit", "probe", "blitz", "pivot",
    "erode", "cascade", "fury", "feint",
    "killchain", "supply_chain", "living_off_land",
    "zeroday_hunt", "social_engineer",
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
    kill_chain_length: int = 0    # Number of phases in kill chain
    stealth_rating: float = 0.0   # How stealthy this attack is


class RedAgent:
    """Relentless offensive AI — uses ALL of cyber history to overthrow Blue.

    Red has access to:
    - Historical attack knowledge base (22+ real-world techniques)
    - Kill chain composer (multi-phase attack planning)
    - Zero-day discovery engine (finds unknown vulnerabilities)
    - Defense pattern analyzer (detects predictable Blue responses)
    """

    def __init__(self, seed: int | None = None) -> None:
        self._rng = random.Random(seed)
        self._successful_vectors: list[str] = []
        self._failed_segments: list[str] = []
        self._round = 0

        # --- Core intelligence state ---
        self._segment_outcomes: dict[str, list[bool]] = {s: [] for s in ATTACK_SEGMENTS}
        self._intel_dossier: dict[tuple[str, str], list[bool]] = {}
        self._consecutive_failures: int = 0
        self._max_consecutive_failures: int = 0
        self._strategy_outcomes: dict[str, list[bool]] = {}
        self._erosion_pressure: dict[str, float] = {s: 0.0 for s in ATTACK_SEGMENTS}
        self._grudge_score: dict[str, float] = {s: 0.0 for s in ATTACK_SEGMENTS}
        self._last_target: str = ""
        self._last_won: bool = False
        self._last_category: ThreatCategory | None = None
        self._kill_streak: int = 0

        # --- Advanced intelligence systems ---
        self._kill_chain_composer = KillChainComposer(rng=self._rng)
        self._zeroday_engine = ZeroDayDiscovery(rng=self._rng)

        # Track Blue's defense patterns (for pattern analysis)
        self._blue_strategy_history: list[str] = []

        # Supply chain: track which segments trust which
        self._trust_exploitation: dict[str, float] = {s: 0.0 for s in ATTACK_SEGMENTS}

        # Living-off-the-land: knowledge of Blue's own tools
        self._lotl_knowledge: dict[str, float] = {s: 0.0 for s in ATTACK_SEGMENTS}

    @property
    def intensity(self) -> float:
        """Attack intensity. Range: 1.0 → 3.5x"""
        rage = 0.4 * math.log1p(self._consecutive_failures)
        confidence = 0.15 * math.log1p(self._kill_streak)
        experience = min(0.3, self._round * 0.003)
        # Zero-day discoveries boost overall intensity
        zeroday_bonus = min(0.15, self._zeroday_engine.discovered_count * 0.03)
        return min(3.5, 1.0 + rage + confidence + experience + zeroday_bonus)

    @property
    def fury_available(self) -> bool:
        return self._consecutive_failures >= 4

    def generate_attack(self, genome: Genome) -> AttackScenario:
        self._round += 1
        strategy = self._pick_strategy(genome)
        return self._dispatch_strategy(strategy, genome)

    def record_outcome(self, attack: AttackScenario, red_won: bool) -> None:
        """Learn from battle. Red NEVER forgets."""
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

        self._segment_outcomes[attack.target_segment].append(red_won)
        for seg in attack.multi_targets:
            if seg != attack.target_segment:
                self._segment_outcomes[seg].append(red_won)

        key = (attack.target_segment, attack.category.name)
        self._intel_dossier.setdefault(key, []).append(red_won)
        self._strategy_outcomes.setdefault(attack.strategy, []).append(red_won)

        # Erosion
        erosion_gain = 0.18 if red_won else 0.06
        self._erosion_pressure[attack.target_segment] = min(
            1.5, self._erosion_pressure[attack.target_segment] + erosion_gain,
        )
        for seg in attack.multi_targets:
            self._erosion_pressure[seg] = min(
                1.5, self._erosion_pressure[seg] + erosion_gain * 0.5,
            )
        for seg in ATTACK_SEGMENTS:
            if seg != attack.target_segment and seg not in attack.multi_targets:
                self._erosion_pressure[seg] = max(0, self._erosion_pressure[seg] - 0.02)

        # Grudge
        if not red_won:
            self._grudge_score[attack.target_segment] += 0.15
            for seg in ATTACK_SEGMENTS:
                if seg != attack.target_segment:
                    self._grudge_score[seg] += 0.02
        else:
            self._grudge_score[attack.target_segment] = max(
                0, self._grudge_score[attack.target_segment] - 0.10
            )

        # Kill chain learning
        if attack.kill_chain_length > 0:
            chain_techs = self._kill_chain_composer._chain_outcomes
            # (handled internally by composer)

        # Supply chain: success builds trust exploitation knowledge
        if attack.strategy == "supply_chain" and red_won:
            for seg in attack.multi_targets or (attack.target_segment,):
                self._trust_exploitation[seg] = min(
                    1.0, self._trust_exploitation.get(seg, 0) + 0.15
                )

        # Living-off-the-land: success means Red learned Blue's tools
        if attack.strategy == "living_off_land" and red_won:
            self._lotl_knowledge[attack.target_segment] = min(
                1.0, self._lotl_knowledge.get(attack.target_segment, 0) + 0.20
            )

        self._last_target = attack.target_segment
        self._last_won = red_won
        self._last_category = attack.category

    def record_blue_strategy(self, strategy: str) -> None:
        """Track Blue's defense patterns for analysis."""
        self._blue_strategy_history.append(strategy)

    # ------------------------------------------------------------------
    # Intelligence queries
    # ------------------------------------------------------------------

    def _best_category_for_segment(self, segment: str) -> ThreatCategory | None:
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
        density_weakness = 1.0 - genome.density(seg)
        erosion = self._erosion_pressure.get(seg, 0) * 0.4
        grudge = self._grudge_score.get(seg, 0) * 0.2

        intel_bonus = 0.0
        best_cat = self._best_category_for_segment(seg)
        if best_cat:
            key = (seg, best_cat.name)
            outcomes = self._intel_dossier.get(key, [])
            if outcomes:
                intel_bonus = sum(outcomes[-5:]) / len(outcomes[-5:]) * 0.3

        # Zero-day blind spot bonus
        blind_spot = self._zeroday_engine.get_blind_spot(seg)
        # Supply chain trust exploitation bonus
        trust_bonus = self._trust_exploitation.get(seg, 0) * 0.2
        # Living-off-the-land knowledge bonus
        lotl_bonus = self._lotl_knowledge.get(seg, 0) * 0.15

        return (density_weakness + erosion + grudge + intel_bonus
                + blind_spot + trust_bonus + lotl_bonus)

    def _get_weak_segments(self, genome: Genome, top_k: int = 3) -> list[str]:
        """Get most vulnerable segments ranked by vulnerability score."""
        scored = sorted(
            ATTACK_SEGMENTS,
            key=lambda s: self._segment_vulnerability_score(genome, s),
            reverse=True,
        )
        return scored[:top_k]

    # ------------------------------------------------------------------
    # Strategy selection
    # ------------------------------------------------------------------

    def _pick_strategy(self, genome: Genome) -> Strategy:
        base_weights: dict[str, float] = {
            "exploit": 0.15,
            "probe": 0.08,
            "blitz": 0.12,
            "pivot": 0.08,
            "erode": 0.10,
            "cascade": 0.10,
            "fury": 0.00,
            "feint": 0.07,
            "killchain": 0.10,
            "supply_chain": 0.06,
            "living_off_land": 0.05,
            "zeroday_hunt": 0.06,
            "social_engineer": 0.03,
        }

        # Phase-based adjustments
        if self._round <= 5:
            # Early: heavy recon + probing
            base_weights["probe"] += 0.20
            base_weights["zeroday_hunt"] += 0.10
            base_weights["feint"] += 0.05
        elif self._round <= 20:
            # Mid: start using advanced techniques
            base_weights["killchain"] += 0.15
            base_weights["exploit"] += 0.10
            base_weights["erode"] += 0.08
            base_weights["supply_chain"] += 0.05
        else:
            # Late: full arsenal unleashed
            base_weights["killchain"] += 0.20
            base_weights["supply_chain"] += 0.12
            base_weights["living_off_land"] += 0.10
            base_weights["blitz"] += 0.10
            base_weights["cascade"] += 0.10
            base_weights["zeroday_hunt"] += 0.08

        # Frustration escalation
        if self._consecutive_failures >= 2:
            frustration = min(0.40, self._consecutive_failures * 0.05)
            base_weights["blitz"] += frustration
            base_weights["erode"] += frustration * 0.8
            base_weights["feint"] += frustration * 0.5
            base_weights["killchain"] += frustration * 0.6
            base_weights["zeroday_hunt"] += frustration * 0.4

        if self.fury_available:
            base_weights["fury"] = 0.25 + self._consecutive_failures * 0.05

        # Kill streak confidence
        if self._kill_streak >= 2:
            base_weights["pivot"] += 0.20
            base_weights["cascade"] += 0.15
            base_weights["supply_chain"] += 0.10

        # Strategy learning
        for strat, outcomes in self._strategy_outcomes.items():
            if len(outcomes) >= 3:
                recent = outcomes[-15:]
                win_rate = sum(recent) / len(recent)
                if win_rate > 0.25:
                    base_weights[strat] = base_weights.get(strat, 0.05) + win_rate * 0.3
                elif win_rate < 0.05 and len(outcomes) >= 10:
                    base_weights[strat] = max(0.02, base_weights.get(strat, 0.05) - 0.08)

        # Zero-day discoveries unlock more aggressive zero-day hunting
        if self._zeroday_engine.discovered_count > 0:
            base_weights["zeroday_hunt"] += 0.08

        # Living-off-the-land gets stronger with knowledge
        max_lotl = max(self._lotl_knowledge.values())
        if max_lotl > 0.3:
            base_weights["living_off_land"] += 0.12

        # Social engineering after reconnaissance
        if self._round > 10 and len(self._blue_strategy_history) > 5:
            base_weights["social_engineer"] += 0.08

        # Normalize and select
        strategies = list(base_weights.keys())
        probs = [max(0.01, w) for w in base_weights.values()]
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
            "killchain": self._attack_killchain,
            "supply_chain": self._attack_supply_chain,
            "living_off_land": self._attack_living_off_land,
            "zeroday_hunt": self._attack_zeroday_hunt,
            "social_engineer": self._attack_social_engineer,
        }
        return dispatch[strategy](genome)

    # ------------------------------------------------------------------
    # CLASSIC strategies (8)
    # ------------------------------------------------------------------

    def _attack_exploit(self, genome: Genome) -> AttackScenario:
        ranked = self._get_weak_segments(genome, 2)
        target = self._rng.choice(ranked)
        category = self._best_category_for_segment(target)
        if category:
            return self._build_scenario(genome, target, "exploit", force_category=category)
        return self._build_scenario(genome, target, "exploit")

    def _attack_probe(self, genome: Genome) -> AttackScenario:
        attack_counts = {s: len(v) for s, v in self._segment_outcomes.items()}
        min_count = min(attack_counts.values()) if attack_counts else 0
        candidates = [s for s, c in attack_counts.items() if c <= min_count + 2]
        if not candidates:
            candidates = ATTACK_SEGMENTS
        recent_fails = self._failed_segments[-3:]
        filtered = [s for s in candidates if s not in recent_fails]
        target = self._rng.choice(filtered or candidates)
        category = self._rng.choice(list(ThreatCategory))
        return self._build_scenario(genome, target, "probe", force_category=category)

    def _attack_blitz(self, genome: Genome) -> AttackScenario:
        max_targets = min(5, 2 + self._consecutive_failures // 3)
        n_targets = self._rng.randint(2, max_targets)
        ranked = sorted(ATTACK_SEGMENTS, key=lambda s: self._segment_vulnerability_score(genome, s), reverse=True)
        targets = ranked[:n_targets]
        primary = targets[0]
        scenario = self._build_scenario(genome, primary, "blitz")
        extra = []
        for t in targets[1:]:
            extra.extend(self._build_events(self._pick_category(t), t))
        return AttackScenario(
            category=scenario.category, vector=f"blitz_{'_'.join(t.lower() for t in targets)}",
            target_segment=primary, events=scenario.events + extra,
            expected_evasion_layer=scenario.expected_evasion_layer,
            strategy="blitz", multi_targets=tuple(targets), intensity=self.intensity * 1.3,
        )

    def _attack_pivot(self, genome: Genome) -> AttackScenario:
        if not self._successful_vectors:
            return self._attack_exploit(genome)
        past = self._rng.choice(self._successful_vectors[-10:])
        parts = past.split("_")
        target = parts[-1].upper() if parts[-1].upper() in ATTACK_SEGMENTS else self._rng.choice(ATTACK_SEGMENTS)
        best_cat = self._best_category_for_segment(target)
        scenario = self._build_scenario(genome, target, "pivot", force_category=best_cat)
        return AttackScenario(
            category=scenario.category, vector=scenario.vector,
            target_segment=scenario.target_segment, events=scenario.events,
            expected_evasion_layer=scenario.expected_evasion_layer,
            strategy="pivot", intensity=self.intensity * 1.2,
        )

    def _attack_erode(self, genome: Genome) -> AttackScenario:
        target = max(self._erosion_pressure, key=self._erosion_pressure.get)  # type: ignore[arg-type]
        best_cat = self._best_category_for_segment(target) or ThreatCategory.APT
        scenario = self._build_scenario(genome, target, "erode", force_category=best_cat)
        erode_bonus = min(0.7, self._erosion_pressure[target] * 0.35)
        return AttackScenario(
            category=scenario.category, vector=f"erode_{target.lower()}",
            target_segment=target, events=scenario.events,
            expected_evasion_layer=scenario.expected_evasion_layer,
            strategy="erode", intensity=self.intensity * (1.0 + erode_bonus),
        )

    def _attack_cascade(self, genome: Genome) -> AttackScenario:
        adjacency = {
            "RTG": ["ISO", "DCP"], "ISO": ["ATH", "RTG"], "ATH": ["DTX", "ISO"],
            "DTX": ["ATH", "RSP"], "DCP": ["RTG", "RSP"], "RSP": ["DCP", "DTX"],
        }
        ranked = sorted(ATTACK_SEGMENTS, key=lambda s: self._segment_vulnerability_score(genome, s), reverse=True)
        primary = ranked[0]
        neighbors = adjacency.get(primary, [])
        if neighbors:
            chain = sorted(neighbors, key=lambda s: genome.density(s))
            n_chain = min(len(chain), 1 + self._consecutive_failures // 4)
            targets = (primary, *chain[:n_chain])
        else:
            targets = (primary,)
        scenario = self._build_scenario(genome, primary, "cascade")
        extra = []
        for t in targets[1:]:
            extra.extend(self._build_events(self._pick_category(t), t))
        return AttackScenario(
            category=scenario.category, vector=f"cascade_{'_'.join(t.lower() for t in targets)}",
            target_segment=primary, events=scenario.events + extra,
            expected_evasion_layer=scenario.expected_evasion_layer,
            strategy="cascade", multi_targets=tuple(targets), intensity=self.intensity * 1.25,
        )

    def _attack_fury(self, genome: Genome) -> AttackScenario:
        targets = list(ATTACK_SEGMENTS)
        primary = min(targets, key=lambda s: genome.density(s))
        events: list[dict] = []
        for t in targets:
            events.extend(self._build_events(self._pick_category(t), t))
        fury_mult = 1.5 + 0.1 * self._consecutive_failures
        return AttackScenario(
            category=ThreatCategory.ZERO_DAY, vector="fury_all_segments",
            target_segment=primary, events=events, expected_evasion_layer="L1",
            strategy="fury", multi_targets=tuple(targets), intensity=self.intensity * fury_mult,
        )

    def _attack_feint(self, genome: Genome) -> AttackScenario:
        recent_targets = self._failed_segments[-5:] + [
            v.split("_")[-1].upper() for v in self._successful_vectors[-5:]
            if v.split("_")[-1].upper() in ATTACK_SEGMENTS
        ]
        target_counts = Counter(recent_targets)
        if target_counts:
            target = min(ATTACK_SEGMENTS, key=lambda s: target_counts.get(s, 0))
        else:
            target = self._rng.choice(ATTACK_SEGMENTS)
        feint_cats = [ThreatCategory.INSIDER, ThreatCategory.META_ATTACK, ThreatCategory.ZERO_DAY]
        category = self._rng.choice(feint_cats)
        scenario = self._build_scenario(genome, target, "feint", force_category=category)
        return AttackScenario(
            category=scenario.category, vector=f"feint_{target.lower()}",
            target_segment=target, events=scenario.events,
            expected_evasion_layer=scenario.expected_evasion_layer,
            strategy="feint", intensity=self.intensity * 1.15,
        )

    # ------------------------------------------------------------------
    # ADVANCED strategies (5) — NEW
    # ------------------------------------------------------------------

    def _attack_killchain(self, genome: Genome) -> AttackScenario:
        """Multi-stage attack following a real APT kill chain.

        Red plans a complete attack sequence: RECON → WEAPONIZE →
        DELIVER → EXPLOIT → INSTALL → C2 → EXFILTRATE.

        Each phase builds on the previous. A longer chain is more
        powerful but easier to detect (more events = more signals).
        """
        weak_segs = self._get_weak_segments(genome, 3)
        target = weak_segs[0]

        # Build kill chain (3-5 phases depending on experience)
        max_phases = min(6, 3 + self._round // 20)
        chain = self._kill_chain_composer.compose_chain(
            target_segment=target,
            max_phases=max_phases,
            known_weak_segments=weak_segs,
        )

        chain_power = self._kill_chain_composer.chain_power(chain)
        chain_stealth = self._kill_chain_composer.chain_stealth(chain)

        # Build events from chain
        events: list[dict] = []
        all_targets = set()
        for tech in chain:
            for seg in tech.target_segments:
                if seg in ATTACK_SEGMENTS:
                    all_targets.add(seg)
            events.extend(self._build_events_from_technique(tech))

        all_targets.add(target)
        multi = tuple(all_targets)

        # Kill chain intensity: base + significant chain bonus
        kc_intensity = self.intensity * (1.0 + chain_power * 0.8)

        # Best category from the exploit phase technique
        exploit_techs = [t for t in chain if t.phase == KillChainPhase.EXPLOIT]
        if exploit_techs:
            # Map technique to threat category
            category = self._technique_to_category(exploit_techs[0])
        else:
            category = self._pick_category(target)

        evasion = "L3" if chain_stealth > 0.6 else "L1"

        return AttackScenario(
            category=category,
            vector=f"killchain_{target.lower()}_{'→'.join(t.name[:6] for t in chain)}",
            target_segment=target,
            events=events,
            expected_evasion_layer=evasion,
            strategy="killchain",
            multi_targets=multi,
            intensity=kc_intensity,
            kill_chain_length=len(chain),
            stealth_rating=chain_stealth,
        )

    def _attack_supply_chain(self, genome: Genome) -> AttackScenario:
        """Exploit trust relationships between segments.

        Real-world: SolarWinds, Log4Shell, Codecov — compromise a trusted
        upstream dependency to breach downstream systems.

        In AEGIS: if segment A trusts segment B, compromising B gives
        Red a foothold in A. Trust relationships follow adjacency.
        """
        adjacency = {
            "RTG": ["ISO", "DCP"], "ISO": ["ATH", "RTG"], "ATH": ["DTX", "ISO"],
            "DTX": ["ATH", "RSP"], "DCP": ["RTG", "RSP"], "RSP": ["DCP", "DTX"],
        }

        # Find the most exploitable trust chain
        best_chain = None
        best_score = 0.0

        for source in ATTACK_SEGMENTS:
            dependents = adjacency.get(source, [])
            for dependent in dependents:
                # Score = source weakness + trust exploitation + dependent value
                source_weakness = 1.0 - genome.density(source)
                trust = self._trust_exploitation.get(dependent, 0)
                dependent_value = self._segment_vulnerability_score(genome, dependent)
                score = source_weakness + trust * 0.5 + dependent_value

                if score > best_score:
                    best_score = score
                    best_chain = (source, dependent)

        if not best_chain:
            return self._attack_cascade(genome)

        source, dependent = best_chain
        events = self._build_events(ThreatCategory.APT, source)
        events.extend(self._build_events(ThreatCategory.INSIDER, dependent))

        # Supply chain intensity: high because trust is already established
        sc_intensity = self.intensity * 1.35

        return AttackScenario(
            category=ThreatCategory.APT,
            vector=f"supply_chain_{source.lower()}→{dependent.lower()}",
            target_segment=dependent,  # Real target is the dependent
            events=events,
            expected_evasion_layer="L3",
            strategy="supply_chain",
            multi_targets=(source, dependent),
            intensity=sc_intensity,
            stealth_rating=0.75,
        )

    def _attack_living_off_land(self, genome: Genome) -> AttackScenario:
        """Weaponize Blue's own defense mechanisms.

        Real-world: LOLBins (Living Off the Land Binaries) — using
        legitimate system tools (PowerShell, WMI, certutil) for attacks.

        In AEGIS: Red uses Blue's defense infrastructure against it.
        - Use DTX (detection sensors) to map Blue's topology
        - Use RSP (response system) to trigger false positives
        - Use DCP (deception) to confuse Blue's own honeypots
        - Use RTG (routing) to redirect Blue's defense traffic

        Stealth is VERY high because the traffic looks legitimate.
        """
        # Target the segment where Red has the most knowledge
        target = max(
            ATTACK_SEGMENTS,
            key=lambda s: self._lotl_knowledge.get(s, 0) + (1.0 - genome.density(s)),
        )

        # LOTL attacks use INSIDER category (authorized tool usage)
        lotl_bonus = self._lotl_knowledge.get(target, 0)
        lotl_intensity = self.intensity * (1.1 + lotl_bonus * 0.4)

        events = self._build_events(ThreatCategory.INSIDER, target)

        return AttackScenario(
            category=ThreatCategory.INSIDER,
            vector=f"lotl_{target.lower()}",
            target_segment=target,
            events=events,
            expected_evasion_layer="L3",  # Hard to detect — looks legitimate
            strategy="living_off_land",
            intensity=lotl_intensity,
            stealth_rating=0.85,
        )

    def _attack_zeroday_hunt(self, genome: Genome) -> AttackScenario:
        """Actively discover unknown vulnerabilities.

        Red doesn't just use known attacks — it probes for UNDISCOVERED
        weaknesses. This is the vulnerability research lab.

        If a zero-day is discovered, Red gets a powerful new technique
        that Blue has never seen before.
        """
        # Probe the most attacked segment (more probing = more likely to find)
        target = self._get_weak_segments(genome, 1)[0]
        density = genome.density(target)

        # Attempt zero-day discovery
        discovered = self._zeroday_engine.probe_for_weakness(
            segment=target,
            defense_density=density,
            round_num=self._round,
        )

        # Also analyze Blue's defense patterns for blind spots
        if self._blue_strategy_history:
            self._zeroday_engine.analyze_defense_pattern(
                segment=target,
                defense_responses=self._blue_strategy_history,
            )

        if discovered:
            # Zero-day found! Use it immediately
            zd_intensity = self.intensity * (1.0 + discovered.base_power * 0.6)
            return AttackScenario(
                category=ThreatCategory.ZERO_DAY,
                vector=f"zeroday_{discovered.name}",
                target_segment=target,
                events=self._build_events_from_technique(discovered),
                expected_evasion_layer="L1",
                strategy="zeroday_hunt",
                multi_targets=discovered.target_segments,
                intensity=zd_intensity,
                stealth_rating=discovered.stealth,
            )
        else:
            # No zero-day found — still attack with probe-level intensity
            return self._build_scenario(genome, target, "zeroday_hunt",
                                        force_category=ThreatCategory.ZERO_DAY)

    def _attack_social_engineer(self, genome: Genome) -> AttackScenario:
        """Manipulate the human factor — target ATH (authentication).

        Real-world: phishing, pretexting, CEO fraud, SIM swapping.
        The weakest link in any security system is the human.

        In AEGIS: social engineering specifically targets ATH and uses
        INSIDER category because the attack bypasses technical controls.
        It's enhanced by OSINT from the recon phase.
        """
        # Social engineering ALWAYS targets ATH primarily
        primary = "ATH"
        # Secondary targets based on Blue's defense pattern predictability
        secondary = self._rng.choice(["ISO", "RSP", "RTG"])

        # Social engineering power depends on recon data
        recon_bonus = min(0.3, len(self._blue_strategy_history) * 0.01)
        se_intensity = self.intensity * (1.15 + recon_bonus)

        events = self._build_events(ThreatCategory.INSIDER, primary)
        events.extend(self._build_events(ThreatCategory.COMMODITY, secondary))

        return AttackScenario(
            category=ThreatCategory.INSIDER,
            vector=f"social_engineer_{primary.lower()}_{secondary.lower()}",
            target_segment=primary,
            events=events,
            expected_evasion_layer="L3",
            strategy="social_engineer",
            multi_targets=(primary, secondary),
            intensity=se_intensity,
            stealth_rating=0.65,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_scenario(self, genome, target, strategy, *, force_category=None):
        category = force_category or self._pick_category(target)
        events = self._build_events(category, target)
        evasion = self._pick_evasion_target(category)
        return AttackScenario(
            category=category, vector=f"{category.name.lower()}_{target.lower()}",
            target_segment=target, events=events,
            expected_evasion_layer=evasion, strategy=strategy, intensity=self.intensity,
        )

    def _pick_category(self, weak_seg: str) -> ThreatCategory:
        if self._round > 8:
            best = self._best_category_for_segment(weak_seg)
            if best and self._rng.random() < 0.5:
                return best
        mapping = {
            "DTX": ThreatCategory.ZERO_DAY, "DCP": ThreatCategory.APT,
            "ATH": ThreatCategory.INSIDER, "ISO": ThreatCategory.VOLUME,
            "RTG": ThreatCategory.APT, "RSP": ThreatCategory.COMMODITY,
        }
        base = mapping.get(weak_seg, ThreatCategory.COMMODITY)
        if self._round > 8 and self._rng.random() < 0.25:
            return self._rng.choice(list(ThreatCategory))
        return base

    def _build_events(self, cat: ThreatCategory, target: str) -> list[dict]:
        base = {
            "source_ip": f"10.{self._rng.randint(0, 255)}.{self._rng.randint(0, 255)}.1",
            "cloud": self._rng.choice(["aws", "azure", "oracle"]),
            "identity": f"attacker-{self._rng.randint(1000, 9999)}",
        }
        n_steps = self._rng.randint(3, max(8, int(self.intensity * 5)))
        return [base | {"action": f"probe_{target.lower()}", "step": i} for i in range(n_steps)]

    def _build_events_from_technique(self, tech) -> list[dict]:
        """Build event payload from an AttackTechnique."""
        base = {
            "source_ip": f"10.{self._rng.randint(0, 255)}.{self._rng.randint(0, 255)}.1",
            "cloud": self._rng.choice(["aws", "azure", "oracle"]),
            "identity": f"attacker-{self._rng.randint(1000, 9999)}",
            "technique": tech.name,
        }
        n_steps = self._rng.randint(3, max(8, int(tech.base_power * 10)))
        return [base | {"action": tech.name, "step": i} for i in range(n_steps)]

    def _technique_to_category(self, tech) -> ThreatCategory:
        """Map technique tags to threat category."""
        tags = set(tech.combo_tags)
        if "meta" in tags or "ai" in tags:
            return ThreatCategory.META_ATTACK
        if "social" in tags:
            return ThreatCategory.INSIDER
        if "zeroday" in tags or "novel" in tags:
            return ThreatCategory.ZERO_DAY
        if "supply_chain" in tags:
            return ThreatCategory.APT
        if tech.stealth > 0.7:
            return ThreatCategory.APT
        return ThreatCategory.COMMODITY

    def _pick_evasion_target(self, cat: ThreatCategory) -> str:
        return {
            ThreatCategory.COMMODITY: "L1", ThreatCategory.VOLUME: "L2",
            ThreatCategory.APT: "L3", ThreatCategory.ZERO_DAY: "L1",
            ThreatCategory.META_ATTACK: "L5", ThreatCategory.INSIDER: "L3",
        }.get(cat, "L1")
