"""Novel Defense Systems — Blue's revolutionary security structures.

These are defense mechanisms that go beyond traditional approaches.
Inspired by biological immune systems, quantum computing, and
military defense-in-depth doctrine.

Systems:
  1. ImmuneMemory:       Biological immune model — remember & instantly
                         counter known attacks (antibody response)
  2. MovingTargetDefense: Constantly shift attack surface so Red's
                         intelligence becomes stale
  3. SelfHealingEngine:  Autonomous recovery — segments repair themselves
                         between rounds without explicit strategy
  4. HoneypotNetwork:    Dynamic decoys that trap attackers and gather
                         intelligence on their methods
  5. ThreatHunter:       Proactive search for Red's infrastructure —
                         find attackers before they find you
"""

from __future__ import annotations

import math
import random
from collections import Counter
from dataclasses import dataclass, field


# ==================================================================
# 1. IMMUNE MEMORY SYSTEM
# Modeled after biological adaptive immunity:
#   - B-cells: produce antibodies against known attack signatures
#   - T-cells: active threat hunting for unknown threats
#   - Memory cells: instant recognition of previously seen attacks
# ==================================================================

@dataclass
class Antibody:
    """Defense signature tuned to a specific attack pattern."""

    target_category: str        # Attack category this counters
    target_segment: str         # Segment this protects
    strength: float             # 0.0-1.0 effectiveness
    generation: int             # When this was created
    activations: int = 0        # Times this antibody has been used


class ImmuneMemory:
    """Adaptive immune system — learns from every attack.

    First encounter: slow response (innate immunity only)
    Second encounter: antibodies activate → faster, stronger defense
    Repeated encounters: memory cells → near-instant response

    This means Red can NEVER use the same attack twice for free.
    """

    def __init__(self) -> None:
        self._antibodies: dict[str, Antibody] = {}  # key = category:segment
        self._memory_cells: dict[str, int] = {}      # key -> encounter count
        self._innate_defense: float = 0.05            # Base defense bonus
        self._round = 0

    def encounter_attack(
        self,
        category: str,
        segment: str,
        red_won: bool,
        red_strategy: str = "",
    ) -> None:
        """Record an attack encounter. Build immunity."""
        self._round += 1
        key = f"{category}:{segment}"
        strat_key = f"{red_strategy}:{segment}"

        # Count encounters
        self._memory_cells[key] = self._memory_cells.get(key, 0) + 1
        if red_strategy:
            self._memory_cells[strat_key] = self._memory_cells.get(strat_key, 0) + 1

        # Generate or strengthen antibody
        if red_won:
            # Attack succeeded → generate stronger antibody (immune response)
            existing = self._antibodies.get(key)
            if existing:
                # Boost existing antibody (secondary immune response)
                self._antibodies[key] = Antibody(
                    target_category=category,
                    target_segment=segment,
                    strength=min(0.90, existing.strength + 0.15),
                    generation=self._round,
                    activations=existing.activations,
                )
            else:
                # Create new antibody (primary immune response)
                self._antibodies[key] = Antibody(
                    target_category=category,
                    target_segment=segment,
                    strength=0.25,
                    generation=self._round,
                )
        else:
            # Attack blocked → mild antibody maintenance
            existing = self._antibodies.get(key)
            if existing:
                self._antibodies[key] = Antibody(
                    target_category=category,
                    target_segment=segment,
                    strength=min(0.90, existing.strength + 0.03),
                    generation=self._round,
                    activations=existing.activations + 1,
                )

    def get_defense_bonus(self, category: str, segment: str) -> float:
        """Get immune defense bonus for a specific attack pattern.

        Returns 0.0 for never-seen attacks (no immunity).
        Returns up to 0.25 for well-known attacks (full immunity).
        """
        key = f"{category}:{segment}"
        encounters = self._memory_cells.get(key, 0)

        if encounters == 0:
            return self._innate_defense  # Innate only

        antibody = self._antibodies.get(key)
        if not antibody:
            return self._innate_defense

        # Memory cell bonus: more encounters = faster recognition
        memory_factor = min(1.0, encounters / 8)  # Full memory at 8 encounters

        # Antibody strength
        ab_bonus = antibody.strength * 0.25

        # Total immune defense (capped to prevent invincibility)
        return min(0.12, self._innate_defense + ab_bonus * memory_factor)

    def get_category_immunity(self, category: str) -> float:
        """Overall immunity to an attack category (across all segments)."""
        total = 0.0
        count = 0
        for key, antibody in self._antibodies.items():
            if key.startswith(f"{category}:"):
                total += antibody.strength
                count += 1
        return total / max(1, count) if count > 0 else 0.0

    @property
    def antibody_count(self) -> int:
        return len(self._antibodies)

    @property
    def total_encounters(self) -> int:
        return sum(self._memory_cells.values())


# ==================================================================
# 2. MOVING TARGET DEFENSE
# Constantly shifts attack surface to invalidate Red's intelligence.
# Inspired by military camouflage rotation and IP hopping.
# ==================================================================

class MovingTargetDefense:
    """Defense surface that never stays still.

    Every N rounds, the defense topology shifts:
    - Segment roles partially rotate
    - Synergy pairs reconfigure
    - Defense density distribution shuffles

    This makes Red's accumulated intelligence go stale.
    Red's erosion pressure and segment vulnerability scores
    become less accurate over time.
    """

    def __init__(self, rotation_interval: int = 8) -> None:
        self._interval = rotation_interval
        self._round = 0
        self._rotation_count = 0
        self._last_rotation_round = 0
        # Track which segments had their density redistributed
        self._redistribution_history: list[dict[str, float]] = []

    def should_rotate(self) -> bool:
        """Check if it's time to rotate the defense surface."""
        self._round += 1
        return (self._round - self._last_rotation_round) >= self._interval

    def compute_redistribution(
        self,
        current_densities: dict[str, float],
        threatened_segments: list[str],
    ) -> dict[str, float]:
        """Compute new density distribution after rotation.

        Rules:
        - Total density budget is preserved (zero-sum redistribution)
        - Threatened segments get priority
        - Some randomness to stay unpredictable
        - Minimum floor is maintained

        Returns target density adjustments (delta per segment).
        """
        self._rotation_count += 1
        self._last_rotation_round = self._round

        segments = list(current_densities.keys())
        total_density = sum(current_densities.values())
        mean_density = total_density / len(segments)

        # Compute adjustments
        adjustments: dict[str, float] = {}
        for seg in segments:
            current = current_densities[seg]

            if seg in threatened_segments:
                # Threatened → pull toward mean + small boost
                target = mean_density + 0.03
            else:
                # Non-threatened → slight reduction (zero-sum budget)
                target = mean_density - 0.01

            # Add noise to stay unpredictable
            noise = random.uniform(-0.02, 0.02)
            adjustment = (target - current) * 0.3 + noise
            adjustments[seg] = max(-0.10, min(0.10, adjustment))

        # Ensure zero-sum (total density preserved)
        total_adj = sum(adjustments.values())
        if abs(total_adj) > 0.001:
            correction = total_adj / len(segments)
            for seg in segments:
                adjustments[seg] -= correction

        self._redistribution_history.append(adjustments)
        return adjustments

    @property
    def staleness_factor(self) -> float:
        """How stale is Red's intelligence? (0.0 = fresh, 1.0 = completely stale)

        Increases with each rotation, decays between rotations.
        """
        rounds_since = self._round - self._last_rotation_round
        if self._rotation_count == 0:
            return 0.0
        # Staleness peaks right after rotation, decays over time
        base_staleness = min(0.6, self._rotation_count * 0.08)
        decay = min(1.0, rounds_since / self._interval)
        return base_staleness * (1.0 - decay * 0.5)


# ==================================================================
# 3. SELF-HEALING ENGINE
# Autonomous segment recovery between rounds.
# Inspired by biological wound healing: platelets → inflammation →
# proliferation → remodeling.
# ==================================================================

class SelfHealingEngine:
    """Autonomous segment recovery — Blue heals without explicit action.

    After a breach, the damaged segment enters a healing cycle:
      Phase 1 (Containment):  Isolate damage, prevent spread
      Phase 2 (Repair):       Rebuild segment density
      Phase 3 (Hardening):    Post-repair hardening (scar tissue)

    Healing is not free — it draws resources from healthy segments.
    But it means Blue never has to "waste" a strategy turn on simple repair.
    """

    def __init__(self) -> None:
        self._healing_queue: dict[str, float] = {}  # segment -> healing_progress
        self._scar_tissue: dict[str, float] = {}     # segment -> bonus from healing
        self._total_healed: int = 0

    def register_breach(self, segment: str) -> None:
        """Register a breach that needs healing."""
        # Reset healing progress for re-breached segments
        self._healing_queue[segment] = 0.0

    def heal_tick(self) -> dict[str, float]:
        """Advance healing by one tick. Returns density adjustments.

        Each tick heals ~3-5% of damage. Complete healing takes 3-5 ticks.
        """
        adjustments: dict[str, float] = {}
        completed: list[str] = []

        for seg, progress in self._healing_queue.items():
            # Healing rate: slow and resource-intensive (not free!)
            if progress < 0.3:
                heal_rate = 0.02  # Containment
            elif progress < 0.7:
                heal_rate = 0.015  # Repair
            else:
                heal_rate = 0.01  # Hardening

            new_progress = min(1.0, progress + heal_rate)
            self._healing_queue[seg] = new_progress
            adjustments[seg] = heal_rate

            if new_progress >= 1.0:
                completed.append(seg)
                self._total_healed += 1
                # Scar tissue: minimal permanent bonus (not free defense)
                self._scar_tissue[seg] = min(
                    0.04, self._scar_tissue.get(seg, 0.0) + 0.01,
                )

        for seg in completed:
            del self._healing_queue[seg]

        return adjustments

    def get_scar_bonus(self, segment: str) -> float:
        """Scar tissue bonus: previously healed segments are tougher."""
        return self._scar_tissue.get(segment, 0.0)

    @property
    def is_healing(self) -> bool:
        return len(self._healing_queue) > 0

    @property
    def healing_segments(self) -> list[str]:
        return list(self._healing_queue.keys())


# ==================================================================
# 4. HONEYPOT NETWORK
# Dynamic decoys that trap attackers and gather intelligence.
# ==================================================================

@dataclass
class HoneypotNode:
    """A single honeypot in the network."""

    segment: str                # Which segment this honeypot mimics
    attractiveness: float       # 0.0-1.0 how tempting it looks to Red
    intel_gathered: int = 0     # How much Red intel this honeypot has collected
    triggered: bool = False     # Has Red interacted with this honeypot?


class HoneypotNetwork:
    """Dynamic decoy network that traps and studies Red.

    Honeypots look like vulnerable segments to Red, but are actually
    traps. When Red attacks a honeypot:
    1. The attack is wasted (no real damage)
    2. Blue gathers intelligence about Red's methods
    3. Red's erosion pressure on the REAL segment decays

    The network adapts: honeypots are deployed where Red attacks most.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, HoneypotNode] = {}
        self._total_intel: int = 0
        self._trap_count: int = 0

    def deploy_honeypot(self, segment: str, attractiveness: float = 0.5) -> None:
        """Deploy a honeypot mimicking the given segment."""
        self._nodes[segment] = HoneypotNode(
            segment=segment,
            attractiveness=min(0.9, attractiveness),
        )

    def check_trap(
        self,
        target_segment: str,
        red_intensity: float,
        rng: random.Random,
    ) -> bool:
        """Check if Red stumbles into a honeypot.

        Returns True if Red attacked a honeypot instead of the real segment.
        Probability based on honeypot attractiveness vs Red's skill (intensity).
        """
        node = self._nodes.get(target_segment)
        if not node:
            return False

        # Higher attractiveness = more likely to trap
        # Higher intensity = Red is more experienced (less likely to fall for it)
        trap_prob = node.attractiveness * 0.15 / max(1.0, red_intensity * 0.8)
        trap_prob = min(0.10, max(0.01, trap_prob))

        if rng.random() < trap_prob:
            node.triggered = True
            node.intel_gathered += 1
            self._total_intel += 1
            self._trap_count += 1
            return True
        return False

    def gather_intel(self, segment: str) -> int:
        """Get intelligence gathered from honeypot on this segment."""
        node = self._nodes.get(segment)
        return node.intel_gathered if node else 0

    def erosion_reduction(self, segment: str) -> float:
        """Honeypot reduces Red's erosion effectiveness.

        When a honeypot has gathered intel, it helps Blue understand
        Red's erosion strategy, reducing its effectiveness.
        """
        intel = self.gather_intel(segment)
        if intel == 0:
            return 0.0
        return min(0.10, intel * 0.02)

    @property
    def active_count(self) -> int:
        return len(self._nodes)

    @property
    def total_traps(self) -> int:
        return self._trap_count


# ==================================================================
# 5. THREAT HUNTER
# Proactive detection — find attackers before they find you.
# ==================================================================

class ThreatHunter:
    """Proactive threat hunting — Blue doesn't just defend, it HUNTS.

    Instead of waiting for Red to attack, Blue actively:
    1. Scans for anomalous patterns in segment behavior
    2. Correlates attack history to predict infrastructure
    3. Pre-emptively hardens segments before Red discovers weaknesses

    Hunt effectiveness increases with more data (more battles = better hunting).
    """

    def __init__(self) -> None:
        self._attack_patterns: list[tuple[str, str, str]] = []  # (segment, category, strategy)
        self._hunt_results: dict[str, float] = {}  # segment -> threat score
        self._total_hunts: int = 0

    def ingest_attack_data(
        self,
        segment: str,
        category: str,
        strategy: str,
    ) -> None:
        """Feed attack data to the hunter."""
        self._attack_patterns.append((segment, category, strategy))

    def hunt(self) -> dict[str, float]:
        """Execute a threat hunt. Returns threat scores per segment.

        Threat score = how likely Red is to target this segment next.
        Higher score = needs more defense attention.
        """
        self._total_hunts += 1

        if len(self._attack_patterns) < 5:
            return {}

        # Analyze attack frequency per segment
        seg_counts = Counter(p[0] for p in self._attack_patterns[-50:])
        total = sum(seg_counts.values())

        # Analyze category preferences per segment
        seg_cat = Counter(
            (p[0], p[1]) for p in self._attack_patterns[-30:]
        )

        # Analyze strategy patterns
        strat_counts = Counter(p[2] for p in self._attack_patterns[-20:])

        scores: dict[str, float] = {}
        for seg in ["RTG", "ISO", "ATH", "DTX", "DCP", "RSP"]:
            # Frequency-based threat (what Red targets most)
            freq_score = seg_counts.get(seg, 0) / max(1, total)

            # Diversity of attacks (many different categories = determined attacker)
            cat_diversity = len([k for k in seg_cat if k[0] == seg])
            diversity_score = min(0.3, cat_diversity * 0.05)

            # Erode detection (if Red uses erode strategy on this segment)
            erode_focus = sum(
                1 for p in self._attack_patterns[-15:]
                if p[0] == seg and p[2] == "erode"
            )
            erode_score = min(0.3, erode_focus * 0.06)

            scores[seg] = freq_score + diversity_score + erode_score

        self._hunt_results = scores
        return scores

    def get_priority_segments(self, top_k: int = 3) -> list[str]:
        """Get segments that need immediate attention based on hunt results."""
        if not self._hunt_results:
            self.hunt()
        sorted_segs = sorted(
            self._hunt_results.items(),
            key=lambda x: x[1],
            reverse=True,
        )
        return [seg for seg, _ in sorted_segs[:top_k]]
