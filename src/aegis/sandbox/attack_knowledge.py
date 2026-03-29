"""Attack Knowledge Base — Red's collective intelligence from past & future.

Inspired by MITRE ATT&CK framework. Every technique Red uses has:
  - A real-world historical basis (documented attack method)
  - Effectiveness ratings per defense segment
  - Combo potential with other techniques (kill chain synergy)
  - Evolution potential (can mutate into new, undiscovered variants)

Red doesn't just try random attacks — it draws from humanity's
complete offensive cyber history and actively discovers new vectors.

Kill Chain phases (Lockheed Martin model):
  1. RECON:      Map target, identify weak points
  2. WEAPONIZE:  Craft attack payload
  3. DELIVER:    Get payload to target
  4. EXPLOIT:    Trigger vulnerability
  5. INSTALL:    Establish persistence
  6. C2:         Command & control channel
  7. EXFILTRATE: Extract value / cause damage

Each technique targets specific segments and has specific counters.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from enum import Enum, auto


class KillChainPhase(Enum):
    RECON = auto()
    WEAPONIZE = auto()
    DELIVER = auto()
    EXPLOIT = auto()
    INSTALL = auto()
    C2 = auto()
    EXFILTRATE = auto()


@dataclass(frozen=True, slots=True)
class AttackTechnique:
    """A single attack technique from the knowledge base."""

    name: str
    description: str
    phase: KillChainPhase
    target_segments: tuple[str, ...]     # Primary targets
    counter_segments: tuple[str, ...]    # What defends against this
    base_power: float                    # 0.0-1.0
    stealth: float                       # 0.0-1.0 (higher = harder to detect)
    combo_tags: tuple[str, ...]          # Tags for kill chain combos


# ==========================================================================
# HISTORICAL ATTACK TECHNIQUE LIBRARY
# Real-world attacks mapped to AEGIS defense segments
# ==========================================================================

TECHNIQUE_LIBRARY: list[AttackTechnique] = [
    # --- RECON phase ---
    AttackTechnique(
        name="port_scan",
        description="Systematic port scanning to map network topology",
        phase=KillChainPhase.RECON,
        target_segments=("RTG",),
        counter_segments=("DTX", "DCP"),
        base_power=0.15,
        stealth=0.3,
        combo_tags=("network_map", "recon"),
    ),
    AttackTechnique(
        name="osint_harvesting",
        description="Open source intelligence gathering — employee info, tech stack",
        phase=KillChainPhase.RECON,
        target_segments=("ATH",),
        counter_segments=("DCP",),
        base_power=0.10,
        stealth=0.95,
        combo_tags=("social", "recon"),
    ),
    AttackTechnique(
        name="dns_enumeration",
        description="DNS zone transfer / subdomain enumeration",
        phase=KillChainPhase.RECON,
        target_segments=("RTG", "ISO"),
        counter_segments=("DTX",),
        base_power=0.12,
        stealth=0.5,
        combo_tags=("network_map", "recon"),
    ),

    # --- WEAPONIZE phase ---
    AttackTechnique(
        name="custom_malware",
        description="Bespoke malware crafted for target environment",
        phase=KillChainPhase.WEAPONIZE,
        target_segments=("DTX", "RSP"),
        counter_segments=("DTX", "DCP"),
        base_power=0.45,
        stealth=0.7,
        combo_tags=("payload", "custom"),
    ),
    AttackTechnique(
        name="exploit_kit",
        description="Automated exploit kit targeting known CVEs",
        phase=KillChainPhase.WEAPONIZE,
        target_segments=("RTG", "ISO"),
        counter_segments=("DTX", "RSP"),
        base_power=0.35,
        stealth=0.3,
        combo_tags=("payload", "automated"),
    ),
    AttackTechnique(
        name="polymorphic_payload",
        description="Self-mutating payload that changes signature each execution",
        phase=KillChainPhase.WEAPONIZE,
        target_segments=("DTX",),
        counter_segments=("DCP", "DTX"),
        base_power=0.50,
        stealth=0.85,
        combo_tags=("payload", "evasion", "custom"),
    ),

    # --- DELIVER phase ---
    AttackTechnique(
        name="spearphish",
        description="Targeted phishing with social engineering",
        phase=KillChainPhase.DELIVER,
        target_segments=("ATH",),
        counter_segments=("ATH", "DTX"),
        base_power=0.40,
        stealth=0.6,
        combo_tags=("social", "delivery"),
    ),
    AttackTechnique(
        name="watering_hole",
        description="Compromise trusted website to deliver payload",
        phase=KillChainPhase.DELIVER,
        target_segments=("RTG", "ATH"),
        counter_segments=("ISO", "DTX"),
        base_power=0.38,
        stealth=0.75,
        combo_tags=("supply_chain", "delivery"),
    ),
    AttackTechnique(
        name="supply_chain_inject",
        description="Compromise upstream dependency or build pipeline",
        phase=KillChainPhase.DELIVER,
        target_segments=("RTG", "ISO", "DTX"),
        counter_segments=("DCP", "ATH"),
        base_power=0.55,
        stealth=0.90,
        combo_tags=("supply_chain", "delivery", "trust"),
    ),

    # --- EXPLOIT phase ---
    AttackTechnique(
        name="buffer_overflow",
        description="Memory corruption → arbitrary code execution",
        phase=KillChainPhase.EXPLOIT,
        target_segments=("RSP", "DTX"),
        counter_segments=("ISO", "RSP"),
        base_power=0.50,
        stealth=0.4,
        combo_tags=("memory", "exploit"),
    ),
    AttackTechnique(
        name="sql_injection",
        description="Database manipulation through input injection",
        phase=KillChainPhase.EXPLOIT,
        target_segments=("ATH", "ISO"),
        counter_segments=("ATH", "DTX"),
        base_power=0.42,
        stealth=0.35,
        combo_tags=("injection", "exploit"),
    ),
    AttackTechnique(
        name="privilege_escalation",
        description="Escalate from low-priv to admin/root",
        phase=KillChainPhase.EXPLOIT,
        target_segments=("ATH", "ISO"),
        counter_segments=("ATH", "ISO"),
        base_power=0.48,
        stealth=0.5,
        combo_tags=("escalation", "exploit"),
    ),
    AttackTechnique(
        name="deserialization_attack",
        description="Exploit insecure deserialization for RCE",
        phase=KillChainPhase.EXPLOIT,
        target_segments=("RSP", "DTX"),
        counter_segments=("DTX", "RSP"),
        base_power=0.46,
        stealth=0.55,
        combo_tags=("injection", "exploit"),
    ),
    AttackTechnique(
        name="llm_prompt_injection",
        description="Inject malicious prompts into L3/L4 LLM layers",
        phase=KillChainPhase.EXPLOIT,
        target_segments=("DTX", "DCP"),
        counter_segments=("DCP", "ATH"),
        base_power=0.52,
        stealth=0.80,
        combo_tags=("meta", "exploit", "ai"),
    ),

    # --- INSTALL phase ---
    AttackTechnique(
        name="rootkit",
        description="Kernel-level persistence — invisible to standard detection",
        phase=KillChainPhase.INSTALL,
        target_segments=("DTX", "RSP"),
        counter_segments=("DTX", "DCP"),
        base_power=0.55,
        stealth=0.90,
        combo_tags=("persistence", "stealth"),
    ),
    AttackTechnique(
        name="living_off_the_land",
        description="Use legitimate system tools (powershell, wmic) for persistence",
        phase=KillChainPhase.INSTALL,
        target_segments=("DTX", "RSP"),
        counter_segments=("DTX",),
        base_power=0.40,
        stealth=0.85,
        combo_tags=("lotl", "persistence", "stealth"),
    ),
    AttackTechnique(
        name="webshell",
        description="Plant web shell for persistent remote access",
        phase=KillChainPhase.INSTALL,
        target_segments=("RTG", "ATH"),
        counter_segments=("DTX", "ISO"),
        base_power=0.38,
        stealth=0.60,
        combo_tags=("persistence", "web"),
    ),

    # --- C2 phase ---
    AttackTechnique(
        name="dns_tunneling",
        description="Exfiltrate data through DNS queries",
        phase=KillChainPhase.C2,
        target_segments=("RTG",),
        counter_segments=("DTX", "RTG"),
        base_power=0.30,
        stealth=0.80,
        combo_tags=("c2", "covert"),
    ),
    AttackTechnique(
        name="encrypted_c2",
        description="TLS-encrypted command channel blending with legitimate traffic",
        phase=KillChainPhase.C2,
        target_segments=("RTG", "DTX"),
        counter_segments=("DTX", "DCP"),
        base_power=0.35,
        stealth=0.85,
        combo_tags=("c2", "covert", "encryption"),
    ),
    AttackTechnique(
        name="domain_fronting",
        description="Hide C2 behind legitimate CDN domains",
        phase=KillChainPhase.C2,
        target_segments=("RTG",),
        counter_segments=("DTX", "ISO"),
        base_power=0.32,
        stealth=0.90,
        combo_tags=("c2", "covert", "evasion"),
    ),

    # --- EXFILTRATE phase ---
    AttackTechnique(
        name="data_exfil_encrypted",
        description="Exfiltrate sensitive data through encrypted channels",
        phase=KillChainPhase.EXFILTRATE,
        target_segments=("RTG", "ISO"),
        counter_segments=("DTX", "ISO", "DCP"),
        base_power=0.40,
        stealth=0.70,
        combo_tags=("exfil", "data"),
    ),
    AttackTechnique(
        name="ransomware_deploy",
        description="Encrypt critical data, demand ransom",
        phase=KillChainPhase.EXFILTRATE,
        target_segments=("RSP", "ISO", "ATH"),
        counter_segments=("RSP", "ISO", "DCP"),
        base_power=0.60,
        stealth=0.10,
        combo_tags=("destructive", "ransomware"),
    ),
    AttackTechnique(
        name="wiper_attack",
        description="Destroy data and systems — pure destruction",
        phase=KillChainPhase.EXFILTRATE,
        target_segments=("RSP", "RTG", "ISO"),
        counter_segments=("RSP", "ISO"),
        base_power=0.65,
        stealth=0.05,
        combo_tags=("destructive", "wiper"),
    ),
]


# ==========================================================================
# Kill Chain Composer
# ==========================================================================

# Techniques that combo well together (tag-based)
_COMBO_BONUS: dict[tuple[str, str], float] = {
    ("recon", "exploit"): 0.12,       # Recon → targeted exploit
    ("recon", "social"): 0.10,        # Recon → social engineering
    ("social", "delivery"): 0.15,     # Social → delivery success
    ("payload", "exploit"): 0.10,     # Custom payload → exploit
    ("payload", "evasion"): 0.18,     # Evasion payload → stealth
    ("exploit", "persistence"): 0.12, # Exploit → persistence
    ("persistence", "c2"): 0.10,      # Persistence → C2 setup
    ("c2", "exfil"): 0.15,           # C2 → exfiltration
    ("supply_chain", "trust"): 0.20,  # Supply chain → trust exploitation
    ("stealth", "covert"): 0.14,      # Stealth install → covert C2
    ("meta", "ai"): 0.16,            # Meta + AI = LLM compromise
    ("injection", "escalation"): 0.12, # Inject → escalate
    ("lotl", "stealth"): 0.15,       # Living-off-land + stealth
}


class KillChainComposer:
    """Composes multi-stage attack chains from the technique library.

    Red uses this to plan full kill chains, not just individual attacks.
    A well-composed chain has synergy bonuses from technique combinations.
    """

    def __init__(self, rng: random.Random | None = None) -> None:
        self._rng = rng or random.Random()
        self._technique_outcomes: dict[str, list[bool]] = {}
        self._chain_outcomes: list[tuple[list[str], bool]] = []

    def compose_chain(
        self,
        target_segment: str,
        max_phases: int = 4,
        *,
        known_weak_segments: list[str] | None = None,
    ) -> list[AttackTechnique]:
        """Build a kill chain targeting a specific segment.

        Selects techniques from different phases that target the given
        segment (or its dependencies) and have good combo synergy.
        """
        weak = set(known_weak_segments or [])
        weak.add(target_segment)

        # Group techniques by phase
        by_phase: dict[KillChainPhase, list[AttackTechnique]] = {}
        for t in TECHNIQUE_LIBRARY:
            by_phase.setdefault(t.phase, []).append(t)

        # Build chain: select best technique per phase
        chain: list[AttackTechnique] = []
        phases_order = [
            KillChainPhase.RECON,
            KillChainPhase.WEAPONIZE,
            KillChainPhase.DELIVER,
            KillChainPhase.EXPLOIT,
            KillChainPhase.INSTALL,
            KillChainPhase.C2,
            KillChainPhase.EXFILTRATE,
        ]

        for phase in phases_order[:max_phases]:
            candidates = by_phase.get(phase, [])
            if not candidates:
                continue

            # Score candidates based on target relevance + learning
            scored: list[tuple[float, AttackTechnique]] = []
            for tech in candidates:
                score = tech.base_power
                # Bonus for targeting weak segments
                if any(s in weak for s in tech.target_segments):
                    score += 0.20
                # Bonus for combo with previous techniques in chain
                if chain:
                    combo_bonus = self._calc_combo_bonus(chain[-1], tech)
                    score += combo_bonus
                # Learning: boost techniques that worked before
                outcomes = self._technique_outcomes.get(tech.name, [])
                if outcomes:
                    recent = outcomes[-10:]
                    score += sum(recent) / len(recent) * 0.15
                scored.append((score, tech))

            scored.sort(key=lambda x: x[0], reverse=True)
            # Probabilistic selection from top 3 (not always best, allows exploration)
            top = scored[:min(3, len(scored))]
            weights = [s for s, _ in top]
            total = sum(weights)
            if total > 0:
                weights = [w / total for w in weights]
            else:
                weights = [1 / len(top)] * len(top)
            selected = self._rng.choices([t for _, t in top], weights=weights, k=1)[0]
            chain.append(selected)

        return chain

    def chain_power(self, chain: list[AttackTechnique]) -> float:
        """Calculate total attack power of a kill chain.

        Power = sum of individual powers + combo bonuses.
        A well-composed chain is more than the sum of its parts.
        """
        if not chain:
            return 0.0

        base = sum(t.base_power for t in chain) / len(chain)

        # Combo bonuses between adjacent phases
        combo = 0.0
        for i in range(len(chain) - 1):
            combo += self._calc_combo_bonus(chain[i], chain[i + 1])

        # Stealth average (stealthy chain is harder to detect)
        stealth = sum(t.stealth for t in chain) / len(chain)

        return min(1.0, base + combo + stealth * 0.15)

    def chain_stealth(self, chain: list[AttackTechnique]) -> float:
        """Average stealth of the kill chain."""
        if not chain:
            return 0.0
        return sum(t.stealth for t in chain) / len(chain)

    def record_outcome(self, chain: list[AttackTechnique], success: bool) -> None:
        """Learn from chain outcome."""
        names = [t.name for t in chain]
        self._chain_outcomes.append((names, success))
        for tech in chain:
            self._technique_outcomes.setdefault(tech.name, []).append(success)

    def _calc_combo_bonus(self, prev: AttackTechnique, curr: AttackTechnique) -> float:
        bonus = 0.0
        for tag_a in prev.combo_tags:
            for tag_b in curr.combo_tags:
                bonus += _COMBO_BONUS.get((tag_a, tag_b), 0.0)
                bonus += _COMBO_BONUS.get((tag_b, tag_a), 0.0)
        return min(0.25, bonus)  # Cap per-pair bonus


class ZeroDayDiscovery:
    """Vulnerability discovery engine — finds UNKNOWN weaknesses.

    Red doesn't just use known techniques. It actively probes for
    undiscovered vulnerabilities by:
    1. Mutating successful attack vectors
    2. Fuzzing segment boundaries
    3. Analyzing defense response patterns to infer blind spots
    4. Combining techniques in novel ways

    Each discovered zero-day is unique and has bonus power because
    Blue has never seen it before.
    """

    def __init__(self, rng: random.Random | None = None) -> None:
        self._rng = rng or random.Random()
        self._discovered: list[AttackTechnique] = []
        self._probe_history: dict[str, int] = {}  # segment -> probe count
        self._blind_spots: dict[str, float] = {}   # segment -> estimated blind spot size

    def probe_for_weakness(
        self,
        segment: str,
        defense_density: float,
        round_num: int,
    ) -> AttackTechnique | None:
        """Attempt to discover a zero-day in the given segment.

        Discovery probability increases with:
          - Number of probes on this segment (more probing = more likely)
          - Lower defense density (more surface area to explore)
          - Campaign progress (Red gets smarter over time)

        Returns new technique if discovered, None otherwise.
        """
        self._probe_history[segment] = self._probe_history.get(segment, 0) + 1
        probes = self._probe_history[segment]

        # Discovery probability
        probe_factor = min(0.15, probes * 0.008)  # More probes = higher chance
        density_factor = (1.0 - defense_density) * 0.10  # Lower density = more surface
        experience_factor = min(0.08, round_num * 0.001)  # Experience matters

        discover_prob = 0.01 + probe_factor + density_factor + experience_factor
        discover_prob = min(0.20, discover_prob)  # Max 20% per probe

        if self._rng.random() < discover_prob:
            return self._generate_zeroday(segment)
        return None

    def analyze_defense_pattern(
        self,
        segment: str,
        defense_responses: list[str],
    ) -> float:
        """Analyze Blue's defense patterns to estimate blind spots.

        If Blue always uses the same response pattern, Red can find gaps.
        Returns estimated blind spot size [0.0, 0.3].
        """
        if len(defense_responses) < 5:
            return 0.0

        # Measure response predictability (low entropy = predictable = exploitable)
        from collections import Counter
        counts = Counter(defense_responses[-20:])
        total = sum(counts.values())
        entropy = 0.0
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)

        # Max entropy for len(counts) unique values
        max_entropy = math.log2(max(1, len(counts)))
        if max_entropy > 0:
            normalized_entropy = entropy / max_entropy
        else:
            normalized_entropy = 0.0

        # Low entropy = predictable defense = larger blind spot
        blind_spot = max(0.0, 0.30 * (1.0 - normalized_entropy))
        self._blind_spots[segment] = blind_spot
        return blind_spot

    def get_blind_spot(self, segment: str) -> float:
        return self._blind_spots.get(segment, 0.0)

    @property
    def discovered_count(self) -> int:
        return len(self._discovered)

    def _generate_zeroday(self, segment: str) -> AttackTechnique:
        """Generate a unique zero-day technique."""
        idx = len(self._discovered) + 1

        # Zero-days are powerful and stealthy
        power = 0.45 + self._rng.random() * 0.25  # 0.45-0.70
        stealth = 0.60 + self._rng.random() * 0.30  # 0.60-0.90

        # Random secondary target
        other_segments = [s for s in ["RTG", "ISO", "ATH", "DTX", "DCP", "RSP"] if s != segment]
        secondary = self._rng.choice(other_segments)

        tech = AttackTechnique(
            name=f"zeroday_{segment.lower()}_{idx:03d}",
            description=f"Discovered zero-day vulnerability in {segment} defense layer",
            phase=KillChainPhase.EXPLOIT,
            target_segments=(segment, secondary),
            counter_segments=("DTX", "DCP"),  # Only behavioral detection catches zero-days
            base_power=power,
            stealth=stealth,
            combo_tags=("zeroday", "exploit", "novel"),
        )
        self._discovered.append(tech)
        return tech
