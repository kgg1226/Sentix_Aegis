"""Red agent — Offensive AI for the sandbox arena.

Generates attack scenarios targeting the current genome's weaknesses.
Successful attacks feed into the Memory Bank for defense evolution.
"""
from __future__ import annotations
import random
from dataclasses import dataclass
from aegis.common.types import Genome, ThreatCategory

@dataclass(frozen=True, slots=True)
class AttackScenario:
    category: ThreatCategory
    vector: str
    target_segment: str
    events: list[dict]
    expected_evasion_layer: str  # Which detection layer this aims to bypass

class RedAgent:
    def __init__(self, seed: int | None = None) -> None:
        self._rng = random.Random(seed)

    def generate_attack(self, genome: Genome) -> AttackScenario:
        """Generate attack targeting the genome's weakest segment."""
        weakest = min(
            ["RTG","ISO","ATH","DTX","DCP","RSP"],
            key=lambda s: genome.density(s),
        )
        category = self._pick_category(weakest)
        events = self._build_events(category, weakest)
        evasion = self._pick_evasion_target(category)
        return AttackScenario(
            category=category, vector=f"{category.name.lower()}_{weakest.lower()}",
            target_segment=weakest, events=events, expected_evasion_layer=evasion,
        )

    def _pick_category(self, weak_seg: str) -> ThreatCategory:
        mapping = {
            "DTX": ThreatCategory.ZERO_DAY, "DCP": ThreatCategory.APT,
            "ATH": ThreatCategory.INSIDER, "ISO": ThreatCategory.VOLUME,
            "RTG": ThreatCategory.APT, "RSP": ThreatCategory.COMMODITY,
        }
        return mapping.get(weak_seg, ThreatCategory.COMMODITY)

    def _build_events(self, cat: ThreatCategory, target: str) -> list[dict]:
        base = {"source_ip": f"10.{self._rng.randint(0,255)}.{self._rng.randint(0,255)}.1",
                "cloud": self._rng.choice(["aws","azure","oracle"]),
                "identity": f"attacker-{self._rng.randint(1000,9999)}"}
        return [base | {"action": f"probe_{target.lower()}", "step": i} for i in range(5)]

    def _pick_evasion_target(self, cat: ThreatCategory) -> str:
        return {ThreatCategory.COMMODITY:"L1", ThreatCategory.VOLUME:"L2",
                ThreatCategory.APT:"L3", ThreatCategory.ZERO_DAY:"L1",
                ThreatCategory.META_ATTACK:"L5", ThreatCategory.INSIDER:"L3"
               }.get(cat, "L1")
