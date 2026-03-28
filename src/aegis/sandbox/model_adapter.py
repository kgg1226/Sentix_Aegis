"""Model adapter — translates battle analysis into security model improvements.

Closes the feedback loop:
    BattleLog.analyze() → BattleAnalysis → ModelAdapter → config/homeostasis/fitness deltas

Produces concrete, auditable adjustments to:
  1. Homeostasis target profiles (raise floor for weak segments)
  2. Fitness function weights (prioritize underperforming objectives)
  3. Detection thresholds (tighten for targeted layers)
  4. Genome constraints (minimum density floors per segment)
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aegis.common.config import DetectionConfig, GenomeConfig
from aegis.sandbox.battle_log import BattleAnalysis


@dataclass(frozen=True, slots=True)
class Adjustment:
    """A single, auditable config change."""

    target: str       # e.g. "homeostasis.wartime.ISO", "fitness.w_coverage"
    old_value: float
    new_value: float
    reason: str       # Human-readable justification from battle data


@dataclass(frozen=True, slots=True)
class ModelPatch:
    """Complete set of model improvements derived from one battle analysis."""

    adjustments: tuple[Adjustment, ...]
    homeostasis_overrides: dict[str, dict[str, float]]   # profile -> {seg: density}
    genome_config: GenomeConfig
    detection_config: DetectionConfig
    min_density_floors: dict[str, float]  # segment -> minimum density
    source_battle_rounds: int
    source_red_win_rate: float


# Segment → fitness objective most affected
_SEGMENT_OBJECTIVE_MAP: dict[str, str] = {
    "DTX": "coverage",
    "ATH": "coverage",
    "ISO": "coverage",
    "RTG": "efficiency",
    "DCP": "synergy",
    "RSP": "synergy",
}

# Detection layer → config threshold key
_LAYER_THRESHOLD_MAP: dict[str, str] = {
    "L1": "l1_bloom_filter_fp_rate",
    "L2": "l2_zscore_threshold",
    "L3": "l3_trigger_threshold",
    "L5": "l5_semantic_threshold",
}


class ModelAdapter:
    """Translates BattleAnalysis into concrete model configuration changes."""

    def __init__(
        self,
        current_genome_config: GenomeConfig | None = None,
        current_detection_config: DetectionConfig | None = None,
    ) -> None:
        self._genome_cfg = current_genome_config or GenomeConfig()
        self._detection_cfg = current_detection_config or DetectionConfig()

    def adapt(self, analysis: BattleAnalysis) -> ModelPatch:
        """Generate a ModelPatch from battle analysis."""
        adjustments: list[Adjustment] = []

        # 1. Compute minimum density floors from breach data
        floors = self._compute_density_floors(analysis, adjustments)

        # 2. Adjust homeostasis target profiles
        homeostasis_overrides = self._adjust_homeostasis(analysis, floors, adjustments)

        # 3. Adjust fitness weights
        new_genome_cfg = self._adjust_fitness_weights(analysis, adjustments)

        # 4. Adjust detection thresholds
        new_detection_cfg = self._adjust_detection(analysis, adjustments)

        return ModelPatch(
            adjustments=tuple(adjustments),
            homeostasis_overrides=homeostasis_overrides,
            genome_config=new_genome_cfg,
            detection_config=new_detection_cfg,
            min_density_floors=floors,
            source_battle_rounds=analysis.total_rounds,
            source_red_win_rate=analysis.red_win_rate,
        )

    # ------------------------------------------------------------------
    # 1. Density floors
    # ------------------------------------------------------------------

    def _compute_density_floors(
        self,
        analysis: BattleAnalysis,
        adjustments: list[Adjustment],
    ) -> dict[str, float]:
        """Set minimum density per segment based on breach history."""
        floors: dict[str, float] = {}
        base_floor = 0.30  # current breach threshold

        for seg, vuln in analysis.segment_vulnerabilities.items():
            if vuln.times_breached == 0:
                floors[seg] = base_floor
                continue

            # Floor = avg density at breach + safety margin proportional to breach count
            margin = min(0.25, 0.10 * vuln.times_breached)
            new_floor = round(vuln.avg_density_at_breach + margin, 2)
            new_floor = max(base_floor, min(0.70, new_floor))  # clamp
            floors[seg] = new_floor

            if new_floor > base_floor:
                adjustments.append(Adjustment(
                    target=f"density_floor.{seg}",
                    old_value=base_floor,
                    new_value=new_floor,
                    reason=(
                        f"{seg} breached {vuln.times_breached}x "
                        f"(avg density {vuln.avg_density_at_breach:.2f} at breach). "
                        f"Raising floor to {new_floor:.2f}."
                    ),
                ))

        return floors

    # ------------------------------------------------------------------
    # 2. Homeostasis targets
    # ------------------------------------------------------------------

    def _adjust_homeostasis(
        self,
        analysis: BattleAnalysis,
        floors: dict[str, float],
        adjustments: list[Adjustment],
    ) -> dict[str, dict[str, float]]:
        """Raise homeostasis targets for vulnerable segments."""
        from aegis.genome.homeostasis import _TARGET_PROFILES

        overrides: dict[str, dict[str, float]] = {}

        for profile_name, profile in _TARGET_PROFILES.items():
            updated = dict(profile)
            for seg, floor in floors.items():
                if floor > profile[seg]:
                    old = profile[seg]
                    updated[seg] = floor
                    adjustments.append(Adjustment(
                        target=f"homeostasis.{profile_name}.{seg}",
                        old_value=old,
                        new_value=floor,
                        reason=(
                            f"Battle data requires {seg} >= {floor:.2f}, "
                            f"but {profile_name} target was {old:.2f}."
                        ),
                    ))
            overrides[profile_name] = updated

        return overrides

    # ------------------------------------------------------------------
    # 3. Fitness weights
    # ------------------------------------------------------------------

    def _adjust_fitness_weights(
        self,
        analysis: BattleAnalysis,
        adjustments: list[Adjustment],
    ) -> GenomeConfig:
        """Boost weights for objectives linked to breached segments."""
        weights = {
            "coverage": self._genome_cfg.w_coverage,
            "efficiency": self._genome_cfg.w_efficiency,
            "adaptability": self._genome_cfg.w_adaptability,
            "synergy": self._genome_cfg.w_synergy,
            "threat_match": self._genome_cfg.w_threat_match,
        }

        # Identify which objectives are underperforming
        boost_targets: set[str] = set()
        for seg in analysis.chronic_weaknesses:
            obj = _SEGMENT_OBJECTIVE_MAP.get(seg)
            if obj:
                boost_targets.add(obj)

        if not boost_targets:
            return self._genome_cfg

        # Boost each target by 0.05, redistribute from others
        boost_amount = 0.05
        for obj in boost_targets:
            old = weights[obj]
            weights[obj] = min(0.40, old + boost_amount)
            adjustments.append(Adjustment(
                target=f"fitness.w_{obj}",
                old_value=old,
                new_value=weights[obj],
                reason=(
                    f"Chronic breach in segments mapped to '{obj}'. "
                    f"Boosting weight from {old:.2f} to {weights[obj]:.2f}."
                ),
            ))

        # Normalize so weights sum to 1.0
        total = sum(weights.values())
        weights = {k: round(v / total, 4) for k, v in weights.items()}

        return GenomeConfig(
            w_coverage=weights["coverage"],
            w_efficiency=weights["efficiency"],
            w_adaptability=weights["adaptability"],
            w_synergy=weights["synergy"],
            w_threat_match=weights["threat_match"],
            damping_base=self._genome_cfg.damping_base,
            damping_nonlinear_alpha=self._genome_cfg.damping_nonlinear_alpha,
            burst_mutation_bits=self._genome_cfg.burst_mutation_bits,
            crossover_segment_count=self._genome_cfg.crossover_segment_count,
        )

    # ------------------------------------------------------------------
    # 4. Detection thresholds
    # ------------------------------------------------------------------

    def _adjust_detection(
        self,
        analysis: BattleAnalysis,
        adjustments: list[Adjustment],
    ) -> DetectionConfig:
        """Tighten detection thresholds for heavily targeted layers."""
        total = analysis.total_rounds or 1
        updates: dict[str, float] = {}

        for layer, count in analysis.evasion_hotspots.items():
            ratio = count / total
            if ratio < 0.3:
                continue  # Not significantly targeted

            threshold_key = _LAYER_THRESHOLD_MAP.get(layer)
            if not threshold_key:
                continue

            old_val = getattr(self._detection_cfg, threshold_key)

            # Tighten threshold (direction depends on the parameter)
            if threshold_key in ("l3_trigger_threshold",):
                # Lower trigger = more sensitive
                new_val = round(max(0.05, old_val * 0.80), 4)
            elif threshold_key in ("l2_zscore_threshold",):
                # Lower z-score = more sensitive
                new_val = round(max(1.5, old_val * 0.85), 2)
            elif threshold_key in ("l5_semantic_threshold",):
                # Higher = more strict
                new_val = round(min(0.90, old_val * 1.10), 4)
            elif threshold_key in ("l1_bloom_filter_fp_rate",):
                # Lower FP rate = more precise
                new_val = round(max(0.0001, old_val * 0.80), 6)
            else:
                continue

            if new_val != old_val:
                updates[threshold_key] = new_val
                adjustments.append(Adjustment(
                    target=f"detection.{threshold_key}",
                    old_value=old_val,
                    new_value=new_val,
                    reason=(
                        f"{layer} targeted in {ratio:.0%} of attacks. "
                        f"Tightening {threshold_key} from {old_val} to {new_val}."
                    ),
                ))

        if not updates:
            return self._detection_cfg

        # Build new config with updates applied
        cfg_dict = {
            "l1_bloom_filter_fp_rate": self._detection_cfg.l1_bloom_filter_fp_rate,
            "l2_zscore_threshold": self._detection_cfg.l2_zscore_threshold,
            "l2_baseline_window_hours": self._detection_cfg.l2_baseline_window_hours,
            "l3_trigger_threshold": self._detection_cfg.l3_trigger_threshold,
            "l3_context_window_events": self._detection_cfg.l3_context_window_events,
            "l3_model_id": self._detection_cfg.l3_model_id,
            "l4_trigger_threshold": self._detection_cfg.l4_trigger_threshold,
            "l4_correlation_window_sec": self._detection_cfg.l4_correlation_window_sec,
            "l4_model_id": self._detection_cfg.l4_model_id,
            "l5_canary_count": self._detection_cfg.l5_canary_count,
            "l5_semantic_threshold": self._detection_cfg.l5_semantic_threshold,
        }
        cfg_dict.update(updates)
        return DetectionConfig(**cfg_dict)
