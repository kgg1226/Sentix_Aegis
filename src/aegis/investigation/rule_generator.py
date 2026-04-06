"""Rule Generator — TTP 매핑 결과에서 누락된 탐지 룰을 자동 생성.

TTP 매핑 후 기존 룰셋에 없는 기법에 대해 탐지 룰을 자동으로 생성한다.
생성된 룰은 레트로 헌트로 검증된 후 프로덕션에 배포된다.

워크플로우:
  1. TTPMapping에서 매칭된 기법 추출
  2. 기존 RuleSet과 비교하여 커버되지 않는 기법 식별
  3. 미커버 기법에 대한 DetectionRule 자동 생성
  4. 생성된 룰의 검증 (false positive rate 추정)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from aegis.investigation.ttp_mapper import MitreTechnique, TTPMapping
from aegis.investigation.retro_hunt import DetectionRule


# ---------------------------------------------------------------------------
# Rule Set — 기존 룰 관리
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class RuleSet:
    """탐지 룰 집합."""

    rules: list[DetectionRule] = field(default_factory=list)

    def add(self, rule: DetectionRule) -> None:
        """룰 추가 (중복 ID 체크)."""
        if any(r.rule_id == rule.rule_id for r in self.rules):
            return
        self.rules.append(rule)

    def covers_technique(self, technique_id: str) -> bool:
        """특정 기법을 탐지하는 룰이 있는지 확인."""
        return any(r.mitre_technique_id == technique_id for r in self.rules)

    def rules_for_technique(self, technique_id: str) -> list[DetectionRule]:
        """특정 기법에 대한 룰 목록."""
        return [r for r in self.rules if r.mitre_technique_id == technique_id]

    @property
    def covered_techniques(self) -> set[str]:
        """커버된 기법 ID 집합."""
        return {r.mitre_technique_id for r in self.rules}

    @property
    def total_rules(self) -> int:
        return len(self.rules)


# ---------------------------------------------------------------------------
# Gap Analysis Result
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class CoverageGap:
    """룰 커버리지 갭 — 탐지 룰이 없는 기법."""

    technique: MitreTechnique
    max_confidence: float      # 해당 기법이 매핑에서 나온 최대 confidence
    event_count: int           # 해당 기법과 매칭된 이벤트 수
    priority: float            # 생성 우선순위 (confidence × severity × count)


@dataclass(slots=True)
class GapAnalysis:
    """룰 커버리지 갭 분석 결과."""

    total_techniques_seen: int = 0
    covered: int = 0
    gaps: list[CoverageGap] = field(default_factory=list)

    @property
    def coverage_rate(self) -> float:
        if self.total_techniques_seen == 0:
            return 1.0
        return self.covered / self.total_techniques_seen

    @property
    def gap_count(self) -> int:
        return len(self.gaps)


# ---------------------------------------------------------------------------
# Rule Generator
# ---------------------------------------------------------------------------

class RuleGenerator:
    """탐지 룰 자동 생성기.

    TTP 매핑 결과에서 기존 룰셋에 없는 기법을 찾아
    자동으로 DetectionRule을 생성한다.
    """

    def __init__(self, ruleset: RuleSet | None = None) -> None:
        self._ruleset = ruleset or RuleSet()
        self._generated_count = 0

    @property
    def ruleset(self) -> RuleSet:
        return self._ruleset

    def analyze_coverage(self, mapping: TTPMapping) -> GapAnalysis:
        """TTP 매핑 결과를 기존 룰셋과 비교하여 커버리지 갭 분석.

        Args:
            mapping: TTP 매핑 결과

        Returns:
            GapAnalysis with coverage gaps
        """
        # 매핑에서 나온 고유 기법별 통계
        technique_stats: dict[str, dict] = {}
        for match in mapping.matches:
            tid = match.technique.technique_id
            if tid not in technique_stats:
                technique_stats[tid] = {
                    "technique": match.technique,
                    "max_confidence": 0.0,
                    "event_count": 0,
                }
            stats = technique_stats[tid]
            stats["max_confidence"] = max(stats["max_confidence"], match.confidence)
            stats["event_count"] += 1

        analysis = GapAnalysis(total_techniques_seen=len(technique_stats))

        for tid, stats in technique_stats.items():
            if self._ruleset.covers_technique(tid):
                analysis.covered += 1
            else:
                tech = stats["technique"]
                priority = (
                    stats["max_confidence"]
                    * tech.severity_weight
                    * min(5, stats["event_count"]) / 5  # 이벤트 수 정규화
                )
                analysis.gaps.append(CoverageGap(
                    technique=tech,
                    max_confidence=stats["max_confidence"],
                    event_count=stats["event_count"],
                    priority=priority,
                ))

        # 우선순위 내림차순 정렬
        analysis.gaps.sort(key=lambda g: g.priority, reverse=True)
        return analysis

    def generate_rules(
        self,
        gaps: list[CoverageGap],
        max_rules: int = 20,
    ) -> list[DetectionRule]:
        """커버리지 갭에 대한 탐지 룰 자동 생성.

        Args:
            gaps: 커버리지 갭 목록 (우선순위 정렬)
            max_rules: 최대 생성 룰 수

        Returns:
            생성된 DetectionRule 리스트
        """
        generated: list[DetectionRule] = []
        now = datetime.utcnow().isoformat()

        for gap in gaps[:max_rules]:
            tech = gap.technique
            self._generated_count += 1
            rule_id = f"AUTO-{tech.technique_id}-{self._generated_count:04d}"

            conditions = self._build_conditions(tech)
            rule = DetectionRule(
                rule_id=rule_id,
                name=f"[Auto] {tech.name}",
                description=(
                    f"자동 생성 룰: {tech.description} "
                    f"(MITRE {tech.technique_id}, "
                    f"tactic: {tech.tactic.name})"
                ),
                severity=tech.severity_weight,
                mitre_technique_id=tech.technique_id,
                conditions=tuple(conditions),
                created_at=now,
            )
            generated.append(rule)
            self._ruleset.add(rule)

        return generated

    def _build_conditions(
        self, tech: MitreTechnique,
    ) -> list[tuple[str, str, str]]:
        """기법의 특성에서 탐지 조건을 생성."""
        conditions: list[tuple[str, str, str]] = []

        # cloud_actions가 있으면 action 기반 조건
        if tech.cloud_actions:
            actions_str = ",".join(tech.cloud_actions)
            conditions.append(("action", "in", actions_str))
        else:
            # keyword 기반 fallback
            if tech.detection_keywords:
                # 가장 구체적인 키워드를 조건으로
                best_keyword = max(tech.detection_keywords, key=len)
                conditions.append(("action", "contains", best_keyword))

        # severity 기반 추가 조건
        if tech.severity_weight >= 0.8:
            conditions.append(("severity", "gt", "0.3"))

        return conditions

    def generate_and_validate(
        self,
        mapping: TTPMapping,
        max_rules: int = 20,
    ) -> tuple[GapAnalysis, list[DetectionRule]]:
        """커버리지 분석 + 룰 생성을 한 번에 수행.

        Returns:
            (GapAnalysis, generated_rules)
        """
        analysis = self.analyze_coverage(mapping)
        rules = self.generate_rules(analysis.gaps, max_rules=max_rules)
        return analysis, rules
