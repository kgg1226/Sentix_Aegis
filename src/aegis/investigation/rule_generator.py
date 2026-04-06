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
        """기법의 특성에서 탐지 조건을 생성.

        전략:
        1. action 매칭 (cloud_actions 기반)
        2. keyword 보조 조건 (detection_keywords 기반)
        3. severity 임계값 (고위험 기법만)
        4. detection 시그널 연동 (bridge 경유 이벤트용)
        """
        conditions: list[tuple[str, str, str]] = []

        # 1차: cloud_actions 기반 조건
        if tech.cloud_actions:
            actions_str = ",".join(tech.cloud_actions)
            conditions.append(("action", "in", actions_str))
        elif tech.detection_keywords:
            best_keyword = max(tech.detection_keywords, key=len)
            conditions.append(("action", "contains", best_keyword))

        # 2차: keyword 보조 조건 (action과 별개로 detail 필드도 체크)
        if tech.detection_keywords and tech.cloud_actions:
            # action 조건이 있으면 keyword는 보조로 detail에서 검색
            top_keywords = sorted(tech.detection_keywords, key=len, reverse=True)[:2]
            for kw in top_keywords:
                conditions.append(("detail", "contains", kw))
                break  # 가장 구체적인 것 1개만

        # 3차: severity 기반 조건 (고위험 기법에만)
        if tech.severity_weight >= 0.9:
            conditions.append(("severity", "gt", "0.5"))
        elif tech.severity_weight >= 0.7:
            conditions.append(("severity", "gt", "0.3"))

        return conditions

    def validate_rules(
        self,
        rules: list[DetectionRule],
        baseline_events: list[dict],
        max_fp_rate: float = 0.05,
    ) -> tuple[list[DetectionRule], list[DetectionRule]]:
        """생성된 룰을 baseline 이벤트에 대해 FP rate 검증.

        Args:
            rules: 검증할 룰 목록
            baseline_events: 정상 이벤트 (false positive 측정용)
            max_fp_rate: 최대 허용 FP rate (기본 5%)

        Returns:
            (approved_rules, rejected_rules)
        """
        approved: list[DetectionRule] = []
        rejected: list[DetectionRule] = []

        if not baseline_events:
            return rules, []

        for rule in rules:
            fp_count = sum(1 for evt in baseline_events if rule.matches(evt))
            fp_rate = fp_count / len(baseline_events)
            if fp_rate <= max_fp_rate:
                approved.append(rule)
            else:
                rejected.append(rule)

        return approved, rejected

    def generate_and_validate(
        self,
        mapping: TTPMapping,
        max_rules: int = 20,
        baseline_events: list[dict] | None = None,
    ) -> tuple[GapAnalysis, list[DetectionRule]]:
        """커버리지 분석 + 룰 생성 + FP 검증을 한 번에 수행.

        Args:
            mapping: TTP 매핑 결과
            max_rules: 최대 생성 룰 수
            baseline_events: FP 검증용 정상 이벤트 (없으면 검증 생략)

        Returns:
            (GapAnalysis, approved_rules)
        """
        analysis = self.analyze_coverage(mapping)
        rules = self.generate_rules(analysis.gaps, max_rules=max_rules)

        if baseline_events:
            rules, _rejected = self.validate_rules(rules, baseline_events)

        return analysis, rules


# ---------------------------------------------------------------------------
# Correlation Rule — 다단계 공격 패턴 탐지
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class CorrelationRule:
    """다단계 상관 분석 룰 — 여러 기법이 순차적으로 발생하는 패턴 탐지.

    예: T1078(Valid Accounts) → T1580(Discovery) → T1098(Persistence)
        → 72시간 내 동일 identity에서 발생하면 APT 캠페인 의심
    """

    rule_id: str
    name: str
    description: str
    technique_sequence: tuple[str, ...]   # e.g. ("T1078", "T1580", "T1098")
    time_window_hours: int = 72           # 시간 윈도우
    require_same_identity: bool = True
    severity: float = 0.9

    def matches_sequence(self, events: list[dict], technique_map: dict[str, str]) -> bool:
        """이벤트 시퀀스가 이 룰의 기법 순서를 만족하는지 검사.

        Args:
            events: 시간순 정렬된 이벤트 목록
            technique_map: event_id → technique_id 매핑
        """
        if not events or not self.technique_sequence:
            return False

        # 시간 윈도우 체크
        timestamps = [e.get("timestamp", "") for e in events if e.get("timestamp")]
        if len(timestamps) >= 2:
            try:
                first = datetime.fromisoformat(timestamps[0].replace("Z", "+00:00"))
                last = datetime.fromisoformat(timestamps[-1].replace("Z", "+00:00"))
                if (last - first).total_seconds() > self.time_window_hours * 3600:
                    return False
            except (ValueError, TypeError):
                pass

        # identity 동일성 체크
        if self.require_same_identity:
            identities = {e.get("identity", "") for e in events if e.get("identity")}
            if len(identities) > 1:
                return False

        # 시퀀스 매칭 (순서 보존, 모든 기법이 발견되어야 함)
        matched_techniques: list[str] = []
        for evt in events:
            eid = evt.get("event_id", "")
            tid = technique_map.get(eid, "")
            if tid and (not matched_techniques or tid != matched_techniques[-1]):
                matched_techniques.append(tid)

        seq_idx = 0
        for tid in matched_techniques:
            if seq_idx < len(self.technique_sequence) and tid == self.technique_sequence[seq_idx]:
                seq_idx += 1
        return seq_idx >= len(self.technique_sequence)


# 사전 정의 상관 룰
PREDEFINED_CORRELATION_RULES: list[CorrelationRule] = [
    CorrelationRule(
        rule_id="CORR-001",
        name="APT Cloud Takeover Pattern",
        description="계정 탈취 → 탐색 → 권한 유지: 클라우드 APT 전형 패턴",
        technique_sequence=("T1078", "T1580", "T1098"),
        time_window_hours=72,
        severity=0.95,
    ),
    CorrelationRule(
        rule_id="CORR-002",
        name="Defense Evasion + Exfiltration",
        description="로깅 비활성화 후 데이터 유출: 은폐-유출 패턴",
        technique_sequence=("T1562", "T1537"),
        time_window_hours=24,
        severity=1.0,
    ),
    CorrelationRule(
        rule_id="CORR-003",
        name="Credential Theft + Lateral Movement",
        description="자격 증명 탈취 후 횡적 이동: 내부 확산 패턴",
        technique_sequence=("T1528", "T1550"),
        time_window_hours=48,
        severity=0.9,
    ),
    CorrelationRule(
        rule_id="CORR-004",
        name="Persistence + Defense Evasion + Impact",
        description="지속성 확보 → 방어 무력화 → 파괴: 랜섬웨어/와이퍼 패턴",
        technique_sequence=("T1098", "T1562", "T1485"),
        time_window_hours=48,
        severity=1.0,
    ),
]
