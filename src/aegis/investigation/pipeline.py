"""Investigation Pipeline — 전체 조사 워크플로우 오케스트레이터.

포스트에서 배운 실전 워크플로우를 파이프라인으로 구현:
  1. 이벤트 수집/수신
  2. TTP 매핑 (MITRE ATT&CK)
  3. 기존 룰 커버리지 확인
  4. 누락 룰 자동 생성
  5. 탐지 검증 (룰 테스트)
  6. 레트로 헌트 (과거 이벤트 재검사)
  7. 반복 분석 (피드백 루프)
  8. 조사 보고서 생성
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aegis.investigation.ttp_mapper import TTPMapper, TTPMapping
from aegis.investigation.retro_hunt import (
    DetectionRule,
    EventStore,
    RetroHuntEngine,
    RetroHuntResult,
)
from aegis.investigation.rule_generator import RuleGenerator, RuleSet, GapAnalysis
from aegis.investigation.report import InvestigationReport


# ---------------------------------------------------------------------------
# Pipeline Configuration
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class InvestigationConfig:
    """조사 파이프라인 설정."""

    max_rules_per_cycle: int = 20        # 사이클당 최대 룰 생성 수
    retro_lookback_hours: int = 720      # 레트로 헌트 기간 (기본 30일)
    max_iterations: int = 3              # 최대 반복 분석 횟수
    min_retro_matches_for_iteration: int = 5  # 반복 분석 트리거 임계값


# ---------------------------------------------------------------------------
# Pipeline Result
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class InvestigationResult:
    """파이프라인 실행 결과."""

    case_id: str
    iterations: int = 0
    ttp_mapping: TTPMapping | None = None
    gap_analysis: GapAnalysis | None = None
    generated_rules: list[DetectionRule] = field(default_factory=list)
    retro_results: list[RetroHuntResult] = field(default_factory=list)
    report: InvestigationReport | None = None

    @property
    def total_retro_matches(self) -> int:
        return sum(r.match_count for r in self.retro_results)


# ---------------------------------------------------------------------------
# Investigation Pipeline
# ---------------------------------------------------------------------------

class InvestigationPipeline:
    """보안 사고 조사 파이프라인 오케스트레이터.

    실전 분석 워크플로우:
      이벤트 → TTP 매핑 → 룰 확인 → 룰 생성 → 레트로 헌트 → 반복 → 보고서
    """

    def __init__(
        self,
        event_store: EventStore | None = None,
        ruleset: RuleSet | None = None,
        config: InvestigationConfig | None = None,
    ) -> None:
        self._event_store = event_store or EventStore()
        self._config = config or InvestigationConfig()
        self._mapper = TTPMapper()
        self._generator = RuleGenerator(ruleset or RuleSet())
        self._retro = RetroHuntEngine(self._event_store)

    @property
    def event_store(self) -> EventStore:
        return self._event_store

    @property
    def ruleset(self) -> RuleSet:
        return self._generator.ruleset

    def investigate(
        self,
        case_id: str,
        title: str,
        events: list[dict],
    ) -> InvestigationResult:
        """전체 조사 파이프라인 실행.

        Args:
            case_id: 사건 ID (예: "CASE-2026-04-06-001")
            title: 사건 제목
            events: 분석 대상 이벤트 목록

        Returns:
            InvestigationResult with full analysis
        """
        result = InvestigationResult(case_id=case_id)

        # Step 1: 이벤트를 저장소에 추가 (레트로 헌트용)
        self._event_store.ingest_batch(events)

        # Step 2: TTP 매핑
        ttp_events = [
            {
                "event_id": evt.get("event_id", f"evt-{i}"),
                "action": evt.get("action", ""),
                "detail": evt.get("detail", ""),
                "indicators": evt.get("indicators"),
            }
            for i, evt in enumerate(events)
        ]
        result.ttp_mapping = self._mapper.map_events(ttp_events)

        # Step 3-6: 반복 분석 루프
        all_generated_rules: list[DetectionRule] = []
        all_retro_results: list[RetroHuntResult] = []

        for iteration in range(self._config.max_iterations):
            result.iterations = iteration + 1

            # Step 3: 커버리지 갭 분석
            gap_analysis, new_rules = self._generator.generate_and_validate(
                result.ttp_mapping,
                max_rules=self._config.max_rules_per_cycle,
            )
            result.gap_analysis = gap_analysis
            all_generated_rules.extend(new_rules)

            if not new_rules:
                break  # 더 이상 생성할 룰이 없음

            # Step 4: 레트로 헌트
            retro_results = self._retro.hunt_batch(
                new_rules,
                lookback_hours=self._config.retro_lookback_hours,
            )
            all_retro_results.extend(retro_results)

            # Step 5: 레트로 헌트 결과로 추가 분석 필요 여부 판단
            new_matches = sum(r.match_count for r in retro_results)
            if new_matches < self._config.min_retro_matches_for_iteration:
                break  # 추가 분석 불필요

            # Step 6: 레트로 헌트에서 발견된 이벤트를 추가 TTP 매핑
            retro_events = []
            for rr in retro_results:
                for match in rr.matches:
                    retro_events.append({
                        "event_id": match.event.get("event_id", "retro"),
                        "action": match.event.get("action", ""),
                        "detail": match.event.get("detail", ""),
                        "indicators": match.event.get("indicators"),
                    })

            if retro_events:
                additional_mapping = self._mapper.map_events(retro_events)
                # 기존 매핑에 추가
                for m in additional_mapping.matches:
                    # 중복 방지
                    existing_keys = {
                        (em.event_id, em.technique.technique_id)
                        for em in result.ttp_mapping.matches
                    }
                    if (m.event_id, m.technique.technique_id) not in existing_keys:
                        result.ttp_mapping.matches.append(m)

        result.generated_rules = all_generated_rules
        result.retro_results = all_retro_results

        # Step 7: 보고서 생성
        report = InvestigationReport(
            case_id=case_id,
            title=title,
            events=events,
            ttp_mapping=result.ttp_mapping,
            gap_analysis=result.gap_analysis,
            generated_rules=result.generated_rules,
            retro_results=result.retro_results,
        )
        # 영향 분석 (severity 설정 포함)
        report.render_markdown()  # 이 과정에서 severity가 설정됨
        result.report = report

        return result
