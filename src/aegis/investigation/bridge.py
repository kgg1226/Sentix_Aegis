"""Bridge — Detection Pipeline(L0-L5)과 Investigation Pipeline 연동.

ThreatAssessment 시그널을 Investigation Pipeline 입력으로 변환하고,
고위험 탐지 시 자동으로 조사를 트리거한다.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

from aegis.common.types import CloudEvent, DetectionSignal, ThreatAssessment, ThreatCategory

if TYPE_CHECKING:
    from aegis.investigation.pipeline import InvestigationPipeline, InvestigationResult


# ---------------------------------------------------------------------------
# Detection Signal → Investigation Event 변환
# ---------------------------------------------------------------------------

def assessment_to_investigation_event(
    event: dict,
    assessment: ThreatAssessment,
) -> dict:
    """ThreatAssessment를 Investigation Pipeline이 소비하는 이벤트로 변환.

    Detection 시그널의 confidence, category, layer 정보를
    investigation 이벤트에 주입하여 TTP 매핑 정확도를 높인다.
    """
    inv_event = dict(event)  # 원본 이벤트 복사
    inv_event["detection_confidence"] = assessment.final_confidence
    inv_event["detection_category"] = assessment.category.name
    inv_event["detection_action"] = assessment.recommended_action
    inv_event["correlation_id"] = assessment.correlation_id

    # 각 레이어 시그널을 detail에 축적 (TTP keyword 매칭 강화)
    signal_details = []
    for sig in assessment.signals:
        if sig.hit:
            signal_details.append(f"[{sig.layer}] {sig.detail}")
    inv_event["detail"] = " | ".join(signal_details) if signal_details else event.get("detail", "")

    # L5 메타 공격 감지 시 플래그
    if assessment.category == ThreatCategory.META_ATTACK:
        inv_event["meta_attack"] = True

    return inv_event


def cloud_event_to_investigation_event(cloud_event: CloudEvent) -> dict:
    """CloudEvent를 Investigation용 dict로 변환."""
    result = cloud_event.to_pipeline_dict()
    result["event_id"] = cloud_event.event_id
    return result


# ---------------------------------------------------------------------------
# Actor Profile — 행위자별 활동 집계
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class ActorProfile:
    """단일 행위자(identity)의 행동 프로필."""

    identity: str
    first_seen: str = ""
    last_seen: str = ""
    event_count: int = 0
    source_ips: set[str] = field(default_factory=set)
    actions: list[str] = field(default_factory=list)
    regions: set[str] = field(default_factory=set)
    resources_accessed: set[str] = field(default_factory=set)
    max_severity: float = 0.0
    detection_categories: set[str] = field(default_factory=set)

    @property
    def unique_ips(self) -> int:
        return len(self.source_ips)

    @property
    def is_multi_region(self) -> bool:
        return len(self.regions) > 1

    @property
    def risk_score(self) -> float:
        """행위자 위험도 점수 (0.0-1.0).

        Multi-IP, multi-region, high severity, 높은 이벤트 수가 위험도를 높임.
        """
        score = 0.0
        # 다수 IP → 의심
        if self.unique_ips > 3:
            score += 0.25
        elif self.unique_ips > 1:
            score += 0.10
        # 다수 리전 → 의심
        if self.is_multi_region:
            score += 0.20
        # 높은 severity
        score += self.max_severity * 0.30
        # 이벤트 수 (많을수록)
        score += min(0.15, self.event_count * 0.01)
        # detection category
        if "META_ATTACK" in self.detection_categories:
            score += 0.10
        return min(1.0, score)


def build_actor_profiles(events: list[dict]) -> dict[str, ActorProfile]:
    """이벤트 목록에서 행위자별 프로필 구축."""
    profiles: dict[str, ActorProfile] = {}

    for evt in events:
        identity = evt.get("identity", "unknown")
        if identity not in profiles:
            profiles[identity] = ActorProfile(identity=identity)

        p = profiles[identity]
        p.event_count += 1

        ts = evt.get("timestamp", "")
        if ts:
            if not p.first_seen or ts < p.first_seen:
                p.first_seen = ts
            if not p.last_seen or ts > p.last_seen:
                p.last_seen = ts

        if evt.get("source_ip"):
            p.source_ips.add(evt["source_ip"])
        if evt.get("action"):
            p.actions.append(evt["action"])
        if evt.get("region"):
            p.regions.add(evt["region"])
        if evt.get("resource"):
            p.resources_accessed.add(evt["resource"])

        severity = evt.get("severity", 0.0)
        if isinstance(severity, (int, float)):
            p.max_severity = max(p.max_severity, float(severity))

        cat = evt.get("detection_category")
        if cat:
            p.detection_categories.add(cat)

    return profiles


# ---------------------------------------------------------------------------
# Temporal Cluster — 시간 기반 이벤트 클러스터링
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class TemporalCluster:
    """시간적으로 인접한 이벤트 그룹."""

    events: tuple[dict, ...]
    start_time: str
    end_time: str
    dominant_action: str      # 가장 빈번한 action
    unique_actions: int

    @property
    def duration_description(self) -> str:
        """클러스터 지속 시간 설명."""
        if not self.start_time or not self.end_time:
            return "unknown"
        try:
            start = datetime.fromisoformat(self.start_time.replace("Z", "+00:00"))
            end = datetime.fromisoformat(self.end_time.replace("Z", "+00:00"))
            delta = end - start
            if delta.total_seconds() < 60:
                return f"{delta.total_seconds():.0f}s"
            if delta.total_seconds() < 3600:
                return f"{delta.total_seconds() / 60:.0f}m"
            return f"{delta.total_seconds() / 3600:.1f}h"
        except (ValueError, TypeError):
            return "unknown"


def cluster_events_by_time(
    events: list[dict],
    gap_minutes: int = 30,
) -> list[TemporalCluster]:
    """이벤트를 시간 갭 기반으로 클러스터링.

    연속 이벤트 사이 gap_minutes 이상 공백이 있으면 새 클러스터 시작.
    """
    if not events:
        return []

    sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))
    clusters: list[TemporalCluster] = []
    current_group: list[dict] = [sorted_events[0]]

    for i in range(1, len(sorted_events)):
        prev_ts = sorted_events[i - 1].get("timestamp", "")
        curr_ts = sorted_events[i].get("timestamp", "")

        if prev_ts and curr_ts:
            try:
                prev_dt = datetime.fromisoformat(prev_ts.replace("Z", "+00:00"))
                curr_dt = datetime.fromisoformat(curr_ts.replace("Z", "+00:00"))
                gap = (curr_dt - prev_dt).total_seconds() / 60.0
                if gap > gap_minutes:
                    clusters.append(_finalize_cluster(current_group))
                    current_group = []
            except (ValueError, TypeError):
                pass

        current_group.append(sorted_events[i])

    if current_group:
        clusters.append(_finalize_cluster(current_group))

    return clusters


def _finalize_cluster(group: list[dict]) -> TemporalCluster:
    """이벤트 그룹을 TemporalCluster로 변환."""
    from collections import Counter

    actions = [e.get("action", "") for e in group]
    counter = Counter(actions)
    dominant = counter.most_common(1)[0][0] if counter else ""

    timestamps = sorted(e.get("timestamp", "") for e in group if e.get("timestamp"))

    return TemporalCluster(
        events=tuple(group),
        start_time=timestamps[0] if timestamps else "",
        end_time=timestamps[-1] if timestamps else "",
        dominant_action=dominant,
        unique_actions=len(set(actions)),
    )


# ---------------------------------------------------------------------------
# Investigation Trigger — 자동 조사 트리거
# ---------------------------------------------------------------------------

class InvestigationTrigger:
    """Detection Pipeline 출력을 감시하여 자동으로 Investigation을 트리거.

    조건:
      - final_confidence >= threshold
      - 또는 META_ATTACK 카테고리
      - 또는 일정 시간 내 동일 identity에서 다수 경고
    """

    def __init__(
        self,
        pipeline: InvestigationPipeline,
        confidence_threshold: float = 0.70,
        alert_window_count: int = 3,
    ) -> None:
        self._pipeline = pipeline
        self._threshold = confidence_threshold
        self._alert_window_count = alert_window_count
        self._pending_events: list[dict] = []
        self._identity_alerts: dict[str, int] = {}
        self._case_counter = 0

    def on_assessment(
        self,
        event: dict,
        assessment: ThreatAssessment,
    ) -> InvestigationResult | None:
        """ThreatAssessment를 수신하여 조사 필요 여부 판단.

        Returns:
            InvestigationResult if investigation was triggered, None otherwise
        """
        inv_event = assessment_to_investigation_event(event, assessment)
        self._pipeline.event_store.ingest(inv_event)

        should_investigate = False

        # 조건 1: 높은 confidence
        if assessment.final_confidence >= self._threshold:
            should_investigate = True

        # 조건 2: 메타 공격
        if assessment.category == ThreatCategory.META_ATTACK:
            should_investigate = True

        # 조건 3: 동일 identity 반복 경고
        identity = event.get("identity", "unknown")
        if assessment.final_confidence > 0.3:
            self._identity_alerts[identity] = self._identity_alerts.get(identity, 0) + 1
            if self._identity_alerts[identity] >= self._alert_window_count:
                should_investigate = True

        self._pending_events.append(inv_event)

        if should_investigate:
            return self._trigger_investigation(identity)
        return None

    def _trigger_investigation(self, identity: str) -> InvestigationResult:
        """조사 실행."""
        self._case_counter += 1
        case_id = f"AUTO-{datetime.utcnow().strftime('%Y%m%d')}-{self._case_counter:04d}"

        events_to_investigate = list(self._pending_events)
        self._pending_events.clear()
        self._identity_alerts.clear()

        return self._pipeline.investigate(
            case_id=case_id,
            title=f"Auto-triggered investigation for {identity}",
            events=events_to_investigate,
        )
