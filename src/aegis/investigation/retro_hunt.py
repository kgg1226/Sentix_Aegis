"""Retro Hunt Engine — 과거 이벤트를 새로운 룰로 재검사.

새로운 탐지 룰이 생성되면, 과거에 수집된 이벤트들을 대상으로
해당 룰을 적용하여 놓친 위협을 찾아낸다.

워크플로우:
  1. 새 룰 수신
  2. 이벤트 저장소에서 과거 이벤트 조회
  3. 각 이벤트에 룰 적용
  4. 매칭된 이벤트를 RetroHuntResult로 반환
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta


# ---------------------------------------------------------------------------
# Detection Rule
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class DetectionRule:
    """탐지 룰 — 이벤트 매칭 조건 정의.

    조건은 AND 로직: 모든 조건이 만족되어야 매칭.
    각 조건은 (field, operator, value) 튜플.
    """

    rule_id: str
    name: str
    description: str
    severity: float                             # 0.0-1.0
    mitre_technique_id: str                     # e.g. "T1562.008"
    conditions: tuple[tuple[str, str, str], ...]  # (field, op, value)
    # op: "eq", "contains", "startswith", "gt", "lt", "in"
    created_at: str = ""                        # ISO 8601

    def matches(self, event: dict) -> bool:
        """이벤트가 이 룰의 모든 조건을 만족하는지 검사."""
        for field_name, op, value in self.conditions:
            event_value = str(event.get(field_name, "")).lower()
            value_lower = value.lower()

            if op == "eq":
                if event_value != value_lower:
                    return False
            elif op == "contains":
                if value_lower not in event_value:
                    return False
            elif op == "startswith":
                if not event_value.startswith(value_lower):
                    return False
            elif op == "gt":
                try:
                    if float(event_value) <= float(value_lower):
                        return False
                except ValueError:
                    return False
            elif op == "lt":
                try:
                    if float(event_value) >= float(value_lower):
                        return False
                except ValueError:
                    return False
            elif op == "in":
                allowed = [v.strip().lower() for v in value_lower.split(",")]
                if event_value not in allowed:
                    return False

        return True


# ---------------------------------------------------------------------------
# Retro Hunt Results
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class RetroHuntMatch:
    """레트로 헌트에서 발견된 단일 매칭."""

    rule: DetectionRule
    event: dict
    event_timestamp: str


@dataclass(slots=True)
class RetroHuntResult:
    """레트로 헌트 전체 결과."""

    rule: DetectionRule
    total_events_scanned: int = 0
    matches: list[RetroHuntMatch] = field(default_factory=list)
    scan_duration_ms: float = 0.0

    @property
    def match_count(self) -> int:
        return len(self.matches)

    @property
    def match_rate(self) -> float:
        if self.total_events_scanned == 0:
            return 0.0
        return self.match_count / self.total_events_scanned


# ---------------------------------------------------------------------------
# Event Store (In-Memory — Phase 7에서 pgvector로 교체)
# ---------------------------------------------------------------------------

class EventStore:
    """과거 이벤트 저장소.

    현재는 인메모리 구현. Phase 7에서 PostgreSQL + pgvector로 교체 예정.
    """

    def __init__(self, max_events: int = 100_000) -> None:
        self._events: list[dict] = []
        self._max_events = max_events

    def ingest(self, event: dict) -> None:
        """이벤트 저장."""
        self._events.append(event)
        if len(self._events) > self._max_events:
            # 오래된 이벤트부터 제거
            self._events = self._events[-self._max_events:]

    def ingest_batch(self, events: list[dict]) -> None:
        """이벤트 배치 저장."""
        for event in events:
            self.ingest(event)

    def query(
        self,
        lookback_hours: int = 720,  # 기본 30일
        filters: dict[str, str] | None = None,
    ) -> list[dict]:
        """과거 이벤트 조회.

        Args:
            lookback_hours: 조회 기간 (시간 단위)
            filters: 필터 조건 {field: value} (contains 매칭)
        """
        cutoff = (datetime.utcnow() - timedelta(hours=lookback_hours)).isoformat()
        result: list[dict] = []

        for event in self._events:
            ts = event.get("timestamp", "")
            if ts and ts < cutoff:
                continue

            if filters:
                match = all(
                    v.lower() in str(event.get(k, "")).lower()
                    for k, v in filters.items()
                )
                if not match:
                    continue

            result.append(event)

        return result

    @property
    def total_events(self) -> int:
        return len(self._events)


# ---------------------------------------------------------------------------
# Retro Hunt Engine
# ---------------------------------------------------------------------------

class RetroHuntEngine:
    """레트로 헌트 실행 엔진.

    새로운 탐지 룰을 과거 이벤트에 적용하여 놓친 위협을 찾는다.
    """

    def __init__(self, event_store: EventStore) -> None:
        self._store = event_store
        self._hunt_history: list[RetroHuntResult] = []

    def hunt(
        self,
        rule: DetectionRule,
        lookback_hours: int = 720,
        filters: dict[str, str] | None = None,
    ) -> RetroHuntResult:
        """단일 룰로 레트로 헌트 실행.

        Args:
            rule: 적용할 탐지 룰
            lookback_hours: 조회 기간
            filters: 추가 필터

        Returns:
            RetroHuntResult with matched events
        """
        import time
        start = time.monotonic()

        events = self._store.query(lookback_hours=lookback_hours, filters=filters)
        result = RetroHuntResult(rule=rule, total_events_scanned=len(events))

        for event in events:
            if rule.matches(event):
                result.matches.append(RetroHuntMatch(
                    rule=rule,
                    event=event,
                    event_timestamp=event.get("timestamp", ""),
                ))

        result.scan_duration_ms = (time.monotonic() - start) * 1000
        self._hunt_history.append(result)
        return result

    def hunt_batch(
        self,
        rules: list[DetectionRule],
        lookback_hours: int = 720,
    ) -> list[RetroHuntResult]:
        """여러 룰을 일괄 적용."""
        return [self.hunt(rule, lookback_hours) for rule in rules]

    @property
    def hunt_history(self) -> list[RetroHuntResult]:
        return list(self._hunt_history)
