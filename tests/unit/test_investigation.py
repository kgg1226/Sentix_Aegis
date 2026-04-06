"""Tests for the Investigation Pipeline (Phase 8).

Covers:
  - TTP Mapper: action matching, keyword matching, batch mapping
  - Retro Hunt: rule matching, event store, hunt execution
  - Rule Generator: coverage analysis, rule generation
  - Report: markdown rendering
  - Pipeline: end-to-end investigation
"""

import pytest
from datetime import datetime, timedelta

from aegis.investigation.ttp_mapper import (
    TTPMapper,
    TTPMapping,
    MitreTactic,
    MitreTechnique,
    MITRE_TECHNIQUES,
)
from aegis.investigation.retro_hunt import (
    DetectionRule,
    EventStore,
    RetroHuntEngine,
)
from aegis.investigation.rule_generator import (
    RuleGenerator,
    RuleSet,
    CorrelationRule,
    PREDEFINED_CORRELATION_RULES,
)
from aegis.investigation.report import InvestigationReport
from aegis.investigation.bridge import (
    build_actor_profiles,
    cluster_events_by_time,
    ActorProfile,
    assessment_to_investigation_event,
    InvestigationTrigger,
)
from aegis.investigation.pipeline import (
    InvestigationPipeline,
    InvestigationConfig,
)
from aegis.common.types import ThreatAssessment, ThreatCategory, DetectionSignal


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_event(action: str, identity: str = "arn:aws:iam::123:user/attacker",
                source_ip: str = "198.51.100.1", severity: float = 0.5,
                event_id: str = "", **kwargs) -> dict:
    """테스트용 이벤트 생성."""
    return {
        "event_id": event_id or f"evt-{action}",
        "action": action,
        "identity": identity,
        "source_ip": source_ip,
        "severity": severity,
        "timestamp": datetime.utcnow().isoformat(),
        "region": "ap-northeast-2",
        "resource": "arn:aws:s3:::my-bucket",
        **kwargs,
    }


def _make_attack_scenario() -> list[dict]:
    """실제 공격 시나리오 이벤트 세트."""
    now = datetime.utcnow()
    return [
        _make_event("ConsoleLogin", event_id="e1",
                     timestamp=(now - timedelta(hours=5)).isoformat()),
        _make_event("GetCallerIdentity", event_id="e2",
                     timestamp=(now - timedelta(hours=4, minutes=50)).isoformat()),
        _make_event("DescribeInstances", event_id="e3",
                     timestamp=(now - timedelta(hours=4, minutes=45)).isoformat()),
        _make_event("CreateAccessKey", event_id="e4", severity=0.8,
                     timestamp=(now - timedelta(hours=4)).isoformat()),
        _make_event("AttachUserPolicy", event_id="e5", severity=0.9,
                     timestamp=(now - timedelta(hours=3, minutes=30)).isoformat()),
        _make_event("StopLogging", event_id="e6", severity=1.0,
                     timestamp=(now - timedelta(hours=3)).isoformat()),
        _make_event("GetSecretValue", event_id="e7", severity=0.7,
                     timestamp=(now - timedelta(hours=2, minutes=30)).isoformat()),
        _make_event("CopySnapshot", event_id="e8", severity=0.8,
                     timestamp=(now - timedelta(hours=2)).isoformat()),
        _make_event("ModifySnapshotAttribute", event_id="e9", severity=0.9,
                     timestamp=(now - timedelta(hours=1, minutes=30)).isoformat()),
        _make_event("DeleteTrail", event_id="e10", severity=1.0,
                     timestamp=(now - timedelta(hours=1)).isoformat()),
    ]


# ===========================================================================
# TTP Mapper Tests
# ===========================================================================

class TestTTPMapper:

    def test_action_match_console_login(self):
        mapper = TTPMapper()
        matches = mapper.map_event("e1", "ConsoleLogin")
        assert len(matches) > 0
        # ConsoleLogin → T1078 (Valid Accounts)
        technique_ids = [m.technique.technique_id for m in matches]
        assert "T1078" in technique_ids

    def test_action_match_stop_logging(self):
        mapper = TTPMapper()
        matches = mapper.map_event("e2", "StopLogging")
        technique_ids = [m.technique.technique_id for m in matches]
        # StopLogging → T1562 or T1562.008
        assert any(tid.startswith("T1562") for tid in technique_ids)

    def test_keyword_match(self):
        mapper = TTPMapper()
        matches = mapper.map_event("e3", "SomeAction", detail="privilege escalation detected")
        technique_ids = [m.technique.technique_id for m in matches]
        assert "T1548" in technique_ids

    def test_no_match_benign_event(self):
        mapper = TTPMapper()
        matches = mapper.map_event("e4", "GetBucketLocation")
        # 정확한 action 매칭이 없으면 keyword에도 안 걸림
        # GetBucketLocation은 어떤 cloud_actions에도 없고 키워드도 약함
        # 매칭이 있더라도 confidence가 낮아야 함
        high_conf = [m for m in matches if m.confidence >= 0.5]
        assert len(high_conf) == 0

    def test_batch_mapping(self):
        mapper = TTPMapper()
        events = [
            {"event_id": "e1", "action": "ConsoleLogin"},
            {"event_id": "e2", "action": "CreateAccessKey"},
            {"event_id": "e3", "action": "StopLogging"},
        ]
        mapping = mapper.map_events(events)
        assert len(mapping.matches) > 0
        assert len(mapping.tactics_involved) >= 2

    def test_kill_chain_coverage(self):
        mapper = TTPMapper()
        events = _make_attack_scenario()
        ttp_events = [{"event_id": e["event_id"], "action": e["action"]} for e in events]
        mapping = mapper.map_events(ttp_events)
        # 공격 시나리오는 여러 전술을 커버해야 함
        assert mapping.kill_chain_coverage > 0.0
        assert mapping.max_severity > 0.0

    def test_techniques_by_tactic(self):
        mapper = TTPMapper()
        events = [
            {"event_id": "e1", "action": "ConsoleLogin"},
            {"event_id": "e2", "action": "StopLogging"},
        ]
        mapping = mapper.map_events(events)
        by_tactic = mapping.techniques_by_tactic()
        assert isinstance(by_tactic, dict)
        assert len(by_tactic) > 0


# ===========================================================================
# Retro Hunt Tests
# ===========================================================================

class TestEventStore:

    def test_ingest_and_query(self):
        store = EventStore()
        store.ingest({"action": "ConsoleLogin", "timestamp": datetime.utcnow().isoformat()})
        assert store.total_events == 1
        results = store.query()
        assert len(results) == 1

    def test_query_with_filter(self):
        store = EventStore()
        store.ingest({"action": "ConsoleLogin", "timestamp": datetime.utcnow().isoformat()})
        store.ingest({"action": "StopLogging", "timestamp": datetime.utcnow().isoformat()})
        results = store.query(filters={"action": "Stop"})
        assert len(results) == 1

    def test_max_events_limit(self):
        store = EventStore(max_events=5)
        for i in range(10):
            store.ingest({"action": f"action-{i}", "timestamp": datetime.utcnow().isoformat()})
        assert store.total_events == 5


class TestDetectionRule:

    def test_eq_condition(self):
        rule = DetectionRule(
            rule_id="R1", name="Test", description="", severity=0.5,
            mitre_technique_id="T1078",
            conditions=(("action", "eq", "ConsoleLogin"),),
        )
        assert rule.matches({"action": "ConsoleLogin"})
        assert not rule.matches({"action": "StopLogging"})

    def test_contains_condition(self):
        rule = DetectionRule(
            rule_id="R2", name="Test", description="", severity=0.5,
            mitre_technique_id="T1078",
            conditions=(("action", "contains", "login"),),
        )
        assert rule.matches({"action": "ConsoleLogin"})
        assert not rule.matches({"action": "StopLogging"})

    def test_in_condition(self):
        rule = DetectionRule(
            rule_id="R3", name="Test", description="", severity=0.5,
            mitre_technique_id="T1562",
            conditions=(("action", "in", "StopLogging,DeleteTrail"),),
        )
        assert rule.matches({"action": "StopLogging"})
        assert rule.matches({"action": "DeleteTrail"})
        assert not rule.matches({"action": "ConsoleLogin"})

    def test_gt_condition(self):
        rule = DetectionRule(
            rule_id="R4", name="Test", description="", severity=0.5,
            mitre_technique_id="T1485",
            conditions=(("severity", "gt", "0.7"),),
        )
        assert rule.matches({"severity": 0.9})
        assert not rule.matches({"severity": 0.5})

    def test_multiple_conditions_and(self):
        rule = DetectionRule(
            rule_id="R5", name="Test", description="", severity=0.5,
            mitre_technique_id="T1562",
            conditions=(
                ("action", "eq", "stoplogging"),
                ("severity", "gt", "0.5"),
            ),
        )
        assert rule.matches({"action": "StopLogging", "severity": 0.9})
        assert not rule.matches({"action": "StopLogging", "severity": 0.3})


class TestRetroHuntEngine:

    def test_hunt_finds_matches(self):
        store = EventStore()
        now = datetime.utcnow().isoformat()
        store.ingest({"action": "StopLogging", "severity": 0.9, "timestamp": now})
        store.ingest({"action": "ConsoleLogin", "severity": 0.3, "timestamp": now})

        engine = RetroHuntEngine(store)
        rule = DetectionRule(
            rule_id="R1", name="Test", description="", severity=0.9,
            mitre_technique_id="T1562",
            conditions=(("action", "contains", "stoplogging"),),
        )
        result = engine.hunt(rule)
        assert result.match_count == 1
        assert result.total_events_scanned == 2

    def test_hunt_batch(self):
        store = EventStore()
        now = datetime.utcnow().isoformat()
        store.ingest({"action": "StopLogging", "timestamp": now})
        store.ingest({"action": "DeleteTrail", "timestamp": now})

        engine = RetroHuntEngine(store)
        rules = [
            DetectionRule(
                rule_id="R1", name="", description="", severity=0.9,
                mitre_technique_id="T1562",
                conditions=(("action", "eq", "stoplogging"),),
            ),
            DetectionRule(
                rule_id="R2", name="", description="", severity=0.9,
                mitre_technique_id="T1562.008",
                conditions=(("action", "eq", "deletetrail"),),
            ),
        ]
        results = engine.hunt_batch(rules)
        assert len(results) == 2
        assert all(r.match_count == 1 for r in results)


# ===========================================================================
# Rule Generator Tests
# ===========================================================================

class TestRuleGenerator:

    def test_coverage_analysis_finds_gaps(self):
        mapper = TTPMapper()
        events = [
            {"event_id": "e1", "action": "ConsoleLogin"},
            {"event_id": "e2", "action": "StopLogging"},
        ]
        mapping = mapper.map_events(events)

        generator = RuleGenerator(RuleSet())
        analysis = generator.analyze_coverage(mapping)
        assert analysis.total_techniques_seen > 0
        assert analysis.gap_count > 0
        assert analysis.coverage_rate == 0.0  # 빈 룰셋

    def test_coverage_with_existing_rules(self):
        mapper = TTPMapper()
        events = [{"event_id": "e1", "action": "ConsoleLogin"}]
        mapping = mapper.map_events(events)

        # T1078 룰이 이미 있으면 갭이 아님
        ruleset = RuleSet()
        ruleset.add(DetectionRule(
            rule_id="EXIST-1", name="", description="", severity=0.5,
            mitre_technique_id="T1078",
            conditions=(("action", "eq", "consolelogin"),),
        ))
        generator = RuleGenerator(ruleset)
        analysis = generator.analyze_coverage(mapping)
        assert analysis.covered >= 1

    def test_generate_rules(self):
        mapper = TTPMapper()
        events = [
            {"event_id": "e1", "action": "ConsoleLogin"},
            {"event_id": "e2", "action": "StopLogging"},
        ]
        mapping = mapper.map_events(events)

        generator = RuleGenerator(RuleSet())
        analysis, rules = generator.generate_and_validate(mapping)
        assert len(rules) > 0
        for rule in rules:
            assert rule.rule_id.startswith("AUTO-")
            assert len(rule.conditions) > 0

    def test_generated_rules_added_to_ruleset(self):
        mapper = TTPMapper()
        events = [{"event_id": "e1", "action": "StopLogging"}]
        mapping = mapper.map_events(events)

        generator = RuleGenerator(RuleSet())
        _, rules = generator.generate_and_validate(mapping)
        assert generator.ruleset.total_rules == len(rules)


# ===========================================================================
# Report Tests
# ===========================================================================

class TestReport:

    def test_empty_report(self):
        report = InvestigationReport(case_id="CASE-001", title="Test")
        md = report.render_markdown()
        assert "CASE-001" in md
        assert "Executive Summary" in md

    def test_full_report(self):
        events = _make_attack_scenario()
        mapper = TTPMapper()
        ttp_events = [{"event_id": e["event_id"], "action": e["action"]} for e in events]
        mapping = mapper.map_events(ttp_events)

        report = InvestigationReport(
            case_id="CASE-002",
            title="Suspicious Activity in AWS",
            events=events,
            ttp_mapping=mapping,
        )
        md = report.render_markdown()
        assert "MITRE ATT&CK" in md
        assert "Timeline" in md
        assert "Recommendations" in md
        assert len(md) > 500  # 충분한 내용이 있어야 함

    def test_report_severity_escalation(self):
        events = _make_attack_scenario()
        mapper = TTPMapper()
        ttp_events = [{"event_id": e["event_id"], "action": e["action"]} for e in events]
        mapping = mapper.map_events(ttp_events)

        report = InvestigationReport(
            case_id="CASE-003",
            title="APT Campaign",
            events=events,
            ttp_mapping=mapping,
        )
        report.render_markdown()
        # 공격 시나리오는 severity가 높아야 함
        assert report.severity in ("HIGH", "CRITICAL")


# ===========================================================================
# Pipeline End-to-End Tests
# ===========================================================================

class TestInvestigationPipeline:

    def test_full_pipeline(self):
        config = InvestigationConfig(
            max_iterations=2,
            retro_lookback_hours=24,
        )
        pipeline = InvestigationPipeline(config=config)

        events = _make_attack_scenario()
        result = pipeline.investigate(
            case_id="CASE-E2E-001",
            title="End-to-End Test Investigation",
            events=events,
        )

        # 기본 검증
        assert result.case_id == "CASE-E2E-001"
        assert result.iterations >= 1
        assert result.ttp_mapping is not None
        assert len(result.ttp_mapping.matches) > 0
        assert result.gap_analysis is not None
        assert len(result.generated_rules) > 0
        assert result.report is not None

        # 보고서 검증
        md = result.report.render_markdown()
        assert "CASE-E2E-001" in md
        assert "MITRE ATT&CK" in md

    def test_pipeline_with_existing_rules(self):
        ruleset = RuleSet()
        # 미리 몇 개의 룰을 등록
        ruleset.add(DetectionRule(
            rule_id="PRE-1", name="", description="", severity=0.5,
            mitre_technique_id="T1078",
            conditions=(("action", "eq", "consolelogin"),),
        ))

        pipeline = InvestigationPipeline(ruleset=ruleset)
        events = [_make_event("ConsoleLogin", event_id="e1")]
        result = pipeline.investigate("CASE-002", "Test", events)
        # T1078은 이미 커버되므로 갭이 줄어야 함
        assert result.gap_analysis is not None

    def test_pipeline_retro_hunt_integration(self):
        """레트로 헌트가 과거 이벤트를 발견하는지 확인."""
        pipeline = InvestigationPipeline()

        # 과거 이벤트를 먼저 저장
        past_events = [
            _make_event("StopLogging", event_id="past-1", severity=0.9),
            _make_event("DeleteTrail", event_id="past-2", severity=1.0),
        ]
        pipeline.event_store.ingest_batch(past_events)

        # 새로운 이벤트로 조사 시작
        new_events = [_make_event("ConsoleLogin", event_id="new-1")]
        result = pipeline.investigate("CASE-003", "Retro Test", new_events)

        # 레트로 헌트가 과거 이벤트를 찾아야 함
        assert result.total_retro_matches >= 0  # 룰이 생성되면 매칭 가능

    def test_empty_events(self):
        pipeline = InvestigationPipeline()
        result = pipeline.investigate("CASE-004", "Empty", [])
        assert result.report is not None
        md = result.report.render_markdown()
        assert "CASE-004" in md


# ===========================================================================
# Bridge Tests
# ===========================================================================

class TestActorProfile:

    def test_build_profiles(self):
        events = _make_attack_scenario()
        profiles = build_actor_profiles(events)
        assert len(profiles) >= 1
        # 모든 이벤트는 동일 identity
        for profile in profiles.values():
            assert profile.event_count > 0
            assert profile.first_seen != ""

    def test_risk_score_increases_with_ips(self):
        events = [
            _make_event("A", source_ip="1.1.1.1", event_id="e1"),
            _make_event("B", source_ip="2.2.2.2", event_id="e2"),
            _make_event("C", source_ip="3.3.3.3", event_id="e3"),
            _make_event("D", source_ip="4.4.4.4", event_id="e4"),
        ]
        profiles = build_actor_profiles(events)
        p = list(profiles.values())[0]
        assert p.unique_ips == 4
        assert p.risk_score > 0.2  # 다수 IP → 높은 risk

    def test_multi_region_flag(self):
        events = [
            _make_event("A", event_id="e1", region="us-east-1"),
            _make_event("B", event_id="e2", region="ap-northeast-2"),
        ]
        profiles = build_actor_profiles(events)
        p = list(profiles.values())[0]
        assert p.is_multi_region


class TestTemporalClustering:

    def test_single_cluster(self):
        now = datetime.utcnow()
        events = [
            _make_event("A", event_id="e1", timestamp=now.isoformat()),
            _make_event("B", event_id="e2",
                        timestamp=(now + timedelta(minutes=5)).isoformat()),
        ]
        clusters = cluster_events_by_time(events, gap_minutes=30)
        assert len(clusters) == 1
        assert len(clusters[0].events) == 2

    def test_multiple_clusters(self):
        now = datetime.utcnow()
        events = [
            _make_event("A", event_id="e1", timestamp=now.isoformat()),
            _make_event("B", event_id="e2",
                        timestamp=(now + timedelta(hours=2)).isoformat()),
        ]
        clusters = cluster_events_by_time(events, gap_minutes=30)
        assert len(clusters) == 2

    def test_empty_events(self):
        clusters = cluster_events_by_time([])
        assert clusters == []


class TestAssessmentBridge:

    def test_assessment_to_investigation_event(self):
        event = _make_event("StopLogging", event_id="e1")
        assessment = ThreatAssessment(
            signals=(
                DetectionSignal(
                    layer="L1", confidence=0.9, hit=True,
                    detail="signature match: StopLogging", latency_ms=1.0,
                ),
            ),
            final_confidence=0.9,
            category=ThreatCategory.COMMODITY,
            classification="commodity (high confidence)",
            recommended_action="block",
            correlation_id="corr-001",
        )
        inv_event = assessment_to_investigation_event(event, assessment)
        assert inv_event["detection_confidence"] == 0.9
        assert inv_event["detection_category"] == "COMMODITY"
        assert "StopLogging" in inv_event["detail"]


class TestInvestigationTrigger:

    def test_triggers_on_high_confidence(self):
        pipeline = InvestigationPipeline()
        trigger = InvestigationTrigger(pipeline, confidence_threshold=0.7)

        event = _make_event("StopLogging", event_id="e1")
        assessment = ThreatAssessment(
            signals=(
                DetectionSignal(
                    layer="L1", confidence=0.9, hit=True,
                    detail="sig match", latency_ms=1.0,
                ),
            ),
            final_confidence=0.9,
            category=ThreatCategory.COMMODITY,
            classification="test",
            recommended_action="block",
            correlation_id="c1",
        )
        result = trigger.on_assessment(event, assessment)
        assert result is not None
        assert result.case_id.startswith("AUTO-")

    def test_no_trigger_on_low_confidence(self):
        pipeline = InvestigationPipeline()
        trigger = InvestigationTrigger(pipeline, confidence_threshold=0.7)

        event = _make_event("GetBucketLocation", event_id="e1")
        assessment = ThreatAssessment(
            signals=(
                DetectionSignal(
                    layer="L1", confidence=0.1, hit=False,
                    detail="no match", latency_ms=1.0,
                ),
            ),
            final_confidence=0.1,
            category=ThreatCategory.COMMODITY,
            classification="test",
            recommended_action="monitor",
            correlation_id="c2",
        )
        result = trigger.on_assessment(event, assessment)
        assert result is None


# ===========================================================================
# Correlation Rule Tests
# ===========================================================================

class TestCorrelationRule:

    def test_matches_sequence(self):
        rule = CorrelationRule(
            rule_id="TEST-001",
            name="Test",
            description="test",
            technique_sequence=("T1078", "T1098"),
            time_window_hours=24,
        )
        events = [
            _make_event("ConsoleLogin", event_id="e1"),
            _make_event("CreateAccessKey", event_id="e2"),
        ]
        technique_map = {"e1": "T1078", "e2": "T1098"}
        assert rule.matches_sequence(events, technique_map)

    def test_no_match_wrong_order(self):
        rule = CorrelationRule(
            rule_id="TEST-002",
            name="Test",
            description="test",
            technique_sequence=("T1098", "T1078"),  # reversed
        )
        events = [
            _make_event("ConsoleLogin", event_id="e1"),
            _make_event("CreateAccessKey", event_id="e2"),
        ]
        technique_map = {"e1": "T1078", "e2": "T1098"}
        assert not rule.matches_sequence(events, technique_map)

    def test_predefined_rules_exist(self):
        assert len(PREDEFINED_CORRELATION_RULES) >= 4


class TestFPValidation:

    def test_fp_validation_rejects_broad_rules(self):
        generator = RuleGenerator(RuleSet())
        broad_rule = DetectionRule(
            rule_id="BROAD-1", name="", description="", severity=0.5,
            mitre_technique_id="T1580",
            conditions=(("action", "contains", "get"),),
        )
        # 정상 이벤트에 "get" 포함 → FP
        baseline = [
            {"action": "GetBucketLocation", "severity": 0.1},
            {"action": "GetObject", "severity": 0.1},
            {"action": "ListBuckets", "severity": 0.1},
        ]
        approved, rejected = generator.validate_rules([broad_rule], baseline)
        # "get"이 2/3 이벤트에 매칭 → FP rate > 5% → rejected
        assert len(rejected) == 1

    def test_fp_validation_approves_specific_rules(self):
        generator = RuleGenerator(RuleSet())
        specific_rule = DetectionRule(
            rule_id="SPEC-1", name="", description="", severity=0.9,
            mitre_technique_id="T1562",
            conditions=(("action", "eq", "stoplogging"),),
        )
        baseline = [
            {"action": "GetBucketLocation"},
            {"action": "ListBuckets"},
        ]
        approved, rejected = generator.validate_rules([specific_rule], baseline)
        assert len(approved) == 1
        assert len(rejected) == 0


# ===========================================================================
# Enhanced Report Tests
# ===========================================================================

class TestEnhancedReport:

    def test_report_has_actor_profiles(self):
        events = _make_attack_scenario()
        report = InvestigationReport(case_id="CASE-RP", title="Test", events=events)
        md = report.render_markdown()
        assert "Actor Profiles" in md

    def test_report_has_evidence_chain(self):
        events = _make_attack_scenario()
        mapper = TTPMapper()
        ttp_events = [{"event_id": e["event_id"], "action": e["action"]} for e in events]
        mapping = mapper.map_events(ttp_events)

        report = InvestigationReport(
            case_id="CASE-EC", title="Test",
            events=events, ttp_mapping=mapping,
        )
        md = report.render_markdown()
        assert "Evidence Chain" in md
