"""Tests for L0 cloud collectors and CollectorOrchestrator.

All tests run without real cloud SDKs — we mock the SDK calls and verify
that normalization logic produces correct CloudEvent instances.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aegis.common.config import CollectorConfig, DetectionConfig
from aegis.common.types import CloudEvent, CloudProvider


# ---------------------------------------------------------------------------
# CloudEvent type tests
# ---------------------------------------------------------------------------


class TestCloudEvent:
    def test_to_pipeline_dict_contains_required_fields(self):
        event = CloudEvent(
            provider=CloudProvider.AWS,
            event_id="evt-123",
            timestamp="2026-03-29T00:00:00+00:00",
            region="ap-northeast-2",
            source_service="cloudtrail",
            action="ConsoleLogin",
            identity="arn:aws:iam::123456789012:user/alice",
            source_ip="1.2.3.4",
            resource="arn:aws:s3:::my-bucket",
            severity=0.1,
            raw_event={"raw": True},
            indicators={"ip": "1.2.3.4"},
        )
        d = event.to_pipeline_dict()
        assert d["cloud"] == "aws"
        assert d["source_ip"] == "1.2.3.4"
        assert d["identity"] == "arn:aws:iam::123456789012:user/alice"
        assert d["action"] == "ConsoleLogin"
        assert d["ip"] == "1.2.3.4"  # indicators merged

    def test_cloud_event_is_immutable(self):
        event = CloudEvent(
            provider=CloudProvider.AZURE,
            event_id="evt-456",
            timestamp="2026-03-29T00:00:00+00:00",
            region="global",
            source_service="sentinel",
            action="BruteForce",
            identity="",
            source_ip="",
            resource="",
            severity=0.5,
            raw_event={},
        )
        with pytest.raises(AttributeError):
            event.severity = 0.9  # type: ignore[misc]

    def test_default_indicators_is_empty_dict(self):
        event = CloudEvent(
            provider=CloudProvider.ORACLE,
            event_id="evt-789",
            timestamp="",
            region="",
            source_service="cloudguard",
            action="",
            identity="",
            source_ip="",
            resource="",
            severity=0.0,
            raw_event={},
        )
        assert event.indicators == {}


# ---------------------------------------------------------------------------
# AWS collector tests
# ---------------------------------------------------------------------------


class TestAwsCollector:
    def test_returns_empty_without_boto3(self):
        from aegis.detection.collectors.aws import AwsCollector

        with patch("aegis.detection.collectors.aws._HAS_BOTO3", False):
            collector = AwsCollector()
            result = asyncio.get_event_loop().run_until_complete(collector.collect())
            assert result == []

    def test_healthcheck_false_without_boto3(self):
        from aegis.detection.collectors.aws import AwsCollector

        with patch("aegis.detection.collectors.aws._HAS_BOTO3", False):
            collector = AwsCollector()
            result = asyncio.get_event_loop().run_until_complete(collector.healthcheck())
            assert result is False

    def test_normalize_cloudtrail_event(self):
        from aegis.detection.collectors.aws import AwsCollector

        collector = AwsCollector()
        raw = {
            "EventId": "ct-001",
            "EventTime": datetime(2026, 3, 29, tzinfo=timezone.utc),
            "EventName": "ConsoleLogin",
            "Username": "alice",
            "Resources": [{"ResourceName": "arn:aws:s3:::bucket"}],
        }
        event = collector._normalize_cloudtrail(raw)
        assert event.provider == CloudProvider.AWS
        assert event.event_id == "ct-001"
        assert event.action == "ConsoleLogin"
        assert event.identity == "alice"
        assert event.source_service == "cloudtrail"
        assert event.severity == 0.1

    def test_normalize_guardduty_finding(self):
        from aegis.detection.collectors.aws import AwsCollector

        collector = AwsCollector()
        finding = {
            "Id": "gd-001",
            "Severity": 6.4,
            "UpdatedAt": "2026-03-29T00:00:00Z",
            "Region": "ap-northeast-2",
            "Type": "Recon:EC2/PortProbeUnprotectedPort",
            "Resource": {"AccessKeyDetails": {"UserName": "bob"}},
            "Service": {
                "Action": {
                    "NetworkConnectionAction": {
                        "RemoteIpDetails": {"IpAddressV4": "5.6.7.8"},
                    },
                },
            },
        }
        event = collector._normalize_guardduty(finding)
        assert event.provider == CloudProvider.AWS
        assert event.source_service == "guardduty"
        assert event.severity == 6.4 / 8.0
        assert event.source_ip == "5.6.7.8"
        assert event.indicators["ip"] == "5.6.7.8"
        assert event.identity == "bob"

    def test_normalize_securityhub_finding(self):
        from aegis.detection.collectors.aws import AwsCollector

        collector = AwsCollector()
        finding = {
            "Id": "sh-001",
            "UpdatedAt": "2026-03-29T00:00:00Z",
            "Region": "ap-northeast-2",
            "Severity": {"Normalized": 70},
            "Types": ["Software and Configuration Checks"],
            "Resources": [{"Id": "arn:aws:ec2:::instance/i-1234"}],
            "CreatedBy": "securityhub",
        }
        event = collector._normalize_securityhub(finding)
        assert event.provider == CloudProvider.AWS
        assert event.source_service == "securityhub"
        assert event.severity == 0.7
        assert event.resource == "arn:aws:ec2:::instance/i-1234"


# ---------------------------------------------------------------------------
# Azure collector tests
# ---------------------------------------------------------------------------


class TestAzureCollector:
    def test_returns_empty_without_azure_sdk(self):
        from aegis.detection.collectors.azure import AzureCollector

        with patch("aegis.detection.collectors.azure._HAS_AZURE", False):
            collector = AzureCollector()
            result = asyncio.get_event_loop().run_until_complete(collector.collect())
            assert result == []

    def test_returns_empty_when_disabled(self):
        from aegis.detection.collectors.azure import AzureCollector

        config = CollectorConfig(azure_enabled=False)
        with patch("aegis.detection.collectors.azure._HAS_AZURE", True):
            collector = AzureCollector(config)
            result = asyncio.get_event_loop().run_until_complete(collector.collect())
            assert result == []

    def test_normalize_incident(self):
        from aegis.detection.collectors.azure import AzureCollector

        collector = AzureCollector()
        incident = MagicMock()
        incident.name = "inc-001"
        incident.last_modified_time_utc = datetime(2026, 3, 29, tzinfo=timezone.utc)
        incident.severity = "High"
        incident.title = "BruteForce attempt"
        incident.owner = MagicMock()
        incident.owner.user_principal_name = "alice@contoso.com"
        incident.id = "/subscriptions/sub1/incidents/inc-001"
        incident.as_dict.return_value = {"mock": True}

        event = collector._normalize_incident(incident)
        assert event.provider == CloudProvider.AZURE
        assert event.source_service == "sentinel"
        assert event.severity == 0.9
        assert event.action == "BruteForce attempt"

    def test_normalize_alert(self):
        from aegis.detection.collectors.azure import AzureCollector

        collector = AzureCollector()
        alert = MagicMock()
        alert.name = "alert-001"
        alert.time_generated = datetime(2026, 3, 29, tzinfo=timezone.utc)
        alert.severity = "Low"
        alert.alert_display_name = "Suspicious SSH activity"
        alert.id = "/subscriptions/sub1/alerts/alert-001"
        alert.entities = []
        alert.as_dict.return_value = {"mock": True}

        event = collector._normalize_alert(alert)
        assert event.provider == CloudProvider.AZURE
        assert event.source_service == "sentinel-alert"
        assert event.severity == 0.3


# ---------------------------------------------------------------------------
# Oracle collector tests
# ---------------------------------------------------------------------------


class TestOracleCollector:
    def test_returns_empty_without_oci_sdk(self):
        from aegis.detection.collectors.oracle import OracleCollector

        with patch("aegis.detection.collectors.oracle._HAS_OCI", False):
            collector = OracleCollector()
            result = asyncio.get_event_loop().run_until_complete(collector.collect())
            assert result == []

    def test_returns_empty_when_disabled(self):
        from aegis.detection.collectors.oracle import OracleCollector

        config = CollectorConfig(oracle_enabled=False)
        with patch("aegis.detection.collectors.oracle._HAS_OCI", True):
            collector = OracleCollector(config)
            result = asyncio.get_event_loop().run_until_complete(collector.collect())
            assert result == []

    def test_normalize_problem(self):
        from aegis.detection.collectors.oracle import OracleCollector

        collector = OracleCollector()
        problem = MagicMock()
        problem.id = "prob-001"
        problem.time_last_detected = datetime(2026, 3, 29, tzinfo=timezone.utc)
        problem.region = "ap-seoul-1"
        problem.detector_rule_id = "PUBLIC_BUCKET"
        problem.target_id = "ocid1.target.oc1"
        problem.resource_id = "ocid1.bucket.oc1"
        problem.resource_type = "Bucket"
        problem.risk_level = "HIGH"
        problem.additional_details = {"sourceIp": "10.0.0.1"}

        event = collector._normalize_problem(problem)
        assert event.provider == CloudProvider.ORACLE
        assert event.source_service == "cloudguard"
        assert event.severity == 0.8
        assert event.source_ip == "10.0.0.1"
        assert event.resource == "Bucket:ocid1.bucket.oc1"


# ---------------------------------------------------------------------------
# CollectorOrchestrator tests
# ---------------------------------------------------------------------------


class TestCollectorOrchestrator:
    def test_build_collectors_respects_config(self):
        from aegis.detection.pipeline import CollectorOrchestrator, DetectionPipeline

        pipeline = DetectionPipeline(analyzers={})

        # Only AWS enabled (default)
        config = CollectorConfig(aws_enabled=True, azure_enabled=False, oracle_enabled=False)
        orch = CollectorOrchestrator(pipeline, config)
        assert len(orch._collectors) == 1
        assert orch._collectors[0].provider == "aws"

        # All enabled
        config_all = CollectorConfig(aws_enabled=True, azure_enabled=True, oracle_enabled=True)
        orch_all = CollectorOrchestrator(pipeline, config_all)
        assert len(orch_all._collectors) == 3

    def test_collect_and_process_with_no_sdks(self):
        """Without cloud SDKs, orchestrator returns empty assessments."""
        from aegis.detection.pipeline import CollectorOrchestrator, DetectionPipeline

        pipeline = DetectionPipeline(analyzers={})
        config = CollectorConfig(aws_enabled=True, azure_enabled=False, oracle_enabled=False)
        orch = CollectorOrchestrator(pipeline, config)

        with patch("aegis.detection.collectors.aws._HAS_BOTO3", False):
            assessments = asyncio.get_event_loop().run_until_complete(
                orch.collect_and_process()
            )
        assert assessments == []


# ---------------------------------------------------------------------------
# CollectorConfig tests
# ---------------------------------------------------------------------------


class TestCollectorConfig:
    def test_defaults(self):
        config = CollectorConfig()
        assert config.aws_enabled is True
        assert config.azure_enabled is False
        assert config.oracle_enabled is False
        assert config.batch_size == 100

    def test_immutable(self):
        config = CollectorConfig()
        with pytest.raises(AttributeError):
            config.aws_enabled = False  # type: ignore[misc]
