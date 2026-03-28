"""AWS signal collector — CloudTrail, GuardDuty, SecurityHub normalization.

Requires: boto3 (optional — collector gracefully degrades without it).
Normalizes events from three AWS security services into CloudEvent format.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from aegis.common.config import CollectorConfig
from aegis.common.types import CloudEvent, CloudProvider

logger = logging.getLogger(__name__)

try:
    import boto3
    from botocore.exceptions import ClientError

    _HAS_BOTO3 = True
except ImportError:
    _HAS_BOTO3 = False


class AwsCollector:
    """Collects and normalizes AWS security events.

    Sources:
        - CloudTrail: API call audit logs
        - GuardDuty: threat intelligence findings
        - SecurityHub: aggregated compliance/security findings
    """

    provider = "aws"

    def __init__(self, config: CollectorConfig | None = None) -> None:
        self._config = config or CollectorConfig()
        self._region = self._config.aws_region
        self._clients: dict[str, Any] = {}

    def _get_client(self, service: str) -> Any:
        if not _HAS_BOTO3:
            return None
        if service not in self._clients:
            self._clients[service] = boto3.client(
                service, region_name=self._region,
            )
        return self._clients[service]

    async def collect(self) -> list[CloudEvent]:
        """Collect events from all enabled AWS security services."""
        if not _HAS_BOTO3:
            logger.warning("boto3 not installed — AWS collector returning empty")
            return []

        tasks = [
            self._collect_cloudtrail(),
            self._collect_guardduty(),
            self._collect_securityhub(),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        events: list[CloudEvent] = []
        for result in results:
            if isinstance(result, Exception):
                logger.error("AWS collector sub-task failed: %s", result)
            else:
                events.extend(result)
        return events

    async def healthcheck(self) -> bool:
        """Verify AWS credentials and service access."""
        if not _HAS_BOTO3:
            return False
        try:
            client = self._get_client("sts")
            await asyncio.to_thread(client.get_caller_identity)
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # CloudTrail
    # ------------------------------------------------------------------

    async def _collect_cloudtrail(self) -> list[CloudEvent]:
        client = self._get_client("cloudtrail")
        if client is None:
            return []

        cutoff = datetime.now(timezone.utc) - timedelta(
            hours=self._config.max_event_age_hours,
        )
        try:
            response = await asyncio.to_thread(
                client.lookup_events,
                StartTime=cutoff,
                MaxResults=self._config.batch_size,
            )
        except Exception as exc:
            logger.error("CloudTrail lookup failed: %s", exc)
            return []

        events: list[CloudEvent] = []
        for raw in response.get("Events", []):
            events.append(self._normalize_cloudtrail(raw))
        return events

    def _normalize_cloudtrail(self, raw: dict) -> CloudEvent:
        resources = raw.get("Resources", [{}])
        resource_name = resources[0].get("ResourceName", "") if resources else ""
        return CloudEvent(
            provider=CloudProvider.AWS,
            event_id=raw.get("EventId", ""),
            timestamp=_to_iso(raw.get("EventTime")),
            region=self._region,
            source_service="cloudtrail",
            action=raw.get("EventName", ""),
            identity=raw.get("Username", ""),
            source_ip=raw.get("CloudTrailEvent", {}).get("sourceIPAddress", "")
            if isinstance(raw.get("CloudTrailEvent"), dict)
            else "",
            resource=resource_name,
            severity=0.1,  # CloudTrail events are audit logs, low baseline severity
            raw_event=raw,
        )

    # ------------------------------------------------------------------
    # GuardDuty
    # ------------------------------------------------------------------

    async def _collect_guardduty(self) -> list[CloudEvent]:
        client = self._get_client("guardduty")
        if client is None:
            return []

        try:
            detector_ids = list(self._config.aws_guardduty_detector_ids)
            if not detector_ids:
                resp = await asyncio.to_thread(client.list_detectors)
                detector_ids = resp.get("DetectorIds", [])

            events: list[CloudEvent] = []
            for detector_id in detector_ids:
                findings_resp = await asyncio.to_thread(
                    client.list_findings,
                    DetectorId=detector_id,
                    FindingCriteria={
                        "Criterion": {
                            "updatedAt": {
                                "GreaterThanOrEqual": int(
                                    (
                                        datetime.now(timezone.utc)
                                        - timedelta(hours=self._config.max_event_age_hours)
                                    ).timestamp()
                                    * 1000
                                ),
                            },
                        },
                    },
                    MaxResults=self._config.batch_size,
                )
                finding_ids = findings_resp.get("FindingIds", [])
                if not finding_ids:
                    continue

                detail_resp = await asyncio.to_thread(
                    client.get_findings,
                    DetectorId=detector_id,
                    FindingIds=finding_ids,
                )
                for finding in detail_resp.get("Findings", []):
                    events.append(self._normalize_guardduty(finding))
            return events
        except Exception as exc:
            logger.error("GuardDuty collection failed: %s", exc)
            return []

    def _normalize_guardduty(self, finding: dict) -> CloudEvent:
        severity_raw = finding.get("Severity", 0)
        # GuardDuty severity is 0-8, normalize to [0, 1]
        severity = min(severity_raw / 8.0, 1.0)

        resource = finding.get("Resource", {})
        action_info = finding.get("Service", {}).get("Action", {})
        remote_ip = (
            action_info.get("NetworkConnectionAction", {})
            .get("RemoteIpDetails", {})
            .get("IpAddressV4", "")
        )

        indicators: dict[str, str] = {}
        if remote_ip:
            indicators["ip"] = remote_ip

        return CloudEvent(
            provider=CloudProvider.AWS,
            event_id=finding.get("Id", ""),
            timestamp=finding.get("UpdatedAt", ""),
            region=finding.get("Region", self._region),
            source_service="guardduty",
            action=finding.get("Type", ""),
            identity=finding.get("Resource", {})
            .get("AccessKeyDetails", {})
            .get("UserName", ""),
            source_ip=remote_ip,
            resource=_extract_resource_arn(resource),
            severity=severity,
            raw_event=finding,
            indicators=indicators,
        )

    # ------------------------------------------------------------------
    # SecurityHub
    # ------------------------------------------------------------------

    async def _collect_securityhub(self) -> list[CloudEvent]:
        if not self._config.aws_securityhub_enabled:
            return []

        client = self._get_client("securityhub")
        if client is None:
            return []

        cutoff = datetime.now(timezone.utc) - timedelta(
            hours=self._config.max_event_age_hours,
        )
        try:
            response = await asyncio.to_thread(
                client.get_findings,
                Filters={
                    "UpdatedAt": [
                        {
                            "Start": cutoff.isoformat(),
                            "End": datetime.now(timezone.utc).isoformat(),
                        },
                    ],
                    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                },
                MaxResults=self._config.batch_size,
            )
        except Exception as exc:
            logger.error("SecurityHub collection failed: %s", exc)
            return []

        events: list[CloudEvent] = []
        for finding in response.get("Findings", []):
            events.append(self._normalize_securityhub(finding))
        return events

    def _normalize_securityhub(self, finding: dict) -> CloudEvent:
        # ASFF normalized severity: 0-100
        severity_raw = (
            finding.get("Severity", {}).get("Normalized", 0)
        )
        severity = min(severity_raw / 100.0, 1.0)

        resources = finding.get("Resources", [{}])
        resource_id = resources[0].get("Id", "") if resources else ""

        return CloudEvent(
            provider=CloudProvider.AWS,
            event_id=finding.get("Id", ""),
            timestamp=finding.get("UpdatedAt", ""),
            region=finding.get("Region", self._region),
            source_service="securityhub",
            action=finding.get("Types", [""])[0] if finding.get("Types") else "",
            identity=finding.get("CreatedBy", ""),
            source_ip="",
            resource=resource_id,
            severity=severity,
            raw_event=finding,
        )


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _to_iso(dt: Any) -> str:
    """Convert datetime-like value to ISO 8601 string."""
    if isinstance(dt, datetime):
        return dt.isoformat()
    return str(dt) if dt else ""


def _extract_resource_arn(resource: dict) -> str:
    """Best-effort ARN extraction from GuardDuty resource block."""
    for key in ("InstanceDetails", "S3BucketDetails", "EksClusterDetails"):
        detail = resource.get(key)
        if isinstance(detail, dict) and "Arn" in detail:
            return detail["Arn"]
        if isinstance(detail, list) and detail and "Arn" in detail[0]:
            return detail[0]["Arn"]
    return ""
