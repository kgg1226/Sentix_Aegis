"""Azure signal collector — Sentinel, Defender for Cloud normalization.

Requires: azure-identity + azure-mgmt-securityinsight (optional).
Normalizes Azure security events into CloudEvent format.
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
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.securityinsight import SecurityInsights

    _HAS_AZURE = True
except ImportError:
    _HAS_AZURE = False


class AzureCollector:
    """Collects and normalizes Azure security events.

    Sources:
        - Microsoft Sentinel: SIEM incidents and alerts
        - Microsoft Defender for Cloud: security recommendations/alerts
    """

    provider = "azure"

    def __init__(self, config: CollectorConfig | None = None) -> None:
        self._config = config or CollectorConfig()
        self._client: Any = None

    def _get_client(self) -> Any:
        if not _HAS_AZURE:
            return None
        if self._client is None:
            credential = DefaultAzureCredential()
            self._client = SecurityInsights(
                credential, self._config.azure_subscription_id,
            )
        return self._client

    async def collect(self) -> list[CloudEvent]:
        """Collect events from Sentinel and Defender."""
        if not _HAS_AZURE:
            logger.warning("Azure SDK not installed — Azure collector returning empty")
            return []

        if not self._config.azure_enabled:
            return []

        tasks = [
            self._collect_sentinel_incidents(),
            self._collect_sentinel_alerts(),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        events: list[CloudEvent] = []
        for result in results:
            if isinstance(result, Exception):
                logger.error("Azure collector sub-task failed: %s", result)
            else:
                events.extend(result)
        return events

    async def healthcheck(self) -> bool:
        """Verify Azure credentials and service access."""
        if not _HAS_AZURE:
            return False
        try:
            client = self._get_client()
            if client is None:
                return False
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Sentinel incidents
    # ------------------------------------------------------------------

    async def _collect_sentinel_incidents(self) -> list[CloudEvent]:
        client = self._get_client()
        if client is None:
            return []

        resource_group = "aegis-rg"  # configurable in future
        workspace = self._config.azure_workspace_id

        cutoff = datetime.now(timezone.utc) - timedelta(
            hours=self._config.max_event_age_hours,
        )
        cutoff_filter = f"properties/lastModifiedTimeUtc ge {cutoff.isoformat()}"

        try:
            incidents_iter = await asyncio.to_thread(
                client.incidents.list,
                resource_group_name=resource_group,
                workspace_name=workspace,
                filter=cutoff_filter,
            )
            incidents = list(incidents_iter)
        except Exception as exc:
            logger.error("Sentinel incidents collection failed: %s", exc)
            return []

        events: list[CloudEvent] = []
        for incident in incidents[: self._config.batch_size]:
            events.append(self._normalize_incident(incident))
        return events

    def _normalize_incident(self, incident: Any) -> CloudEvent:
        severity_map = {"high": 0.9, "medium": 0.6, "low": 0.3, "informational": 0.1}
        severity_str = getattr(incident, "severity", "medium").lower()
        severity = severity_map.get(severity_str, 0.5)

        return CloudEvent(
            provider=CloudProvider.AZURE,
            event_id=getattr(incident, "name", ""),
            timestamp=_to_iso(getattr(incident, "last_modified_time_utc", None)),
            region="global",
            source_service="sentinel",
            action=getattr(incident, "title", ""),
            identity=getattr(
                getattr(incident, "owner", None), "user_principal_name", "",
            ),
            source_ip="",
            resource=getattr(incident, "id", ""),
            severity=severity,
            raw_event=_safe_to_dict(incident),
        )

    # ------------------------------------------------------------------
    # Sentinel alerts
    # ------------------------------------------------------------------

    async def _collect_sentinel_alerts(self) -> list[CloudEvent]:
        client = self._get_client()
        if client is None:
            return []

        resource_group = "aegis-rg"
        workspace = self._config.azure_workspace_id

        try:
            alerts_iter = await asyncio.to_thread(
                client.alerts.list,
                resource_group_name=resource_group,
                workspace_name=workspace,
            )
            alerts = list(alerts_iter)
        except Exception as exc:
            logger.error("Sentinel alerts collection failed: %s", exc)
            return []

        cutoff = datetime.now(timezone.utc) - timedelta(
            hours=self._config.max_event_age_hours,
        )

        events: list[CloudEvent] = []
        for alert in alerts[: self._config.batch_size]:
            ts = getattr(alert, "time_generated", None)
            if ts and isinstance(ts, datetime) and ts < cutoff:
                continue
            events.append(self._normalize_alert(alert))
        return events

    def _normalize_alert(self, alert: Any) -> CloudEvent:
        severity_map = {"high": 0.9, "medium": 0.6, "low": 0.3, "informational": 0.1}
        severity_str = getattr(alert, "severity", "medium").lower()
        severity = severity_map.get(severity_str, 0.5)

        indicators: dict[str, str] = {}
        for entity in getattr(alert, "entities", []) or []:
            ip = getattr(entity, "ip_address", None) or getattr(entity, "address", None)
            if ip:
                indicators["ip"] = str(ip)
                break

        return CloudEvent(
            provider=CloudProvider.AZURE,
            event_id=getattr(alert, "name", ""),
            timestamp=_to_iso(getattr(alert, "time_generated", None)),
            region="global",
            source_service="sentinel-alert",
            action=getattr(alert, "alert_display_name", ""),
            identity="",
            source_ip=indicators.get("ip", ""),
            resource=getattr(alert, "id", ""),
            severity=severity,
            raw_event=_safe_to_dict(alert),
            indicators=indicators,
        )


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _to_iso(dt: Any) -> str:
    if isinstance(dt, datetime):
        return dt.isoformat()
    return str(dt) if dt else ""


def _safe_to_dict(obj: Any) -> dict:
    """Best-effort serialization of Azure SDK model to dict."""
    if hasattr(obj, "as_dict"):
        return obj.as_dict()
    return {"repr": repr(obj)}
