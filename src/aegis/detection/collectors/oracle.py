"""Oracle Cloud signal collector — Cloud Guard normalization.

Requires: oci (optional — collector gracefully degrades without it).
Normalizes Oracle Cloud Guard problems/findings into CloudEvent format.
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
    import oci

    _HAS_OCI = True
except ImportError:
    _HAS_OCI = False


class OracleCollector:
    """Collects and normalizes Oracle Cloud Guard security events.

    Sources:
        - Cloud Guard: problems (security findings) and recommendations
    """

    provider = "oracle"

    def __init__(self, config: CollectorConfig | None = None) -> None:
        self._config = config or CollectorConfig()
        self._client: Any = None

    def _get_client(self) -> Any:
        if not _HAS_OCI:
            return None
        if self._client is None:
            config = oci.config.from_file()
            self._client = oci.cloud_guard.CloudGuardClient(config)
        return self._client

    async def collect(self) -> list[CloudEvent]:
        """Collect Cloud Guard problems."""
        if not _HAS_OCI:
            logger.warning("OCI SDK not installed — Oracle collector returning empty")
            return []

        if not self._config.oracle_enabled:
            return []

        try:
            return await self._collect_problems()
        except Exception as exc:
            logger.error("Oracle collector failed: %s", exc)
            return []

    async def healthcheck(self) -> bool:
        """Verify OCI credentials and Cloud Guard access."""
        if not _HAS_OCI:
            return False
        try:
            client = self._get_client()
            if client is None:
                return False
            await asyncio.to_thread(
                client.list_problems,
                compartment_id=self._config.oracle_compartment_id,
                limit=1,
            )
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Cloud Guard problems
    # ------------------------------------------------------------------

    async def _collect_problems(self) -> list[CloudEvent]:
        client = self._get_client()
        if client is None:
            return []

        compartment_id = self._config.oracle_compartment_id
        cutoff = datetime.now(timezone.utc) - timedelta(
            hours=self._config.max_event_age_hours,
        )

        try:
            response = await asyncio.to_thread(
                client.list_problems,
                compartment_id=compartment_id,
                time_last_detected_greater_than_or_equal_to=cutoff,
                lifecycle_state="ACTIVE",
                limit=self._config.batch_size,
            )
        except Exception as exc:
            logger.error("Cloud Guard list_problems failed: %s", exc)
            return []

        events: list[CloudEvent] = []
        for problem in response.data.items if response.data else []:
            events.append(self._normalize_problem(problem))
        return events

    def _normalize_problem(self, problem: Any) -> CloudEvent:
        risk_map = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.2, "MINOR": 0.1}
        risk_level = getattr(problem, "risk_level", "MEDIUM")
        severity = risk_map.get(risk_level, 0.5)

        resource_id = getattr(problem, "resource_id", "")
        resource_type = getattr(problem, "resource_type", "")

        indicators: dict[str, str] = {}
        # Cloud Guard problems may include IP info in additional details
        additional = getattr(problem, "additional_details", {}) or {}
        if isinstance(additional, dict):
            ip = additional.get("sourceIp") or additional.get("source_ip")
            if ip:
                indicators["ip"] = str(ip)

        return CloudEvent(
            provider=CloudProvider.ORACLE,
            event_id=getattr(problem, "id", ""),
            timestamp=_to_iso(getattr(problem, "time_last_detected", None)),
            region=getattr(problem, "region", ""),
            source_service="cloudguard",
            action=getattr(problem, "detector_rule_id", ""),
            identity=getattr(problem, "target_id", ""),
            source_ip=indicators.get("ip", ""),
            resource=f"{resource_type}:{resource_id}" if resource_type else resource_id,
            severity=severity,
            raw_event=_safe_to_dict(problem),
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
    """Best-effort serialization of OCI SDK model to dict."""
    if hasattr(obj, "__dict__"):
        return {
            k: v for k, v in obj.__dict__.items()
            if not k.startswith("_") and not callable(v)
        }
    return {"repr": repr(obj)}
