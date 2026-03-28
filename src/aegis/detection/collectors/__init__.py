"""L0 cloud signal collectors.

Each collector normalizes provider-specific security events into CloudEvent
instances that the detection pipeline can process uniformly.
"""

from __future__ import annotations

from typing import Protocol, Sequence

from aegis.common.types import CloudEvent


class Collector(Protocol):
    """Interface all cloud collectors must satisfy."""

    provider: str

    async def collect(self) -> list[CloudEvent]: ...

    async def healthcheck(self) -> bool: ...
