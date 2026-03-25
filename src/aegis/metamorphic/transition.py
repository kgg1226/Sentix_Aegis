"""Blue-green form transition.

Ensures zero defense gap during form switching.
New form spins up in parallel, traffic migrates, old form tears down.
Rollback on degradation.
"""
from __future__ import annotations
import asyncio
from dataclasses import dataclass
from enum import Enum, auto
from aegis.common.types import Genome
from aegis.metamorphic.compiler import TopologyConfig, compile_genome

class TransitionState(Enum):
    IDLE = auto()
    PREPARING = auto()
    MIGRATING = auto()
    VALIDATING = auto()
    COMPLETE = auto()
    ROLLED_BACK = auto()

@dataclass
class TransitionResult:
    state: TransitionState
    old_topology: TopologyConfig | None
    new_topology: TopologyConfig | None
    duration_ms: float
    rollback_reason: str | None = None

class FormTransitioner:
    def __init__(self) -> None:
        self._state = TransitionState.IDLE
        self._current_genome: Genome | None = None

    @property
    def state(self) -> TransitionState:
        return self._state

    async def transition(self, old: Genome, new: Genome) -> TransitionResult:
        old_topo = compile_genome(old)
        new_topo = compile_genome(new)
        self._state = TransitionState.PREPARING
        # Phase 1: spin up new topology in parallel
        await asyncio.sleep(0)  # Placeholder for real infra provisioning
        self._state = TransitionState.MIGRATING
        # Phase 2: migrate traffic
        await asyncio.sleep(0)
        self._state = TransitionState.VALIDATING
        # Phase 3: validate new topology performance
        valid = self._validate(new_topo)
        if not valid:
            self._state = TransitionState.ROLLED_BACK
            return TransitionResult(
                state=self._state, old_topology=old_topo, new_topology=new_topo,
                duration_ms=0.0, rollback_reason="Validation failed",
            )
        self._state = TransitionState.COMPLETE
        self._current_genome = new
        return TransitionResult(
            state=self._state, old_topology=old_topo, new_topology=new_topo,
            duration_ms=0.0,
        )

    def _validate(self, topo: TopologyConfig) -> bool:
        # Placeholder: real validation checks health endpoints
        return topo.sensor_coverage > 0.05
